/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-17 09:44:46 macan>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "hvfs.h"
#include "xnet.h"
#include "mds.h"
#include "lib.h"
#include "ring.h"

#define HVFS_MDS_REDO_LOG       "redo"

struct redo_logger_local_queue
{
    struct list_head head1, head2;
    union 
    {
        struct list_head *open;
        u64 __open;
    };
    union 
    {
        struct list_head *wb;
        u64 __wb;
    };
    xlock_t lock;
};

struct redo_logger_queue
{
    struct list_head head;
    xlock_t lock;
};

struct redo_logger
{
    /* redo log file's fd */
    xlock_t rlfd_lock;
    int rlfd;
    int reap_interval;
    
    /* select N - 1 random remote nodes to replicate */
    u64 *replica_sites;         /* which site to send */
    u64 *replicated_sites;      /* which site to notify recovery */
    int replica_nr;
    int replicated_nr;
    atomic64_t g_id;            /* global redo log entry id */

    /* profilings */
    atomic64_t client_redo_nr;   /* client redo log entry NR */
    atomic64_t in_rep_redo_nr;   /* incoming replicated redo log entry NR */
    atomic64_t reap_rep_redo_nr; /* reaped replicated redo log entry NR */

    pthread_t thread;
    int thread_stop:1;
    int is_active:1;
    sem_t sem;
    struct redo_logger_local_queue rllq;
    struct redo_logger_queue *rlq;
};

#define GET_REDO_LOG_ID() atomic64_inc_return(&g_rl.g_id)
#define READ_REDO_LOG_ID() atomic64_read(&g_rl.g_id)

static struct redo_logger g_rl;

u64 get_redo_prof(int type)
{
    switch (type) {
    case REDO_PROF_CLIENT:
        return atomic64_read(&g_rl.client_redo_nr);
    default:
        return 0;
    }
}

static inline
struct xnet_group *__get_active_site(struct chring *r)
{
    struct xnet_group *xg = NULL;
    int i, __UNUSED__ err;

    for (i = 0; i < r->used; i++) {
        err = xnet_group_add(&xg, r->array[i].site_id);
    }

    return xg;
}

/* send a reply message
 */
int __send_reply(struct xnet_msg *msg, int err, void *data, int dlen)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (err) {
        xnet_msg_set_err(rpy, err);
    } else if (dlen > 0)
        xnet_msg_add_sdata(rpy, data, dlen);

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(mds, "HA reply to site %lx failed w/ %d\n",
                 msg->tx.ssite_id, err);
        goto out_free_msg;
    }

out_free_msg:
    xnet_free_msg(rpy);
out:
    return err;
}

struct xnet_msg *__get_reply_msg(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        return NULL;
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    return rpy;
}

void __send_reply_msg(struct xnet_msg *rpy)
{
    int err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(mds, "HA reply to site %lx failed w/ %d\n",
                 rpy->tx.dsite_id, err);
    }
}

/* send a reap request
 */
int __send_reap(u64 txg, u64 dsite)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS_HA, HA_REAP, txg);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "HA reap request to site %lx failed w/ %d\n",
                 dsite, err);
        goto out_free_msg;
    }

out_free_msg:
    xnet_free_msg(msg);
out:
    return err;
}

/* reap log_site entries
 */
int __reap_log_entry(u64 txg)
{
    int i;

    if (hmo.aux_state < HMO_AUX_STATE_HA)
        return 0;

    for (i = 0; i < g_rl.replica_nr - 1; i++) {
        /* FIXME: this should be an isend */
        __send_reap(txg, g_rl.replica_sites[i]);
    }

    return 0;
}

/* do reap on replicated memory queue
 *
 * @site: which site to reap
 * @txg: reap to which txg
 */
void __do_reap_log_entry(u64 site, u64 txg)
{
    struct redo_log_site *pos, *n;
    int i;
    
    for (i = 0; i < g_rl.replicated_nr; i++) {
        if (g_rl.replicated_sites[i] == site) {
            xlock_lock(&g_rl.rlq[i].lock);
            list_for_each_entry_safe(pos, n, &g_rl.rlq[i].head, list) {
                if (pos->rlsd.rle.txg <= txg) {
                    list_del(&pos->list);
                    xfree(pos);
                    atomic64_inc(&g_rl.reap_rep_redo_nr);
                }
            }
            xlock_unlock(&g_rl.rlq[i].lock);
            break;
        }
    }
}

int do_reap_log_entry(struct xnet_msg *msg)
{
    __do_reap_log_entry(msg->tx.ssite_id, msg->tx.arg1);
    
    /* send a ok reply */
    __send_reply(msg, 0, NULL, 0);
    
    xnet_free_msg(msg);

    return 0;
}

/* truncate the redo log file, protect EINTR error
 */
int __trunc_log_file(void)
{
    int err = 0;
    
    if (g_rl.rlfd <= 0)
        return -EINVAL;

    do {
        xlock_lock(&g_rl.rlfd_lock);
        err = ftruncate(g_rl.rlfd, 0);
        err = err < 0 ? -errno : 0;
        /* seek to file head */
        if (lseek(g_rl.rlfd, 0, SEEK_SET) < 0) {
            hvfs_err(mds, "lseek redo log head failed w/ %d\n", errno);
        }
        xlock_unlock(&g_rl.rlfd_lock);
        if (err) {
            hvfs_err(mds, "ftruncate redo log file failed w/ %d\n", err);
        }
    } while (err == -EINTR);

    return err;
}

/* write the redo log file
 */
void __write_log_entry(struct redo_log_site *rls)
{
    int cnt = 0, bl, bw;

    if (g_rl.rlfd <= 0)
        return;

    bl = 0;
    xlock_lock(&g_rl.rlfd_lock);
    do {
        bw = write(g_rl.rlfd, (void *)&rls->rlsd + bl, 
                   sizeof(rls->rlsd) - bl);
        if (bw < 0) {
            hvfs_err(mds, "write redo log file failed w/ %d\n", errno);
            goto out;
        }
        bl += bw;
    } while (bl < sizeof(rls->rlsd));

    bl = 0;
retry:
    do {
        bw = write(g_rl.rlfd, (void *)rls + sizeof(*rls) + bl, 
                   rls->rlsd.rle.len - bl);
        if (bw < 0) {
            hvfs_err(mds, "write redo log file failed w/ %d, corrupted!\n", 
                     errno);
            cnt++;
            if (cnt <= 5)
                goto retry;
            else {
                int err = 0;
                
                hvfs_err(mds, "Completely corrupted file, truncate it!\n");

                if ((err = ftruncate(g_rl.rlfd, 0)) < 0) {
                    hvfs_err(mds, "truncate file failed w/ %d (%s)!\n",
                             err, strerror(err));
                }
                goto out;
            }            
        }
        bl += bw;
    } while (bl < rls->rlsd.rle.len);
    
out:
    xlock_unlock(&g_rl.rlfd_lock);
    return;
}

void *redo_logger_main(void *arg)
{
    sigset_t set;
    struct redo_log_site *pos, *n;
    struct xnet_msg *msg;
    u64 last_commited_txg;
    u64 last_txg = 1;
    u32 last_id = 0, from_id = 0;
    int err, nr;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    while (!g_rl.thread_stop) {
        err = sem_wait(&g_rl.sem);
        if (err == EINTR)
            continue;
        if (hmo.state < HMO_STATE_RUNNING)
            continue;
        /* cleanup the committed entry and replicate remain entry */
        last_commited_txg = hmo.txg[TXG_OPEN]->txg;
        if (hmo.txg[TXG_WB]) {
            last_commited_txg -= 2;
        } else {
            last_commited_txg -= 1;
        }
        
        /* Step 1: clean local commited entry */
        list_for_each_entry_safe(pos, n, g_rl.rllq.wb, list) {
            if (pos->rlsd.rle.txg <= last_commited_txg) {
                list_del(&pos->list);
                xfree(pos);
            }
        }

        /* Step 2: clean replicated commited entry */
        __reap_log_entry(last_commited_txg);

        /* Step 3: write remain entry */
        msg = __prepare_replicate_log_entry();
        if (!msg) {
            /* do NOT write back any entries */
            continue;
        }
        
        from_id = last_id;
        if (last_txg <= last_commited_txg) {
            /* last written txg has been commited, truncate and write remain
             * entries */
            __trunc_log_file();
            last_txg = last_commited_txg + 1;
            last_id = 0;
            list_for_each_entry_safe(pos, n, g_rl.rllq.wb, list) {
                if (pos->rlsd.rle.txg >= last_txg &&
                    pos->rlsd.rle.id > last_id) {
                    err = __construct_replicate_log_entry(msg, pos);
                    if (err)
                        break;
                    __write_log_entry(pos);

                    last_txg = pos->rlsd.rle.txg;
                    last_id = pos->rlsd.rle.id;
                }
            }
        } else {
            /* last written txg has not been commited yet, continue written
             * back */
            list_for_each_entry_safe(pos, n, g_rl.rllq.wb, list) {
                if (pos->rlsd.rle.txg >= last_txg &&
                    pos->rlsd.rle.id > last_id) {
                    err = __construct_replicate_log_entry(msg, pos);
                    if (err)
                        break;
                    __write_log_entry(pos);

                    last_txg = pos->rlsd.rle.txg;
                    last_id = pos->rlsd.rle.id;
                }
            }
        }
        nr = (int)msg->tx.arg1;
        __replicate_log_entry(msg);

        if (nr > 0)
            hvfs_info(mds, "Commit/Rep %d entries to TXG:ID "
                      "<%ld,<%d,%d>> => [%ld] last_commit_txg %ld\n",
                      nr, last_txg, from_id, last_id, READ_REDO_LOG_ID(),
                      last_commited_txg);

        /* free the wb list until we got STOP entry */
        list_for_each_entry_safe(pos, n, g_rl.rllq.wb, list) {
            if (pos->rlsd.rle.txg <= last_txg &&
                pos->rlsd.rle.id <= last_id) {
                /* ok, it can be freed */
                list_del(&pos->list);
                xfree(pos);
            }
        }

        /* xchg the pointer, nobody should access wb pointer, thus save it
         * first */
        if (list_empty(g_rl.rllq.wb)) {
            xlock_lock(&g_rl.rllq.lock);
            g_rl.rllq.__wb ^= g_rl.rllq.__open;
            g_rl.rllq.__open ^= g_rl.rllq.__wb;
            g_rl.rllq.__wb ^= g_rl.rllq.__open;
            /* after xchg the pointer, nobody can still access the old
             * open queue. */
            xlock_unlock(&g_rl.rllq.lock);
        }
    }
    pthread_exit(NULL);
}

/* read in the log from disk or other mds. make a decision whether we should
 * redo something
 */
int redo_log_recovery_check(int fd)
{
    int br = 0;
    int test;
    
    if (fd <= 0)
        return 0;

    /* this is the first read, do not need to seek */
    br = read(fd, &test, sizeof(test));
    if (br > 0) {
        /* ok, this means we may need a redo log recovery, setup the state */
        hmo.aux_state |= HMO_AUX_STATE_RECOVER;
        return 1;
    }

    return 0;
}

#define NEXT_SITE(idx, xg) ({                   \
            idx++;                              \
            if (idx >= xg->asize)               \
                idx = 0;                        \
            idx;                                \
        })

int redo_log_init(struct chring *r, int replica_nr)
{
    char path[256];
    struct xnet_group *xg;
    pthread_attr_t attr;
    int err = 0, stacksize, i, j, e = 0;
    
    memset(&g_rl, 0, sizeof(g_rl));
    atomic64_set(&g_rl.g_id, 1); /* always count from 1 */
    atomic64_set(&g_rl.client_redo_nr, 0);
    atomic64_set(&g_rl.in_rep_redo_nr, 0);
    atomic64_set(&g_rl.reap_rep_redo_nr, 0);
    g_rl.is_active = 1;

    /* get the reap interval from EV */
    {
        char *value = getenv("redo_log_reap_interval");
        if (value)
            g_rl.reap_interval = atoi(value);
        if (!g_rl.reap_interval)
            g_rl.reap_interval = 5; /* default to 5 seconds */
    }
    
    /* make sure the dir exists */
    err = mds_dir_make_exist(hmo.conf.mds_home);
    if (err) {
        hvfs_err(mds, "dir %s does not exist %d.\n", hmo.conf.mds_home, err);
        return -ENOTEXIST;
    }
    sprintf(path, "%s/%lx", hmo.conf.mds_home, hmo.site_id);
    err = mds_dir_make_exist(path);
    if (err) {
        hvfs_err(mds, "dir %s does not exist %d.\n", path, err);
        return -ENOTEXIST;
    }

    /* open the redo log file, if it doesn't exist, just create it */
    xlock_init(&g_rl.rlfd_lock);
    sprintf(path, "%s/%lx/redo_log", hmo.conf.mds_home, hmo.site_id);
    g_rl.rlfd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (g_rl.rlfd < 0) {
        hvfs_err(mds, "open file '%s' failed w/ %d\n", path, errno);
        return -errno;
    }
    err = redo_log_recovery_check(g_rl.rlfd);
    hvfs_warning(mds, "MDS %lx log recovery return %s\n",
                 hmo.site_id,
                 (err == 0 ? "CLEAN" : (err == 1 ? "DIRTY" : "UNKNOWN")));

    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(mds, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hmo.conf.stacksize > (1 << 20) ?
                 hmo.conf.stacksize : (2 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(mds, "set thread stack size to %d failed w/ %d\n",
                 stacksize, err);
        goto out;
    }

    if (replica_nr < 1) {
        err = -EINVAL;
        goto out;
    } else if (replica_nr >= 2) {
        g_rl.replica_sites = xzalloc((replica_nr - 1)* sizeof(u64));
        if (!g_rl.replica_sites) {
            hvfs_err(mds, "xzalloc() relica_sites' array failed\n");
            err = -ENOMEM;
            goto out;
        }

        /* select replicas */
        xg = __get_active_site(r);
        if (!xg) {
            hvfs_warning(mds, "Only use local logger, not HA now!\n");
            replica_nr = 1;
        } else {
            if (replica_nr > xg->asize) {
                /* this means that user defined replica is larger than active
                 * site group, we decrease the replica_nr */
                replica_nr = xg->asize;
            }

            /* select next replica_nr - 1 sites from xg group for load
             * balance */
            for (i = 0; i < xg->asize; i++) {
                if (xg->sites[i].site_id == hmo.site_id) {
                    e = i;
                    break;
                }
            }
            
            for (i = 0; i < replica_nr - 1; i++) {
            reselect:
                e = NEXT_SITE(e, xg);
                if (xg->sites[e].site_id == hmo.site_id)
                    goto reselect;
                for (j = 0; j < i; j++) {
                    if (xg->sites[e].site_id == g_rl.replica_sites[j]) {
                        /* conflict, reselect */
                        goto reselect;
                    }
                }
                g_rl.replica_sites[i] = xg->sites[e].site_id;
                hvfs_info(mds, "Select site %lx as my replica <%d/%d>.\n",
                          xg->sites[e].site_id, i, replica_nr - 1);
            }
        }
    } else {
        g_rl.is_active = 0;
    }

    hvfs_info(mds, "Setting up %d replica(s) for site %lx\n", 
              replica_nr - 1, hmo.site_id);

    /* set the replica_nr */
    g_rl.replica_nr = replica_nr;

    /* setup local logger */
    INIT_LIST_HEAD(&g_rl.rllq.head1);
    INIT_LIST_HEAD(&g_rl.rllq.head2);
    g_rl.rllq.open = &g_rl.rllq.head1;
    g_rl.rllq.wb = &g_rl.rllq.head2;
    xlock_init(&g_rl.rllq.lock);
    
    g_rl.rlq = NULL;

    /* setup a standalone thread to check and replicate */
    g_rl.thread_stop = 0;
    sem_init(&g_rl.sem, 0, 0);
    err = pthread_create(&g_rl.thread, &attr, redo_logger_main,
                         NULL);
    if (err) {
        hvfs_err(mds, "pthread_create() failed w/ %d\n", err);
        goto out;
    }

    /* finalize and update hmo aux state */
    if (replica_nr > 1)
        hmo.aux_state |= HMO_AUX_STATE_HA;
    else
        hmo.aux_state |= HMO_AUX_STATE_LOGGER;

out:
    if (err) {
        /* do cleanups */
        xfree(g_rl.replica_sites);
    }

    return err;
}

void redo_log_destroy(void)
{
    hvfs_info(mds, "Free redo resources.\n");
    /* truncate redo log file */
    __trunc_log_file();
    close(g_rl.rlfd);
}

/* alloc and add a log_site entry (client)
 *
 * NOTE that, this interface will IGNORE argument: id!
 */
static inline
struct redo_log_site *__add_cli_log_entry(
    struct redo_logger_local_queue *rllq, 
    u64 txg, u32 id, u16 op, 
    u32 dlen, struct hvfs_index *hi, 
    void *data)
{
    struct redo_log_site *rls = NULL;
    
    rls = xzalloc(sizeof(*rls) + dlen);
    if (!rls) {
        hvfs_err(mds, "xzalloc() redo_log_site failed\n");
        goto out;
    }
    INIT_LIST_HEAD(&rls->list);
    rls->rlsd.rle.txg = txg;
    rls->rlsd.rle.op = op;
    rls->rlsd.rle.len = dlen;
    rls->rlsd.u.rlc.hi = *hi;
    memcpy((void *)rls + sizeof(*rls), data, dlen);

    if (!rllq)
        rllq = &g_rl.rllq;
    
    xlock_lock(&rllq->lock);
    rls->rlsd.rle.id = GET_REDO_LOG_ID();
    list_add_tail(&rls->list, rllq->open);
    xlock_unlock(&rllq->lock);

out:
    return rls;
}

/* internal counter
 */
void __DO_SEMPOST()
{
    static int nr = 0;

    if (++nr >> 8 > 0) {
        sem_post(&g_rl.sem);
        nr = 0;
    }
}

/* Called by source site
 */
struct redo_log_site *add_cli_log_entry(u64 txg, u32 id, u16 op,
                                        u32 dlen, struct hvfs_index *hi,
                                        void *data)
{
    struct redo_log_site *rls;

    if (hmo.state < HMO_STATE_RUNNING || !g_rl.is_active)
        return NULL;
    
    rls = __add_cli_log_entry(NULL, txg, id, op, dlen, hi, data);

    __DO_SEMPOST();
    atomic64_inc(&g_rl.client_redo_nr);
    
    return rls;
}

/* Called by source site (for create)
 */
struct redo_log_site *add_create_log_entry(u64 txg, u32 dlen,
                                           struct hvfs_index *hi,
                                           void *data,
                                           struct hvfs_md_reply *hmr)
{
    struct redo_log_site *rls;
    struct gdt_md *go = data, *gi;

    if (hmo.state < HMO_STATE_RUNNING || !g_rl.is_active)
        return NULL;
    
    if (hi->flag & INDEX_CREATE_GDT) {
        /* save hmr info to data region */
        if (go && hmr && hmr->data) {
            gi = hmr->data + sizeof(*hi);
            go->puuid = gi->puuid;
            go->salt = gi->salt;
            go->psalt = gi->psalt;
        }
    }
    rls = __add_cli_log_entry(NULL, txg, 0, LOG_CLI_CREATE, dlen, 
                              hi, data);

    __DO_SEMPOST();
    atomic64_inc(&g_rl.client_redo_nr);
    
    return rls;
}

/* called by source site (for ausplit)
 */
struct redo_log_site *add_ausplit_log_entry(u64 txg, u64 ssite, u32 dlen,
                                            void *data)
{
    struct redo_log_site *rls = NULL;

    if (hmo.state < HMO_STATE_RUNNING || !g_rl.is_active)
        return NULL;

    rls = xzalloc(sizeof(*rls) + dlen);
    if (!rls) {
        hvfs_err(mds, "xzalloc() redo_log_site failed\n");
        goto out;
    }
    INIT_LIST_HEAD(&rls->list);
    rls->rlsd.rle.txg = txg;
    rls->rlsd.rle.op = LOG_CLI_AUSPLIT;
    rls->rlsd.rle.len = dlen;
    rls->rlsd.u.rla.ssite = ssite;
    memcpy((void *)rls + sizeof(*rls), data, dlen);
    
    xlock_lock(&g_rl.rllq.lock);
    rls->rlsd.rle.id = GET_REDO_LOG_ID();
    list_add_tail(&rls->list, g_rl.rllq.open);
    hvfs_err(mds, "add ausplit entry txg %ld id %u to %p\n", 
             txg, rls->rlsd.rle.id, g_rl.rllq.open);
    xlock_unlock(&g_rl.rllq.lock);

    __DO_SEMPOST();
    atomic64_inc(&g_rl.client_redo_nr);

out:
    return rls;
}

/* alloc and add a log_site entry (generally)
 */
struct redo_log_site *__add_log_entry(struct redo_logger_queue *rlq,
                                      u64 txg, u32 id, u16 op,
                                      u32 dlen, void *u,
                                      void *data)
{
    struct redo_log_site *rls = NULL;

    if (!rlq)
        return NULL;

    rls = xzalloc(sizeof(*rls) + dlen);
    if (!rls) {
        hvfs_err(mds, "xzalloc() redo_log_site failed\n");
        goto out;
    }
    INIT_LIST_HEAD(&rls->list);
    rls->rlsd.rle.txg = txg;
    rls->rlsd.rle.id = id;
    rls->rlsd.rle.op = op;
    rls->rlsd.rle.len = dlen;
    memcpy(&rls->rlsd.u, u, sizeof(rls->rlsd.u));
    memcpy((void *)rls + sizeof(*rls), data, dlen);

    xlock_lock(&rlq->lock);
    list_add_tail(&rls->list, &rlq->head);
    xlock_unlock(&rlq->lock);

out:
    return rls;
}

/* send a log_site entry
 */
int __send_log_entry(struct xnet_msg *msg, u64 dsite)
{
    int err = 0;

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.site_id, dsite);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "HA request to site %lx failed w/ %d\n",
                 dsite, err);
        goto out;
    }
    hvfs_debug(mds, "Send a replicate request to site %lx nr %ld\n",
               dsite, msg->tx.arg1);

    /* it is ok to get here */
    xnet_free_msg(msg->pair);
    msg->pair = NULL;

out:
    return err;
}

/* prepare a batch replicate
 *
 * ABI: tx.arg1 => # of RLS
 *      xm_data => RLSs
 */
struct xnet_msg *__prepare_replicate_log_entry(void)
{
    struct xnet_msg *msg;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        return NULL;
    }
    xnet_msg_fill_cmd(msg, HVFS_MDS_HA, HA_REPLICATE, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    return msg;
}

/* construct a batch replicate request
 */
int __construct_replicate_log_entry(struct xnet_msg *msg, 
                                    struct redo_log_site *rls)
{
    int err = 0;
    
    /* remember how many RLS we sent */
    err = xnet_msg_add_sdata(msg, &rls->rlsd, sizeof(rls->rlsd));
    if (!err && rls->rlsd.rle.len > 0)
        err = xnet_msg_add_sdata(msg, (void *)rls + sizeof(*rls), 
                                 rls->rlsd.rle.len);
    if (!err)
        msg->tx.arg1++;
    else
        return err;

    return 0;
}

/* replicate a log_site entry in batch mode
 */
int __replicate_log_entry(struct xnet_msg *msg)
{
    int i;
    
    if (!(hmo.aux_state & HMO_AUX_STATE_HA))
        goto out;
    if (!msg->tx.arg1)
        goto out;

    for (i = 0; i < g_rl.replica_nr - 1; i++) {
        /* FIXME: this should be an isend */
        __send_log_entry(msg, g_rl.replica_sites[i]);
    }

out:
    xnet_free_msg(msg);

    return 0;
}

/* do replicate on replicated memory queue
 */
int do_replicate_log_entry(struct xnet_msg *msg)
{
    struct redo_log_site_disk *rlsd;
    int i, found = -1, err = 0;

    /* sanity checking */
    if (msg->tx.len < msg->tx.arg1 * sizeof(*rlsd)) {
        hvfs_err(mds, "Invalid replication request from site %lx\n",
                 msg->tx.ssite_id);
        err = -EINVAL;
        goto out_free;
    }
    
    for (i = 0; i < g_rl.replicated_nr; i++) {
        if (g_rl.replicated_sites[i] == msg->tx.ssite_id) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        /* add a new replicated site entry now */
        u64 *new_site_array;
        struct redo_logger_queue *new_queue;

        new_site_array = xrealloc(g_rl.replicated_sites, 
                                  (g_rl.replicated_nr + 1) * sizeof(u64));
        if (!new_site_array) {
            hvfs_err(mds, "xrealloc() replicated site entry failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        g_rl.replicated_sites = new_site_array;
        g_rl.replicated_sites[g_rl.replicated_nr] = msg->tx.ssite_id;

        new_queue = xrealloc(g_rl.rlq, (g_rl.replicated_nr + 1) *
                             sizeof(struct redo_logger_queue));
        if (!new_queue) {
            hvfs_err(mds, "xrealloc() replicated site queue failed\n");
            err = -ENOMEM;
            goto out_free;
        }

        /* update pointer and nr */
        g_rl.replicated_nr++;
        g_rl.rlq = new_queue;

        memset(&g_rl.rlq[g_rl.replicated_nr - 1], 0, 
               sizeof(struct redo_logger_queue));
        xlock_init(&g_rl.rlq[g_rl.replicated_nr - 1].lock);
        INIT_LIST_HEAD(&g_rl.rlq[g_rl.replicated_nr - 1].head);

        found = g_rl.replicated_nr - 1;
    }

    /* alloc and add a log_site entry */
    rlsd = msg->xm_data;

    /* FIXME: make sure we are in-order inserting! */
    for (i = 0; i < msg->tx.arg1; i++) {
        __add_log_entry(&g_rl.rlq[found], rlsd->rle.txg,
                        rlsd->rle.id,
                        rlsd->rle.op,
                        rlsd->rle.len,
                        &rlsd->u,
                        (void *)rlsd + sizeof(*rlsd));
        rlsd = (void *)rlsd + sizeof(*rlsd) + rlsd->rle.len;
    }
    atomic64_add(msg->tx.arg1, &g_rl.in_rep_redo_nr);

    /* send reply */
    __send_reply(msg, 0, NULL, 0);

out_free:
    if (err) {
        __send_reply(msg, err, NULL, 0);
    }
    xnet_free_msg(msg);

    return err;
}

/* query in local file
 */
int __fquery_log_entry(u64 txg, u64 *otxg, u32 *oid)
{
    struct redo_log_site_disk head;
    void *data;
    u64 ftxg = 0;
    u32 fid = 0;
    int bl, br, err = 0;

    if (g_rl.rlfd <= 0)
        return -EINVAL;

    xlock_lock(&g_rl.rlfd_lock);
    /* seek to file head */
    err = lseek(g_rl.rlfd, 0, SEEK_SET);
    if (err) {
        hvfs_err(mds, "lseek redo log head failed w/ %d\n", errno);
        err = -errno;
        goto out;
    }
    do {
        /* read in the rlsd */
        bl = 0;
        do {
            br = read(g_rl.rlfd, (void *)&head + bl,
                      sizeof(head) - bl);
            if (br < 0) {
                hvfs_err(mds, "read redo log file failed w/ %d\n", errno);
                err = -errno;
                goto out;
            } else if (br == 0) {
                /* safely break here */
                goto out;
            }
            bl += br;
        } while (bl < sizeof(head));

        /* read in the data if needed */
        if (head.rle.len) {
            data = xmalloc(head.rle.len);
            if (!data) {
                hvfs_err(mds, "xmalloc(%d) failed\n", head.rle.len);
                err = -ENOMEM;
                goto out;
            }
            bl = 0;
            do {
                br = read(g_rl.rlfd, data + bl, head.rle.len - bl);
                if (br < 0) {
                    hvfs_err(mds, "read redo log file failed w/ %d\n", 
                             errno);
                    err = -errno;
                    goto out;
                } else if (br == 0) {
                    hvfs_err(mds, "read in extra data failed, EOF\n");
                    err = -EINVAL;
                    goto out;
                }
                bl += br;
            } while (bl < head.rle.len);
        }

        /* rlsd is ready, query it */
        if (head.rle.txg > txg) {
            if (head.rle.txg > ftxg) {
                ftxg = head.rle.txg;
                fid = head.rle.id;
            } else if (head.rle.txg == ftxg) {
                if (head.rle.id > fid)
                    fid = head.rle.id;
            }
        }
    } while (1);
out:
    xlock_unlock(&g_rl.rlfd_lock);

    /* even on error, we try to report more as we can */
    *otxg = ftxg;
    *oid = fid;

    if (err)
        return err;

    return 0;
}

/* send a query request
 */
int __send_query(u64 txg, u64 dsite, u64 *otxg, u32 *oid)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS_RECOVERY, HA_QUERY, txg);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "HA query request to site %lx failed w/ %d\n",
                 dsite, err);
        goto out_free_msg;
    }

    /* ABI: should return max txg and id in arg0 and arg1 */
    *otxg = msg->pair->tx.arg0;
    *oid = msg->pair->tx.arg1;

out_free_msg:
    xnet_free_msg(msg);
out:
    return err;
}

/* lookup the replicas (including local), from original site. Return txg,id
 * info of pending log entry whose txg is larger than current txg. Called by
 * sender.
 */
int redo_log_query_replica(u64 txg, u64 *otxg, u32 *oid)
{
    u64 max_txg = 0;
    u32 max_id = 0;
    int err = 0, i;
    
    err = __fquery_log_entry(txg, &max_txg, &max_id);
    if (err) {
        hvfs_warning(mds, "Try to fquery local redo log failed w/ %d\n",
                     err);
    }

    /* check remote replicas */
    for (i = 0; i < g_rl.replica_nr - 1; i++) {
        u64 __txg = 0;
        u32 __id = 0;
        
        err = __send_query(txg, g_rl.replica_sites[i], &__txg, &__id);
        if (err) {
            hvfs_warning(mds, "Try to fquery remote (%lx) redo log failed w/ %d\n",
                         g_rl.replica_sites[i], err);
        } else {
            if (__txg > max_txg) {
                max_txg = __txg;
                if (__id > max_id) {
                    max_id = __id;
                }
            }
        }
    }

    *otxg = max_txg;
    *oid = max_id;

    return err;
}

/* do query on replicated memory queue
 */
void __do_query_log_entry(u64 site, u64 txg, u64 *otxg, u32 *oid)
{
    struct redo_log_site *pos;
    u64 __txg = 0;
    u32 __id = 0;
    int i;

    for (i = 0; i < g_rl.replicated_nr; i++) {
        if (g_rl.replicated_sites[i] == site) {
            xlock_lock(&g_rl.rlq[i].lock);
            list_for_each_entry(pos, &g_rl.rlq[i].head, list) {
                if (pos->rlsd.rle.txg > txg) {
                    if (pos->rlsd.rle.txg > __txg) {
                        __txg = pos->rlsd.rle.txg;
                        __id = pos->rlsd.rle.id;
                    } else if (pos->rlsd.rle.txg == __txg) {
                        if (pos->rlsd.rle.id > __id)
                            __id = pos->rlsd.rle.id;
                    }
                }
            }
            xlock_unlock(&g_rl.rlq[i].lock);
            break;
        }
    }

    *otxg = __txg;
    *oid = __id;
}

/* query and report info of the replicated sites. Called by receiver.
 */
int do_query_log_entry(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    u64 txg;
    u32 id;
    
    __do_query_log_entry(msg->tx.ssite_id, msg->tx.arg1, &txg, &id);

    /* send a ok reply */
    rpy = __get_reply_msg(msg);
    if (!rpy) {
        __send_reply(msg, -ENOMEM, NULL, 0);
        goto out;
    }

    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, txg, id);

    __send_reply_msg(rpy);

out:
    xnet_free_msg(rpy);
    xnet_free_msg(msg);

    return 0;
}

/* get redo_log_site_disk array from local file
 */
int __fget_log_entry(u64 txg, struct redo_log_site_disk **orlsd, long *onr)
{
    struct redo_log_site_disk head;
    void *rlsd = NULL, *data;
    size_t size = 0;
    off_t offset = 0;
    long nr = 0;
    int err = 0, bl, br;

    if (g_rl.rlfd <= 0)
        return -EINVAL;

    xlock_lock(&g_rl.rlfd_lock);
    /* seek to file head */
    err = lseek(g_rl.rlfd, 0, SEEK_SET);
    if (err) {
        hvfs_err(mds, "lseek redo log head failed w/ %d\n", errno);
        err = -errno;
        goto out;
    }
    do {
        /* read in the rlsd */
        bl = 0;
        do {
            br = read(g_rl.rlfd, (void *)&head + bl,
                      sizeof(head) - bl);
            if (br < 0) {
                hvfs_err(mds, "read redo log file failed w/ %d\n", errno);
                err = -errno;
                goto out;
            } else if (br == 0) {
                /* safely break here */
                goto out;
            }
            bl += br;
        } while (bl < sizeof(head));

        /* check if we should bypass this entry */
        if (head.rle.txg <= txg) {
            if (head.rle.len) {
                data = xmalloc(head.rle.len);
                if (!data) {
                    hvfs_err(mds, "xmalloc(%d) failed\n", head.rle.len);
                    err = -ENOMEM;
                    goto out;
                }
            } else
                data = NULL;
        } else {
            size += sizeof(head) + head.rle.len;
            rlsd = xrealloc(rlsd, size);
            if (!rlsd) {
                hvfs_err(mds, "xrealloc(%ld) failed\n", size);
                err = -ENOMEM;
                goto out;
            }
            memcpy(rlsd + offset, &head, sizeof(head));
            offset += sizeof(head);
            data = rlsd + offset;
        }

        /* read in the data if needed */
        if (head.rle.len) {
            bl = 0;
            do {
                br = read(g_rl.rlfd, data + bl, head.rle.len - bl);
                if (br < 0) {
                    hvfs_err(mds, "read redo log file failed w/ %d\n", 
                             errno);
                    err = -errno;
                    goto out;
                } else if (br == 0) {
                    hvfs_err(mds, "read in extra data failed, EOF\n");
                    err = -EINVAL;
                    goto out;
                }
                bl += br;
            } while (bl < head.rle.len);
            offset += head.rle.len;
        }

        /* adjust connter */
        if (head.rle.txg <= txg) {
            xfree(data);
        } else
            nr++;
    } while (1);
out:
    xlock_unlock(&g_rl.rlfd_lock);

    if (err) {
        *orlsd = NULL;
        *onr = 0;
        xfree(rlsd);
    } else {
        *orlsd = rlsd;
        *onr = nr;
    }

    return err;
}

/* send a get request and get a buffer of rlsd (larger than txg and # is in
 * nr)
 */
int __send_get(u64 txg, u64 dsite, struct redo_log_site_disk **rlsd, 
               long *nr)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS_RECOVERY, HA_GET, txg);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "HA get request to site %lx failed w/ %d\n",
                 dsite, err);
        goto out_free_msg;
    }
    if (msg->pair->tx.err) {
        hvfs_err(mds, "HA get request to site %lx return %d\n",
                 dsite, msg->pair->tx.err);
        goto out_free_msg;
    }

    /* ABI: should return a list of rlsd w/ # in arg1 */
    *nr = msg->pair->tx.arg1;
    if (*nr)
        *rlsd = msg->pair->xm_data;
    else
        *rlsd = NULL;
    xnet_clear_auto_free(msg->pair);

out_free_msg:
    xnet_free_msg(msg);
out:
    return err;
}

struct rlsd_analyze 
{
    struct redo_log_site_disk *p;
    u64 nr;
    u32 max, min;
    int has_hole, oo, redundant, wired;
};

/* analyse rlsd array */
int __analyse_rlsd(struct redo_log_site_disk *ina, long inanr,
                   struct rlsd_analyze *ra)
{
    u32 last = 0;
    long i;
    
    memset(ra, 0, sizeof(*ra));
    ra->p = ina;
    ra->nr = inanr;

    for (i = 0; i < inanr; i++) {
        hvfs_debug(mds, "txg %ld id %u\n", ina->rle.txg, ina->rle.id);
        /* hole detection */
        if (!last) {
            if (!ra->wired) {
                /* start point, ignore holes */
                ;
            } else {
                /* wired */
                if (ina->rle.id > last + 1)
                    ra->has_hole = 1;
                else if (ina->rle.id < last)
                    ra->oo = 1;
                else if (ina->rle.id == last)
                    ra->redundant = 1;
            }
        } else if (last == (u32)-1) {
            if (ina->rle.id != 0)
                ra->has_hole = 1;
            ra->wired = 1;
        } else {
            if (ina->rle.id > last + 1)
                ra->has_hole = 1;
            else if (ina->rle.id < last)
                ra->oo = 1;
            else if (ina->rle.id == last)
                ra->redundant = 1;
        }
        last = ina->rle.id;
        /* max/min detection */
        if (i == 0)
            ra->min = ina->rle.id;
        if (i == inanr - 1)
            ra->max = ina->rle.id;
        ina = (void *)ina + sizeof(*ina) + ina->rle.len;
    }

    hvfs_info(mds, "Analyse RLSD: range[%u,%u], has_hole %d, oo %d, "
              "wired %d, rednt %d, nr %ld\n",
              ra->min, ra->max, ra->has_hole, ra->oo, ra->wired,
              ra->redundant, ra->nr);
    
    return 0;
}

int __merge_rlsd(struct rlsd_analyze *ra,
                 struct redo_log_site_disk *inb, long inbnr)
{
    struct rlsd_analyze rb;
    struct redo_log_site_disk *final, *a, *b;
    size_t len = 0;
    int do_merge = 0, minnr = 0, maxnr = 0;
    long i;

    /* Prepare and check input arguments */
    if (!ra->p) {
        /* ina array is empty, just return array B */
        __analyse_rlsd(inb, inbnr, &rb);
        *ra = rb;
        return 0;
    } else if (!inbnr) {
        /* inb array is empty, just return array A */
        return 0;
    }
    
    /* Step 1: Scan the list inb to find any holes in it */
    __analyse_rlsd(inb, inbnr, &rb);

    /* Step 2: do we need modify ina array */
    if (rb.nr > ra->nr) {
        if (rb.min < ra->min ||
            rb.max > ra->max) {
            if (rb.has_hole) {
                /* add entries from head or tail */
                do_merge = 1;
            } else if (!rb.has_hole && !rb.oo) {
                /* we can use inb array */
                xfree(ra->p);
                *ra = rb;
                return 0;
            }
        }
    } else {
        /* keep ina array */
        goto out;
    }

    /* Step 3: do merge head or tail entries from inb array */
    if (!do_merge) {
        goto out;
    }
    if (rb.min < ra->min) {
        a = ra->p;
        b = inb;
        for (i = 0; i < inbnr; i++) {
            if (b->rle.id < a->rle.id) {
                len += sizeof(*b) + b->rle.len;
                minnr++;
            } else
                break;
            b = (void *)b + sizeof(*b) + b->rle.len;
        }
    }
    if (rb.max > ra->max) {
        a = ra->p;
        b = inb;
        for (i = 0; i < ra->nr; i++) {
            len += sizeof(*a) + a->rle.len;
            if (i == ra->nr - 1) {
                break;
            }
            a = (void *)a + sizeof(*a) + a->rle.len;
        }
        for (i = 0; i < inbnr; i++) {
            if (b->rle.id > a->rle.id) {
                len += sizeof(*b) + b->rle.len;
                maxnr++;
            }
            b = (void *)b + sizeof(*b) + b->rle.len;
        }
    }

    final = xmalloc(len);
    if (!final) {
        hvfs_err(mds, "xmalloc(%ld) failed\n", len);
        return -ENOMEM;
    }
    if (rb.min < ra->min) {
        a = final;
        b = inb;
        /* copy minnr */
        for (i = 0; i < minnr; i++) {
            memcpy(a, b, sizeof(*b) + b->rle.len);
            a = (void *)a + sizeof(*a) + a->rle.len;
            b = (void *)b + sizeof(*b) + b->rle.len;
        }
    } else
        a = final;
    /* copy original ina array */
    b = ra->p;
    for (i = 0; i < ra->nr; i++) {
        memcpy(a, b, sizeof(*b) + b->rle.len);
        a = (void *)a + sizeof(*a) + a->rle.len;
        b = (void *)b + sizeof(*b) + b->rle.len;
    }
    if (rb.max > ra->max) {
        /* copy maxnr */
        b = inb;
        for (i = 0; i < inbnr; i++) {
            if (i >= inbnr - maxnr) {
                memcpy(a, b, sizeof(*b) + b->rle.len);
                a = (void *)a + sizeof(*a) + a->rle.len;
            }
            b = (void *)b + sizeof(*b) + b->rle.len;
        }
    }
    xfree(ra->p);
    ra->p = final;
    __analyse_rlsd(final, ra->nr + minnr + maxnr, &rb);
    *ra = rb;

out:
    /* free input array */
    xfree(inb);

    return 0;
}

/* lookup the replicas (including local), from original site. Return all the
 * log entry whose txg is larger than current txg.
 */
int redo_log_get_replica(u64 txg, struct redo_log_site_disk **rlsd, long *nr,
                         int wantN)
{
    struct redo_log_site_disk *__lr, *__r[g_rl.replica_nr - 1];
    long __lnr, __nr[g_rl.replica_nr - 1];
    struct rlsd_analyze ra;
    int err = 0, i, findN = 0;

    /* do init here */
    __lr = NULL;
    __lnr = 0;
    for (i = 0; i < g_rl.replica_nr - 1; i++) {
        __r[i] = NULL;
        __nr[i] = 0;
    }
    
    err = __fget_log_entry(txg, &__lr, &__lnr);
    if (err) {
        hvfs_warning(mds, "Try to fget local redo log failed w/ %d\n",
                     err);
    } else
        findN++;
    __analyse_rlsd(__lr, __lnr, &ra);
    hvfs_info(mds, "fGET(%ld) gets %ld entries in range [%d:%d] %p\n", 
              txg, ra.nr, ra.min, ra.max, ra.p);

    /* Note:
     *
     * Local redo log is in-order, while remote redo log maybe
     * out-of-order. Thus, we scan the remote redo log to find max/min id and
     * comprare them with local redo log.
     */

    /* check remote replicas */
    for (i = 0; i < g_rl.replica_nr - 1; i++) {
        err = __send_get(txg, g_rl.replica_sites[i], &__r[i], &__nr[i]);
        if (err) {
            hvfs_warning(mds, "Try to fget remote (%lx) redo log "
                         "failed w/ %d\n",
                         g_rl.replica_sites[i], err);
        } else {
            /* Merge all the rlsd together */
            err = __merge_rlsd(&ra, __r[i], __nr[i]);
            if (err) {
                hvfs_warning(mds, "Merge site %lx's redo log (#%ld) "
                             "failed w/ %d\n",
                             g_rl.replica_sites[i], __nr[i], err);
            } else
                findN++;
            hvfs_info(mds, "fGET(%ld) gets %ld entries in range [%d:%d] %p\n", 
                      txg, ra.nr, ra.min, ra.max, ra.p);
        }
    }

    *rlsd = ra.p;
    *nr = ra.nr;
    if (wantN <= findN) {
        err = 0;
    }

    return err;
}

/* do get on replicated memory queue. Called by receiver.
 */
int __do_get_log_entry(u64 site, u64 txg, void **rlsd, 
                       int *olen, long *nr)
{
    struct redo_log_site *pos;
    struct redo_log_site_disk *__rlsd = NULL, *tmp;
    off_t offset = 0;
    size_t len = 0;
    long __nr = 0;
    int i, err = 0;

    for (i = 0; i < g_rl.replicated_nr; i++) {
        if (g_rl.replicated_sites[i] == site) {
            xlock_lock(&g_rl.rlq[i].lock);
            list_for_each_entry(pos, &g_rl.rlq[i].head, list) {
                if (pos->rlsd.rle.txg > txg) {
                    len += sizeof(pos->rlsd) + pos->rlsd.rle.len;
                    __nr++;
                }
            }
            xlock_unlock(&g_rl.rlq[i].lock);
            break;
        }
    }
    /* ok, we have got # of rlsd and memory buffer size */
    if (__nr > 0) {
        __rlsd = xmalloc(len);
        if (!__rlsd) {
            hvfs_err(mds, "xmalloc() redo_log_site_disk failed\n");
            goto out;
        }
        /* rescan the list and do copyout */
        tmp = __rlsd;
        for (i = 0; i < g_rl.replicated_nr; i++) {
            if (g_rl.replicated_sites[i] == site) {
                xlock_lock(&g_rl.rlq[i].lock);
                list_for_each_entry(pos, &g_rl.rlq[i].head, list) {
                    if (pos->rlsd.rle.txg > txg) {
                        /* save rlsd */
                        *tmp = pos->rlsd;
                        /* save data region */
                        memcpy((void *)tmp + sizeof(*tmp),
                               (void *)pos + sizeof(*pos),
                               pos->rlsd.rle.len);
                        offset += sizeof(pos->rlsd) + pos->rlsd.rle.len;
                        tmp = (void *)__rlsd + offset;
                    }
                }
                xlock_unlock(&g_rl.rlq[i].lock);
                break;
            }
        }
    }
    *rlsd = __rlsd;
    *olen = len;
    *nr = __nr;
    
out:
    return err;
}

/* get ane report info of the replicated sites
 */
int do_get_log_entry(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    void *data;
    long nr;
    int len, err = 0;

    rpy = __get_reply_msg(msg);
    if (!rpy) {
        __send_reply(msg, -ENOMEM, NULL, 0);
        return -ENOMEM;
    }

    err = __do_get_log_entry(msg->tx.ssite_id, msg->tx.arg1, 
                             &data, &len, &nr);
    if (err) {
        hvfs_err(mds, "get log entry failed w/ %d\n", err);
        xnet_msg_set_err(rpy, err);
    } else {
        xnet_msg_add_sdata(rpy, data, len);
        /* ABI: set NR to tx.arg1 */
        xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, nr);
    }

    __send_reply_msg(rpy);

    xnet_free_msg(rpy);
    xnet_free_msg(msg);
    xfree(data);

    return err;
}


/* redo_log_recovery() read the local file and remote replicas to find out
 * pending txgs
 */
int redo_log_recovery(u64 txg, u64 *redo_txg)
{
    u64 rtxg = 0;
    u32 id = 0;
    int err = 0;

    err = redo_log_query_replica(txg, &rtxg, &id);
    if (err) {
        hvfs_err(mds, "Query on local and remote replcas failed w/ %d\n",
                 err);
        return err;
    }

    hvfs_info(mds, "Detect recovery state: redo_txg %ld max_id %d\n",
              rtxg, id);
    
    if (!rtxg && !id) {
        /* there is no need to do recovery */
        return 0;
    }
    *redo_txg = rtxg;

    /* txg and id are not EMPTY, maybe we need to do recovery */
    return 1;
}

/* called by timer thread to reap obsolete redo_log_site
 */
void redo_log_reap(time_t cur)
{
    static time_t last_reap = 0;
    
    if (cur - last_reap < g_rl.reap_interval)
        return;

    sem_post(&g_rl.sem);
    last_reap = cur;
}

/* do NOT check if we should redirect this log entry */
int __redo_log_apply_one(struct redo_log_site_disk *r)
{
    struct mdu *m;
    int err = 0;
    
    switch (r->rle.op) {
    case LOG_CLI_NOOP:
        break;
    case LOG_CLI_CREATE:
        m = r->u.rlc.hi.data;
        hvfs_err(mds, "Got REDO log entry: [create] txg %ld id %d "
                 "MDU flags %x\n",
                 r->rle.txg, r->rle.id,
                 (r->u.rlc.hi.flag & INDEX_CREATE_COPY ? m->flags : 0));
        /* Note that hi.data has been set */
        r->u.rlc.hi.auxflag |= AUX_RECOVERY;
        err = mds_create_redo(&r->u.rlc.hi);
        break;
    case LOG_CLI_UPDATE:
        break;
    case LOG_CLI_UNLINK:
        break;
    case LOG_CLI_SYMLINK:
        break;
    case LOG_CLI_AUSPLIT:
        hvfs_err(mds, "Got REDO log entry: [ausplt] txg %ld id %d\n",
                 r->rle.txg, r->rle.id);
        if (r->rle.len)
            mds_ausplit_redo((void *)r + sizeof(*r), r->rle.len);
        break;
    default:
        hvfs_err(mds, "Invalid REDO log entry: txg %ld id %d, op %d\n",
                 r->rle.txg, r->rle.id, r->rle.op);
        err = -EINVAL;
    }

    return err;
}

int do_apply_log_entry(struct xnet_msg *msg)
{
    int err = 0;
    
    /* ABI:
     * @tx.arg1: data length
     */
    if (msg->tx.len < sizeof(struct redo_log_site_disk) ||
        !msg->xm_datacheck) {
        hvfs_err(mds, "Invalid redo log entry to apply from site %lx\n",
                 msg->tx.ssite_id);
        return -EINVAL;
    }

    /* Apply this log entry to ourself */
    err = redo_log_apply_one(msg->xm_data);
    if (err) {
        hvfs_err(mds, "Apply log entry(from %lx) failed w/ %d\n",
                 msg->tx.ssite_id, err);
    }

    __send_reply(msg, err, NULL, 0);
    xnet_free_msg(msg);

    return err;
}

int redo_log_apply_one(struct redo_log_site_disk *r)
{
    u64 dsite;
    int check, err = 0;
    
retry:
    check = 0;
    /* do we need redirect? */
    switch (r->rle.op) {
    case LOG_CLI_CREATE:
    case LOG_CLI_UPDATE:
    case LOG_CLI_UNLINK:
    case LOG_CLI_SYMLINK:
        if (r->rle.len) {
            if (r->u.rlc.hi.flag & INDEX_BY_NAME) {
                if (r->rle.len > r->u.rlc.hi.namelen) {
                    r->u.rlc.hi.data = (void *)r + sizeof(*r) + 
                        r->u.rlc.hi.namelen;
                } else
                    r->u.rlc.hi.data = NULL;
            } else 
                r->u.rlc.hi.data = (void *)r + sizeof(*r);
            check = 1;
        }
        break;
    default:
        /* ignore any redirect checking */
        ;
    }
    if (check) {
        check = mds_redo_redirect(&r->u.rlc.hi, &dsite);
        if (check > 0) {
            /* ignore and print error */
            if (check == EFWD) {
                struct xnet_msg *msg;

                msg = xnet_alloc_msg(XNET_MSG_NORMAL);
                if (!msg) {
                    hvfs_warning(mds, "xnet_alloc_msg() failed, abort!\n");
                    HVFS_BUGON("No memory!");
                }
                xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                                 hmo.site_id, dsite);
                xnet_msg_fill_cmd(msg, HVFS_MDS_RECOVERY, HA_APPLY, 
                                  r->rle.len);
#ifdef XNET_EAGER_WRITEV
                xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
                xnet_msg_add_sdata(msg, r, sizeof(*r));
                if (r->rle.len)
                    xnet_msg_add_sdata(msg, (void *)r + sizeof(*r), 
                                       r->rle.len);
                err = xnet_send(hmo.xc, msg);
                if (err) {
                    hvfs_err(mds, "redirect request in redo apply "
                             "failed w/ %d\n", err);
                    goto msg_free;
                }
                ASSERT(msg->pair, mds);
                if (msg->pair->tx.err) {
                    hvfs_err(mds, "Site %lx handle redo apply failed w/ %d\n",
                             dsite, msg->pair->tx.err);
                    /* ignore any errors */
                }
            msg_free:
                xnet_free_msg(msg);
            } else if (check != EIGNORE) {
                hvfs_warning(mds, "In mds_redo_redirect, ignore this entry "
                             "and continue.\n");
            }
            return 0;
        } else if (check < 0) {
            /* abort recovery */
            hvfs_err(mds, "In mds_redo_redirect, abort recovery on w/ %d\n", 
                     check);
            HVFS_BUGON("Invalid Internal State!");
        }
    }

    err = __redo_log_apply_one(r);
    if (err == -EAGAIN) {
        goto retry;
    } else if (err) {
        hvfs_err(mds, "__redo_log_apply_one() failed w/ %d\n", err);
    }

    return err;
}

/* redo log apply (a bunch of log entries) in recover site */
int redo_log_apply(u64 txg, int wantN)
{
    struct redo_log_site_disk *rlsd = NULL, *r;
    long nr = 0, i;
    int err;

    if (wantN <= 0)
        wantN = 1;
    
    err = redo_log_get_replica(txg, &rlsd, &nr, wantN);
    if (err) {
        hvfs_err(mds, "redo log get replica failed w/ %d\n",
                 err);
        return err;
    }

    r = rlsd;
    for (i = 0; i < nr; i++) {
        redo_log_apply_one(r);
        r = (void *)r + sizeof(*r) + r->rle.len;
    }

    xfree(rlsd);
    
    return 0;
}

/* do_move_ite() move a ite E from itb I.
 */
int do_move_ite(struct ite *e, struct itb *i)
{
    struct redo_log_site_disk *r;
    struct hvfs_index *hi;
    struct dhe *de;
    u64 psalt;
    int err = 0, isgdt = 0, needupdate = 0, j, k;

    /* lookup and find the parent salt */
    de = mds_dh_search(&hmo.dh, i->h.puuid);
    if (IS_ERR(de)) {
        err = PTR_ERR(de);
        goto out;
    }
    psalt = de->salt;
    mds_dh_put(de);

    if (!(e->flag & ITE_FLAG_GDT)) {
        isgdt = e->namelen;
    }
    
    r = xzalloc(sizeof(*r) + isgdt + HVFS_MDU_SIZE);
    if (!r) {
        hvfs_err(mds, "xmalloc() create RLSD failed\n");
        err = -ENOMEM;
        goto out;
    }

    /* setup rlsd info */
    r->rle.op = LOG_CLI_CREATE;
    r->rle.len = isgdt + HVFS_MDU_SIZE;
    
    /* only copy mdu info, FIXME: need to fix GDT entry copy */
    hi = &r->u.rlc.hi;
    hi->namelen = isgdt;
    hi->column = 0;
    hi->flag = INDEX_CREATE | INDEX_CREATE_COPY | 
        (isgdt ? INDEX_BY_NAME : INDEX_BY_UUID);
    hi->uuid = e->uuid;
    hi->hash = e->hash;
    hi->itbid = i->h.itbid;
    hi->puuid = i->h.puuid;
    hi->psalt = psalt;

    if (isgdt)
        memcpy((void *)r + sizeof(*r), e->s.name, isgdt);
    memcpy((void *)r + sizeof(*r) + isgdt,
           &e->g, HVFS_MDU_SIZE);
    hvfs_err(mds, "Move ite <%lx,%lx> mdu flags %x off %ld\n",
             hi->uuid, hi->hash, e->g.mdu.flags, sizeof(*r) + isgdt);

    /* recreate it now */
    err = redo_log_apply_one(r);
    if (err) {
        hvfs_err(mds, "Try to recreate ITE <%lx,%lx> failed w/ %d\n",
                 hi->uuid, hi->hash, err);
        goto out_free;
    }
    xfree(r);
    
    /* update column info */
    for (j = 0; j < 6; j++) {
        if (e->column[j].len > 0)
            needupdate++;
    }
    
    if (needupdate) {
        struct mdu_update *mu;
        struct llfs_ref *lr;
        struct mu_column *mc;
        int len = isgdt + sizeof(struct mdu_update) +
            sizeof(struct llfs_ref) + 
            needupdate * sizeof(struct mu_column);
        
        r = xzalloc(sizeof(*r) + len);
        if (!r) {
            hvfs_err(mds, "xzalloc() update RLSD failed\n");
            err = -ENOMEM;
            goto out;
        }
        
        /* setup rlsd info */
        r->rle.op = LOG_CLI_UPDATE;
        r->rle.len = len;

        /* setup hi */
        hi = &r->u.rlc.hi;
        hi->namelen = isgdt;
        hi->column = 0;
        hi->flag = INDEX_MDU_UPDATE | 
            (isgdt ? INDEX_BY_NAME : INDEX_BY_UUID);
        hi->uuid = e->uuid;
        hi->hash = e->hash;
        hi->itbid = i->h.itbid;
        hi->puuid = i->h.puuid;
        hi->psalt = psalt;
        hi->data = (void *)hi + sizeof(*hi) + isgdt;
        if (isgdt)
            memcpy((void *)hi + sizeof(*hi), e->s.name, isgdt);

        /* setup mdu_update */
        mu = (void *)hi + sizeof(*hi) + isgdt;
        mu->valid = MU_MODE | MU_UID | MU_GID | MU_FLAG_ADD |
            MU_ATIME | MU_MTIME | MU_CTIME | MU_VERSION |
            MU_SIZE | MU_LLFS | MU_NLINK | MU_DEV;
        mu->atime = e->s.mdu.atime;
        mu->mtime = e->s.mdu.mtime;
        mu->ctime = e->s.mdu.ctime;
        mu->size = e->s.mdu.size;
        mu->uid = e->s.mdu.uid;
        mu->gid = e->s.mdu.gid;
        mu->flags = e->s.mdu.flags;
        mu->version = e->s.mdu.version;
        mu->nlink = e->s.mdu.nlink;
        mu->mode = e->s.mdu.mode;
        mu->column_no = needupdate;
        /* setup llfs_ref */
        lr = (void *)hi + sizeof(*hi) + isgdt + sizeof(*mu);
        *lr = e->s.mdu.lr;
        /* setup mu_column */
        mc = (void *)hi + sizeof(*hi) + isgdt + sizeof(*mu) + sizeof(*lr);
        for (j = 0, k = 0; j < 6; j++) {
            if (e->column[j].len > 0) {
                (mc + k)->cno = j;
                (mc + k)->c = e->column[j];
                k++;
            }
        }

        /* update it now */
        err = redo_log_apply_one(r);
        if (err) {
            hvfs_err(mds, "Try to update ITE <!%lx,%lx> failed w/ %d\n",
                     hi->uuid, hi->hash, err);
            goto out_free;
        }
        xfree(r);
    } else
        goto out;

out_free:
    xfree(r);
out:
    
    return err;
}

/* redo operations' dispatcher
 */
int redo_dispatch(struct xnet_msg *msg)
{
    int err = 0;
    
    /* ABI:
     * tx.arg0: subcommand
     * tx.arg1: ?
     */
    switch (msg->tx.arg0) {
    case HA_REPLICATE:
        err = do_replicate_log_entry(msg);
        break;
    case HA_REAP:
        err = do_reap_log_entry(msg);
        break;
    case HA_QUERY:
        err = do_query_log_entry(msg);
        break;
    case HA_GET:
        err = do_get_log_entry(msg);
        break;
    case HA_APPLY:
        err = do_apply_log_entry(msg);
        break;
    default:
        hvfs_err(mds, "Invalid HA/RECOVERY reqeust <%ld> from site %lx\n",
                 msg->tx.arg1, msg->tx.ssite_id);
        __send_reply(msg, -EINVAL, NULL, 0);
        xnet_free_msg(msg);
    }

    return err;
}
