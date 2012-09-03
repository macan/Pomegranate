/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-06-08 00:02:04 macan>
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
#include "mdsl.h"

struct sync_record
{
    struct list_head list;

    u64 duuid;
#define SYNC_NONE       0x00
#define SYNC_MD         0x01
#define SYNC_RANGE      0x02
#define SYNC_DATA       0x04
#define SYNC_ALL        0xff
    u8 flag;
};

struct syncer_mgr
{
    struct list_head queue;
    xlock_t qlock;
    sem_t qsem;

    /* replicas, select N - 1 remote nodes to replicate */
    u64 *replica_sites;         /* which site to send */
    u64 *replicated_sites;      /* which site to notify sync */
    int replica_nr;
    int replicated_nr;

    /* sync state */
#define SYNC_STATE_INIT         0x00 /* init state */
#define SYNC_STATE_CHK          0x01 /* booting check */
#define SYNC_STATE_ADDIN        0x02 /* add a new sync node */
#define SYNC_STATE_NORM         0x03 /* normal state */
    u8 state;
#define SYNC_FREE               0x00
#define SYNC_ING                0x01 /* there is an active syncing */
    u8 sync_state;
    
    /* thread info */
    pthread_t syncer_thread;
    u8 syncer_thread_stop;
};

struct syncer_thread_arg
{
    int tid;
};

static struct syncer_mgr g_sm;

int syncer_add(u64 duuid, u8 flag)
{
    struct sync_record *sr;

    sr = xzalloc(*sr);
    if (!sr) {
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&sr->list);
    /* no argument checking */
    sr->duuid = duuid;
    sr->flag = flag;

    xlock_lock(&g_sm.qlock);
    list_add_tail(&sr->list, &g_sm.queue);
    xlock_unlock(&g_sm.qlock);

    /* notify the syncer */
    sem_post(&g_sm.qsem);

    return 0;
}

static inline
int __serv_request(void)
{
    struct sync_record *sr = NULL, *pos, *n;
    u64 site;
    int err = 0;

    xlock_lock(&g_sm.qlock);
    list_for_each_entry_safe(pos, n, &g_sm.queue, list) {
        list_del_init(&pos->list);
        sr = pos;
        break;
    }
    xlock_unlock(&g_sm.qlock);

    if (!sr)
        return -EHSTOP;

    /* ok, deal with it */
    /* Step 1: determine which node to sync? */
    
    /* Step 2: compare and sync the specific files */
    if (sr->flag & SYNC_MD) {
        err = __sync_md(sr->duuid);
        if (err) {
            hvfs_err(mdsl, "Sync dir %lx MD failed w/ %d\n",
                     sr->duuid, err);
            goto out_failed;
        }
    }
    if (sr->flag & SYNC_RANGE) {
        err = __sync_range(sr->duuid);
        if (err) {
            hvfs_err(mdsl, "Sync dir %lx MD failed w/ %d\n",
                     sr->duuid, err);
            goto out_failed;
        }
    }
    if (sr->flag & SYNC_DATA) {
        err = __sync_data(sr->duuid);
        if (err) {
            hvfs_err(mdsl, "Sync dir %lx MD failed w/ %d\n",
                     sr->duuid, err);
            goto out_failed;
        }
    }

    return err;
out_failed:
    xlock_lock(&g_sm.qlock);
    list_add_tail(&sr->list, &g_sm.queue);
    xlock_unlock(&g_sm.qlock);
    return err;
}

static
void *syncer_main(void *arg)
{
    struct syncer_thread_arg *sta = (struct syncer_thread_arg *)arg;
    sigset_t set;
    int err = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    while (!g_sm.syncer_thread_stop) {
        err = sem_wait(&g_sm.qsem);
        if (err == EINTR)
            continue;

        /* trying to handle more and more sync request */
        while (1) {
            err = __serv_request();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(mdsl, "Syncer thread handle request w/ err %d\n",
                         err);
            }
        }
    }
    pthread_exit(0);
}

/* Scan the on-disk sync directory
 *
 * MDSL_HOME/600xx/sync/mgr {sync_mgr}
 * MDSL_HOME/600xx/sync/600yy/
 * MDSL_HOME/600xx/sync/600zz/
 * ...
 *
 */
int syncer_disk_scan()
{
    int err = 0;

    return err;
}

int syncer_init(int replica_nr)
{
    char path[256];
    struct xnet_group *xg;
    pthread_attr_t attr;
    int err = 0, stacksize;
    
    /* make sure the dir exists */
    sprintf(path, "%s/%lx/sync", hmo.conf.mdsl_home, hmo.site_id);
    err = mdsl_dir_make_exist(path);
    if (err) {
        hvfs_err(mdsl, "dir %s does not exist %d.\n", path, err);
        return -ENOTEXIST;
    }

    /* prepare the new replica view */
    if (replica_nr < 2) {
        hvfs_warning(mdsl, "Setting no HARD replica for this node.\n");
    } else if (replica_nr >= 2) {
        g_sm.replica_sites = xzalloc((replica_nr - 1)* sizeof(u64));
        if (!g_sm.replica_sites) {
            hvfs_err(mdsl, "xzalloc() relica_sites' array failed\n");
            err = -ENOMEM;
            goto out;
        }

        /* select replicas */
        xg = __get_active_site(r);
        if (!xg) {
            hvfs_warning(mdsl, "Only use local logger, not HA now!\n");
            replica_nr = 1;
        } else {
            /* sort the group, thus we will get consistent group view */
            xnet_group_sort(xg);

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
                    if (xg->sites[e].site_id == g_sm.replica_sites[j]) {
                        /* conflict, reselect */
                        goto reselect;
                    }
                }
                g_sm.replica_sites[i] = xg->sites[e].site_id;
                hvfs_info(mdsl, "Select site %lx as my SYNC replica <%d/%d>.\n",
                          xg->sites[e].site_id, i, replica_nr - 1);
            }
        }
    }

    /* check the on-disk replica view */
    err = syncer_disk_scan();
    if (err) {
        hvfs_err(mdsl, "Scan syncer disk state failed w/ %d\n", err);
        goto out;
    }
    
    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(mdsl, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hmo.conf.stacksize > (1 << 20) ? 
                 hmo.conf.stacksize : (1 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(mdsl, "set thread stack size to %d failed w/ %d\n", 
                 stacksize, err);
        goto out;
    }

    /* init the mgr struct */
    INIT_LIST_HEAD(&g_sm.queue);
    xlock_init(&g_sm.qlock);
    sem_init(&g_sm.qsem, 0, 0);

    /* init syncer thread */
    err = pthread_create(&g_sm.syncer_thread, &attr, &syncer_main, NULL);
    if (err) {
        hvfs_err(mdsl, "create syncer thread failed w/ %d\n", err);
        goto out;
    }

out:
    return err;
}

void syncer_destory()
{
    g_sm.syncer_thread_stop = 1;
    sem_post(&g_sm.qsem);
    /* FIXME: shall we wait for all the pending sync records are handled? */
    pthread_join(g_sm.syncer_thread, NULL);
    sem_destroy(&g_sm.qsem);
}

