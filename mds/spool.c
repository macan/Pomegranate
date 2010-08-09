/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-08-06 20:26:49 macan>
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
#include "mds.h"
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "ring.h"
#include "lib.h"

struct spool_mgr
{
    struct list_head reqin;
    struct list_head modify_req; /* for suspending modify requests */
    xlock_t rin_lock;
    xlock_t pmreq_lock;
    sem_t rin_sem;
};

struct spool_thread_arg
{
    int tid;
};

static struct spool_mgr spool_mgr;

int mds_spool_dispatch(struct xnet_msg *msg)
{
    xlock_lock(&spool_mgr.rin_lock);
    list_add_tail(&msg->list, &spool_mgr.reqin);
    xlock_unlock(&spool_mgr.rin_lock);
    atomic64_inc(&hmo.prof.misc.reqin_total);
    sem_post(&spool_mgr.rin_sem);

    return 0;
}

int mds_spool_modify_pause(struct xnet_msg *msg)
{
    xlock_lock(&spool_mgr.pmreq_lock);
    list_add_tail(&msg->list, &spool_mgr.modify_req);
    xlock_unlock(&spool_mgr.pmreq_lock);
    atomic64_inc(&hmo.prof.mds.paused_mreq);
    
    return 0;
}

static inline
void mds_spool_modify_resume(void)
{
    int i;

    for (i = 0; i < hmo.conf.spool_threads; i++) {
        sem_post(&spool_mgr.rin_sem);
    }
}

void mds_spool_mp_check(time_t t)
{
    if (!hmo.spool_modify_pause)
        return;
    if (hmo.scrub_running)
        return;
    
    /* check to see if we should resume the modify requests' handling */
    if (hmo.conf.memlimit > atomic64_read(&hmo.prof.cbht.aitb) * 
        (sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE)) {
        /* ok, we disable the scrub thread now */
        hmo.conf.option |= HVFS_MDS_NOSCRUB;
        hmo.conf.scrub_interval = 600;
        mds_reset_itimer();

        hmo.spool_modify_pause = 0;
        mds_spool_modify_resume();
        hvfs_err(mds, "resume modify operations\n");
    } else {
        /* we trigger the scrubbing thread to evict the clean ITBs */
        hmo.conf.option &= ~HVFS_MDS_NOSCRUB;
        hmo.conf.scrub_interval = 1;
        mds_reset_itimer();
        mds_scrub_trigger();

        hvfs_err(mds, "trigger scrub thread\n");
        if (t > hmo.mp_ts + hmo.conf.mp_to) {
            hvfs_err(mds, "MDS pausing modification for a long time: %lds\n",
                     (u64)(t - hmo.mp_ts));
        }
    }
}

static inline
int __serv_request(void)
{
    struct xnet_msg *msg = NULL, *pos, *n;

    if (unlikely(!hmo.spool_modify_pause)) {
        if (!list_empty(&spool_mgr.modify_req)) {
            xlock_lock(&spool_mgr.pmreq_lock);
            list_for_each_entry_safe(pos, n, &spool_mgr.modify_req, list) {
                list_del_init(&pos->list);
                msg = pos;
                break;
            }
            xlock_unlock(&spool_mgr.pmreq_lock);
            if (msg) {
                ASSERT(msg->xc, mds);
                return msg->xc->ops.dispatcher(msg);
            }
        }
    }
    
    xlock_lock(&spool_mgr.rin_lock);
    list_for_each_entry_safe(pos, n, &spool_mgr.reqin, list) {
        list_del_init(&pos->list);
        msg = pos;
        break;
    }
    xlock_unlock(&spool_mgr.rin_lock);

    if (!msg)
        return -EHSTOP;

    /* ok, deal with it, we just calling the secondary dispatcher */
    ASSERT(msg->xc, mds);
    atomic64_inc(&hmo.prof.misc.reqin_handle);
    return msg->xc->ops.dispatcher(msg);
}

static
void *spool_main(void *arg)
{
    struct spool_thread_arg *sta = (struct spool_thread_arg *)arg;
    sigset_t set;
    int err = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    while (!hmo.spool_thread_stop) {
        err = sem_wait(&spool_mgr.rin_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Service thread %d wakeup to handle the requests.\n",
                   sta->tid);
        /* trying to handle more and more requsts. */
        while (1) {
            err = __serv_request();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(mds, "Service thread handle request w/ error %d\n",
                         err);
            }
        }
    }
    pthread_exit(0);
}

int mds_spool_create(void)
{
    struct spool_thread_arg *sta;
    int i, err = 0;
    
    /* init the mgr struct */
    INIT_LIST_HEAD(&spool_mgr.reqin);
    INIT_LIST_HEAD(&spool_mgr.modify_req);
    xlock_init(&spool_mgr.rin_lock);
    xlock_init(&spool_mgr.pmreq_lock);
    sem_init(&spool_mgr.rin_sem, 0, 0);
    hmo.spool_modify_pause = 0;

    /* init service threads' pool */
    if (!hmo.conf.spool_threads)
        hmo.conf.spool_threads = 4;

    hmo.spool_thread = xzalloc(hmo.conf.spool_threads * sizeof(pthread_t));
    if (!hmo.spool_thread) {
        hvfs_err(mds, "xzalloc() pthread_t failed\n");
        return -ENOMEM;
    }

    sta = xzalloc(hmo.conf.spool_threads * sizeof(struct spool_thread_arg));
    if (!sta) {
        hvfs_err(mds, "xzalloc() struct spool_thread_arg failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    for (i = 0; i < hmo.conf.spool_threads; i++) {
        (sta + i)->tid = i;
        err = pthread_create(hmo.spool_thread + i, NULL, &spool_main,
                             sta + i);
        if (err)
            goto out;
    }

out:
    return err;
out_free:
    xfree(hmo.spool_thread);
    goto out;
}

void mds_spool_destroy(void)
{
    int i;

    hmo.spool_thread_stop = 1;
    for (i = 0; i < hmo.conf.spool_threads; i++) {
        sem_post(&spool_mgr.rin_sem);
    }
    for (i = 0; i < hmo.conf.spool_threads; i++) {
        pthread_join(*(hmo.spool_thread + i), NULL);
    }
    sem_destroy(&spool_mgr.rin_sem);
}
