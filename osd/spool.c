/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-07 14:46:04 macan>
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
#include "osd.h"
#include "ring.h"
#include "lib.h"

struct spool_mgr
{
    struct list_head reqin;
    xlock_t rin_lock;
    sem_t rin_sem;
#define OSD_CMD_PAUSE           0x01    /* is pause now (drop all messages) */
#define OSD_CMD_RDONLY          0x02    /* drop all modify messages */
#define OSD_CMD_OFFLINE         0x04    /* drop all but R2 messages */
#define OSD_CMD_MASK            0x0f
    u32 flags;
};

#define OSD_IS_PAUSED(mgr) ((mgr).flags & OSD_CMD_PAUSE)
#define OSD_IS_RDONLY(mgr) ((mgr).flags & OSD_CMD_RDONLY)
#define OSD_IS_OFFLINE(mgr) ((mgr).flags & OSD_CMD_OFFLINE)

struct spool_thread_arg
{
    int tid;
};

static struct spool_mgr spool_mgr;

int osd_spool_dispatch(struct xnet_msg *msg)
{
    xlock_lock(&spool_mgr.rin_lock);
    list_add_tail(&msg->list, &spool_mgr.reqin);
    xlock_unlock(&spool_mgr.rin_lock);
    atomic64_inc(&hoo.prof.misc.reqin_total);
    sem_post(&spool_mgr.rin_sem);

    return 0;
}

void osd_spool_redispatch(struct xnet_msg *msg, int sempost)
{
    xlock_lock(&spool_mgr.rin_lock);
    list_add_tail(&msg->list, &spool_mgr.reqin);
    xlock_unlock(&spool_mgr.rin_lock);
    if (sempost)
        sem_post(&spool_mgr.rin_sem);
}

static inline
int osd_dispatch_check(struct xnet_msg *msg)
{
    if (msg->tx.cmd == HVFS_OSD_READ) {
        if (atomic_inc_return(&obj_reads) >= hoo.conf.spool_threads) {
            atomic_dec(&obj_reads);
            return 1;
        }
    }

    return 0;
}

static inline
int osd_is_marker(struct xnet_msg *msg)
{
    if (msg->tx.type == XNET_MSG_CMD)
        return 1;
    return 0;
}

static inline
void osd_update_marker(struct xnet_msg *msg, struct spool_mgr *mgr)
{
    switch (msg->tx.cmd) {
    case OSD_MRK_PAUSE:
        mgr->flags |= OSD_CMD_PAUSE;
        break;
    case OSD_MRK_RDONLY:
        mgr->flags |= OSD_CMD_RDONLY;
        break;
    case OSD_MRK_OFFLINE:
        mgr->flags |= OSD_CMD_OFFLINE;
        break;
    case OSD_CLR_PAUSE:
        mgr->flags &= (~OSD_CMD_PAUSE);
        break;
    case OSD_CLR_RDONLY:
        mgr->flags &= (~OSD_CMD_RDONLY);
        break;
    case OSD_CLR_OFFLINE:
        mgr->flags &= (~OSD_CMD_OFFLINE);
        break;
    default:
        hvfs_warning(osd, "Invalid OSD Spool marker (%ld)\n", msg->tx.cmd);
    }
    /* free the msg now */
    xnet_raw_free_msg(msg);
}

static inline
int __osd_set_marker(u32 type)
{
    struct xnet_msg *msg;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(osd, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_CMD, 0, hoo.site_id, hoo.site_id);

    /* insert the message to reqin queue */
    osd_spool_dispatch(msg);

    return 0;
}

int osd_set_marker(u32 type)
{
    return __osd_set_marker(type);
}

int osd_clr_marker(u32 type)
{
    return __osd_set_marker(type);
}

static inline
int osd_marked(struct spool_mgr *mgr)
{
    return mgr->flags & OSD_CMD_MASK;
}

/* 
 * Return value: 1=>filtered; 0=>not_filtered
 */
static int osd_filter_msg(struct xnet_msg *msg)
{
    if (OSD_IS_PAUSED(spool_mgr)) {
        /* drop all messages */
        xnet_free_msg(msg);
        return 1;
    }
    if (OSD_IS_RDONLY(spool_mgr)) {
        /* drop modify messages */
        if (msg->tx.cmd == HVFS_OSD_WRITE) {
            xnet_free_msg(msg);
            return 1;
        }
    }
    if (OSD_IS_OFFLINE(spool_mgr)) {
        /* drop all but RING messages */
        if (!HVFS_IS_RING(msg->tx.ssite_id)) {
            xnet_free_msg(msg);
            return 1;
        }
    }
    
    return 0;
}

static inline
int __serv_request(void)
{
    struct xnet_msg *msg = NULL, *pos, *n;

    xlock_lock(&spool_mgr.rin_lock);
    list_for_each_entry_safe(pos, n, &spool_mgr.reqin, list) {
        list_del_init(&pos->list);
        msg = pos;
        break;
    }
    xlock_unlock(&spool_mgr.rin_lock);

    if (!msg)
        return -EHSTOP;

    /* check if this request can be dealed right now */
    if (osd_dispatch_check(msg)) {
        /* reinsert the request to the queue */
        xlock_lock(&spool_mgr.rin_lock);
        list_add_tail(&msg->list, &spool_mgr.reqin);
        xlock_unlock(&spool_mgr.rin_lock);
        sem_post(&spool_mgr.rin_sem);

        return 0;
    }

    /* check if we should handle the following requests */
    if (osd_is_marker(msg)) {
        osd_update_marker(msg, &spool_mgr);
        return 0;
    }
    if (osd_marked(&spool_mgr)) {
        /* filter the msg now */
        if (osd_filter_msg(msg)) {
            return 0;
        }
    }

    /* ok, deal with it, we just calling the secondary dispatcher */
    ASSERT(msg->xc, osd);
    ASSERT(msg->xc->ops.dispatcher, osd);
    atomic64_inc(&hoo.prof.misc.reqin_handle);
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
    while (!hoo.spool_thread_stop) {
        err = sem_wait(&spool_mgr.rin_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(osd, "Service thread %d wakeup to handle the requests.\n",
                   sta->tid);
        /* trying to handle more and more requsts. */
        while (1) {
            err = __serv_request();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(osd, "Service thread handle request w/ error %d\n",
                         err);
                break;
            }
        }
    }
    pthread_exit(0);
}

int osd_spool_create(void)
{
    pthread_attr_t attr;
    struct spool_thread_arg *sta;
    int i, err = 0, stacksize;
    
    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(osd, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hoo.conf.stacksize > (1 << 20) ? 
                 hoo.conf.stacksize : (2 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(osd, "set thread stack size to %d failed w/ %d\n", 
                 stacksize, err);
        goto out;
    }

    /* init the mgr struct */
    memset(&spool_mgr, 0, sizeof(spool_mgr));
    INIT_LIST_HEAD(&spool_mgr.reqin);
    xlock_init(&spool_mgr.rin_lock);
    sem_init(&spool_mgr.rin_sem, 0, 0);

    /* init service threads' pool */
    if (!hoo.conf.spool_threads)
        hoo.conf.spool_threads = 4;

    hoo.spool_thread = xzalloc(hoo.conf.spool_threads * sizeof(pthread_t));
    if (!hoo.spool_thread) {
        hvfs_err(osd, "xzalloc() pthread_t failed\n");
        return -ENOMEM;
    }

    sta = xzalloc(hoo.conf.spool_threads * sizeof(struct spool_thread_arg));
    if (!sta) {
        hvfs_err(osd, "xzalloc() struct spool_thread_arg failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    for (i = 0; i < hoo.conf.spool_threads; i++) {
        (sta + i)->tid = i;
        err = pthread_create(hoo.spool_thread + i, &attr, &spool_main,
                             sta + i);
        if (err)
            goto out;
    }

out:
    return err;
out_free:
    xfree(hoo.spool_thread);
    goto out;
}

void osd_spool_destroy(void)
{
    int i;

    hoo.spool_thread_stop = 1;
    for (i = 0; i < hoo.conf.spool_threads; i++) {
        sem_post(&spool_mgr.rin_sem);
    }
    for (i = 0; i < hoo.conf.spool_threads; i++) {
        pthread_join(*(hoo.spool_thread + i), NULL);
    }
    sem_destroy(&spool_mgr.rin_sem);
}
