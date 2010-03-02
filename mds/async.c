/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-02 16:22:51 macan>
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
#include "tx.h"
#include "mds.h"
#include "lib.h"
#include "async.h"
#include "ring.h"

struct async_update_mlist g_aum;

void async_update_checking(time_t t)
{
    static time_t last_ts;
    static int last_requested, last_handled;

    if (atomic64_read(&hmo.prof.itb.split_submit) == 
        atomic64_read(&hmo.prof.itb.split_local)) {
        last_ts = t;
        /* for now, we do not go back to fast mode */
#if 0
        if (hmo.conf.cbht_slow_down) {
            hmo.conf.cbht_slow_down = 0;
            hvfs_info(mds, "OK, back to fast mode @ %s", ctime(&t));
        }
#endif
        last_requested = last_handled = 
            atomic64_read(&hmo.prof.itb.split_submit);
    }
    
    if (t < last_ts + 30) {
        last_requested = atomic64_read(&hmo.prof.itb.split_submit);
        last_handled = atomic64_read(&hmo.prof.itb.split_local);
        return;
    }
    
    if (atomic64_read(&hmo.prof.itb.split_submit) >= last_requested &&
        atomic64_read(&hmo.prof.itb.split_local) == last_handled) {
        /* going into slow mode now */
        if (!hmo.conf.cbht_slow_down) {
            hvfs_info(mds, "Ho, going into slow mode @ %s", ctime(&t));
            hmo.conf.cbht_slow_down = 1;
        }
    }
}

int __aur_itb_split(struct async_update_request *aur)
{
    struct itb *i = (struct itb *)aur->arg;
    struct dhe *e;
    struct chp *p;
    int err = 0;

    if (!i)
        return -EINVAL;

    /* first, we should find the destination MDS of the ITB */
    e = mds_dh_search(&hmo.dh, i->h.puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "We can not find the DH of PUUID %ld.\n",
                 i->h.puuid);
        err = PTR_ERR(e);
        goto out;
    }
    p = ring_get_point(i->h.itbid, e->salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto out;
    }
    
    /* then, we send the ITB or insert it in the local CBHT */
    if (hmo.site_id != p->site_id) {
        /* FIXME: need truely AU, for now we just ignore the mismatch */
        /* NOTE: we should transfer the ITB to the dest site w/ bitmap flip
         * notification. */
        struct xnet_msg *msg;
        /* Step 0: preparing */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_warning(xnet, "xnet_alloc_msg() failed, re-submit the"
                         " AU request.\n");
            au_submit(aur);
            return -ENOMEM;
        }
        /* Step 1: we should update the local bitmap */
        mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid,
                             MDS_BITMAP_SET);
        /* Step 2: we begin to transfer the ITB to the dest site */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                         hmo.site_id, p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_SPITB, 0, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        /* FIXME: for now we just send the whole ITB */
        ASSERT(list_empty(&i->h.list), mds);
        xnet_msg_add_sdata(msg, i, atomic_read(&i->h.len));
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mds, "AU split ITB sending failed w/ %d\n", err);
            goto msg_free;
        }
        /* Step 3: we waiting for the reply to confirm the delivery and
         * release the splitted ITB */
        ASSERT(msg->pair, mds);
        if (msg->pair->tx.err) {
            hvfs_err(mds, "Site %lx handle AUSplit failed w/ %d\n",
                     p->site_id, msg->pair->tx.err);
        }
        /* Step 3.inf we should free the ITB */
        itb_put((struct itb *)i->h.twin);
        itb_free(i);
        hvfs_debug(mds, "Receive the AU split reply.\n");
        atomic64_inc(&hmo.prof.mds.split);
    msg_free:
        xnet_free_msg(msg);
        if (err) {
            /* FIXME: we re-submit the request! */
            au_submit(aur);
        }
    } else {
        struct bucket *nb;
        struct bucket_entry *nbe;
        struct itb *ti, *saved_oi;
        struct hvfs_txg *t;

        /* pre-dirty this itb */
        t = mds_get_open_txg(&hmo);
        i->h.txg = t->txg;
        i->h.state = ITB_STATE_DIRTY;
        INIT_LIST_HEAD(&i->h.list);
        txg_add_itb(t, i);
        txg_put(t);
        /* change the splited ITB's state to NORMAL */
        saved_oi = (struct itb *)i->h.twin;
        i->h.twin = 0;

        /* insert into the CBHT */
        err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &nb, &nbe, &ti);
        if (err == -EEXIST) {
            /* someone create the new ITB, we have data losing */
            hvfs_err(mds, "Someone create ITB %ld, data losing ...\n",
                     i->h.itbid);
            xrwlock_runlock(&nbe->lock);
            xrwlock_runlock(&nb->lock);
        } else if (err) {
            hvfs_err(mds, "Internal error %d, data losing.\n", err);
        }

        /* it is ok, we need free the locks */
        xrwlock_runlock(&nbe->lock);
        xrwlock_runlock(&nb->lock);

        /* FIXME: should we just use the rlock? */
        itb_put(saved_oi);
        /* then, we set the bitmap now */
        mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid, 
                             MDS_BITMAP_SET);
        atomic64_inc(&hmo.prof.itb.split_local);

        hvfs_debug(mds, "we update the bit of ITB %ld\n", i->h.itbid);
/*         mds_dh_bitmap_dump(&hmo.dh, i->h.puuid); */
    }
    
out:
    return err;
}

int __aur_itb_bitmap(struct async_update_request *aur)
{
    return 0;
}

int __aur_txg_wb(struct async_update_request *aur)
{
    hvfs_err(mds, "AU TXG write-back has not been implemented yet.\n");
    return 0;
}

int __au_req_handle(void)
{
    struct async_update_request *aur = NULL, *n;
    int err = 0;

    xlock_lock(&g_aum.lock);
    if (!list_empty(&g_aum.aurlist)) {
        list_for_each_entry_safe(aur, n, &g_aum.aurlist, list) {
            list_del(&aur->list);
            break;
        }
    }
    xlock_unlock(&g_aum.lock);

    if (!aur)
        return -EHSTOP;
    
    /* ok, deal with it */
    switch (aur->op) {
    case AU_ITB_SPLIT:
        err = __aur_itb_split(aur);
        break;
    case AU_ITB_BITMAP:
        err = __aur_itb_bitmap(aur);
        break;
    case AU_TXG_WB:
        err = __aur_txg_wb(aur);
        break;
    default:
        hvfs_err(mds, "Invalid AU Request: op %ld arg 0x%lx\n",
                     aur->op, aur->arg);
    }
    return err;
}

/* Handle the split in synchronous mode
 */
void au_handle_split_sync(void)
{
    struct async_update_request *aur = NULL, *n;
    int err = 0;

    /* test only */
    if (list_empty(&g_aum.aurlist))
        return;

    xlock_lock(&g_aum.lock);
    if (!list_empty(&g_aum.aurlist)) {
        list_for_each_entry_safe(aur, n, &g_aum.aurlist, list) {
            if (aur->op == AU_ITB_SPLIT) {
                list_del(&aur->list);
                break;
            }
        }
    }
    xlock_unlock(&g_aum.lock);

    if (!aur)
        return;

    err = __aur_itb_split(aur);
    if (err) {
        hvfs_err(mds, "AU (split) handle error %d\n", err);
    }

    return;
}

int au_submit(struct async_update_request *aur)
{
    xlock_lock(&g_aum.lock);
    list_add_tail(&aur->list, &g_aum.aurlist);
    xlock_unlock(&g_aum.lock);
    atomic64_inc(&hmo.prof.itb.split_submit);
    sem_post(&hmo.async_sem);

    return 0;
}

void *async_update(void *arg)
{
    struct async_thread_arg *ata = (struct async_thread_arg *)arg;
    sigset_t set;
    int err, c;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */

    while (!hmo.async_thread_stop) {
        err = sem_wait(&hmo.async_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Async update thread %d wakeup to progress the AUs.\n",
                   ata->tid);
        /* processing N request in the list */
        for (c = 0; c < hmo.conf.async_update_N; c++) {
            err = __au_req_handle();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(mds, "AU handle error %d\n", err);
            }
        }
    }
    pthread_exit(0);
}

/* async_tp_init()
 */
int async_tp_init(void)
{
    struct async_thread_arg *ata;
    int i, err = 0;

    /* init the global manage structure */
    INIT_LIST_HEAD(&g_aum.aurlist);
    xlock_init(&g_aum.lock);
    
    sem_init(&hmo.async_sem, 0, 0);

    /* init async threads' pool */
    if (!hmo.conf.async_threads)
        hmo.conf.async_threads = 4;

    hmo.async_thread = xzalloc(hmo.conf.async_threads * sizeof(pthread_t));
    if (!hmo.async_thread) {
        hvfs_err(mds, "xzalloc() pthread_t failed\n");
        return -ENOMEM;
    }

    ata = xzalloc(hmo.conf.async_threads * sizeof(struct async_thread_arg));
    if (!ata) {
        hvfs_err(mds, "xzalloc() struct async_thread_arg failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    for (i = 0; i < hmo.conf.async_threads; i++) {
        (ata + i)->tid = i;
        err = pthread_create(hmo.async_thread + i, NULL, &async_update,
                             ata + i);
        if (err)
            goto out;
    }
    
out:
    return err;
out_free:
    xfree(hmo.async_thread);
    goto out;
}

void async_tp_destroy(void)
{
    int i;

    hmo.async_thread_stop = 1;
    for (i = 0; i < hmo.conf.async_threads; i++) {
        sem_post(&hmo.async_sem);
    }
    for (i = 0; i < hmo.conf.async_threads; i++) {
        pthread_join(*(hmo.async_thread + i), NULL);
    }
    sem_destroy(&hmo.async_sem);
}
