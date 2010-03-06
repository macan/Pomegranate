/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-05 17:53:22 macan>
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
#include "ring.h"

struct hvfs_txg *txg_alloc(void)
{
    struct hvfs_txg *t;
    
    t = xzalloc(sizeof(struct hvfs_txg));
    if (!t)
        return NULL;
    /* init the lock region */
    t->state = TXG_STATE_OPEN;
    mcond_init(&t->cond);
    xlock_init(&t->ckpt_lock);
    xlock_init(&t->delta_lock);
    xlock_init(&t->itb_lock);
    xlock_init(&t->ccb_lock);
    INIT_LIST_HEAD(&t->bdb);
    INIT_LIST_HEAD(&t->ddb);
    INIT_LIST_HEAD(&t->ckpt);
    INIT_LIST_HEAD(&t->dirty_list);
    INIT_LIST_HEAD(&t->ccb_list);

    return t;
}

#define TXG_SET_TIME(txg) ((txg)->open_time = time(NULL))

int txg_init(u64 txg)
{
    struct hvfs_txg *t;
    t = txg_alloc();
    if (!t) {
        hvfs_err(mds, "txg_alloc() failed\n");
        return -ENOMEM;
    }
    TXG_SET_TIME(t);
    t->txg = txg;

    /* init the global txg array */
    hmo.txg[TXG_OPEN] = t;
    hmo.txg[TXG_WB] = NULL;

    return 0;
}

/* txg_switch()
 *
 * NOTE: only one thread can call this function, and the WB txg should be
 * commited BEFORE calling this function!
 */
int txg_switch(struct hvfs_mds_info *hmi, struct hvfs_mds_object *hmo)
{
    struct hvfs_txg *nt;
    int err = 0;
    
    /* alloc a txg */
    nt = txg_alloc();
    if (!nt) {
        hvfs_err(mds, "xzalloc() struct hvfs_txg failed.\n");
        err = -ENOMEM;
        goto out;
    }
    TXG_SET_TIME(nt);

    /* make sure the WB txg is commited */
    ASSERT(hmo->txg[TXG_WB] == NULL, mds);

    /* atomic inc the txg # */
    atomic64_inc(&hmi->mi_txg);
    nt->txg = atomic64_read(&hmi->mi_txg);
    
    /* the current opened txg is going into WB state */
    txg_get(hmo->txg[TXG_OPEN]);
    hmo->txg[TXG_WB] = hmo->txg[TXG_OPEN];
    hmo->txg[TXG_WB]->state = TXG_STATE_WB;
    txg_put(hmo->txg[TXG_OPEN]);

    /* atomic swith to the current opened txg */
    hmo->txg[TXG_OPEN] = nt;

out:
    return err;
}

/* txg_add_itb()
 *
 * NOTE: adding the itb to the txg's dirty list.
 */
void txg_add_itb(struct hvfs_txg *txg, struct itb *i)
{
    xlock_lock(&txg->itb_lock);
    if (list_empty(&i->h.list))
        list_add_tail(&i->h.list, &txg->dirty_list);
    xlock_unlock(&txg->itb_lock);
    TXG_SET_DIRTY(txg);
}

/* txg_changer()
 */
void txg_changer(time_t t)
{
    int err;

    /* pre-check */
    if (!TXG_IS_DIRTY(hmo.txg[TXG_OPEN])) {
        /* the txg is clean, just return */
        return;
    }
    /* first, check the open time */
    if (!hmo.conf.txg_interval)
        return;
    else {
        if (t < hmo.txg[TXG_OPEN]->open_time + hmo.conf.txg_interval) {
            return;
        }
    }
    /* then, check if the writeback slot is free */
    if (hmo.txg[TXG_WB] != NULL) {
        return;
    }
    /* ok, we can switch the txg */
    err = txg_switch(&hmi, &hmo);
    if (err) {
        hvfs_err(mds, "txg_switch() failed w/ low memory.\n");
    } else {
        hvfs_info(mds, "Entering new txg %ld\n", hmo.txg[TXG_OPEN]->txg);
        sem_post(&hmo.commit_sem);
    }
}

/* txg_trigger_ccb()
 */
void txg_trigger_ccb(struct hvfs_txg *txg)
{
    struct hvfs_tx *tx, *n;

    list_for_each_entry_safe(tx, n, &txg->ccb_list, ccb) {
        mds_tx_commit(tx);
        list_del(&tx->ccb);
    }
}

/* txg_prepare_begin
 *
 */
int txg_prepare_begin(struct commit_thread_arg *cta, struct hvfs_txg *t)
{
    /* construct the TXG_BEGIN region, prepare writing back */
    memset(&cta->begin, 0, sizeof(cta->begin));
    cta->begin.magic = TXG_BEGIN_MAGIC;

    /* bitmap delta nr */
    if (!list_empty(&t->bdb)) {
        /* Note that we do NOT need any locks here, becaust we know nobody
         * could access this list now. */
        struct bitmap_delta_buf *pos;

        list_for_each_entry(pos, &t->bdb, list) {
            cta->begin.bitmap_delta_nr += pos->asize;
        }
    }

    /* dir delta nr */
    if (!list_empty(&t->ddb)) {
        /* Note that we do NOT need any locks here, becaust we know nobody
         * could access this list now. */
        struct hvfs_dir_delta_buf *pos;

        list_for_each_entry(pos, &t->ddb, list) {
            cta->begin.dir_delta_nr += pos->asize;
        }
    }

    /* ckpt nr */
    if (!list_empty(&t->ckpt)) {
        /* Note that we do NOT need any locks here, becaust we know nobody
         * could access this list now. */
        struct hvfs_rmds_ckpt_buf *pos;

        list_for_each_entry(pos, &t->ckpt, list) {
            cta->begin.ckpt_nr += pos->asize;
        }
    }
    cta->begin.txg = t->txg;
    cta->begin.site_id = hmo.site_id;
    cta->begin.session_id = hmi.session_id;

    return 0;
}

/* txg_wb_itb_ll()
 *
 * NOTE: low level ITB write back function.
 */
static inline
int txg_wb_itb_ll(struct commit_thread_arg *cta, struct itb *itb)
{
    struct txg_wb_slice *tws;
    struct xnet_msg *msg;
    struct dhe *e;
    struct chp *p;
    int err = 0;

    if (hmo.conf.option & HVFS_MDS_MEMONLY)
        return 0;

    /* Step 1: find the target mdsl site */
    e = mds_dh_search(&hmo.dh, itb->h.puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    
    p = ring_get_point(itb->h.itbid, e->salt, hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(e));
        err = -ECHP;
        goto out;
    }

    /* Step 1.inf: prepare the xnet msg a litte earlier */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }
    /* Step 2: lookup in the CTA hash table */
    tws = tws_find_create(cta, p->site_id);
    if (!tws) {
        hvfs_err(mds, "tws_find_create() failed.\n");
        err = -ENOMEM;
        goto out_free_msg;
    }
    /* Step 3: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0, 
                     hmo.site_id, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_WBTXG, HVFS_WBTXG_ITB, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    if (IS_TWS_NEW(tws)) {
        TWS_CLEAN_NEW(tws);
        msg->tx.arg0 |= HVFS_WBTXG_BEGIN;
        xnet_msg_add_sdata(msg, &cta->begin, sizeof(cta->begin));
    }
    xnet_msg_add_sdata(msg, itb, atomic_read(&itb->h.len));
#if 1
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Write back ITB %ld failed w/ %d\n",
                 itb->h.itbid, err);
        TWS_SET_NEW(tws);
        goto out_free_msg;
    }
#endif
    hvfs_debug(mds, "Write back ITB %ld to site %lx [%ld,%lx]\n",
               itb->h.itbid, p->site_id, itb->h.itbid, e->salt);

    xnet_free_msg(msg);
    return err;

out_free_msg:
    xnet_raw_free_msg(msg);
out:
    return err;
}

static inline
int txg_wb_bcast_delta(struct commit_thread_arg *cta, int err)
{
    return err;
}

/* txg_wb_itb()
 *
 * NOTE: write back the ITBs to their own site, 
 */
static inline
int txg_wb_itb(struct commit_thread_arg *cta, struct hvfs_txg *t,
               int *freed, int *clean, int *notknown)
{
    struct itbh *ih, *n;
    struct itb *i;
    int err = 0;

    list_for_each_entry_safe(ih, n, &t->dirty_list, list) {
        i = (struct itb *)ih;
        list_del_init(&ih->list);
        xrwlock_wlock(&ih->lock);
        hvfs_debug(mds, "T %ld ITB %ld %p state %x, ref %d.\n",
                   t->txg, ih->itbid, i, ih->state, atomic_read(&ih->ref));
        if (ih->state == ITB_STATE_COWED) {
            xrwlock_wunlock(&ih->lock);
            if (atomic_read(&ih->ref) != 1) {
                hvfs_err(mds, "REF %d\n", atomic_read(&ih->ref));
                HVFS_BUGON(atomic_read(&ih->ref) != 1);
            }
            /* can write w/o lock */
            err = txg_wb_itb_ll(cta, i);
            itb_put(i);
            (*freed)++;
        } else if (ih->state == ITB_STATE_DIRTY) {
            /* write w/ lock holding */
            err = txg_wb_itb_ll(cta, i);
            ih->state = ITB_STATE_CLEAN;
            xrwlock_wunlock(&ih->lock);
            (*clean)++;
        } else {
            /* write w/ lock holding */
            err = txg_wb_itb_ll(cta, i);
            ih->state = ITB_STATE_CLEAN;
            xrwlock_wunlock(&ih->lock);
            (*notknown)++;
        }
    }
    err = txg_wb_bcast_delta(cta, err);

    return err;
}

/* txg_commit()
 *
 * NOTE: this is the main function for commit thread
 * NOTE: we should design the txg parallel writeback model.
 */
void *txg_commit(void *arg)
{
    struct commit_thread_arg *cta = (struct commit_thread_arg *)arg;
    struct hvfs_txg *t;
    struct timespec ts;
    sigset_t set;
    int err, freed, clean, notknown;
    
    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */

    while (!hmo.commit_thread_stop) {
        err = sem_wait(&hmo.commit_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Commit thread %d wakeup to progress the TXG"
                   " writeback.\n", cta->tid);
        /* ok, we should commit the dirty TXG to the MDSL */
        t = hmo.txg[TXG_WB];
        if (!t)
            continue;
        /* Step1: wait for any pending TXs */
        mcond_lock(&t->cond);
        if (t->state != TXG_STATE_WB) {
            mcond_unlock(&t->cond);
            continue;
        } else {
            t->state = TXG_STATE_WBING;
        }
        mcond_unlock(&t->cond);

        while (atomic64_read(&t->tx_pending)) {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 2000;  /* 2000 ns */
            mcond_timedwait(&t->cond, &ts);
            hvfs_debug(mds, "><--%ld--><\n", atomic64_read(&t->tx_pending));
            if (t != hmo.txg[TXG_WB]) {
                goto retry;
            }
        }

        hvfs_debug(mds, "TXG %ld is write-backing.\n", t->txg);
        /* Step2: no reference to this TXG, we can write back now */
        CTA_INIT(cta, t);
        txg_prepare_begin(cta, t);

        freed = clean = notknown = 0;
        err = txg_wb_itb(cta, t, &freed, &clean, &notknown);
        if (err) {
            hvfs_err(mds, "txg_wb_itb() failed w/ %d\n", err);
        }

        CTA_FINA(cta);
        
        hmo.txg[TXG_WB] = NULL;
        /* free the TXG */
        hvfs_info(mds, "TXG %ld is released (free:%d, clean:%d, ntkwn:%d).\n", 
                  t->txg, freed, clean, notknown);
        mcond_destroy(&t->cond);
        /* trigger the commit callback on the TXs */
        txg_trigger_ccb(t);
        xfree(t);
    retry:
        ;
    }
    pthread_exit(0);
}

int commit_tp_init()
{
    struct commit_thread_arg *cta;
    int i, err = 0;

    sem_init(&hmo.commit_sem, 0, 0);
    
    /* init commit threads' pool */
    if (!hmo.conf.commit_threads)
        hmo.conf.commit_threads = 4;

    hmo.commit_thread = xzalloc(hmo.conf.commit_threads * sizeof(pthread_t));
    if (!hmo.commit_thread) {
        hvfs_err(mds, "xzalloc() pthread_t failed\n");
        return -ENOMEM;
    }

    cta = xzalloc(hmo.conf.commit_threads * sizeof(struct commit_thread_arg));
    if (!cta) {
        hvfs_err(mds, "xzalloc() struct commit_thread_arg failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    
    for (i = 0; i < hmo.conf.commit_threads; i++) {
        (cta + i)->tid = i;
        err = pthread_create(hmo.commit_thread + i, NULL, &txg_commit,
                             cta + i);
        if (err)
            goto out;
    }

out:
    return err;
out_free:
    xfree(hmo.commit_thread);
    goto out;
}

void commit_tp_destroy(void)
{
    int i;
    
    hmo.commit_thread_stop = 1;
    for (i = 0; i < hmo.conf.commit_threads; i++) {
        sem_post(&hmo.commit_sem);
    }
    for (i = 0; i < hmo.conf.commit_threads; i++) {
        pthread_join(*(hmo.commit_thread + i), NULL);
    }
    sem_destroy(&hmo.commit_sem);
}
