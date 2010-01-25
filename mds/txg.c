/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 10:43:22 macan>
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

/* __txg_busy_loop_detector()
 *
 * NOTE: I observe the busy loop situation in the test cast this day, but it
 * is very hard to reproduce it, so I put this loop detector() here in the
 * following test cases to catch it.
 */
#define BLD_COUNT       0
#define BLD_RESET       1
static inline void __txg_busy_loop_detector(struct hvfs_txg *t, int bld)
{
    static int i = 0;
    if (bld == BLD_COUNT) {
        i++;
    } else if (bld == BLD_RESET) {
        i = 0;
    }
    if (i == 100000000) {
        hvfs_err(mds, "TXG %p %ld state %x\n", t, t->txg, t->state);
        exit(0);
    }
}


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

struct hvfs_txg *mds_get_open_txg(struct hvfs_mds_object *hmo)
{
    struct hvfs_txg *t;

retry:
    /* get the txg first */
    t = hmo->txg[TXG_OPEN];     /* atomic read */
    txg_get(t);
    /* checking the txg state */
    if (t->state != TXG_STATE_OPEN) {
        /* oh, txg switched, for correctness, retry myself */
        txg_put(t);
        __txg_busy_loop_detector(t, BLD_COUNT);
        goto retry;
    }

    __txg_busy_loop_detector(t, BLD_RESET);
    return t;
}

struct hvfs_txg *mds_get_wb_txg(struct hvfs_mds_object *hmo)
{
    return hmo->txg[TXG_WB];
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

/* txg_commit()
 *
 * NOTE: this is the main function for commit thread
 * NOTE: we should design the txg parallel writeback model.
 */
void *txg_commit(void *arg)
{
    struct commit_thread_arg *cta = (struct commit_thread_arg *)arg;
    struct hvfs_txg *t;
    struct itbh *ih, *n;
    struct itb *i;
    struct timespec ts;
    sigset_t set;
    int err, freed, clean;
    
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
        freed = clean = 0;
        list_for_each_entry_safe(ih, n, &t->dirty_list, list) {
            i = (struct itb *)ih;
            list_del_init(&ih->list);
            xrwlock_rlock(&ih->lock);
            if (ih->state == ITB_STATE_COWED) {
                xrwlock_runlock(&ih->lock);
                itb_free(i);
                freed++;
            } else {
                ih->state = ITB_STATE_CLEAN;
                xrwlock_runlock(&ih->lock);
                clean++;
            }
        }
        hmo.txg[TXG_WB] = NULL;
        /* free the TXG */
        hvfs_info(mds, "TXG %ld is released (free:%d, clean:%d).\n", 
                  t->txg, freed, clean);
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

    cta = xzalloc(hmo.conf.commit_threads * sizeof(pthread_t));
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
