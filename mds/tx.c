/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-21 18:52:42 macan>
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
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "mds.h"

static inline u64 mds_rdtx()
{
    return atomic64_inc_return(&hmi.mi_tx);
}

/* mds_tx_fix_ccb()
 *
 * Note: this function fix the relationship between TX and TXG on COMMIT
 * requests.
 */
static inline
void mds_tx_fix_ccb(struct hvfs_tx *tx)
{
    if (tx->op == HVFS_TX_NORMAL) {
        if (list_empty(&tx->ccb)) {
            list_add_tail(&tx->ccb, &tx->txg->ccb_list);
        }
    }
}

/* fast allocate TX in TXC lru list */
static inline
struct hvfs_tx *mds_txc_alloc_tx(struct hvfs_txc *txc)
{
    struct list_head *l = NULL;
    struct hvfs_tx *tx = NULL;
    
    xlock_lock(&txc->lock);
    if (atomic_read(&txc->ftx) > MDS_TXC_MAX_FREE) {
        /* ok, we need to free some memory for other modules */
    }
    if (atomic_read(&txc->ftx) > 0) {
        atomic_dec(&txc->ftx);
        l = txc->lru.next;
        ASSERT(l != &txc->lru, mds);
        list_del_init(l);
    }

    if (l) {
        /* remove from the TXC */
        tx = list_entry(l, struct hvfs_tx, lru);
        if (!hlist_unhashed(&tx->hlist)) {
            hvfs_debug(mds, "Remove TX %p from the TXC.\n", tx);
            mds_txc_evict(txc, tx);
        }
    }
    xlock_unlock(&txc->lock);

    return tx;
}

struct hvfs_tx *mds_alloc_tx(u16 op, struct xnet_msg *req)
{
    struct hvfs_tx *tx;
    
    /* Step 1: try the fast allocation path */
    tx = mds_txc_alloc_tx(&hmo.txc);
    if (likely(tx))
        goto init_tx;
    /* fall back to slow path */
    tx = xzalloc(sizeof(*tx));
    if (unlikely(!tx)) {
        hvfs_debug(mds, "zalloc() hvfs_tx failed\n");
        return NULL;
    }
    atomic_inc(&hmo.txc.total);
    
init_tx:
    tx->op = op;
    tx->state = HVFS_TX_PROCESSING;
    tx->tx = mds_rdtx();
    tx->reqno = req->tx.reqno;
    tx->reqin_site = req->tx.ssite_id;
    tx->req = req;
    tx->rpy = NULL;
    tx->txg = mds_get_open_txg(&hmo); /* get the current opened TXG */
    atomic_set(&tx->ref, 1);
    INIT_LIST_HEAD(&tx->lru);
    INIT_LIST_HEAD(&tx->tx_list);
    INIT_LIST_HEAD(&tx->ccb);
    INIT_HLIST_NODE(&tx->hlist);

    /* FIXME: insert in the TXC */
    mds_txc_add(&hmo.txc, tx);
    mds_tx_fix_ccb(tx);
    /* FIXME: tx_list? */

    return tx;
}

/* mds_free_tx()
 *
 * Note: this function should NOT be called unless the TX need to be dropped
 * immediately!
 */
void mds_free_tx(struct hvfs_tx *tx)
{
    ASSERT(list_empty(&tx->lru), mds);
    /* evict the TX, and we should set the tx->state to DONE to pass the
     * assertation */
    tx->state = HVFS_TX_DONE;
    mds_txc_evict(&hmo.txc, tx);
    
    mds_put_tx(tx);
    txg_put(tx->txg);

    xlock_lock(&hmo.txc.lock);
    list_add_tail(&tx->lru, &hmo.txc.lru);
    atomic_inc(&hmo.txc.ftx);
    xlock_unlock(&hmo.txc.lock);
}

void mds_pre_free_tx(int hint)
{
    struct hvfs_tx *tx;

#if 0
    if (lib_random(hint))       /* exec @ p = 1/HINT */
        return;
#endif
    
    xlock_lock(&hmo.txc.lock);
    list_for_each_entry(tx, &hmo.txc.lru, lru) {
        if (!hlist_unhashed(&tx->hlist)) {
            hvfs_debug(mds, "OK, pre free this TX %p.\n", tx);
            mds_txc_evict(&hmo.txc, tx);
        }
        if (--hint == 0)
            break;
    }
    xlock_unlock(&hmo.txc.lock);
}

void mds_get_tx(struct hvfs_tx *tx)
{
    atomic_inc(&tx->ref);
}

void mds_put_tx(struct hvfs_tx *tx)
{
    atomic_dec(&tx->ref);
}

/*
 * @hsize: hash table size
 * @ftx:   free TXs, for fast TX allocation
 */
int mds_init_txc(struct hvfs_txc *txc, int hsize, int ftx)
{
    struct hvfs_tx *txs;
    int err = 0, i;
    
    INIT_LIST_HEAD(&txc->lru);
    xlock_init(&txc->lock);

    /* regular hash init */
    hsize = (hsize == 0) ? MDS_TXC_DEFAULT_SIZE : hsize;
    i = fls64(hsize);
    if ((u64)hsize != (1UL << i)) {
        hvfs_err(mds, "TXC hash table size should be 2^N.\n");
        return -EINVAL;
    }
    txc->txht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!txc->txht) {
        hvfs_err(mds, "TXC hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&txc->txht[i].h);
        xlock_init(&txc->txht[i].lock);
    }
    
    /* pre-allocate TXs */
    ftx = (ftx == 0) ? MDS_TXC_DEFAULT_FTX : ftx;
    txs = xzalloc(ftx * sizeof(struct hvfs_tx));
    if (!txs) {
        hvfs_info(mds,  "TXC pre-allocate TX failed\n");
        ftx = 0;
    } else {
        for (i = 0; i < ftx; i++) {
            INIT_LIST_HEAD(&(txs + i)->lru);
            /* no need to hold the lock at this moment */
            list_add_tail(&(txs + i)->lru, &txc->lru);
        }
    }

    txc->hsize = hsize;
    atomic_set(&txc->total, ftx);
    atomic_set(&txc->ftx, ftx);
out:
    return err;
}

int mds_destroy_txc(struct hvfs_txc *txc)
{
    /* NOTE: there is no need to destroy the TXC actually */
    if (txc->txht)
        xfree(txc->txht);
    atomic_set(&txc->ftx, 0);
    return 0;
}

static inline 
int mds_txc_hash(u64 site_id, u64 reqno, struct hvfs_txc *txc)
{
    u64 val1, val2;

    val1 = hash_64(site_id, 64);
    val2 = hash_64(reqno, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1 & (txc->hsize - 1);
}

/* TXC insert function
 *
 * @tx:
 */
int mds_txc_add(struct hvfs_txc *txc, struct hvfs_tx *tx)
{
    struct regular_hash *rh;
    int i;

    if (tx->op == HVFS_TX_FORGET)
        return 0;

    ASSERT(hlist_unhashed(&tx->hlist), mds);

    /* compute the hash value and select the RH entry */
    i = mds_txc_hash(tx->reqin_site, tx->reqno, txc);
    rh = txc->txht + i;

    xlock_lock(&rh->lock);
    hlist_add_head(&tx->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    return 0;
}

/* TXC search function, w/ TX got, you MUST put it!
 *
 * @site: source site
 * @reqno:source site reqno
 */
struct hvfs_tx *mds_txc_search(struct hvfs_txc *txc, u64 site, u64 reqno)
{
    struct regular_hash *rh;
    struct hvfs_tx *tx = NULL;
    struct hlist_node *l;
    int i, found = 0;

    i = mds_txc_hash(site, reqno, txc);
    rh = txc->txht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(tx, l, &rh->h, hlist) {
        if (unlikely(tx->reqin_site == site && tx->reqno == reqno)) {
            found = 1;
            mds_get_tx(tx);
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (likely(!found))
        tx = NULL;
    return tx;
}

/* Evict the TX from TXC, waiting for tx->ref to zero!
 *
 * NOTE: you should got the TX yourself!
 */
int mds_txc_evict(struct hvfs_txc *txc, struct hvfs_tx *tx)
{
    struct regular_hash *rh;
    int i;

    /* check the state now, ourself holding the last reference */
    while (atomic_read(&tx->ref) > 1)
        xsleep(0);

    i = mds_txc_hash(tx->reqin_site, tx->reqno, txc);
    rh = txc->txht + i;
    xlock_lock(&rh->lock);
    hlist_del_init(&tx->hlist);
    xlock_unlock(&rh->lock);

    /* free all the TX resources */
    ASSERT(tx->state >= HVFS_TX_DONE, mds);
    if (tx->req) {
        xnet_free_msg(tx->req);
        tx->req = NULL;
    }
    if (tx->rpy) {
        xnet_free_msg(tx->rpy);
        tx->rpy = NULL;
    }

    return 0;
}

/* __tx_send_commit_msg()
 *
 * NOTE: send the commit msg to the source site to release the TXs
 */
static inline
void __tx_send_commit_msg(struct hvfs_tx *tx)
{
    struct xnet_msg *msg;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_warning(mds, "xnet_alloc_msg() faield\n");
        /* do not retry myself */
        return;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_RPY, 0, hmo.site_id,
                     tx->reqin_site);
    xnet_msg_fill_reqno(msg, tx->req->tx.reqno);
    xnet_msg_fill_cmd(msg, XNET_RPY_COMMIT, 0, 0);
    msg->tx.handle = tx->req->tx.handle;

    hvfs_err(mds, "SEND COMMIT to site %ld for reqno %ld\n",
             tx->reqin_site, tx->reqno);
    xnet_wait_group_add(mds_gwg, msg);
    if (xnet_isend(hmo.xc, msg)) {
        hvfs_err(mds, "xnet_isend() failed\n");
        /* do not retry myself, client is forced to retry */
        xnet_wait_group_del(mds_gwg, msg);
    }
    /* NOTE: if using XNET_SIMPLE, we need to free the msg here */
}

/* mds_tx_chg2forget()
 *
 * We just remove the TX from the TXC, do NOT free any resources
 */
void mds_tx_chg2forget(struct hvfs_tx *tx)
{
    struct regular_hash *rh;
    int i;

    if (unlikely(tx->op == HVFS_TX_FORGET))
        return;
    
    tx->op = HVFS_TX_FORGET;

    i = mds_txc_hash(tx->reqin_site, tx->reqno, &hmo.txc);
    rh = hmo.txc.txht + i;
    xlock_lock(&rh->lock);
    hlist_del_init(&tx->hlist);
    xlock_unlock(&rh->lock);
}

/*
 * NOTE: you should got the TX yourself!
 */
void mds_tx_done(struct hvfs_tx *tx)
{
    if (likely(tx->state == HVFS_TX_PROCESSING))
        tx->state = HVFS_TX_DONE;
    else {
        hvfs_err(mds, "Invalid TX %p state 0x%x when calling mds_tx_done.\n", 
                 tx, tx->state);
        return;
    }
    /* NOTE: the following function is need to release the alloc
     * reference */
    mds_put_tx(tx);
    txg_put(tx->txg);

    if (tx->op == HVFS_TX_FORGET) {
        /* free the resources */
        if (tx->req) {
            xnet_free_msg(tx->req);
            tx->req = NULL;
        }
        if (tx->rpy) {
            xnet_free_msg(tx->rpy);
            tx->rpy = NULL;
        }
        xlock_lock(&hmo.txc.lock);
        list_add_tail(&tx->lru, &hmo.txc.lru);
        atomic_inc(&hmo.txc.ftx);
        xlock_unlock(&hmo.txc.lock);
    }
}

/*
 * NOTE: you should got the TX yourself!
 */
void mds_tx_reply(struct hvfs_tx *tx)
{
    if (likely(tx->state <= HVFS_TX_DONE))
        tx->state = HVFS_TX_ACKED;
    else
        return;
    /* if tx->state == HVFS_TX_COMMITED, do not change it */

    if (tx->op == HVFS_TX_NOCOMMIT) {
        /* need reply, but no commit */
        xlock_lock(&hmo.txc.lock);
        list_add_tail(&tx->lru, &hmo.txc.lru);
        atomic_inc(&hmo.txc.ftx);
        xlock_unlock(&hmo.txc.lock);
        mds_pre_free_tx(HVFS_TX_PRE_FREE_HINT);
    }
}

/*
 * OK to add to the TXC LRU list, called after TXG commited!
 *
 * NOTE: you should got the TX yourself!
 */
void mds_tx_commit(struct hvfs_tx *tx)
{
    if (tx->state < HVFS_TX_DONE) {
        hvfs_err(mds, "Invalid TX state 0x%x when calling mds_tx_commit.\n", 
                 tx->state);
        return;
    } else if (tx->state <= HVFS_TX_ACKED)
        tx->state = HVFS_TX_COMMITED;
    else
        return;

    if (tx->op == HVFS_TX_NORMAL) {
        /* try to send the commit msg to source site */
        __tx_send_commit_msg(tx);
        xlock_lock(&hmo.txc.lock);
        ASSERT(list_empty(&tx->lru), mds);
        list_add_tail(&tx->lru, &hmo.txc.lru);
        atomic_inc(&hmo.txc.ftx);
        xlock_unlock(&hmo.txc.lock);
        mds_pre_free_tx(HVFS_TX_PRE_FREE_HINT);
    }
}

/* mds_init_tx()
 *
 * NOTE: init the TX subssytem and init the commit threads' pool
 */
int mds_init_tx(u64 txg)
{
    int err;
    
    /* init the txg */
    err = txg_init(txg);
    if (err)
        goto out;
    /* init the commit threads' pool */
    err = commit_tp_init();
    if (err)
        goto out;
out:    
    return 0;
}

/* mds_destroy_tx()
 */
void mds_destroy_tx(void)
{
    commit_tp_destroy();
}
