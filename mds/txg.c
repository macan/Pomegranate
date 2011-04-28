/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-28 13:03:00 macan>
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

static pthread_key_t itb_key;

static pthread_once_t itb_key_once = PTHREAD_ONCE_INIT;
static pthread_once_t lzo_key_once = PTHREAD_ONCE_INIT;

static void
make_tmp_itb()
{
    pthread_key_create(&itb_key, NULL);
}

static void
make_lzo_workmem()
{
    pthread_key_create(&hmo.lzo_workmem, NULL);
}

int txg_lookup_rdir(struct hvfs_txg *txg, u64 uuid)
{
    int found = 0, i;

    for (i = 0; i < txg->rd.asize; i++) {
        if (uuid == txg->rd.rd[i]) {
            found = 1;
            break;
        }
    }
    
    return found;
}

int txg_add_rdir(struct hvfs_txg *txg, u64 uuid)
{
    u64 *p;
    u32 nsize;

    if (txg->rd.asize >= txg->rd.psize) {
        /* alloc new chunks */
        nsize = max(txg->rd.psize << 1, (u32)1);
        p = xrealloc(txg->rd.rd, nsize * sizeof(u64));
        if (!p) {
            return -ENOMEM;
        }
        txg->rd.rd = p;
        txg->rd.psize = nsize;
    }
    txg->rd.rd[txg->rd.asize++] = uuid;
    rdir_insert(&hmo.rm, uuid);

    return 0;
}

struct hvfs_txg *txg_alloc(void)
{
    struct hvfs_txg *t;
    int i;
    
    t = xzalloc(sizeof(struct hvfs_txg) + 
                hmo.conf.txg_ddht_size * sizeof(struct regular_hash));
    if (!t)
        return NULL;

    /* init the lock region */
    t->state = TXG_STATE_OPEN;
    mcond_init(&t->cond);
    xlock_init(&t->ckpt_lock);
    xlock_init(&t->itb_lock);
    xlock_init(&t->rddb_lock);
    xlock_init(&t->bdb_lock);
    xlock_init(&t->ccb_lock);
    xrwlock_init(&t->ddht_lock);
    INIT_LIST_HEAD(&t->bdb);
    INIT_LIST_HEAD(&t->ddb);
    INIT_LIST_HEAD(&t->ckpt);
    INIT_LIST_HEAD(&t->rddb);
    INIT_LIST_HEAD(&t->dirty_list);
    INIT_LIST_HEAD(&t->ccb_list);
    INIT_LIST_HEAD(&t->ddht_list);

    /* init the hash table */
    for (i = 0; i < hmo.conf.txg_ddht_size; i++) {
        INIT_HLIST_HEAD(&t->ddht[i].h);
        xlock_init(&t->ddht[i].lock);
    }

    return t;
}

void txg_free(struct hvfs_txg *t)
{
    struct bitmap_delta_buf *bdb, *bdbn;
    struct hvfs_dir_delta_buf *ddb, *ddbn;
    struct hvfs_rmds_ckpt_buf *ckpt, *ckptn;
    
    if (t->rd.psize)
        xfree(t->rd.rd);
    
    list_for_each_entry_safe(bdb, bdbn, &t->bdb, list) {
        list_del(&bdb->list);
        xfree(bdb);
    }

    list_for_each_entry_safe(ddb, ddbn, &t->ddb, list) {
        list_del(&ddb->list);
        xfree(ddb);
    }

    list_for_each_entry_safe(ddb, ddbn, &t->rddb, list) {
        list_del(&ddb->list);
        xfree(ddb);
    }

    list_for_each_entry_safe(ckpt, ckptn, &t->ckpt, list) {
        list_del(&ckpt->list);
        xfree(ckpt);
    }
    /* dirty_list has been already freed */
    /* ccb_list should be freed, this list is NULL :) */
    
    xfree(t);
}

#define TXG_SET_TIME(txg) ((txg)->open_time = time(NULL))

int txg_init(u64 txg)
{
    struct hvfs_txg *t;

    /* init the default hash table size */
    if (hmo.conf.txg_ddht_size <= 0) {
        hmo.conf.txg_ddht_size = HVFS_TXG_DDHT_SIZE;
    }
    
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

static inline
void TXG_COMMITED(u64 txg)
{
retry:
    if (atomic64_read(&hmo.ctxg) + 1 == txg)
        atomic64_inc(&hmo.ctxg);
    else {
        xsleep(100);
        goto retry;
    }
}

int TXG_IS_COMMITED(u64 txg)
{
    if (txg <= atomic_read(&hmo.ctxg))
        return 1;
    else
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
    static atomic_t ref = {.counter = 0,};
    int err = 0;
    
    /* concurrent handling */
    if (atomic_inc_return(&ref) > 1) {
        atomic_dec(&ref);
        return 0;
    }
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
    nt->txg = atomic64_inc_return(&hmi->mi_txg);
    
    /* the current opened txg is going into WB state */
    txg_get(hmo->txg[TXG_OPEN]);
    hmo->txg[TXG_WB] = hmo->txg[TXG_OPEN];
    hmo->txg[TXG_WB]->state = TXG_STATE_WB;
    txg_put(hmo->txg[TXG_OPEN]);

    /* atomic swith to the current opened txg */
    hmo->txg[TXG_OPEN] = nt;

out:
    atomic_dec(&ref);
    
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

/* txg_change_immediately()
 *
 * trigger an immediately txg change
 */
void txg_change_immediately(void)
{
    struct hvfs_txg *old;
    u64 old_txg;
    u32 old_ti;
    u8 old_dati, dirty;

    old = mds_get_open_txg(&hmo);
    old_txg = old->txg;
    dirty = old->dirty;
    txg_put(old);

    old_ti = hmo.conf.txg_interval;
    old_dati = hmo.conf.dati;
    
    
    /* if the current opened txg is clean, just return */
    if (!dirty)
        return;

    /* firstly, disable the DATI */
    hmo.conf.dati = 0;

    /* secondly, try to trigger a change */
    hmo.conf.txg_interval = 1;

    /* waiting for the txg changing */
    do {
        if (hmo.txg[TXG_OPEN]->txg > old_txg) {
            if (hmo.txg[TXG_WB] == NULL || old != hmo.txg[TXG_WB]) {
                hvfs_info(mds, "Clearance of txg %ld to MDSL.\n", old_txg);
                break;
            }
        }
        /* wait for 1 second */
        sleep(1);
    } while (1);

    /* restore the state now */
    hmo.conf.txg_interval = old_ti;
    hmo.conf.dati = old_dati;

    /* commit the cached bitmaps */
    {
        int err;

        err = mds_bc_backend_commit();
        if (err) {
            hvfs_err(mds, "mds_bc_backend_commit failed w/ %d\n", err);
        }
    }
}

void mds_snapshot_fr2(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    int err = 0;

    /* Magic:) if we see tx.arg1 is 1, then we pause request handling */
    if (msg->tx.arg1 == 1) {
        /* pause request handling now */
        hmo.reqin_drop = 1;
    }

    do {
        txg_change_immediately();
    } while (TXG_IS_DIRTY(hmo.txg[TXG_OPEN]));

    /* should evict the bitmapc, dh, and cbht */
    mds_bitmap_cache_evict();
    mds_dh_evict(&hmo.dh);
    do {
        mds_cbht_scan(&hmo.cbht, HVFS_MDS_OP_EVICT_ALL);
    } while (atomic64_read(&hmo.prof.cbht.aitb));

    rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(mds, "xnet_send() failed\n");
    }

    xnet_free_msg(rpy);
    xnet_free_msg(msg);
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
    int err = 0;
    
    /* construct the TXG_BEGIN region, prepare writing back */
    memset(&cta->begin, 0, sizeof(cta->begin));
    cta->begin.magic = TXG_BEGIN_MAGIC;
    cta->begin.mi_txg = t->txg;
    cta->begin.rd_nr = t->rd.asize;
    cta->begin.mi_uuid = atomic64_read(&hmi.mi_uuid);
    cta->begin.mi_fnum = atomic64_read(&hmi.mi_fnum);
    cta->begin.mi_dnum = atomic64_read(&hmi.mi_dnum);

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
    /* Step 1: we should construct the ddb buffer */
    err = txg_ddht_compact(t);
    if (err) {
        hvfs_err(mds, "txg_ddht_compact() failed w/ %d, metadata lossing\n",
                 err);
    }

    /* Step 2: compute the ddb buffer size */
    if (!list_empty(&t->ddb)) {
        /* Note that we do NOT need any locks here, becaust we know nobody
         * could access this list now. */
        struct hvfs_dir_delta_buf *pos;

        list_for_each_entry(pos, &t->ddb, list) {
            cta->begin.dir_delta_nr += pos->asize;
        }
    }

    /* remote dir delta nr */
    if (!list_empty(&t->rddb)) {
        /* Note that we do NOT need any locks here, because we know nobody
         * could access this list now. */
        struct hvfs_dir_delta_buf *pos;

        list_for_each_entry(pos, &t->rddb, list) {
            cta->begin.rdd_nr += pos->asize;
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
    hvfs_debug(mds, "Prepare to wb %lx %ld %ld\n", itb->h.puuid,
               itb->h.itbid, e->salt);
    mds_dh_put(e);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
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
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_WBTXG, HVFS_WBTXG_ITB, cta->wbt->txg);
    msg->tx.reserved = p->vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    if (IS_TWS_NEW(tws)) {
        TWS_CLEAN_NEW(tws);
        msg->tx.arg0 |= HVFS_WBTXG_BEGIN;
        xnet_msg_add_sdata(msg, &cta->begin, sizeof(cta->begin));
        if (cta->begin.dir_delta_nr) {
            msg->tx.arg0 |= HVFS_WBTXG_DIR_DELTA;
            TXG_ADD_SDATA(hvfs_dir_delta_buf, ddb, hvfs_dir_delta, cta, msg);
        }
        if (cta->begin.rdd_nr) {
            msg->tx.arg0 |= HVFS_WBTXG_R_DIR_DELTA;
            TXG_ADD_SDATA(hvfs_dir_delta_buf, rddb, hvfs_dir_delta, cta, msg);
        }
        if (cta->begin.bitmap_delta_nr) {
            msg->tx.arg0 |= HVFS_WBTXG_BITMAP_DELTA;
            TXG_ADD_SDATA(bitmap_delta_buf, bdb, bitmap_delta, cta, msg);
        }
        if (cta->begin.ckpt_nr) {
            msg->tx.arg0 |= HVFS_WBTXG_CKPT;
            TXG_ADD_SDATA(hvfs_rmds_ckpt_buf, ckpt, checkpoint, cta, msg);
        }
        if (cta->begin.rd_nr) {
            msg->tx.arg0 |= HVFS_WBTXG_RDIR;
            xnet_msg_add_sdata(msg, cta->wbt->rd.rd,
                               sizeof(u64) * cta->begin.rd_nr);
        }
        msg->tx.flag |= XNET_NEED_REPLY;
    }
    xnet_msg_add_sdata(msg, itb, atomic_read(&itb->h.len));
#if 1
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Write back ITB %ld failed w/ %d\n",
                 itb->h.itbid, err);
        if (msg->tx.arg0 & HVFS_WBTXG_BEGIN)
            TWS_SET_NEW(tws);
        tws->err = err;
    }
#endif
    hvfs_debug(mds, "Write back ITB %ld to site %lx [%ld,%lx]\n",
               itb->h.itbid, p->site_id, itb->h.itbid, e->salt);

    tws->nr++;
    tws->len += atomic_read(&itb->h.len);
    xnet_free_msg(msg);
    atomic64_inc(&hmo.prof.mdsl.itb_wb);

    return err;

out_free_msg:
    xnet_raw_free_msg(msg);
out:
    return err;
}

int __send_txg_end(struct txg_wb_slice *tws, struct commit_thread_arg *cta)
{
    struct txg_end *te;
    struct xnet_msg *msg;
    int err = 0;

    if (hmo.conf.option & HVFS_MDS_MEMONLY)
        return 0;

    /* Step 1: prepare the memory */
    te = xzalloc(sizeof(struct txg_end));
    if (!te) {
        hvfs_err(mds, "xzalloc txg_end failed.\n");
        err = -ENOMEM;
        goto out;
    }
    te->magic = 0x529adef8;
    te->len = tws->len;
    te->itb_nr = tws->nr;
    te->err = tws->err;
    te->txg = cta->wbt->txg;
    te->site_id = hmo.site_id;
    te->session_id = hmi.session_id;
    
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out_free;
    }

    /* Step 2: fill the msg */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY,
                     hmo.site_id, tws->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_WBTXG, HVFS_WBTXG_END, cta->wbt->txg);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, te, sizeof(*te));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Write back txg_end failed w/ %d\n", err);
    }

    xnet_free_msg(msg);

out:
    return err;
out_free:
    xfree(te);
    return err;
}

static inline
int txg_wb_bcast_end(struct commit_thread_arg *cta, int err)
{
    struct txg_wb_slice *pos, *n;

    list_for_each_entry_safe(pos, n, &cta->tws_list, list) {
        pos->err = err;
        err = __send_txg_end(pos, cta);
        if (err) {
            hvfs_err(mds, "send_txg_end @ TXG %ld failed w/ %d\n",
                     cta->wbt->txg, err);
        }
        list_del(&pos->list);
        tws_free(pos);
    }

    TXG_COMMITED(cta->wbt->txg);

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
    struct itb *i, *tmpi = NULL, *swap = NULL;
    int err = 0, failed = 0;

    /* try to get the temp itb now */
    tmpi = pthread_getspecific(itb_key);
    if (unlikely(!tmpi)) {
        hvfs_err(mds, "Try to get temp itb for WB failed, slow down...\n");
    } else 
        swap = tmpi;
    
    list_for_each_entry_safe(ih, n, &t->dirty_list, list) {
        i = (struct itb *)ih;
        list_del_init(&ih->list);
        xrwlock_wlock(&ih->lock);
        hvfs_debug(mds, "T %ld ITB %ld %p state %x, ref %d.\n",
                   t->txg, ih->itbid, i, ih->state, atomic_read(&ih->ref));
        if (unlikely(ih->state == ITB_STATE_COWED)) {
            xrwlock_wunlock(&ih->lock);
            if (unlikely(atomic_read(&ih->ref) != 1)) {
                hvfs_err(mds, "REF %d\n", atomic_read(&ih->ref));
                /* Note that: ref == 2 means this entry is under splitting,
                 * the async thread will free it! */
                if (unlikely(!(atomic_read(&ih->ref) == 1 ||
                               atomic_read(&ih->ref) == 2))) {
                    HVFS_BUGON("ITB COWED with invalid REF");
                }
            }
            /* can write w/o lock */
            err = txg_wb_itb_ll(cta, i);
            itb_put(i);
            (*freed)++;
        } else if (ih->state == ITB_STATE_DIRTY) {
            /* write w/ lock holding */
            if (tmpi) {
                /* ok, we just copy the itb to the temp itb */
                memcpy(tmpi, i, atomic_read(&i->h.len));
                ih->state = ITB_STATE_CLEAN;
            } else {
                err = txg_wb_itb_ll(cta, i);
                ih->state = ITB_STATE_CLEAN;
            }
            xrwlock_wunlock(&ih->lock);
            if (tmpi) {
                if (hmo.conf.option & HVFS_MDS_MDZIP) {
                    /* reset some regions to ZERO to decrease zip size */
                    memset(tmpi->lock, 0, sizeof(tmpi->lock));
                    /* do lzo compress now */
                    err = itb_lzo_compress(tmpi, 
                                           (struct itb *)
                                           ((void *)tmpi + 
                                            (sizeof(struct itb) + 
                                             sizeof(struct ite) * 
                                             ITB_SIZE)),
                                           &tmpi);
                    if (err) {
                        hvfs_err(mds, "do LZO compress on ITB %ld "
                                 "failed w/ %d\n",
                                 tmpi->h.itbid, err);
                    }
                }
                err = txg_wb_itb_ll(cta, tmpi);
                tmpi = swap;
            }
            (*clean)++;
        } else {
            /* write w/ lock holding */
            err = txg_wb_itb_ll(cta, i);
            ih->state = ITB_STATE_CLEAN;
            xrwlock_wunlock(&ih->lock);
            (*notknown)++;
        }
    }
    err = txg_wb_bcast_end(cta, failed);
    if (err) {
        hvfs_err(mds, "bcast end failed w/ %d\n", err);
    }

#if 0
    if (tmpi) {
        xfree(tmpi);
    }
#endif

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
    time_t begin, end;
    sigset_t set;
    int err, freed, clean, notknown;
    
    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */

    /* init the itb memory key */
    pthread_once(&itb_key_once, make_tmp_itb);
    if (pthread_getspecific(itb_key) == NULL) {
        /* alloc the tmp ITB now */
        void *i = xmalloc((sizeof(struct itb) + 
                           sizeof(struct ite) * ITB_SIZE) * 2);
        if (!i) {
            HVFS_BUGON("Allocate TLS tmp itb failed!");
        }
        pthread_setspecific(itb_key, i);
        hvfs_info(mds, "Alloc thread specific ITB memory %ldB\n", 
                  (sizeof(struct itb) + 
                   sizeof(struct ite) * ITB_SIZE) * 2);
    }

    /* init the lzo memory key */
    pthread_once(&lzo_key_once, make_lzo_workmem);
    if (pthread_getspecific(hmo.lzo_workmem) == NULL) {
        /* alloc the LZO work memory now */
        void *p = xmalloc(LZO1X_1_MEM_COMPRESS + (sizeof(lzo_align_t) - 1));

        if (!p) {
            HVFS_BUGON("Failed to allocate lzo work memroy!");
        }
        pthread_setspecific(hmo.lzo_workmem, p);
    }

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
            hvfs_debug(mds, "%p><--%ld--><\n", 
                       t, atomic64_read(&t->tx_pending));
            if (t != hmo.txg[TXG_WB]) {
                goto retry;
            }
        }

        hvfs_debug(mds, "TXG %ld is write-backing.\n", t->txg);
        /* Step2: no reference to this TXG, we can write back now */
        begin = time(NULL);
        CTA_INIT(cta, t);
        txg_prepare_begin(cta, t);

        freed = clean = notknown = 0;
        err = txg_wb_itb(cta, t, &freed, &clean, &notknown);
        if (err) {
            hvfs_err(mds, "txg_wb_itb() failed w/ %d\n", err);
        }

        CTA_FINA(cta);
        end = time(NULL);
        
        hmo.txg[TXG_WB] = NULL;
        /* free the TXG */
        hvfs_info(mds, "TXG %ld is released (free:%d, clean:%d, ntkwn:%d) %ld s.\n", 
                  t->txg, freed, clean, notknown, (end - begin));
        mcond_destroy(&t->cond);
        /* try to clean the removed directories */
        mds_rdir_check(0);
        /* trigger the commit callback on the TXs */
        txg_trigger_ccb(t);

        /* ok, now we support async dir delta handling :) */
#if 1
        /* do dir delta for ddb list to async update here! */
        {
            /* we should take over of the txg->ddb list and construct a
             * request to instruct async thread to sending the request */
            struct async_update_request *aur =
                xzalloc(sizeof(struct async_update_request) +
                        sizeof(struct list_head));
            struct list_head *list = (void *)aur +
                sizeof(struct async_update_request);

            if (!aur) {
                hvfs_err(mds, "xzalloc() AU request failed, data lossing.\n");
            } else {
                aur->op = AU_DIR_DELTA;
                aur->arg = (u64)list;
                INIT_LIST_HEAD(&aur->list);
                INIT_LIST_HEAD(list);
                /* magic here, we move the ddb list to a temp list 8-) */
                list_add(list, &t->ddb);
                list_del_init(&t->ddb);

                err = au_submit(aur);
                if (err) {
                    hvfs_err(mds, "submit AU request failed, data lossing.\n");
                    xfree(aur);
                }
            }
        }
        /* do dir delta for rddb list to async update here! */
        {
            /* we should take cover of the txg->rddb list and construct a
             * request to instruct async thread to sending the request. */
            struct async_update_request *aur =
                xzalloc(sizeof(struct async_update_request) + 
                        sizeof(struct list_head));
            struct list_head *list = (void *)aur + 
                sizeof(struct async_update_request);
            
            if (!aur) {
                hvfs_err(mds, "xzalloc() AU request faield, data lossing.\n");
            } else {
                aur->op = AU_DIR_DELTA_REPLY;
                aur->arg = (u64)list;
                INIT_LIST_HEAD(&aur->list);
                INIT_LIST_HEAD(list);
                /* magic here, we move the rddb list to a temp list 8-) */
                list_add(list, &t->rddb);
                list_del_init(&t->rddb);

                err = au_submit(aur);
                if (err) {
                    hvfs_err(mds, "submit AU request failed, data lossing.\n");
                    xfree(aur);
                }
            }
        }
        /* Add the request to async bitmap handler. Note: this must be the
         * last async handler for TXG, because we will free current TXG in
         * this bitmap async handler. */
        {
            struct async_update_request *aur =
                xzalloc(sizeof(struct async_update_request));

            if (!aur) {
                hvfs_err(mds, "xzalloc() AU request failed, data lossing.\n");
            } else {
                aur->op = AU_ITB_BITMAP;
                aur->arg = (u64)t;
                INIT_LIST_HEAD(&aur->list);
                err = au_submit(aur);
                if (err) {
                    hvfs_err(mds, "submit AU request failed, data lossing.\n");
                    xfree(aur);
                }
            }
        }
#else
        txg_free(t);
#endif
    retry:
        ;
    }
    pthread_exit(0);
}

int commit_tp_init()
{
    pthread_attr_t attr;
    struct commit_thread_arg *cta;
    int i, err = 0, stacksize;

    sem_init(&hmo.commit_sem, 0, 0);
    
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

    atomic64_set(&hmo.ctxg, 0);
    
    for (i = 0; i < hmo.conf.commit_threads; i++) {
        (cta + i)->tid = i;
        err = pthread_create(hmo.commit_thread + i, &attr, &txg_commit,
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

struct bitmap_delta_buf *__bitmap_delta_buf_alloc(void)
{
    struct bitmap_delta_buf *buf;

    if (unlikely(!hmo.conf.txg_buf_len)) {
        hvfs_err(mds, "Hey, seems that you do not call mds_verify().\n");
        hmo.conf.txg_buf_len = HVFS_MDSL_TXG_BUF_LEN;
    }
    buf = xzalloc(sizeof(*buf) 
                  + hmo.conf.txg_buf_len * sizeof(struct hvfs_dir_delta));
    if (!buf) {
        hvfs_err(mds, "alloc bitmap_delta_buf faield.\n");
        return NULL;
    }

    INIT_LIST_HEAD(&buf->list);
    buf->psize = hmo.conf.txg_buf_len;
    
    return buf;
}

int mds_add_bitmap_delta(struct hvfs_txg *txg, u64 site_id, u64 uuid,
                         u64 oitb, u64 nitb)
{
    struct bitmap_delta_buf *buf;
    int err = 0, found = 0;

    xlock_lock(&txg->bdb_lock);
    list_for_each_entry(buf, &txg->bdb, list) {
        if (buf->asize < buf->psize) {
            found = 1;
            break;
        }
    }
    if (!found) {
        /* ok, we should add a bitmap delta buffer */
        buf = __bitmap_delta_buf_alloc();
        if (!buf) {
            hvfs_err(mds, "alloc bitmap_delta_buf failed.\n");
            err = -ENOMEM;
            goto out_unlock;
        }
        list_add_tail(&buf->list, &txg->bdb);
    }

    buf->buf[buf->asize].site_id = site_id;
    buf->buf[buf->asize].uuid = uuid;
    buf->buf[buf->asize].oitb = oitb;
    buf->buf[buf->asize++].nitb = nitb;
out_unlock:
    xlock_unlock(&txg->bdb_lock);

    return err;
}

/*
 * txg_add_update_ddelta() add or update a dir delta entry.
 *
 * @txg:
 * @duid: which dir uuid you want to update
 * @nlink:
 * @flag: NLINK/ATIME/CTIME/MTIME
 */
int txg_add_update_ddelta(struct hvfs_txg *txg, u64 duuid, s32 nlink, u32 flag)
{
    struct dir_delta_entry *dde, *pos;
    struct hlist_node *n;
    int err = 0;
    int idx, found = 0;

    idx = hvfs_hash_ddht(duuid, txg->txg) % hmo.conf.txg_ddht_size;
    xrwlock_rlock(&txg->ddht_lock);
    hlist_for_each_entry(dde, n, &txg->ddht[idx].h, hlist) {
        if (dde->dd.duuid == duuid) {
            /* ok, we find the target in the hash table */
            found = 1;
            /* we just update the entry now */
            if (flag & DIR_DELTA_NLINK) {
                atomic_add(nlink, &dde->dd.nlink);
            }
            dde->dd.flag |= flag;
            break;
        }
    }
    xrwlock_runlock(&txg->ddht_lock);

    if (!found) {
        /* we should add a new dde to the hash table */
        dde = txg_dde_alloc();
        if (!dde) {
            err = -ENOMEM;
            goto out;
        }
        if (flag & DIR_DELTA_NLINK) {
            atomic_set(&dde->dd.nlink, nlink);
        }
        dde->dd.flag |= flag;
        dde->dd.duuid = duuid;

        /* then, insert the new entry to the hash table */
        xrwlock_wlock(&txg->ddht_lock);
        /* recheck if this entry has been inserted by another thread */
        hlist_for_each_entry(pos, n, &txg->ddht[idx].h, hlist) {
            if (pos->dd.duuid == duuid) {
                /* bad, we should release this new dde */
                found = 1;
                break;
            }
        }
        if (!found) {
            hlist_add_head(&dde->hlist, &txg->ddht[idx].h);
            list_add_tail(&dde->list, &txg->ddht_list);
            txg->ddht_nr++;
        } else {
            if (flag & DIR_DELTA_NLINK) {
                atomic_add(nlink, &pos->dd.nlink);
            }
            pos->dd.flag |= flag;
        }
        xrwlock_wunlock(&txg->ddht_lock);
        if (found) {
            xfree(dde);
        }
    }
    
out:
    return err;
}

/*
 * txg_ddht_compact() compact the ddht hash table to the ddb buffer
 *
 * Note: should we hold the ddht locks, if we try to support multiple compact,
 * then we need the ddht locks to protect us :)
 */
int txg_ddht_compact(struct hvfs_txg *t)
{
    struct dir_delta_entry *dde, *n;
    struct hvfs_dir_delta_buf *ddb;
    int err = 0;

    ddb = xzalloc(sizeof(*ddb) + sizeof(struct hvfs_dir_delta) * t->ddht_nr);
    if (!ddb) {
        hvfs_err(mds, "xzalloc() dir_delta_buf failed.\n");
        err = -ENOMEM;
        goto out;
    }
    INIT_LIST_HEAD(&ddb->list);
    ddb->psize = t->ddht_nr;
    ddb->asize = 0;

    xrwlock_wlock(&t->ddht_lock);
    list_for_each_entry_safe(dde, n, &t->ddht_list, list) {
        list_del(&dde->list);
        hlist_del(&dde->hlist);
        /* copy the dde content to the buffer */
        dde->dd.site_id = hmo.site_id; /* set the site_id to myself */
        ddb->buf[ddb->asize++] = dde->dd;
        xfree(dde);
    }
    xrwlock_wunlock(&t->ddht_lock);

    /* finally, add the ddb to the hvfs_txg */
    list_add_tail(&ddb->list, &t->ddb);
    /* FIXME: do we need lock here? */
    hvfs_warning(mds, "In txg %ld compact %d dir delta(s)\n",
                 t->txg, t->ddht_nr);

out:
    return err;
}

struct hvfs_dir_delta_buf *__dir_delta_buf_alloc(void)
{
    struct hvfs_dir_delta_buf *buf;

    if (unlikely(!hmo.conf.txg_buf_len)) {
        hvfs_err(mds, "Hey, seems that you do not call mds_verify().\n");
        hmo.conf.txg_buf_len = HVFS_MDSL_TXG_BUF_LEN;
    }
    buf = xzalloc(sizeof(*buf) +
                  hmo.conf.txg_buf_len * sizeof(struct hvfs_dir_delta));
    if (!buf) {
        hvfs_err(mds, "alloc dir_delta_buf failed.\n");
        return NULL;
    }

    INIT_LIST_HEAD(&buf->list);
    buf->psize = hmo.conf.txg_buf_len;

    return buf;
}

/*
 * txg_rddb_add() add an entry to the txg's rddb buffer list
 *
 * @site_id: which site this request comes from
 * @txg: the txg id on the remote site
 * @duuid: the affected dir uuid
 */
int txg_rddb_add(struct hvfs_txg *t, struct dir_delta_au *dda, 
                 u32 add_flag)
{
    struct hvfs_dir_delta_buf *rddb;
    int err = 0, found = 0;

    xlock_lock(&t->rddb_lock);
    list_for_each_entry(rddb, &t->rddb, list) {
        if (rddb->asize < rddb->psize) {
            found = 1;
            break;
        }
    }

    if (!found) {
        /* ok, we should add a new dir delta buffer here */
        rddb = __dir_delta_buf_alloc();
        if (!rddb) {
            hvfs_err(mds, "alloc dir_delta_buf failed.\n");
            err = -ENOMEM;
            goto out_unlock;
        }
        list_add_tail(&rddb->list, &t->rddb);
    }

    rddb->buf[rddb->asize] = dda->dd;
    rddb->buf[rddb->asize].flag |= add_flag;
    rddb->asize++;

    TXG_SET_DIRTY(t);
out_unlock:
    xlock_unlock(&t->rddb_lock);
    
    return err;
}
