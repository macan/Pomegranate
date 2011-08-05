/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-07-28 06:05:57 macan>
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
#include "latency.c"

static inline 
void mds_send_reply(struct hvfs_tx *tx, struct hvfs_md_reply *hmr, 
                    int err)
{
    tx->rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!tx->rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    hvfs_debug(mds, "Send REPLY(err %d) to %ld: hmr->len %d, hmr->flag 0x%x\n",
               err, tx->reqin_site, hmr->len, hmr->flag);

    hmr->err = err;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(tx->rpy, &tx->rpy->tx,
                       sizeof(struct xnet_msg_tx));
#endif
    if (!err) {
        xnet_msg_add_sdata(tx->rpy, hmr, sizeof(*hmr));
        if (hmr->len)
            xnet_msg_add_sdata(tx->rpy, hmr->data, hmr->len);
    } else {
        /* we should change the TX to the FORGET level to avoid pollute the
         * TXCache */
        mds_tx_chg2forget(tx);
        xnet_msg_set_err(tx->rpy, err);
        /* then, we should free the hmr and any allocated buffers */
        if (hmr->data)
            xfree(hmr->data);
        xfree(hmr);
        xnet_set_auto_free(tx->req);
    }
        
    xnet_msg_fill_tx(tx->rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     tx->reqin_site);
    xnet_msg_fill_reqno(tx->rpy, tx->req->tx.reqno);
    xnet_msg_fill_cmd(tx->rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    tx->rpy->tx.handle = tx->req->tx.handle;

    if (xnet_send(hmo.xc, tx->rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry myself, client is forced to retry */
        /* FIXME: should we free the tx->rpy? */
    }
    /* FIXME: state machine of TX, MSG */
    mds_tx_done(tx);
    if (!err)
        mds_tx_reply(tx);
}

static inline
void mds_send_reply_nodata(struct hvfs_tx *tx, int err, u64 arg0)
{
    tx->rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!tx->rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(tx->rpy, &tx->rpy->tx,
                       sizeof(tx->rpy->tx));
#endif
    if (err)
        xnet_msg_set_err(tx->rpy, err);
    xnet_msg_fill_tx(tx->rpy, XNET_MSG_RPY, 0,
                     hmo.site_id, tx->reqin_site);
    xnet_msg_fill_reqno(tx->rpy, tx->req->tx.reqno);
    xnet_msg_fill_cmd(tx->rpy, XNET_RPY_DATA, arg0, 0);
    /* match the original request at the source site */
    tx->rpy->tx.handle = tx->req->tx.handle;

    if (xnet_send(hmo.xc, tx->rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
    }
    mds_tx_done(tx);
    mds_tx_reply(tx);
}

static inline
void __customized_send_reply(struct xnet_msg *msg, struct iovec iov[], int nr)
{
    struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    int i;
    
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx,
                       sizeof(struct xnet_msg_tx));
#endif
    for (i = 0; i < nr; i++) {
        xnet_msg_add_sdata(rpy, iov[i].iov_base, iov[i].iov_len);
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry myself, client is forced to retry */
    }
    xnet_free_msg(rpy);
}

/* STATFS */
void __mdsdisp mds_statfs(struct hvfs_tx *tx)
{
    struct statfs *s = (struct statfs *)xzalloc(sizeof(struct statfs));

    if (!s) {
        hvfs_err(mds, "xzalloc() failed\n");
        mds_free_tx(tx);
        return;
    }
    s->f_ffree = (HVFS_MAX_UUID_PER_MDS - atomic64_read(&hmi.mi_uuid));
    s->f_files = atomic64_read(&hmi.mi_dnum) + atomic64_read(&hmi.mi_fnum) +
        s->f_ffree;

    tx->rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!tx->rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(tx->rpy, &tx->rpy->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(tx->rpy, s, sizeof(struct statfs));

    xnet_msg_fill_tx(tx->rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     tx->reqin_site);
    xnet_msg_fill_reqno(tx->rpy, tx->req->tx.reqno);
    xnet_msg_fill_cmd(tx->rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    tx->rpy->tx.handle = tx->req->tx.handle;

    mds_tx_done(tx);

    if (xnet_send(hmo.xc, tx->rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry myself, client is forced to retry */
    }
    /* FIXME: state machine of TX, MSG */
    mds_tx_reply(tx);
}

/* LOOKUP */
void __mdsdisp mds_lookup(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    TIMER_DEF();
    int err;

    TIMER_B();
    /* ABI:
     * tx.arg1: lease timestamp
     */
    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid LOOKUP request %d received len %d\n", 
                 tx->req->tx.reqno, tx->req->tx.len);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    hvfs_debug(mds, "LOOKUP %ld %ld %lx %s %d uuid %ld flag %x\n",
               hi->puuid, hi->itbid, hi->hash, hi->name, hi->namelen,
               hi->uuid, hi->flag);

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_LOOKUP;
    /* reuse dlen as the lease timestamp */
    hi->dlen = tx->req->tx.arg1;
    
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    TIMER_EaU(LAT_STAT_LOOKUP);
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* CREATE */
void __mdsdisp mds_create(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    u64 txgid = tx->txg->txg, dlen;
    TIMER_DEF();
    int err;

    TIMER_B();
    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid CREATE request %d received\n", 
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* create in the CBHT */
    hi->flag |= INDEX_CREATE;
    dlen = hi->dlen;
    if (hi->dlen) {
        hi->data = tx->req->xm_data + sizeof(*hi) + hi->namelen;
    } else {
        /* we may got zero payload create */
        hi->data = NULL;
    }

    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);
    if (!err)
        add_cli_log_entry(txgid, 0, LOG_CLI_CREATE, dlen + hi->namelen, 
                          hi, (dlen > 0 ? hi->data - hi->namelen : 
                               (tx->req->xm_data + sizeof(*hi))));

actually_send:
    TIMER_EaU(LAT_STAT_CREATE);
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* ACQUIRE 
 *
 * use ACQUIRE to issue a search
 */
void __mdsdisp mds_acquire(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    u64 value = 0;
    int err;
    
    /* ABI
     * @tx.arg1: lock type(LEASE_EXCLUDE/LEASE_SHARED)
     */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid ACQUIRE request %d received\n",
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_ACQUIRE;
    hi->dlen = tx->req->tx.arg1;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);
    value = *(u64 *)hmr;

    xfree(hmr);

send_rpy:
    return mds_send_reply_nodata(tx, err, value);
}

/* RELEASE
 *
 * use RELEASE to release a lease.
 */
void __mdsdisp mds_release(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    int err;

    /* ABI
     * @tx.arg1: lease magic
     */
    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid RELEASE request %d received\n",
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_RELEASE;
    hi->dlen = tx->req->tx.arg1;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

    xfree(hmr);

send_rpy:
    return mds_send_reply_nodata(tx, err, 0);
}

/* UPDATE */
void __mdsdisp mds_update(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    int err;

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid UPDATE request %d received\n", 
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_MDU_UPDATE;
    if (!hi->dlen) {
        hvfs_warning(mds, "UPDATE w/ zero length data payload.\n");
        /* FIXME: we should drop the TX */
        mds_free_tx(tx);
        return;
    }
    hi->data = tx->req->xm_data + sizeof(*hi) + hi->namelen;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* LINKADD */
void __mdsdisp mds_linkadd(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    int err;

    /* ABI (changed):
     *
     * if msg->tx.arg0 == 0, we just do nlink+1, else we add the delta value
     * (cast to int firstly) to the nlink.
     */

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid LINKADD request %d received\n", 
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* ok, get the delta value */
    hi->dlen = tx->req->tx.arg0;
    if (!hi->dlen)
        hi->dlen = 1UL;
    
    /* search in the CBHT */
    hi->flag |= INDEX_LINK_ADD;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* UNLINK */
void __mdsdisp mds_unlink(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    TIMER_DEF();
    int err;

    TIMER_B();
    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid UNLINK request %d received\n", 
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_UNLINK;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    TIMER_EaU(LAT_STAT_UNLINK);
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* SYMLINK */
void __mdsdisp mds_symlink(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    int err;

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid LINKADD request %d received\n", 
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    /* alloc hmr */
    hmr = get_hmr();
    if (unlikely(!hmr)) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= (INDEX_CREATE | INDEX_SYMLINK);
    if (!hi->dlen) {
        hvfs_warning(mds, "SYMLINK w/ zero length symname.\n");
        /* FIXME: we should drop the TX */
        mds_free_tx(tx);
        return;
    }
    hi->data = tx->req->xm_data + sizeof(*hi) + hi->namelen; /* symname */
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
}

/* LOAD BITMAP */
void __mdsdisp mds_lb(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct ibmap ibmap;
    struct hvfs_md_reply *hmr;
    struct bc_entry *be;
    u64 location, size, offset;
    int err = 0;

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid LoadBitmap request %d received\n",
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto send_err_rpy;
    }

    /* ABI:
     *
     * tx.arg0: uuid to load
     * tx.arg1: offset
     */

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    ASSERT(hi->uuid == tx->req->tx.arg0, mds);
    /* the offset should be aligned */
    offset = tx->req->tx.arg1;
    offset = BITMAP_ROUNDDOWN(offset);

    /* cut the bitmap to valid range */
    err = mds_bc_dir_lookup(hi, &location, &size);
    if (unlikely(err)) {
        hvfs_err(mds, "bc_dir_lookup failed w/ %d\n", err);
        goto send_err_rpy;
    }

    if (size == 0) {
        /* this means that offset should be ZERO */
        offset = 0;
    } else {
        /* Note that, we should just have a try to find if there is a slice in
         * the cache! It is important! */
        be = mds_bc_get(tx->req->tx.arg0, offset);
        if (!IS_ERR(be)) {
            goto find_it;
        }
        /* Caution: we should cut the offset to the valid bitmap range
         * by size! */
        offset = mds_bitmap_cut(offset, size << 3);
        offset = BITMAP_ROUNDDOWN(offset);
    }
    
    /* next, we should get the bc_entry */
    be = mds_bc_get(hi->uuid, offset);
    if (IS_ERR(be)) {
        if (be == ERR_PTR(-ENOENT)) {
            struct iovec iov[2];
            struct bc_entry *nbe;
                
            /* ok, we should create one bc entry now */
            be = mds_bc_new();
            if (!be) {
                hvfs_err(mds, "New BC entry failed\n");
                err = -ENOMEM;
                goto send_err_rpy;
            }
            mds_bc_set(be, hi->uuid, offset);

            /* we should load the bitmap from mdsl */
    
            if (size == 0) {
                /* this means that we should just return a new default bitmap
                 * slice */
                int i;

                for (i = 0; i < 1; i++) {
                    be->array[i] = 0xff;
                }
            } else {
                /* load the bitmap slice from MDSL */
                err = mds_bc_backend_load(be, hi->itbid, location);
                if (err) {
                    hvfs_err(mds, "bc_backend_load failed w/ %d\n", err);
                    mds_bc_free(be);
                    goto send_err_rpy;
                }
            }
            
            /* finally, we insert the bc into the cache, should we check
             * whether there is a conflict? */
            nbe = mds_bc_insert(be);
            if (nbe != be) {
                mds_bc_free(be);
                be = nbe;
            }
            /* we need to send the reply w/ the bitmap data */
            ibmap.offset = be->offset;
            ibmap.flag = ((size - (be->offset >> 3) > XTABLE_BITMAP_BYTES) ? 
                          0 : BITMAP_END);
            ibmap.ts = time(NULL);
            iov[0].iov_base = &ibmap;
            iov[0].iov_len = sizeof(struct ibmap);
            iov[1].iov_base = be->array;
            iov[1].iov_len = XTABLE_BITMAP_BYTES;
            __customized_send_reply(tx->req, iov, 2);

            mds_bc_put(be);
        } else {
            hvfs_err(mds, "bc_get() failed w/ %d\n", err);
            goto send_err_rpy;
        }
    } else {
        /* we find the entry in the cache, just return the bitmap array */
        /* FIXME: be sure to put the bc_entry after copied */
        struct iovec iov[2];

    find_it:
        ibmap.offset = be->offset;
        ibmap.flag = ((size - (be->offset >> 3) > XTABLE_BITMAP_BYTES) ? 0 :
                      BITMAP_END);
        ibmap.ts = time(NULL);
        iov[0].iov_base = &ibmap;
        iov[0].iov_len = sizeof(struct ibmap);
        iov[1].iov_base = be->array;
        iov[1].iov_len = XTABLE_BITMAP_BYTES;
        __customized_send_reply(tx->req, iov, 2);
        
        mds_bc_put(be);
    }
    
    return;
send_err_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        return;
    }
    return mds_send_reply(tx, hmr, err);
}

/* DUMP ITB */
void mds_dump_itb(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    int err;

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid DITB request %d recieved\n",
                 tx->req->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    /* NOTE: hi and hi->hash are checked in fe_dispatch() */
    hi = tx->req->xm_data;

    mds_cbht_search_dump_itb(hi);
    /* dump the previous ITB */
    hi->itbid &= ~(1UL << (fls64(hi->itbid)));
    mds_cbht_search_dump_itb(hi);
out:
    mds_tx_done(tx);
    return;
}

void __mdsdisp mds_c2m_ldh(struct hvfs_tx *tx)
{
    struct xnet_msg *msg = tx->req;

    /* call the m2m API here */
    mds_ldh(msg);

    mds_tx_done(tx);
}

/* LIST/Readdir */
void __mdsdisp mds_list(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr;
    struct chp *p;
    int err;

    /* sanity checking */
    if (unlikely(tx->req->tx.len < sizeof(*hi))) {
        hvfs_err(mds, "Invalid LIST request %d received len %d\n", 
                 tx->req->tx.reqno, tx->req->tx.len);
        err = -EINVAL;
        goto send_rpy;
    }

    hi = tx->req->xm_data;

    hvfs_debug(mds, "LIST %ld %ld %lx %s %d uuid %ld flag %x\n",
               hi->puuid, hi->itbid, hi->hash, hi->name, hi->namelen,
               hi->uuid, hi->flag);

    /* Note that, we should check if we should do message forwarding here */
    p = ring_get_point(hi->itbid, hi->psalt, hmo.chring[CH_RING_MDS]);
    if (unlikely(IS_ERR(p))) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto send_rpy;
    }
    if (hmo.site_id != p->site_id) {
        hi->flag |= INDEX_BIT_FLIP;
        err = mds_do_forward(tx->req, p->site_id);
        goto out;
    }

    switch (hi->op) {
    case KV_OP_SCAN:
    case KV_OP_SCAN_CNT:
        break;
    case KV_OP_GREP:
    case KV_OP_GREP_CNT:
        hi->data = tx->req->xm_data + sizeof(*hi);
        break;
    default:;
    }
    
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* ok, should we set trigger flag? */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hi->puuid);
        /* ignore error, do not set the trigger flag */
        if (!IS_ERR(e)) {
            if (unlikely(e->data))
                hi->flag |= INDEX_DTRIG;
            mds_dh_put(e);
        }
    }
    
    /* search in the CBHT */
    hi->flag |= INDEX_BY_ITB;
    err = mds_cbht_search(hi, hmr, tx->txg, &tx->txg);

actually_send:
    return mds_send_reply(tx, hmr, err);
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    goto actually_send;
out:
    if (unlikely(err)) {
        hvfs_warning(mds, "MDS(%lx->%lx)(reqno %d) can't be handled w/ %d\n",
                     tx->req->tx.ssite_id, tx->req->tx.dsite_id,
                     tx->req->tx.reqno, err);
    }
    mds_tx_chg2forget(tx);
    mds_tx_done(tx);
}

void __mdsdisp mds_snapshot(struct hvfs_tx *tx)
{
    struct hvfs_md_reply *hmr;
    
    /* Step 0: this is black magic */
    txg_put(tx->txg);

    /* Step 1: do a snapshot and wait for the TXG to MDSL */
    txg_change_immediately();

    tx->txg = mds_get_open_txg(&hmo);

    /* Step 2: reply the request */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    return mds_send_reply(tx, hmr, 0);
}

/* REDO region for basic operations */
void mds_create_redo(struct hvfs_index *hi)
{
    struct hvfs_md_reply *hmr;
    struct hvfs_txg *txg;
    int err = 0;

    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* just return */
        return;
    }

    /* create in the CBHT */
    hi->flag |= INDEX_CREATE;
    /* hi->data has been already installed */

    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);

    /* free resources */
    if (hmr->data)
        xfree(hmr->data);
    xfree(hmr);
    
    return;
}
