/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-05 10:57:24 macan>
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

static inline 
void mds_send_reply(struct xnet_msg *msg, struct hvfs_md_reply *hmr,
                    int err)
{
    struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_CACHE);

    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }

    hmr->err = err;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(struct xnet_msg_tx));
#endif
    if (!err) {
        xnet_msg_add_sdata(rpy, hmr, sizeof(*hmr));
        if (hmr->len)
            xnet_msg_add_sdata(rpy, hmr->data, hmr->len);
    } else {
        xnet_msg_set_err(rpy, hmr->err);
        if (hmr->data)
            xfree(hmr->data);
        xfree(hmr);
    }

    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry myself */
    }
    xnet_free_msg(rpy);         /* data auto free */
}

static inline
void __customized_send_bitmap(struct xnet_msg *msg, struct iovec iov[], int nr)
{
    struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    int i;

    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
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
        hvfs_err(mds, "xnet_isend() failed\n");
        /* do not retyr myself, client is forced to retry */
    }
    xnet_free_msg(rpy);
}

/* mds_do_reject() return the reject reply message to the caller
 */
void mds_do_reject(struct xnet_msg *msg)
{
    struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_CACHE);

    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        xnet_free_msg(msg);
        return;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_set_err(rpy, -EFAULT);

    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry my self */
    }
    xnet_free_msg(rpy);
    xnet_free_msg(msg);
}

/* mds_ldh() use the hvfs_index interface, so request forward is working.
 */
void mds_ldh(struct xnet_msg *msg)
{
    struct hvfs_index *hi = NULL;
    struct hvfs_md_reply *hmr = NULL;
    struct hvfs_txg *txg;
    struct dhe *e;
    struct chp *p;
    u64 itbid;
    int err = 0;

    /* sanity checking */
    if (msg->tx.len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid LDH request %d received from %lx\n", 
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    if (msg->xm_datacheck)
        hi = msg->xm_data;
    else {
        hvfs_err(mds, "Internal error, data lossing ...\n");
        err = -EINVAL;
        goto send_rpy;
    }

    if (!(hi->flag & INDEX_BY_UUID)) {
        err = -EINVAL;
        goto send_rpy;
    }

    e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(e)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(e);
        goto send_rpy;
    }
    itbid = mds_get_itbid(e, hi->hash);
    mds_dh_put(e);
    if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            err = -ECHP;
            goto send_rpy;
        }
        if (hmo.site_id != p->site_id) {
            /* FIXME: forward */
            if (itbid == hi->itbid) {
                /* itbid is correct, but ring changed */
                err = -ERINGCHG;
                goto send_rpy;
            }
            /* doing the forward now */
            hi->flag |= INDEX_BIT_FLIP;
            hi->itbid = itbid;
            err = mds_do_forward(msg, p->site_id);
            goto out;
        }
        hi->itbid = itbid;
    }

    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        goto out;
    }
    hi->flag |= INDEX_LOOKUP | INDEX_COLUMN;
    hi->column = HVFS_TRIG_COLUMN;
    hi->puuid = hmi.gdt_uuid;
    hi->psalt = hmi.gdt_salt;

    /* search in the CBHT */
retry:
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);

    /* Note that we should set the salt manually */
    if (!err) {
        struct hvfs_index *_hi;
        struct gdt_md *m;
        int nr = 0;
        
        _hi = hmr_extract_local(hmr, EXTRACT_HI, &nr);
        if (!_hi) {
            hvfs_err(mds, "Extract HI failed\n");
            err = -EINVAL;
            goto send_rpy;
        }
        
        m = hmr_extract_local(hmr, EXTRACT_MDU, &nr);
        if (!m) {
            hvfs_err(mds, "Extract MDU failed\n");
            err = -EINVAL;
            goto send_rpy;
        }
        _hi->ssalt = m->salt;
    } else {
        if (err == -EAGAIN || err == -ESPLIT ||
            err == -ERESTART) {
            /* have a breath */
            sched_yield();
            goto retry;
        }
        hvfs_err(mds, "do_ldh() cbht search %lx failed w/ %d\n",
                 hi->uuid, err);
    }

actually_send:
    mds_send_reply(msg, hmr, err);
out:
    xnet_free_msg(msg);
    return;
send_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        return;
    }
    goto actually_send;
}

void mds_ausplit(struct xnet_msg *msg)
{
    struct itb *i, *ti;
    struct bucket *nb;
    struct bucket_entry *nbe;
    struct hvfs_txg *t;
    int err = 0;

    /* API:
     * tx.arg0: new itbid
     * tx.arg1: old itbid
     */

    /* sanity checking */
    if (msg->tx.len < sizeof(struct itb)) {
        hvfs_err(mds, "Invalid SPITB request %d received from %lx\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    if (msg->xm_datacheck)
        i = msg->xm_data;
    else {
        hvfs_err(mds, "Internal error, data lossing ...\n");
        err = -EINVAL;
        goto send_rpy;
    }

    /* checking the ITB */
#if 1
    if (msg->tx.len != atomic_read(&i->h.len)) {
        hvfs_err(mds, "msg %d vs itb %d from %lx\n",
                 msg->tx.len, atomic_read(&i->h.len), msg->tx.ssite_id);
    }
#endif
    ASSERT(msg->tx.len == atomic_read(&i->h.len), mds);
    
    /* pre-dirty the itb */
    t = mds_get_open_txg(&hmo);
    i->h.txg = t->txg;
    i->h.flag = ITB_ACTIVE;
    i->h.state = ITB_STATE_DIRTY;
    /* re-init */
    itb_reinit(i);

    txg_add_itb(t, i);
    txg_put(t);

    /* insert the ITB to CBHT */
    err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &nb, &nbe, &ti);
    if (err == -EEXIST) {
        /* someone has already create the new ITB, we just ignore ourself? */
        hvfs_err(mds, "Someone create ITB %ld, fatal failed w/ "
                 "data loss @ txg %ld\n", i->h.itbid, i->h.txg);
        /* it is ok, we need to free the locks */
        xrwlock_runlock(&nbe->lock);
        xrwlock_runlock(&nb->lock);
        /* this maybe a resend message, we just send the reply now */
        goto send_rpy;
    } else if (err) {
        hvfs_err(mds, "Internal error %d, data lossing.\n", err);
        goto send_rpy;
    }

    /* it is ok, we need to free the locks */
    xrwlock_runlock(&nbe->lock);
    xrwlock_runlock(&nb->lock);

    mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid,
                         MDS_BITMAP_SET);
    mds_dh_bitmap_update(&hmo.dh, i->h.puuid, msg->tx.arg1,
                         MDS_BITMAP_SET);
    /* FIXME: if we using malloc to alloc the ITB, then we need to inc the
     * csize counter */
    atomic64_inc(&hmo.prof.mds.ausplit);
    atomic64_add(atomic_read(&i->h.entries), &hmo.prof.cbht.aentry);

    hvfs_warning(mds, "We update the bit of ITB %ld txg %ld\n", 
                 i->h.itbid, i->h.txg);
    xnet_clear_auto_free(msg);

send_rpy:
    {
        struct xnet_msg *rpy;

    alloc_retry:
        rpy = xnet_alloc_msg(XNET_MSG_CACHE);
        if (!rpy) {
            hvfs_err(mds, "xnet_alloc_msg() failed, we should retry!\n");
            goto alloc_retry;
        }
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(struct xnet_msg_tx));
#endif
        xnet_msg_set_err(rpy, err);
        xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id,
                         msg->tx.ssite_id);
        xnet_msg_fill_reqno(rpy, msg->tx.reqno);
        xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
        /* match the original request at the source site */
        rpy->tx.handle = msg->tx.handle;

        if (xnet_send(hmo.xc, rpy)) {
            hvfs_err(mds, "xnet_send() failed\n");
        }
        hvfs_debug(mds, "We have sent the AU reply msg from %lx to %lx\n",
                   rpy->tx.ssite_id, rpy->tx.dsite_id);
        xnet_free_msg(rpy);
    }
    xnet_free_msg(msg);         /* do not free the allocated ITB */
}

void mds_forward(struct xnet_msg *msg)
{
    struct mds_fwd *mf;
    struct xnet_msg_tx *tx;
    /* FIXME: we know we are using xnet-simple, so all the receiving iovs are
     * packed into one buf, we should save the begin address here */
    
    xnet_set_auto_free(msg);

    /* sanity checking */
    if (likely(msg->xm_datacheck)) {
        tx = msg->xm_data;
        mf = msg->xm_data + tx->len + sizeof(*tx);
    } else {
        hvfs_err(mds, "Internal error, data lossing ...\n");
        goto out;
    }
#if 0
    {
        int i, pos = 0;
        char line[256];

        memset(line, 0, sizeof(line));
        pos += snprintf(line, 256, "FW request from %lx route ", tx->ssite_id);
        for (i = 0; i < ((mf->len - sizeof(*mf)) / sizeof(u32)); i++) {
            pos += snprintf(line + pos, 256 - pos, "%lx->", mf->route[i]);
        }
        pos += snprintf(line + pos, 256 - pos, "%lx(E).\n", hmo.site_id);
        hvfs_err(mds, "%s", line);
    }
#endif
    memcpy(&msg->tx, tx, sizeof(*tx));
    /* FIXME: we know there is only one iov entry */
    msg->tx.flag |= (XNET_PTRESTORE | XNET_FWD);
    msg->tx.reserved = (u64)msg->xm_data;
    msg->xm_data += sizeof(*tx);
    msg->tx.dsite_id = hmo.site_id;

    atomic64_inc(&hmo.prof.mds.forward);
    mds_fe_dispatch(msg);

    return;
out:
    xnet_free_msg(msg);
}

/* actually we do not send the normal reply message, we send another request
 * message.
 */
void mds_aubitmap(struct xnet_msg *msg)
{
    struct hvfs_index hi;
    struct bc_delta *bd;
    struct dhe *e;
    struct chp *p;
    struct bc_entry *be, *nbe;
    u64 hash, itbid, offset, location, size;
    int err = 0;

    /* ABI:
     *
     * tx.arg0: uuid to update
     * tx.arg1: itbid to flip
     */

    /* sanity checking */
    if (msg->tx.len != 0) {
        hvfs_err(mds, "Invalid AUBITMAP request %d received from %lx\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    /* recheck whether ourself is the target site for the bitmap cache
     * entry */
    e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(e)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(e);
        goto send_rpy;
    }
    hash = hvfs_hash_gdt(msg->tx.arg0, hmi.gdt_salt);
    itbid = mds_get_itbid(e, hash);
    mds_dh_put(e);
    if (itbid != msg->tx.arg1 || hmo.conf.option & HVFS_MDS_CHRECHK) {
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            err = -ECHP;
            goto send_rpy;
        }
        if (hmo.site_id != p->site_id) {
            /* forward it */
            if (itbid == msg->tx.arg1) {
                /* itbid is correct, but ring changed */
                err = -ERINGCHG;
                goto send_rpy;
            }
#if 0
            /* we should do the forward, but if we do forward, we need a hi
             * struct to log some additional info. It is a little bad, so we
             * just reply w/ a bitmap change error. */
            err = -EBITMAP;
            goto send_rpy;
#else
            err = mds_do_forward(msg, p->site_id);
            goto out;
#endif
        }
    }

    bd = mds_bc_delta_alloc();
    if (!bd) {
        hvfs_err(mds, "mds_bc_delta_alloc() failed.\n");
        err = -ENOMEM;
        goto send_rpy;
    }
    /* set site_id to ssite_id to send the reply message */
    bd->site_id = msg->tx.ssite_id;
    bd->uuid = msg->tx.arg0;
    bd->itbid = msg->tx.arg1;

    /* Then, we should add this bc_delta to the BC */
    xlock_lock(&hmo.bc.delta_lock);
    list_add(&bd->list, &hmo.bc.deltas);
    xlock_unlock(&hmo.bc.delta_lock);

    /* Finally, we should update the bc_entry if it exists */
    offset = BITMAP_ROUNDDOWN(msg->tx.arg1);
    be = mds_bc_get(msg->tx.arg0, offset);
    if (IS_ERR(be)) {
        if (be == ERR_PTR(-ENOENT)) {
            hvfs_err(mds, "Warning: bc_entry %lx offset %ld does not "
                     "exist.\n", msg->tx.arg0, offset);

            /* ok, we should create one bc_entry now */
            be = mds_bc_new();
            if (!be) {
                hvfs_err(mds, "New BC entry failed for new slice\n");
                goto send_rpy;
            }
            mds_bc_set(be, msg->tx.arg0, offset);

            /* we should load the bitmap from mdsl */
            memset(&hi, 0, sizeof(hi));
            hi.flag = INDEX_BY_UUID;
            hi.uuid = msg->tx.arg0;
            hi.puuid = hmi.gdt_uuid;
            hi.psalt = hmi.gdt_salt;
            hi.hash = hvfs_hash_gdt(hi.uuid, hmi.gdt_salt);
            hi.itbid = mds_get_itbid(e, hi.hash);
            
            err = mds_bc_dir_lookup(&hi, &location, &size);
            if (err) {
                hvfs_err(mds, "bc_dir_lookup failed w/ %d\n", err);
                mds_bc_free(be);
                goto send_rpy;
            }

            if (size == 0) {
                /* this means that we should just return a new default bitmap
                 * slice */

                if (be->offset) {
                    /* ooo, it is very complex here! */
                    struct bc_entry *__be;

                    __be = mds_bc_get(msg->tx.arg0, 0);
                    if (IS_ERR(__be)) {
                        if (__be == ERR_PTR(-ENOENT)) {
                            __be = mds_bc_new();
                            if (!__be) {
                                hvfs_err(mds, "New BC entry failed for new slice\n");
                                goto send_rpy;
                            }
                            mds_bc_set(__be, msg->tx.arg0, 0);
                            __be->array[0] = 0xff;

                            nbe = mds_bc_insert(__be);
                            if (nbe != __be) {
                                mds_bc_free(__be);
                                __be = nbe;
                            }
                            mds_bc_put(__be);
                        } else {
                            hvfs_err(mds, "bc_get() %lx failed w/ %d\n", 
                                     msg->tx.arg0, err);
                        }
                    }
                } else {
                    be->array[0] = 0xff;
                }
            } else if ((size << 3) <= offset) {
                /* oh, we should enlarge the bitmap now */
                hvfs_warning(mds, "Create a bitmap slice for uuid %lx offset %ld\n",
                          msg->tx.arg0, offset);
            } else {
                /* ok, no enlarge is need */
                err = mds_bc_backend_load(be, hi.itbid, location);
                if (err) {
                    hvfs_err(mds, "bc_backend_load failed w/ %d\n", err);
                    mds_bc_free(be);
                    goto send_rpy;
                }
            }
            /* finally, we insert the bc into the cache */
            nbe = mds_bc_insert(be);
            if (nbe != be) {
                mds_bc_free(be);
                be = nbe;
            }
            /* at last, we update the bits in bitmap */
            __set_bit(msg->tx.arg1 - offset, (unsigned long *)be->array);
            mds_bc_put(be);
        } else {
            hvfs_err(mds, "bc_get() %ld failed w/ %d\n", msg->tx.arg0, err);
        }
    } else {
        /* update the bits in bitmap */
        __set_bit(msg->tx.arg1 - offset, (unsigned long *)be->array);
        mds_bc_put(be);
    }
        
out:
    return;
send_rpy:
    /* Note that: we do NOT reply actually, the sender do not block on the
     * receiving! if isend is working, maybe we can do the reply 8-) */
    hvfs_err(mds, "handle AUBITMAP w/ %d.\n", err);
}

void mds_m2m_lb(struct xnet_msg *msg)
{
    /* arg0: uuid; arg1: offset(aligned) */
    struct ibmap ibmap;
    struct hvfs_index hi;
    struct hvfs_md_reply *hmr;
    struct bc_entry *be;
    struct dhe *gdte;
    u64 location, size, offset;
    int err = 0;

    /* ABI:
     *
     * tx.arg0: uuid to load
     * tx.arg1: offset
     */

    /* first, we should get hte bc_entry */
    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out_free;
    }
    
    memset(&hi, 0, sizeof(hi));
    hi.flag = INDEX_BY_UUID;
    hi.uuid = msg->tx.arg0;
    hi.puuid = hmi.gdt_uuid;
    hi.psalt = hmi.gdt_salt;
    hi.hash = hvfs_hash_gdt(hi.uuid, hmi.gdt_salt);
    hi.itbid = mds_get_itbid(gdte, hi.hash);
    mds_dh_put(gdte);

    offset = msg->tx.arg1;
    offset = BITMAP_ROUNDDOWN(offset);
    
    /* cut the bitmap to valid range */
    err = mds_bc_dir_lookup(&hi, &location, &size);
    if (err) {
        hvfs_err(mds, "bc_dir_lookup failed w/ %d\n", err);
        goto send_err_rpy;
    }

    hvfs_debug(mds, "LOOKUP0 bc %lx offset %ld @ %ld size %ld\n", 
               hi.uuid, offset, location, size);
    if (size == 0) {
        /* this means that offset should be ZERO */
        offset = 0;
    } else {
        /* Note that, we should just have a try to find if there is a slice in
         * the cache! It is important! */
        be = mds_bc_get(msg->tx.arg0, offset);
        if (!IS_ERR(be)) {
            goto find_it;
        }
        /* Caution: we should cut the offset to the valid bitmap range
         * by size! */
        offset = mds_bitmap_cut(offset, size << 3);
        offset = BITMAP_ROUNDDOWN(offset);
    }
    hvfs_debug(mds, "LOOKUP1 bc %lx offset %ld @ %ld size %ld\n", 
               hi.uuid, offset, location, size);

    be = mds_bc_get(msg->tx.arg0, offset);
    if (IS_ERR(be)) {
        if (be == ERR_PTR(-ENOENT)) {
            struct iovec iov[2];
            struct bc_entry *nbe;

            /* ok, we should create one bc_entry now */
            be = mds_bc_new();
            if (!be) {
                hvfs_err(mds, "New BC entry failed\n");
                err = -ENOMEM;
                goto send_err_rpy;
            }
            mds_bc_set(be, hi.uuid, offset);

            /* we should load the bitmap from mdsl */
            err = mds_bc_dir_lookup(&hi, &location, &size);
            if (err) {
                hvfs_err(mds, "bc_dir_lookup failed w/ %d\n", err);
                mds_bc_free(be);
                goto send_err_rpy;
            }

            if (size == 0) {
                /* this means that we should just return a new default bitmap
                 * slice */
                int i;

                for (i = 0; i < 1; i++) {
                    be->array[i] = 0xff;
                }
            } else {
                /* load the bitmap slice from MDSL */
                err = mds_bc_backend_load(be, hi.itbid, location);
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
            /* FIXME */
            ibmap.flag = ((size - (be->offset >> 3) > XTABLE_BITMAP_BYTES) ? 
                          0 : BITMAP_END);
            ibmap.ts = time(NULL);
            iov[0].iov_base = &ibmap;
            iov[0].iov_len = sizeof(struct ibmap);
            iov[1].iov_base = be->array;
            iov[1].iov_len = XTABLE_BITMAP_BYTES;
            __customized_send_bitmap(msg, iov, 2);

            mds_bc_put(be);
        } else {
            hvfs_err(mds, "bc_get() failed w/ %d\n", err);
            goto send_err_rpy;
        }
    } else {
        /* we find the entry in the cache, jsut return the bitmap array */
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
        __customized_send_bitmap(msg, iov, 2);

        mds_bc_put(be);
    }

out_free:
    xnet_free_msg(msg);
    atomic64_inc(&hmo.prof.mds.bitmap_in);

    return;
send_err_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        return;
    }
    mds_send_reply(msg, hmr, err);
    goto out_free;
}

void mds_aubitmap_r(struct xnet_msg *msg)
{
    /* we should call async_aubitmap_cleanup to remove the entry in the
     * g_bitmap_deltas list */
    async_aubitmap_cleanup(msg->tx.arg0, msg->tx.arg1);
}

void mds_audirdelta(struct xnet_msg *msg)
{
    struct dir_delta_au *dda;
    struct hvfs_dir_delta *hdd;
    struct hvfs_txg *txg;
    int err = 0;
    
    /* sanity check */
    if (msg->tx.len < sizeof(*hdd)) {
        hvfs_err(mds, "Invalid AUDIRDELTA request %d received from %lx\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    if (msg->xm_datacheck) {
        hdd = (struct hvfs_dir_delta *)msg->xm_data;
    } else {
        hvfs_err(mds, "Internal error, data lossing...\n");
        err = -EFAULT;
        goto send_rpy;
    }

    /* ABI:
     *
     * arg0: dir uuid
     * arg1: flag << 32 | nlink
     */

    hvfs_warning(mds, "Recv uuid %lx nlink %d from site %lx salt %lx\n", 
                 hdd->duuid, atomic_read(&hdd->nlink), msg->tx.ssite_id,
                 hdd->salt);

    /* construct a dir_delta_au struct and add this entry to the txg's ddb
     * list and update the local CBHT state */
    dda = txg_dda_alloc();
    if (!dda) {
        hvfs_err(mds, "alloc dir_delta_au failed.\n");
        err = -ENOMEM;
        goto send_rpy;
    }

    /* update the local CBHT state */
    dda->dd = *hdd;
    dda->dd.site_id = msg->tx.ssite_id;
    ASSERT(msg->tx.arg0 == dda->dd.duuid, mds);
    
    err = txg_ddc_update_cbht(dda);
    if (err) {
        hvfs_err(mds, "DDA %ld update CBHT failed w/ %d\n",
                 hdd->duuid, err);
    }

    /* add to the txg->rddb list */
    txg = mds_get_open_txg(&hmo);
    err = txg_rddb_add(txg, dda, DIR_DELTA_REMOTE_UPDATE);
    txg_put(txg);
    if (err) {
        hvfs_err(mds, "Remote update uuid %ld to rddb failed w/ %d\n",
                 hdd->duuid, err);
        err = -EUPDATED;        /* this means that the original site can be
                                 * safely release the dda entry even there is
                                 * a error in myself. */
        goto send_rpy;
    }

    /* the reply will be send after TXG commit on rddb list handling. */
    
out_free:
    xnet_free_msg(msg);

    return;
send_rpy:
    /* Note That:
     *
     * XNET-simple do not support isend, so we cant send the reply here :(
     * After the true XNET is working, we should change this behavier.
     */
    goto out_free;
}

void mds_audirdelta_r(struct xnet_msg *msg)
{
    struct hvfs_dir_delta *hdd;
    int err = 0;
    
    /* sanity checking */
    if (msg->tx.len < sizeof(struct hvfs_dir_delta)) {
        hvfs_err(mds, "Invalid AUDIRDELTA_R request %d received from %lx\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto out;
    }

    if (msg->xm_datacheck) {
        hdd = (struct hvfs_dir_delta *)msg->xm_data;
    } else {
        hvfs_err(mds, "Internal error, data lossing...\n");
        goto out;
    }

    /* ABI:
     *
     * tx.arg0: duuid
     * tx.arg1: salt
     * data: struct hvfs_dir_delta
     */

    /* Step 0: data checking? */
    /* Step 1: add this entry to the txg->rddb list */
    /* Step 2: cleanup the local g_dir_deltas list */
    ASSERT(msg->tx.arg0 == hdd->duuid, mds);
    async_audirdelta_cleanup(msg->tx.arg0, msg->tx.arg1);

    hvfs_warning(mds, "Recv AUDD reply uuid %lx nlink %d from site %lx "
                 "salt %lx\n",
                 hdd->duuid, atomic_read(&hdd->nlink), msg->tx.ssite_id,
                 hdd->salt);

out:
    xnet_free_msg(msg);
    
    return;
}

void mds_gossip_bitmap(struct xnet_msg *msg)
{
    struct itbitmap *b = NULL, *pos;
    struct dhe *e;
    int processed = 0, err = 0;
    
    /* ABI:
     *
     * tx.arg0: duuid
     * tx.arg1: offset
     * xm_data: bitmap slice
     */

    /* sanity checking */
    if (msg->tx.len < sizeof(*b)) {
        hvfs_err(mds, "Invalid bitmap gossip message from %lx\n",
                 msg->tx.ssite_id);
        goto out;
    }

    b = msg->xm_data;
    ASSERT(msg->tx.arg1 == b->offset, mds);

    atomic64_inc(&hmo.prof.mds.gossip_bitmap);
    /* find the dh firstly */
    e = mds_dh_search(&hmo.dh, msg->tx.arg0);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_search() duuid %lx failed w/ %ld\n",
                 msg->tx.arg0, PTR_ERR(e));
        goto out;
    }

    /* find the bitmap slice now */
    xlock_lock(&e->lock);
    list_for_each_entry(pos, &e->bitmap, list) {
        if (pos->offset == b->offset) {
            mds_bitmap_update(pos, b);
            xnet_set_auto_free(msg);
            processed = 1;
            break;
        }
    }
    xlock_unlock(&e->lock);
    if (!processed) {
        /* check the offset */
        ASSERT(BITMAP_ROUNDDOWN(b->offset) == b->offset, mds);
        INIT_LIST_HEAD(&b->list);
        err = __mds_bitmap_insert(e, b);
        hvfs_warning(mds, "Gossip insert new (%lx) bitmap slice @ %lx w/ %d\n",
                     msg->tx.arg0, (u64)b->offset, err);
        if (!err) {
            xnet_clear_auto_free(msg);
        }
    }
    mds_dh_put(e);

out:
    xnet_free_msg(msg);
}

void mds_gossip_rdir(struct xnet_msg *msg)
{
    struct hvfs_txg *txg;
    u64 *array;
    int i, found;
    
    /* ABI:
     *
     * tx.arg0: size of the array
     * xm_data: rdir array
     */

    /* sanity checking */
    if (msg->tx.len < sizeof(u64) * msg->tx.arg0) {
        hvfs_err(mds, "Invalid rdir gossip message from %lx\n",
                 msg->tx.ssite_id);
        goto out;
    }

    array = msg->xm_data;

    /* add the rdir array to hmo.rm */
    for (i = 0; i < msg->tx.arg0; i++) {
        found = rdir_insert(&hmo.rm, array[i]);
        if (!found) {
            /* add to the txg rdir list */
            txg = mds_get_open_txg(&hmo);
            found = txg_lookup_rdir(txg, array[i]);
            if (!found)
                txg_add_rdir(txg, array[i]);
            txg_put(txg);
        }
    }

out:
    xnet_free_msg(msg);
}

/* mds_rpc() handle the generic rpc calls. The arguments are in the tx.arg*
 * and other fields.
 */
void mds_rpc(struct xnet_msg *msg)
{
    struct rpc_args ra;
    struct hvfs_md_reply *hmr;
    void *result;
    int err = 0;

    /* in mds_init() we setup a call table for rpc calls */
    /* ABI:
     * @tx.arg0: rpc index!
     */
    ra.arg = msg->tx.arg1;
    if (msg->xm_datacheck) {
        ra.data = msg->xm_data;
    } else {
        ra.data = NULL;
    }

    /* check the rpc table and call the RPC now */
    if (hmo.mrt->asize >= msg->tx.arg0) {
    } else {
        hvfs_err(mds, "Invalid RPC call %ld from %lx\n", msg->tx.arg0,
                 msg->tx.ssite_id);
        err = -EINVAL;
        goto err_rpy;
    }

    result = hmo.mrt->mre[msg->tx.arg0].cb(&ra);
    if (IS_ERR(result)) {
        err = PTR_ERR(result);
        goto err_rpy;
    }

    /* return the value to caller
     * ABI:
     * 1:u32 length
     * 2:u8* data region
     */
    {
        struct rpc_result *rr = (struct rpc_result *)result;
        struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_NORMAL);

        if (!rpy) {
            hvfs_err(mds, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto err_rpy;
        }
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
        xnet_msg_add_sdata(rpy, result, rr->length + sizeof(u32));
        xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                         msg->tx.ssite_id);
        xnet_msg_fill_reqno(rpy, msg->tx.reqno);
        xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
        /* match the original request at the source site */
        rpy->tx.handle = msg->tx.handle;

        err = xnet_send(hmo.xc, rpy);
        if (err) {
            hvfs_err(mds, "xnet_send() failed w/ %d\n", err);
        }
        xnet_free_msg(rpy);
    }

out:

    xnet_free_msg(msg);
    return;
err_rpy:
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        goto out;
    }
    mds_send_reply(msg, hmr, err);
    goto out;
}
