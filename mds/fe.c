/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-10 15:48:09 macan>
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
#include "tx.h"
#include "xtable.h"
#include "mds.h"
#include "xnet.h"
#include "lib.h"
#include "ring.h"

/* return the recent reqno for COMPARE
 */
u32 mds_get_recent_reqno(u64 site)
{
    /* FIXME: we do not support TXC for now */
    return 0;
}

/* update the recent reqno
 */
void mds_update_recent_reqno(u64 site, u64 reqno)
{
    return;
}

/* loop_detect the route info
 *
 * Return value: 0:no loop; 1: first loop; 2: second or greater loop;
 */
int __mds_fwd_loop_detect(struct mds_fwd *mf, u64 dsite)
{
    int i, looped = 0;
    
    for (i = 0; i < MDS_FWD_MAX; i++) {
        if (mf->route[i] != 0) {
            if (mf->route[i] == hmo.site_id) {
                if (looped < 2)
                    looped++;
            }
        } else
            break;
    }
    if (!looped) {
        /* check if it will be looped */
        for (i = 0; i < MDS_FWD_MAX; i++) {
            if (mf->route[i] != 0) {
                if (mf->route[i] == dsite) {
                    if (looped < 2)
                        looped++;
                }
            } else
                break;
        }
    }

    return looped;
}

/* mds_fe_handle_err()
 *
 * NOTE: how to handle the err from the dispatcher? We just print the err
 * message and free the msg.
 */
void mds_fe_handle_err(struct xnet_msg *msg, int err)
{
    if (unlikely(err)) {
        hvfs_warning(mds, "MSG(%lx->%lx)(reqno %d) can't be handled w/ %d\n",
                     msg->tx.ssite_id, msg->tx.dsite_id, msg->tx.reqno, err);
    }

    xnet_set_auto_free(msg);
    xnet_free_msg(msg);
}

int mds_do_forward(struct xnet_msg *msg, u64 dsite)
{
    int err = 0, i, relaied = 0, looped = 0;
    
    /* Note that lots of forward request may incur the system performance, we
     * should do fast forwarding and fast bitmap changing. */
    struct mds_fwd *mf = NULL, *rmf = NULL;
    struct xnet_msg *fmsg;

    if (unlikely(msg->tx.flag & XNET_FWD)) {
        atomic64_inc(&hmo.prof.mds.loop_fwd);
        /* check if this message is looped. if it is looped, we should refresh
         * the bitmap and just forward the message as normal. until receive
         * the second looped request, we stop or slow down the request */
        rmf = (struct mds_fwd *)((void *)(msg->tx.reserved) + 
                                 msg->tx.len + sizeof(msg->tx));
        looped = __mds_fwd_loop_detect(rmf, dsite);
        
        if (unlikely((atomic64_read(&hmo.prof.mds.loop_fwd) + 1) % 
                     MAX_RELAY_FWD == 0)) {
            /* we should trigger the bitmap reload now */
            mds_bitmap_refresh(msg->xm_data);
        }
        relaied = 1;
    }

    mf = xzalloc(sizeof(*mf) + MDS_FWD_MAX * sizeof(u32));
    if (!mf) {
        hvfs_err(mds, "alloc mds_fwd failed.\n");
        err = -ENOMEM;
        goto out;
    }
    mf->len = MDS_FWD_MAX * sizeof(u32) + sizeof(*mf);
    switch (looped) {
    case 0:
        /* not looped request */
        mf->route[0] = hmo.site_id;
        break;
    case 1:        
        /* first loop, copy the entries */
        au_handle_split_sync();
        for (i = 0; i < MDS_FWD_MAX; i++) {
            if (rmf->route[i] != 0)
                mf->route[i] = rmf->route[i];
            else
                break;
        }
        if (i < MDS_FWD_MAX)
            mf->route[i] = hmo.site_id;
        break;
    case 2:
        /* second loop, slow down the forwarding */
        au_handle_split_sync();
        for (i = 0; i < MDS_FWD_MAX; i++) {
            if (rmf->route[i] != 0)
                mf->route[i] = rmf->route[i];
            else
                break;
        }
        if (i < MDS_FWD_MAX)
            mf->route[i] = hmo.site_id;
        break;
    default:;
    }

    fmsg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!fmsg) {
        hvfs_err(mds, "xnet_alloc_msg() failed, we should retry!\n");
        err = -ENOMEM;
        goto out_free;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(fmsg, &fmsg->tx, sizeof(fmsg->tx));
#endif
    xnet_msg_set_err(fmsg, err);
    xnet_msg_fill_tx(fmsg, XNET_MSG_REQ, 0, hmo.site_id, dsite);
    xnet_msg_fill_cmd(fmsg, HVFS_MDS2MDS_FWREQ, 0, 0);
    xnet_msg_add_sdata(fmsg, &msg->tx, sizeof(msg->tx));

    if (msg->xm_datacheck) {
        if (unlikely(relaied)) {
            xnet_msg_add_sdata(fmsg, msg->xm_data, msg->tx.len);
        } else {
            for (i = 0; i < msg->riov_ulen; i++) {
                xnet_msg_add_sdata(fmsg, msg->riov[i].iov_base, 
                                   msg->riov[i].iov_len);
            }
        }
    }

    /* piggyback the route info @ the last iov entry */
    xnet_msg_add_sdata(fmsg, mf, mf->len);

    err = xnet_send(hmo.xc, fmsg);

    if (err) {
        hvfs_err(mds, "Forwarding the request to %lx failed w/ %d.\n",
                 dsite, err);
    }

    /* cleaning */
    xnet_clear_auto_free(fmsg);
    xnet_free_msg(fmsg);
    
out_free:
    xfree(mf);
out:
    return err;
}

/* return 1 means this msg is PAUSED.
 * return 0 means this msg has passed the controler.
 */
static inline
int mds_modify_control(struct xnet_msg *msg)
{
    if (unlikely(hmo.spool_modify_pause)) {
        if (msg->tx.cmd & HVFS_CLT2MDS_RDONLY) {
            return 0;
        }
        /* pause this handling */
        mds_spool_modify_pause(msg);
        return 1;
    }

    return 0;
}

int mds_pause(struct xnet_msg *msg)
{
    hmo.reqin_drop = 1;
    xnet_free_msg(msg);

    return 0;
}

int mds_resume(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    
    hmo.reqin_drop = 0;

    rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        goto out;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mds, "xnet_send() failed\n");
        /* do not retry myself */
    }
    xnet_free_msg(rpy);
out:    
    xnet_free_msg(msg);

    return 0;
}

int mds_ring_update(struct xnet_msg *msg)
{
    if (msg->xm_datacheck) {
        /* ok, we should call the ring update callback function */
        if (hmo.cb_ring_update)
            hmo.cb_ring_update(msg->xm_data);
    } else {
        hvfs_err(mds, "Invalid data region of ring update request from %ld\n",
                 msg->tx.ssite_id);
        return -EINVAL;
    }

    xnet_free_msg(msg);

    return 0;
}

int mds_addr_table_update(struct xnet_msg *msg)
{
    if (msg->xm_datacheck) {
        if (hmo.cb_addr_table_update)
            hmo.cb_addr_table_update(msg->xm_data);
    } else {
        hvfs_err(mds, "Invalid addr table update message, incomplete hst!\n");
        return -EINVAL;
    }

    xnet_free_msg(msg);

    return 0;
}

/* Callback for XNET, should be thread-safe!
 */
int mds_fe_dispatch(struct xnet_msg *msg)
{
    u64 itbid;
    int err = 0;
    u8 depth = 0;
#ifdef HVFS_DEBUG_LATENCY
    lib_timer_def();
#endif

    if (HVFS_IS_CLIENT(msg->tx.ssite_id)) {
        struct hvfs_index *hi;
        struct hvfs_tx *tx;
        struct chp *p;
        struct dhe *e;

    client_proxy:
        /* fast path for proxy load bitmap */
        if (unlikely(((msg->tx.cmd & ~HVFS_CLT2MDS_BASE) & HVFS_CLT2MDS_LB) 
                     || (msg->tx.cmd == HVFS_CLT2MDS_LB_PROXY))) {
            mds_m2m_lb(msg);
            return 0;
        }

        /* sanity checking */
        if (likely(msg->xm_datacheck))
            hi = msg->xm_data;
        else {
            hvfs_err(mds, "Internal error, data lossing ...\n");
            err = -EINVAL;
            goto out;
        }
        
        /* fast path for statfs/readdir/release */
        if (unlikely(msg->tx.cmd & HVFS_CLT2MDS_NODHLOOKUP)) {
            return mds_client_dispatch(msg);
        }
        if (msg->tx.cmd & HVFS_CLT2MDS_NOCACHE)
            goto dh_lookup;
        /* FIXME: how to origanize reqin_site? */
        if (unlikely(mds_get_recent_reqno(msg->tx.ssite_id) > msg->tx.reqno)) {
            /* resend request */
            tx = mds_txc_search(&hmo.txc, msg->tx.ssite_id, msg->tx.reqno);
            if (!tx) {
                /* already evicted, respond w/ err */
                hvfs_err(mds, "request from %lx w/ seqno %u has been evicted.\n",
                         msg->tx.ssite_id, msg->tx.reqno);
                err = -ETXCED;
                goto out;
            }
            if (tx->state != HVFS_TX_PROCESSING) {
                /* need resend */
                xnet_wait_group_add(mds_gwg, tx->rpy);
                xnet_isend(hmo.xc, tx->rpy);
            }
            hvfs_err(mds, "You should not goto this cache respond!\n");
            mds_put_tx(tx);
            return 0;
        }

        /* modify controller */
        if (unlikely(mds_modify_control(msg))) {
            return 0;
        }
    dh_lookup:
        /* search in the DH */
        /* FIXME: DH load blocking may happen */
#ifdef HVFS_DEBUG_LATENCY
        lib_timer_B();
#endif
        e = mds_dh_search(&hmo.dh, hi->puuid);
        if (unlikely(IS_ERR(e))) {
            /* reply err = -ENOENT */
            err = PTR_ERR(e);
            goto out;
        }
        /* do we need set trigger flag? */
        if (unlikely(e->data))
            hi->flag |= INDEX_DTRIG;
        /* search in the bitmap(optional) */
        /* FIXME: bitmap load blocking may happen */
        if (!(hi->hash) && (hi->flag & INDEX_BY_NAME)) {
            hi->hash = hvfs_hash(hi->puuid, (u64)hi->name, hi->namelen,
                                 HASH_SEL_EH);
        }
    recal_itbid:
        itbid = mds_get_itbid_depth(e, hi->hash, &depth);
        hi->depth = depth;
        /* recheck CH ring and forward the request on demand */
        if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
            p = ring_get_point(itbid, hi->psalt, hmo.chring[CH_RING_MDS]);
            if (unlikely(IS_ERR(p))) {
                hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
                err = -ECHP;
                mds_dh_put(e);
                goto out;
            }
            if (hmo.site_id != p->site_id) {
                /* FIXME: need forward, for now we just ignore the mismatch */
                if (itbid == hi->itbid) {
                    /* itbid is correct, but ring changed */
                    if (msg->tx.flag & XNET_FWD) {
                        goto recal_itbid;
                    } else {
                        hvfs_debug(mds, "itbid %ld %d RING CHANGED "
                                   "(%lx vs %lx)\n",
                                   itbid, (msg->tx.flag & XNET_FWD), 
                                   hmo.site_id, p->site_id);
                        mds_dh_put(e);
                        HVFS_BUG();
                        err = -ERINGCHG;
                        goto out;
                    }
                }
                mds_dh_put(e);
                hvfs_debug(mds, "NEED FORWARD the request to Site %lx "
                           "(%ld vs %ld).\n",
                           p->site_id, itbid, (u64)hi->itbid);
                /* doing the forward now */
                hi->flag |= INDEX_BIT_FLIP;
                hi->itbid = itbid;
                err = mds_do_forward(msg, p->site_id);
                goto out;
            }
            hi->itbid = itbid;
        }
        mds_dh_put(e);
#ifdef HVFS_DEBUG_LATENCY
        lib_timer_E();
        lib_timer_O(1, "DH and Bitmap search");
#endif
        return mds_client_dispatch(msg);
    } else if (HVFS_IS_MDS(msg->tx.ssite_id)) {
        if (unlikely(msg->tx.cmd == HVFS_CLT2MDS_CREATE ||
                     msg->tx.cmd == HVFS_CLT2MDS_LOOKUP ||
                     msg->tx.cmd == HVFS_CLT2MDS_UPDATE ||
                     msg->tx.cmd == HVFS_CLT2MDS_UNLINK)) {
            hvfs_debug(mds, "Request %lx from %lx proxy to client "
                       "processing.\n", msg->tx.cmd, msg->tx.ssite_id);
            goto client_proxy;
        }
        return mds_mds_dispatch(msg);
    } else if (HVFS_IS_MDSL(msg->tx.ssite_id)) {
        return mds_mdsl_dispatch(msg);
    } else if (HVFS_IS_AMC(msg->tx.ssite_id) ||
               HVFS_IS_BP(msg->tx.ssite_id)) {
        if (unlikely(msg->tx.cmd == HVFS_CLT2MDS_CREATE ||
                     msg->tx.cmd == HVFS_CLT2MDS_LOOKUP ||
                     msg->tx.cmd == HVFS_CLT2MDS_UPDATE ||
                     msg->tx.cmd == HVFS_CLT2MDS_LD ||
                     msg->tx.cmd == HVFS_CLT2MDS_LB_PROXY ||
                     msg->tx.cmd == HVFS_CLT2MDS_UNLINK ||
                     msg->tx.cmd == HVFS_CLT2MDS_LIST)) {
            hvfs_debug(mds, "Request %lx from %lx proxy to client "
                       "processing.\n", msg->tx.cmd, msg->tx.ssite_id);
            goto client_proxy;
        }
        return mds_amc_dispatch(msg);
    } else if (HVFS_IS_RING(msg->tx.ssite_id)) {
        if (msg->tx.cmd & HVFS_CLT2MDS_BASE ||
            msg->tx.cmd == HVFS_CLT2MDS_LB_PROXY) {
            hvfs_debug(mds, "Request %lx from %lx proxy to client "
                       "processing.\n", msg->tx.cmd, msg->tx.ssite_id);
            goto client_proxy;
        }
        return mds_ring_dispatch(msg);
    } else if (HVFS_IS_ROOT(msg->tx.ssite_id)) {
        return mds_root_dispatch(msg);
    }
        
    hvfs_err(mds, "MDS front-end handle INVALID request <0x%lx %d>\n", 
             msg->tx.ssite_id, msg->tx.reqno);
out:
    mds_fe_handle_err(msg, err);
    return err;
}
