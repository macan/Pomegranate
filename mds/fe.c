/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-06 10:15:54 macan>
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
u64 mds_get_recent_reqno(u64 site)
{
    /* FIXME: we do not support TXC for now */
    return 0UL;
}

/* update the recent reqno
 */
void mds_update_recent_reqno(u64 site, u64 reqno)
{
    return;
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
    int err = 0, i, relaied = 0;
    
    /* Note that lots of forward request may incur the system performance, we
     * should do fast forwarding and fast bitmap changing. */
    struct mds_fwd *mf = NULL;
    struct xnet_msg *fmsg;

    if (unlikely(msg->tx.flag & XNET_FWD)) {
        atomic64_inc(&hmo.prof.mds.loop_fwd);
        relaied = 1;
    }

    mf = xzalloc(sizeof(*mf) + sizeof(u64));
    if (!mf) {
        hvfs_err(mds, "alloc mds_fwd failed.\n");
        err = -ENOMEM;
        goto out;
    }
    mf->len = sizeof(u64) + sizeof(*mf);
    mf->route[0] = hmo.site_id;

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

/* Callback for XNET, should be thread-safe!
 */
int mds_fe_dispatch(struct xnet_msg *msg)
{
    u64 itbid;
    int err = 0;
#ifdef HVFS_DEBUG_LATENCY
    lib_timer_def();
#endif

    if (HVFS_IS_CLIENT(msg->tx.ssite_id)) {
        struct hvfs_index *hi = NULL;
        struct hvfs_tx *tx;
        struct chp *p;
        struct dhe *e;

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
        
        /* fast path for statfs */
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
                err = -ETXCED;
                goto out;
            }
            if (tx->state != HVFS_TX_PROCESSING) {
                /* need resend */
                xnet_wait_group_add(mds_gwg, tx->rpy);
                xnet_isend(hmo.xc, tx->rpy);
            }
            mds_put_tx(tx);
            return 0;
        }

        /* modify controller */
        if (mds_modify_control(msg)) {
            return 0;
        }
    dh_lookup:
        /* search in the DH */
        /* FIXME: DH load blocking may happen */
#ifdef HVFS_DEBUG_LATENCY
        lib_timer_B();
#endif
        e = mds_dh_search(&hmo.dh, hi->puuid);
        if (IS_ERR(e)) {
            /* reply err = -ENOENT */
            err = PTR_ERR(e);
            goto out;
        }
        /* search in the bitmap(optional) */
        /* FIXME: bitmap load blocking may happen */
        if (!(hi->hash) && (hi->flag & INDEX_BY_NAME)) {
            hi->hash = hvfs_hash(hi->puuid, (u64)hi->name, hi->namelen,
                                 HASH_SEL_EH);
        }
    recal_itbid:
        itbid = mds_get_itbid(e, hi->hash);
        /* recheck CH ring and forward the request on demand */
        if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
            p = ring_get_point(itbid, hi->psalt, hmo.chring[CH_RING_MDS]);
            if (IS_ERR(p)) {
                hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
                err = -ECHP;
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
                        HVFS_BUG();
                        err = -ERINGCHG;
                        goto out;
                    }
                }
                hvfs_debug(mds, "NEED FORWARD the request to Site %lx "
                           "(%ld vs %ld).\n",
                           p->site_id, itbid, hi->itbid);
                /* doing the forward now */
                hi->flag |= INDEX_BIT_FLIP;
                hi->itbid = itbid;
                err = mds_do_forward(msg, p->site_id);
                goto out;
            }
            hi->itbid = itbid;
        }
#ifdef HVFS_DEBUG_LATENCY
        lib_timer_E();
        lib_timer_O(1, "DH and Bitmap search");
#endif
        return mds_client_dispatch(msg);
    } else if (HVFS_IS_MDS(msg->tx.ssite_id)) {
        return mds_mds_dispatch(msg);
    } else if (HVFS_IS_MDSL(msg->tx.ssite_id)) {
        return mds_mdsl_dispatch(msg);
    } else if (HVFS_IS_RING(msg->tx.ssite_id)) {
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
