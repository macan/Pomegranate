/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 22:00:43 macan>
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
    hvfs_warning(mds, "MSG(%ld->%ld)(reqno %ld) can't be handled w/ %d\n",
                 msg->tx.ssite_id, msg->tx.dsite_id, msg->tx.reqno, err);
    xnet_free_msg(msg);
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
            } else {
                if (itbid == hi->itbid) {
                    /* itbid is correct, but ring changed */
                    err = -ERINGCHG;
                    goto out;
                }
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
    hvfs_err(mds, "MDS front-end handle INVALID request <0x%lx %ld>\n", 
             msg->tx.ssite_id, msg->tx.reqno);
out:
    mds_fe_handle_err(msg, err);
    return err;
}
