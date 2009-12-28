/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-28 09:08:41 macan>
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

/* Callback for XNET, should be thread-safe!
 */
void mds_fe_dispatch(struct xnet_msg *msg)
{
    u64 itbid, site_id;
    int err = 0;

    if (HVFS_IS_CLIENT(msg->site)) {
        struct hvfs_index *hi = msg->xm_data;
        struct hvfs_tx *tx;
        struct chp *p;
        struct dhe *e;

        /* fast path for statfs */
        if (unlikely(msg->tx.cmd & HVFS_CLT2MDS_NODHLOOKUP)) {
            return mds_client_dispatch(msg);
        }
        if (msg->tx.cmd & HVFS_CLT2MDS_NOCACHE)
            goto dh_lookup;
        /* FIXME: how to origanize reqin_site? */
        if (unlikely(mds_get_recent_reqno(msg->reqin_site) >= msg->tx.reqno)) {
            /* resend request */
            tx = mds_txc_search(&hmo.txc, msg->reqin_site, msg->tx.reqno);
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
            return;
        }
    dh_lookup:
        /* search in the DH */
        /* FIXME: DH load blocking may happen */
        e = mds_dh_search(hmo.dh, hi);
        if (!e) {
            /* reply err = -ENOENT */
            err = -ENOENT;
            goto out;
        }
        /* search in the bitmap(optional) */
        /* FIXME: bitmap load blocking may happen */
        itbid = mds_get_itbid(e, hi->hash);
        /* recheck CH ring and forward the request on demand */
        if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
            p = ring_get_point(itbid, hi->psalt, hmo.ring[CH_RING_MDS]);
            if (IS_ERR(p)) {
                hvfs_err(mds, "ring_get_point() failed w/ %d\n", PTR_ERR(p));
                err = -ECHP;
                goto out;
            }
            if (hmo.site_id != p->site_id) {
                /* FIXME: forward */
            } else {
                if (itbid == hi->itbid) {
                    /* itbid is correct, but ring changed */
                    err = -ERINGCHG;
                    goto out;
                }
            }
        }
        return mds_client_dispatch(msg);
    } else if (HVFS_IS_MDS(msg->site)) {
        return mds_mds_dispatch(msg);
    } else if (HVFS_IS_MDSL(msg->site)) {
        return mds_mdsl_dispatch(msg);
    } else if (HVFS_IS_RING(msg->site)) {
        return mds_ring_dispatch(msg);
    } else if (HVFS_IS_ROOT(msg->site)) {
        return mds_root_dispatch(msg);
    }
    hvfs_err(mds, "MDS front-end handle INVALID request <0x%lx %ld>\n", 
             msg->reqin_site, msg->reqno);
out:
    mds_fe_handle_err(msg, err);
    return;
}
