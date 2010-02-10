/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-10 20:28:53 macan>
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
        hvfs_err(mds, "Invalid LDH request %ld received\n", msg->tx.reqno);
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
    if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            err = -ECHP;
            goto send_rpy;
        }
        if (hmo.site_id != p->site_id) {
            /* FIXME: forward */
        } else {
            if (itbid == hi->itbid) {
                /* itbid is correct, but ring changed */
                err = -ERINGCHG;
                goto send_rpy;
            }
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
    hi->flag |= INDEX_LOOKUP;
    hi->puuid = hmi.gdt_uuid;
    hi->psalt = hmi.gdt_salt;

    /* search in the CBHT */
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);

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

