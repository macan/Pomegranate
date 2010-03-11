/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-11 19:43:08 macan>
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
        hvfs_err(mds, "Invalid LDH request %ld received from %lx\n", 
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

void mds_ausplit(struct xnet_msg *msg)
{
    struct itb *i, *ti;
    struct bucket *nb;
    struct bucket_entry *nbe;
    struct hvfs_txg *t;
    int err = 0;

    /* sanity checking */
    if (msg->tx.len < sizeof(struct itb)) {
        hvfs_err(mds, "Invalid SPITB request %ld received from %lx\n",
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
    ASSERT(msg->tx.len == atomic_read(&i->h.len), mds);
    
    /* pre-dirty the itb */
    t = mds_get_open_txg(&hmo);
    i->h.txg = t->txg;
    i->h.state = ITB_STATE_DIRTY;
    /* re-init */
    itb_reinit(i);

    txg_add_itb(t, i);
    txg_put(t);

    /* insert the ITB to CBHT */
    err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &nb, &nbe, &ti);
    if (err == -EEXIST) {
        /* someone has already create the new ITB, we just ignore ourself? */
        hvfs_err(mds, "Someone create ITB %ld, maybe data lossing ...\n",
                 i->h.itbid);
        xrwlock_runlock(&nbe->lock);
        xrwlock_runlock(&nb->lock);
    } else if (err) {
        hvfs_err(mds, "Internal error %d, data lossing.\n", err);
    }

    /* it is ok, we need to free the locks */
    xrwlock_runlock(&nbe->lock);
    xrwlock_runlock(&nb->lock);

    mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid,
                         MDS_BITMAP_SET);
    /* FIXME: if we using malloc to alloc the ITB, then we need to inc the
     * csize counter */
    atomic64_inc(&hmo.prof.mds.ausplit);
    atomic64_add(atomic_read(&i->h.entries), &hmo.prof.cbht.aentry);

    hvfs_debug(mds, "We update the bit of ITB %ld\n", i->h.itbid);

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
        for (i = 0; i < ((mf->len - sizeof(*mf)) / sizeof(u64)); i++) {
            pos += snprintf(line + pos, 256 - pos, "%lx->", mf->route[i]);
        }
        pos += snprintf(line + pos, 256 - pos, "%lx(E).\n", hmo.site_id);
        hvfs_err(mds, "%s", line);
    }
#endif
    memcpy(&msg->tx, tx, sizeof(*tx));
    /* FIXME: we know there is only one iov entry */
    msg->tx.flag |= (XNET_PTRESTORE | XNET_FWD);
    msg->tx.arg1 = (u64)msg->xm_data;
    msg->xm_data += sizeof(*tx);
    msg->tx.dsite_id = hmo.site_id;

    atomic64_inc(&hmo.prof.mds.forward);
    mds_fe_dispatch(msg);

    return;
out:
    xnet_free_msg(msg);
}
