/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-01 16:23:49 macan>
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

static inline void mds_send_reply(struct hvfs_tx *tx, struct hvfs_md_reply *hmr, 
                                  int err)
{
    tx->rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!tx->rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    hmr->err = err;
    if (!hmr->err) {
        xnet_msg_add_data(tx->rpy, hmr, sizeof(hmr));
        if (hmr->len)
            xnet_msg_add_data(tx->rpy, hmr->data, hmr->len);
    } else
        xnet_msg_set_err(tx->rpy, hmr->err);
        
    xnet_msg_set_site(tx->rpy, rx->reqin_site);
    xnet_msg_fill_tx(tx->rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     tx->reqin_site);
    xnet_msg_fill_reqno(tx->rpy, tx->req->tx.reqno);
    xnet_msg_fill_cmd(tx->rpy, XNET_RPY_ACK | XNET_PRY_DATA);

    mds_txc_add(&hmo.txc, tx);
    xnet_wait_group_add(mds_gwg, tx->rpy);
    if (xnet_isend(tx->rpy)) {
        hvfs_err(mds, "xnet_isend() failed\n");
        /* do not retry myself, client is forced to retry */
        xnet_wait_group_del(mds_gwg, tx->rpy);
        /* FIXME: free the tx->rpy! */
    }
    /* FIXME: state machine of TX, MSG */
    mds_tx_done(tx);
}

/* STATFS */
void mds_statfs(struct hvfs_tx *tx)
{
    struct statfs *s = zalloc(struct statfs);

    if (!s) {
        hvfs_err(mds, "zalloc() failed\n");
        mds_free_tx(tx);
        return;
    }
    s->f_files = hmi.mi_dnum = hmi.mi_fnum;
    s->f_ffree = (MAX_UUID_PER_MDS - hmi.mi_fuuid) +
        (MAX_UUID_PER_MDS - hmi.mi_duuid);

    tx->rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!tx->rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }
    
    xnet_msg_add_data(tx->rpy, s, sizeof(struct statfs));

    xnet_msg_set_site(tx->rpy, tx->reqin_site);
    xnet_msg_fill_tx(tx->rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     tx->reqin_site);
    xnet_msg_fill_reqno(tx->rpy, tx->req->tx.reqno);
    xnet_msg_fill_cmd(tx->rpy, XNET_RPY_ACK | XNET_RPY_DATA);

    mds_txc_add(&hmo.txc, tx);
    xnet_wait_group_add(mds_gwg, tx->rpy);
    if (xnet_isend(tx->rpy)) {
        hvfs_err(mds, "xnet_isend() failed\n");
        /* do not retry myself, client is forced to retry */
        xnet_wait_group_del(mds_gwg, tx->rpy);
    }
    /* FIXME: state machine of TX, MSG */
    mds_tx_done(tx);
}

/* LOOKUP */
void mds_lookup(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid LOOKUP request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }
    
    if (hi->flag & INDEX_BY_NAME && !hi->hash) {
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);
    }
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_LOOKUP;
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}

/* CREATE */
void mds_create(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid CREATE request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    if (hi->flag & INDEX_BY_NAME && !hi->hash)
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);

    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* create in the CBHT */
    hi->flag |= INDEX_CREATE;
    hi->data = tx->req->xm_data + sizeof(*hi) + hi->len;
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}

/* RELEASE */
void mds_release(struct hvfs_tx *tx)
{
    /* FIXME */
    hvfs_info(mds, "Not implement yet.\n");
}

/* UPDATE */
void mds_update(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid LOOKUP request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }
    if (hi->flag & INDEX_BY_NAME && !hi->hash) {
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);
    }
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_MDU_UPDATE;
    hi->data = tx->req->xm_data + sizeof(*hi) + hi->len;
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}

/* LINKADD */
void mds_linkadd(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid LINKADD request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }
    
    if (hi->flag & INDEX_BY_NAME && !hi->hash) {
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);
    }
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_LINK_ADD;
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}

/* UNLINK */
void mds_unlink(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid UNLINK request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }
    
    if (hi->flag & INDEX_BY_NAME && !hi->hash) {
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);
    }
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_UNLINK;
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}

/* symlink */
void mds_symlink(struct hvfs_tx *tx)
{
    struct hvfs_index *hi = tx->req->xm_data;
    struct hvfs_md_reply *hmr;
    int err;

    if (tx->req->len < sizeof(*hi)) {
        hvfs_err(mds, "Invalid LINKADD request %d received\n", tx->req->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }
    
    if (hi->flag & INDEX_BY_NAME && !hi->hash) {
        hi->hash = hvfs_hash(hi->puuid, hi->name, hi->len, HASH_SEL_EH);
    }
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        /* do not retry myself */
        mds_free_tx(tx);
        return;
    }

    /* search in the CBHT */
    hi->flag |= INDEX_SYMLINK;
    hi->data = tx->req->xm_data + sizeof(*hi) + hi->len; /* symname */
    err = mds_cbht_search(hi, hmr);

send_rpy:
    mds_send_reply(tx, hmr, err);
}
