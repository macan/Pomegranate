/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-14 10:43:36 macan>
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
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "mds.h"

int mds_client_dispatch(struct xnet_msg *msg)
{
    struct hvfs_tx *tx;
    u16 op;

#ifdef HVFS_DEBUG_LATENCY
    lib_timer_def();
    lib_timer_B();
#endif
    if (msg->tx.flag & XNET_NEED_TX)
        op = HVFS_TX_NORMAL;    /* need tx(ack/rpy+commit) */
    else if (msg->tx.flag & XNET_NEED_REPLY)
        op = HVFS_TX_NOCOMMIT;  /* no tx but need reply */
    else
        op = HVFS_TX_FORGET;    /* no need to TXC, one-shot */

    tx = mds_alloc_tx(op, msg);
    if (!tx) {
        /* do not retry myself */
        hvfs_err(mds, "mds_alloc_tx() failed");
        return -ENOMEM;
    }

    switch (msg->tx.cmd) {
    case HVFS_CLT2MDS_STATFS:
        mds_statfs(tx);
        break;
    case HVFS_CLT2MDS_LOOKUP:
        mds_lookup(tx);
        break;
    case HVFS_CLT2MDS_CREATE:
        mds_create(tx);
        break;
    case HVFS_CLT2MDS_RELEASE:
        mds_release(tx);
        break;
    case HVFS_CLT2MDS_UPDATE:
        mds_update(tx);
        break;
    case HVFS_CLT2MDS_UNLINK:
        mds_unlink(tx);
        break;
    case HVFS_CLT2MDS_SYMLINK:
        mds_symlink(tx);
        break;
    case HVFS_CLT2MDS_LINKADD:
        mds_linkadd(tx);
        break;
    case HVFS_CLT2MDS_LB:
        mds_lb(tx);
        break;
    case HVFS_CLT2MDS_DITB:
        mds_dump_itb(tx);
        break;
    case HVFS_CLT2MDS_LD:
        mds_c2m_ldh(tx);
        break;
    case HVFS_CLT2MDS_LIST:
        mds_list(tx);
        break;
    case HVFS_CLT2MDS_COMMIT:
        mds_snapshot(tx);
        break;
    default:
        hvfs_err(mds, "Invalid client2MDS command: 0x%lx\n", msg->tx.cmd);
        /* free tx and xnet_msg */
        mds_free_tx(tx);
    }
#ifdef HVFS_DEBUG_LATENCY
    lib_timer_E();
    lib_timer_O(1, "ALLOC TX and HANDLE.");
#endif
    
    return 0;
}

int mds_mds_dispatch(struct xnet_msg *msg)
{
    if (msg->tx.cmd == HVFS_MDS2MDS_FWREQ) {
        /* FIXME: forward request */
        mds_forward(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_SPITB) {
        /* FIXME: split itb */
        mds_ausplit(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_AUBITMAP) {
        mds_aubitmap(msg);
        xnet_free_msg(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_AUBITMAP_R) {
        mds_aubitmap_r(msg);
        xnet_free_msg(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_AUDIRDELTA) {
        mds_audirdelta(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_AUDIRDELTA_R) {
        mds_audirdelta_r(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_AUPDATE) {
        /* FIXME: async update */
    } else if (msg->tx.cmd == HVFS_MDS2MDS_REDODELTA) {
        /* FIXME: redo delta */
    } else if (msg->tx.cmd == HVFS_MDS2MDS_LB) {
        /* FIXME: load bitmap */
        mds_m2m_lb(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_LD) {
        /* FIXME: load dir hash entry, just return the hvfs_index */
        mds_ldh(msg);
    } else if (msg->tx.cmd == HVFS_MDS2MDS_GB) {
        mds_gossip_bitmap(msg);
    } else {
        xnet_free_msg(msg);
    }

    return 0;
}

int mds_mdsl_dispatch(struct xnet_msg *msg)
{
    xnet_free_msg(msg);
    return 0;
}

int mds_ring_dispatch(struct xnet_msg *msg)
{
    if (msg->tx.cmd == HVFS_MDS2MDS_AUBITMAP_R) {
        mds_aubitmap_r(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_PAUSE) {
        mds_pause(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_RESUME) {
        mds_resume(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_COMMIT) {
        mds_snapshot_fr2(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_RUPDATE) {
        mds_ring_update(msg);
    } else {
        xnet_free_msg(msg);
    }
    
    return 0;
}

int mds_root_dispatch(struct xnet_msg *msg)
{
    if (msg->tx.cmd == HVFS_MDS2MDS_AUBITMAP_R) {
        mds_aubitmap_r(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_PAUSE) {
        mds_pause(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_RESUME) {
        mds_resume(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_COMMIT) {
        mds_snapshot_fr2(msg);
    } else if (msg->tx.cmd == HVFS_R22MDS_RUPDATE) {
        mds_ring_update(msg);
    } else {
        xnet_free_msg(msg);
    }

    return 0;
}

int mds_amc_dispatch(struct xnet_msg *msg)
{
    switch (msg->tx.cmd) {
    case HVFS_AMC2MDS_REQ:
        xtable_handle_req(msg);
        break;
    case HVFS_AMC2MDS_EXT:
        break;
    default:
        hvfs_err(mds, "Invalid AMC2MDS command: 0x%lx\n", msg->tx.cmd);
    }

    return 0;
}
