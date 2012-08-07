/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-06 16:26:34 macan>
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
#include "xnet.h"
#include "mdsl.h"

/* control the itb_loads to N - 1 spool threads */
atomic_t itb_loads = {.counter = 0,};

static inline
int mdsl_mds_dispatch(struct xnet_msg *msg)
{
    switch (msg->tx.cmd) {
    case HVFS_MDS2MDSL_ITB:
        mdsl_itb(msg);
        atomic_dec(&itb_loads);
        break;
    case HVFS_MDS2MDSL_BITMAP:
        mdsl_bitmap(msg);
        break;
    case HVFS_MDS2MDSL_WBTXG:
        mdsl_wbtxg(msg);
        break;
    case HVFS_MDS2MDSL_WDATA:
        mdsl_wdata(msg);
        break;
    case HVFS_MDS2MDSL_BTCOMMIT:
        mdsl_bitmap_commit_v2(msg);
        break;
    case HVFS_CLT2MDSL_READ:
        mdsl_read(msg);
        break;
    case HVFS_CLT2MDSL_WRITE:
        mdsl_write(msg);
        break;
    case HVFS_MDS2MDSL_ANALYSE:
        mdsl_analyse(msg);
        break;
    default:
        hvfs_err(mdsl, "Invalid mds2mdsl command: 0x%lx\n", msg->tx.cmd);
    }
    return 0;
}

static inline
int mdsl_client_dispatch(struct xnet_msg *msg)
{
    switch (msg->tx.cmd) {
    case HVFS_CLT2MDSL_READ:
        mdsl_read(msg);
        break;
    case HVFS_CLT2MDSL_WRITE:
        mdsl_write(msg);
        break;
    case HVFS_CLT2MDSL_SYNC:
        break;
    case HVFS_CLT2MDSL_BGSEARCH:
        break;
    case HVFS_CLT2MDSL_STATFS:
        mdsl_statfs(msg);
        break;
    case HVFS_MDS2MDSL_ANALYSE: /* shadow of mds dispatch */
        mdsl_analyse(msg);
        break;
    default:
        hvfs_err(mdsl, "Invalid clt2mdsl command: 0x%lx\n", msg->tx.cmd);
        xnet_free_msg(msg);
    }
    
    return 0;
}

static
int mdsl_mdsl_dispatch(struct xnet_msg *msg)
{
    xnet_free_msg(msg);
    return 0;
}

static
int mdsl_ring_dispatch(struct xnet_msg *msg)
{
    switch (msg->tx.cmd) {
    case HVFS_FR2_RU:
        mdsl_ring_update(msg);
        break;
    case HVFS_FR2_AU:
        mdsl_addr_table_update(msg);
        break;
    default:
        hvfs_err(mdsl, "Invalid R2 request: 0x%lx\n", msg->tx.cmd);
        xnet_free_msg(msg);
    }

    return 0;
}

void mdsl_handle_err(struct xnet_msg *msg, int err)
{
    xnet_free_msg(msg);
}

/* mdsl_dispatch()
 *
 * The first dispatcher of MDSL
 */
int mdsl_dispatch(struct xnet_msg *msg)
{
    int err = 0;

    /* check the state here */
l0_recheck:
    switch (hmo.state) {
    case HMO_STATE_INIT:
        /* wait */
        while (hmo.state == HMO_STATE_INIT) {
            sched_yield();
        }
        /* recheck it  */
        goto l0_recheck;
    case HMO_STATE_LAUNCH:
        /* reinsert back to reqin list unless it is a RECOVERY request
         * (among MDSLs) */
        if (HVFS_IS_MDSL(msg->tx.ssite_id)) {
            return mdsl_mdsl_dispatch(msg);
        } else
            mdsl_spool_redispatch(msg, 0);
        return -EAGAIN;
    case HMO_STATE_RUNNING:
        break;
    case HMO_STATE_PAUSE:
        break;
    case HMO_STATE_RDONLY:
        break;
    case HMO_STATE_OFFLINE:
        break;
    default:
        HVFS_BUGON("Unknown MDSL state");
    }
    
    if (HVFS_IS_MDS(msg->tx.ssite_id)) {
        return mdsl_mds_dispatch(msg);
    } else if (HVFS_IS_CLIENT(msg->tx.ssite_id)) {
        return mdsl_client_dispatch(msg);
    } else if (HVFS_IS_AMC(msg->tx.ssite_id)) {
        return mdsl_client_dispatch(msg);
    } else if (HVFS_IS_BP(msg->tx.ssite_id)) {
        return mdsl_client_dispatch(msg);
    } else if (HVFS_IS_MDSL(msg->tx.ssite_id)) {
        return mdsl_mdsl_dispatch(msg);
    } else if (HVFS_IS_RING(msg->tx.ssite_id)) {
        return mdsl_ring_dispatch(msg);
    } else if (HVFS_IS_ROOT(msg->tx.ssite_id)) {
        return mdsl_ring_dispatch(msg);
    }
    hvfs_err(mdsl, "MDSL core dispatcher handle INVALID request <0x%lx %d>\n",
             msg->tx.ssite_id, msg->tx.reqno);
    mdsl_handle_err(msg, err);

    return err;
}

