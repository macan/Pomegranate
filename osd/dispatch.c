/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-21 16:32:26 macan>
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
#include "osd.h"

/* control the object read to N - 1 spool threads */
atomic_t obj_reads = {.counter = 0,};

void osd_handle_err(struct xnet_msg *msg, int err)
{
    xnet_free_msg(msg);
}

static
int osd_ring_dispatch(struct xnet_msg *msg)
{
    switch (msg->tx.cmd) {
    case HVFS_FR2_RU:
        hvfs_warning(osd, "Ignore R2 ring update request.\n");
        break;
    case HVFS_FR2_AU:
        osd_addr_table_update(msg);
        break;
    default:
        hvfs_err(osd, "Invalid R2 request: 0x%lx\n", msg->tx.cmd);
        xnet_free_msg(msg);
    }

    return 0;
}

/* osd_dispatch()
 *
 * The first dispatcher of OSD
 */
int osd_dispatch(struct xnet_msg *msg)
{
    int err = 0;

    /* check the state here */
l0_recheck:
    switch (hoo.state) {
    case HOO_STATE_INIT:
        /* wait */
        while (hoo.state == HOO_STATE_INIT) {
            sched_yield();
        }
        /* recheck it */
        goto l0_recheck;
    case HOO_STATE_LAUNCH:
        /* reinsert back to reqin list unless it is a RECOVERY request from
         * RING server */
        if (HVFS_IS_RING(msg->tx.ssite_id)) {
            return osd_ring_dispatch(msg);
        } else
            osd_spool_redispatch(msg, 0);
        return -EAGAIN;
    case HOO_STATE_RUNNING:
        break;
    case HOO_STATE_PAUSE:
        /* enable reqin quest dropping after handling existing requests */
        break;
    case HOO_STATE_RDONLY:
        /* drop modify requests */
        break;
    case HOO_STATE_OFFLINE:
        /* drop object r/w requests */
        break;
    default:
        HVFS_BUGON("Unknown OSD state");
    }

    switch (msg->tx.cmd) {
    case HVFS_OSD_READ:
        err = osd_read(msg);
        break;
    case HVFS_OSD_WRITE:
        err = osd_write(msg);
        break;
    case HVFS_OSD_SWEEP:
        err = osd_sweep(msg);
        break;
    case HVFS_OSD_SYNC:
        err = osd_sync(msg);
        break;
    case HVFS_OSD_TRUNC:
        err = osd_trunc(msg);
        break;
    case HVFS_OSD_DEL:
        err = osd_del(msg);
        break;
    case HVFS_OSD_STATFS:
        err = osd_statfs(msg);
        break;
    default:
        if (HVFS_IS_RING(msg->tx.ssite_id)) {
            return osd_ring_dispatch(msg);
        }
        
        hvfs_err(osd, "OSD core dispatcher handle INVALID request <0x%lx %d>\n",
                 msg->tx.ssite_id, msg->tx.reqno);
        osd_handle_err(msg, -EINVAL);
    }

    return err;
}
