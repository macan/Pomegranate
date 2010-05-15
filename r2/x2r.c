/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-15 23:06:29 macan>
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
#include "root.h"

static inline
int __prepare_xnet_msg(struct xnet_msg *msg, struct xnet_msg *rpy)
{
    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(root, "xnet_alloc_msg() reply failed.\n");
        return -ENOMEM;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_cmd(rpy, XNET_RPY_DATA, 0, 0);
    rpy->tx.handle = msg->tx.handle;

    return 0;
}

/* root_do_reg()
 *
 * do register the site_id in arg0. If the site state is INIT, we should read
 * in the hxi info and return it. If the site state is NORMAL, we should alert
 * the caller that there is already a running server/client with the same
 * site_id. If the site state is SHUTDOWN, we should do state change in atomic
 * fashion. If the site state is TRANSIENT, we should just wait a moment for
 * the state change. If the site state is ERROR, we should do a recover process.
 *
 * Return ABI: | hxi info(fixed size) | ring info(MDS/MDSL) | root info | gdt
 * bitmap | site_table |
 */
int root_do_reg(struct xnet_msg *msg)
{
    struct site_entry *se;
    struct xnet_msg *rpy;
    int err = 0;

    err = __prepare_xnet_msg(rpy, msg);
    if (err) {
        hvfs_err(root, "prepare rpy xnet_msg failed w/ %d\n", err);
        goto out;
    }

    /* ABI:
     * @tx.arg0: site_id or -1UL to random selected a site_id
     * @tx.arg1: fsid
     * @tx.reserved: gid
     */
    err = site_mgr_lookup_create(&hro.sm, msg->tx.arg0, &se);
    if (err > 0) {
        /* it is a new create site entry */
        hvfs_err(root, "Create site entry %lx\n", msg->tx.arg0);
    } else if (err < 0) {
        hvfs_err(root, "lookup create site entry %lx failed w/ %d\n",
                 msg->tx.arg0, err);
        goto send_rpy;
    }
    
    /* now, we get a entry, either new created or an existed one, we should
     * act on the diffierent state */
    xlock_lock(&se->lock);
    switch (se->state) {
    case SE_STATE_INIT:
        /* we should load the site info from MDSL */
        err = root_read_hxi(msg->tx.arg0, msg->tx.arg1, &se->hxi);
        if (err) {
            hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
            goto send_rpy;
        }
        /* pack the hxi in the rpy message */
        err = __pack_msg(&se->hxi, sizeof(se->hxi));
        if (err) {
            hvfs_err(root, "pack hxi failed w/ %d\n", err);
            goto send_rpy;
        }
        /* pack the ring info */
        ring = ring_mgr_lookup(&hro.ring, msg->tx.reserved);
        if (IS_ERR(ring)) {
            hvfs_err(root, "ring_mgr_lookup() failed w/ %ld\n",
                     PTR_ERR(ring));
            goto send_rpy;
        }
        err = __pack_msg(&ring->ring, 
        /* pack the root info */
        /* pack the gdt bitmap */
        /* pack the global site table */
        /* change the state to NORMAL */
        se->state = SE_STATE_NORMAL;
        break;
    case SE_STATE_NORMAL:
        /* we should reject the request, because another site is active to
         * suply service */
        err = -EEXIST;
        break;
    case SE_STATE_SHUTDOWN:
        /* ok, the state is clean, we can grant the site entry to this
         * requested site */
        se->state = SE_STATE_NORMAL;
        break;
    case SE_STATE_TRANSIENT:
        /* we just return the transient state to the caller, they should retry
         * later */
        err = -ETRANSIENT;
        break;
    case SE_STATE_ERROR:
        /* hoo, error occured, the previous instance exit without unregister,
         * we should inform the new instance to begin an recover process */
        err = -ERECOVER;
        break;
    default:
        hvfs_err(root, "Invalid site entry %lx in state %x\n",
                 se->site_id, se->state);
    }
    xlock_unlock(&se->lock);

    if (err) {
    }
    
out:
    xnet_free_msg(msg);

    return err;
}

int root_do_unreg(struct xnet_msg *msg)
{
    int err = 0;

    return err;
}

int root_do_update(struct xnet_msg *msg)
{
    int err = 0;

    return err;
}
