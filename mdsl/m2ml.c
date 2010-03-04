/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-03 21:40:32 macan>
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

static inline
void __mdsl_send_err_rpy(struct xnet_msg *msg, int err)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(mdsl, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_set_err(rpy, err);
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mdsl, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);
}

void mdsl_itb(struct xnet_msg *msg)
{
    hvfs_info(mdsl, "Recv ITB load requst <%ld,%ld> from site %lx\n",
              msg->tx.arg0, msg->tx.arg1, msg->tx.ssite_id);
    __mdsl_send_err_rpy(msg, -ENOSYS);
    xnet_set_auto_free(msg);
    xnet_free_msg(msg);
}

void mdsl_bitmap(struct xnet_msg *msg)
{
}

void mdsl_wbtxg(struct xnet_msg *msg)
{
    void *data = NULL;
    size_t len;

    len = msg->tx.len;
    if (msg->xm_datacheck)
        data = msg->xm_data;
    else
        goto out;
    
    if (msg->tx.arg0 & HVFS_WBTXG_BEGIN) {
        struct txg_begin *tb;
        
        /* sanity checking */
        if (len < sizeof(struct txg_begin)) {
            hvfs_err(mdsl, "Invalid WBTXG region[TXG_BEGIN] received "
                     "from %lx\n",
                     msg->tx.ssite_id);
            goto out;
        }
        /* alloc one txg_open_entry, and filling it */
        if (data) {
            tb = data;
            hvfs_debug(mdsl, "Recv TXG_BEGIN %ld from site %lx\n",
                       tb->txg, tb->site_id);

            /* adjust the data pointer */
            data += sizeof(struct txg_begin);
            len -= sizeof(struct txg_begin);
        }
    }
    if (msg->tx.arg0 & HVFS_WBTXG_ITB) {
        struct itb *i;
        
        /* sanity checking */
        if (len < sizeof(struct itb)) {
            hvfs_err(mdsl, "Invalid WBTXG request %ld received from %lx\n",
                     msg->tx.reqno, msg->tx.ssite_id);
            goto out;
        }
        if (data) {
            i = data;
            /* append the ITB to disk file, and get the location */
            hvfs_debug(mdsl, "Recv ITB %ld from site %lx\n",
                       i->h.itbid, msg->tx.ssite_id);
            /* filling the itb_info */
        }
    }
    if (msg->tx.arg0 & HVFS_WBTXG_END) {
    }
    if (msg->tx.arg0 & HVFS_WBTXG_BITMAP_DELTA) {
    }
    if (msg->tx.arg0 & HVFS_WBTXG_DIR_DELTA) {
    }
    if (msg->tx.arg0 & HVFS_WBTXG_CKPT) {
    }

out:
    xnet_set_auto_free(msg);
    xnet_free_msg(msg);
    return;
}

void mdsl_wdata(struct xnet_msg *msg)
{
}

