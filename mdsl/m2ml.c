/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-13 16:18:15 macan>
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
            struct txg_open_entry *toe;
            
            tb = data;
            hvfs_debug(mdsl, "Recv TXG_BEGIN %ld from site %lx\n",
                       tb->txg, tb->site_id);

            toe = get_txg_open_entry(&hmo.tcc);
            if (IS_ERR(toe)) {
                if (PTR_ERR(toe) == -ENOMEM) {
                    ASSERT(tb->site_id == msg->tx.ssite_id, mdsl);
                    ASSERT(tb->txg == msg->tx.arg1, mdsl);
                    toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_BEGIN, 
                                   tb->site_id, tb->txg, tb);
                    goto end_begin;
                }
                hvfs_err(mdsl, "get txg_open_entry failed\n");
                goto out;
            }

            toe->begin = *tb;
            xlock_lock(&hmo.tcc.active_lock);
            list_add(&toe->list, &hmo.tcc.active_list);
            xlock_unlock(&hmo.tcc.active_lock);

            /* alloc space for region info */
            toe->other_region = xmalloc(tb->dir_delta_nr * 
                                        sizeof(struct hvfs_dir_delta) +
                                        tb->bitmap_delta_nr * 
                                        sizeof(struct bitmap_delta) +
                                        tb->ckpt_nr * 
                                        sizeof(struct checkpoint));
            if (!toe->other_region) {
                hvfs_warning(mdsl, "xmalloc() TOE %p other_region failed, "
                             "we will retry later!\n", toe);
            }

        end_begin:
            /* adjust the data pointer */
            data += sizeof(struct txg_begin);
            len -= sizeof(struct txg_begin);
        }
    }
    if (msg->tx.arg0 & HVFS_WBTXG_ITB) {
        struct itb *i;
        struct txg_open_entry *toe;
        
        /* sanity checking */
        if (len < sizeof(struct itb)) {
            hvfs_err(mdsl, "Invalid WBTXG request %ld received from %lx\n",
                     msg->tx.reqno, msg->tx.ssite_id);
            goto out;
        }
        if (data) {
            struct itb_info *ii;
            
            i = data;
            hvfs_debug(mdsl, "Recv ITB %ld from site %lx\n",
                       i->h.itbid, msg->tx.ssite_id);

            /* find the toe now */
            toe = toe_lookup(msg->tx.ssite_id, msg->tx.arg1);
            if (!toe) {
                hvfs_err(mdsl, "toe lookup <%lx,%ld> failed\n",
                         msg->tx.ssite_id, msg->tx.arg1);
                goto end_itb;
            }

            ii = xzalloc(sizeof(struct itb_info));
            if (!ii) {
                hvfs_warning(mdsl, "xzalloc() itb_info failed\n");
            } else
                INIT_LIST_HEAD(&ii->list);

            /* append the ITB to disk file, get the location and filling the
             * itb_info */
            if (itb_append(i, ii, msg->tx.ssite_id, msg->tx.arg1)) {
                hvfs_err(mdsl, "Append itb <%lx.%ld.%ld> to disk file failed\n",
                         msg->tx.ssite_id, msg->tx.arg1, i->h.itbid);
                xfree(ii);
                goto end_itb;
            }
            
            /* save the itb_info to open entry */
            if (ii) {
                list_add_tail(&ii->list, &toe->itb);
                atomic_inc(&toe->itb_nr);
            }
        end_itb:
            /* adjust the data pointer */
            data += atomic_read(&i->h.len);
            len -= atomic_read(&i->h.len);
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

