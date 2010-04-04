/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-04 15:57:31 macan>
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

static inline
void __mdsl_send_rpy(struct xnet_msg *msg)
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
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mdsl, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);
}

static inline
void __mdsl_send_rpy_data(struct xnet_msg *msg, struct iovec iov[], int nr)
{
    struct xnet_msg *rpy;
    int i;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(mdsl, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(struct xnet_msg_tx));
#endif
    for (i = 0; i < nr; i++) {
        xnet_msg_add_sdata(rpy, iov[i].iov_base, iov[i].iov_len);
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, 
                     hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA_ITB, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mdsl, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);
}

void mdsl_itb(struct xnet_msg *msg)
{
    struct iovec itb_iov[2] = {{0,}, };
    struct mdsl_storage_access msa = {
        .iov = &itb_iov[0],
        .iov_nr = 1,
    };
    struct mmap_args ma;
    struct fdhash_entry *fde;
    range_t *range;
    struct itb *itb;
    void *data = NULL;
    u64 location;
    int master;
    int data_len = 0;
    int err = 0;
    
    hvfs_info(mdsl, "Recv ITB load requst <%ld,%ld> from site %lx\n",
              msg->tx.arg0, msg->tx.arg1, msg->tx.ssite_id);

    itb = xmalloc(sizeof(*itb));
    if (!itb) {
        hvfs_err(mdsl, "xmalloc struct itb failed\n");
        err = -ENOMEM;
        goto out;
    }

    fde = mdsl_storage_fd_lookup_create(msg->tx.arg0, MDSL_STORAGE_MD, 0);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n", PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }
    if (!fde->mdisk.ranges && !fde->mdisk.new_range) {
        err = -ENOENT;
        goto out_put2;
    }
    ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;

    err = __mdisk_lookup(fde, MDSL_MDISK_RANGE, msg->tx.arg1, &range);
    if (err == -ENOENT) {
        goto out_put2;
    }
    ma.foffset = 0;
    ma.range_id = range->range_id;
    ma.range_begin = range->begin;

    err = __range_lookup(msg->tx.arg0, msg->tx.arg1, &ma, &location);
    if (err) {
        goto out_put2;
    }
    if (!location) {
        err = -ENOENT;
        goto out_put2;
    }
    
    master = fde->mdisk.itb_master;
    mdsl_storage_fd_put(fde);

    /* ok, get the itb location now, try to read the itb in file itb-* */
    fde = mdsl_storage_fd_lookup_create(msg->tx.arg0, MDSL_STORAGE_ITB, 
                                        master);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create ITB file failed w/ %ld\n", PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }

    msa.offset = location;
    itb_iov[0].iov_base = itb;
    itb_iov[0].iov_len = sizeof(*itb);
    err = mdsl_storage_fd_read(fde, &msa);
    if (err) {
        hvfs_err(mdsl, "fd read failed w/ %d\n", err);
        goto out_put2;
    }

    hvfs_err(mdsl, "Read ITB %ld len %d\n", itb->h.itbid, atomic_read(&itb->h.len));
    data_len = atomic_read(&itb->h.len) - sizeof(*itb);
    if (data_len) {
        data = xmalloc(data_len);
        if (!data) {
            hvfs_err(mdsl, "try to alloc memory for ITB data region failed\n");
            goto out_put2;
        }
        /* ok, do pread now */
        msa.offset = location + sizeof(*itb);
        msa.iov->iov_base = data;
        msa.iov->iov_len = data_len;
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "fd read failed w/ %d\n", err);
            goto out_put2;
        }
    }

out_put2:
    mdsl_storage_fd_put(fde);
out:
    if (err) {
        __mdsl_send_err_rpy(msg, err);
    } else {
        itb_iov[0].iov_base = itb;
        itb_iov[0].iov_len = sizeof(*itb);
        err = 1;
        if (data_len) {
            itb_iov[1].iov_base = data;
            itb_iov[1].iov_len = data_len;
            err++;
        }
        __mdsl_send_rpy_data(msg, itb_iov, err);
    }

    xnet_set_auto_free(msg);
    xnet_free_msg(msg);
    return;
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
        struct txg_begin *tb = NULL;
        struct txg_open_entry *toe = NULL;
        void *p = NULL;
        
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
            hvfs_debug(mdsl, "Recv TXG_BEGIN %ld[%d,%d,%d] from site %lx\n",
                       tb->txg, tb->dir_delta_nr,
                       tb->bitmap_delta_nr, tb->ckpt_nr,
                       tb->site_id);

            toe = get_txg_open_entry(&hmo.tcc);
            if (IS_ERR(toe)) {
                if (PTR_ERR(toe) == -ENOMEM) {
                    ASSERT(tb->site_id == msg->tx.ssite_id, mdsl);
                    ASSERT(tb->txg == msg->tx.arg1, mdsl);
                    toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_BEGIN, 
                                   tb->site_id, tb->txg, tb);
                    toe = NULL;
                    goto end_begin;
                }
                hvfs_err(mdsl, "get txg_open_entry failed\n");
                goto out;
            }

            toe->begin = *tb;
            toe_active(toe);

        end_begin:
            __mdsl_send_rpy(msg);
            /* adjust the data pointer */
            data += sizeof(struct txg_begin);
            len -= sizeof(struct txg_begin);

            if (toe) {
                /* alloc space for region info */
                toe->osize = tb->dir_delta_nr * 
                    sizeof(struct hvfs_dir_delta) +
                    tb->bitmap_delta_nr * 
                    sizeof(struct bitmap_delta) +
                    tb->ckpt_nr * 
                    sizeof(struct checkpoint);
                if (toe->osize) {
                    toe->other_region = xmalloc(toe->osize);
                    if (!toe->other_region) {
                        hvfs_warning(mdsl, "xmalloc() TOE %p other_region failed, "
                                     "we will retry later!\n", toe);
                    }
                    p = toe->other_region;
                    memcpy(p, data, toe->osize);
                    data += toe->osize;
                    len -= toe->osize;
                }
            } else {
                toe_to_tmpfile_N(TXG_OPEN_ENTRY_DISK_DIR, 
                                 tb->site_id, tb->txg, data, tb->dir_delta_nr);
                data += tb->dir_delta_nr * sizeof(struct hvfs_dir_delta);
                len -= tb->dir_delta_nr * sizeof(struct hvfs_dir_delta);
                toe_to_tmpfile_N(TXG_OPEN_ENTRY_DISK_BITMAP,
                                 tb->site_id, tb->txg, data, tb->bitmap_delta_nr);
                data += tb->bitmap_delta_nr * sizeof(struct bitmap_delta);
                len -= tb->bitmap_delta_nr * sizeof(struct bitmap_delta);
                toe_to_tmpfile_N(TXG_OPEN_ENTRY_DISK_CKPT,
                                 tb->site_id, tb->txg, data, tb->ckpt_nr);
                data += tb->ckpt_nr * sizeof(struct checkpoint);
                len -= tb->ckpt_nr * sizeof(struct checkpoint);
            }
        }

        if (msg->tx.arg0 & HVFS_WBTXG_DIR_DELTA) {
        }
        if (msg->tx.arg0 & HVFS_WBTXG_BITMAP_DELTA) {
            size_t region_len = 0;
            loff_t offset = tb->dir_delta_nr * sizeof(struct hvfs_dir_delta);
            
            if (tb && toe && toe->other_region) {
                region_len = sizeof(struct bitmap_delta) * tb->bitmap_delta_nr;
                p = toe->other_region += offset;
#if 0
                struct bitmap_delta *bd = (struct bitmap_delta *)p;
                int i;
                for (i = 0; i < tb->bitmap_delta_nr; i++) {
                    hvfs_err(mdsl, "sid %lx uuid %ld oitb %ld nitb %ld\n",
                             (bd + i)->site_id, (bd + i)->uuid,
                             (bd + i)->oitb, (bd + i)->nitb);
                }
#endif
            }
        }
        if (msg->tx.arg0 & HVFS_WBTXG_CKPT) {
        }
    }
    if (msg->tx.arg0 & HVFS_WBTXG_ITB) {
        struct itb *i;
        struct txg_open_entry *toe;
        
        /* sanity checking */
        if (len < sizeof(struct itb)) {
            hvfs_err(mdsl, "Invalid WBTXG request %d received from %lx\n",
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
                hvfs_err(mdsl, "ITB %ld[%ld] toe lookup <%lx,%ld> failed\n",
                         i->h.itbid, i->h.puuid, msg->tx.ssite_id, 
                         msg->tx.arg1);
                toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_ITB,
                               msg->tx.ssite_id, msg->tx.arg1,
                               i);
                goto end_itb;
            }

            ii = xzalloc(sizeof(struct itb_info));
            if (!ii) {
                hvfs_warning(mdsl, "xzalloc() itb_info failed\n");
            } else
                INIT_LIST_HEAD(&ii->list);

            /* append the ITB to disk file, get the location and filling the
             * itb_info */
            ii->duuid = i->h.puuid;
            ii->itbid = i->h.itbid;
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
        struct txg_end *te;
        struct txg_open_entry *toe;
        int err = 0, abort = 0;

        if (len < sizeof(struct txg_end)) {
            hvfs_err(mdsl, "Invalid WBTXG END request %d received from %lx\n",
                     msg->tx.reqno, msg->tx.ssite_id);
            goto out;
        }
        if (data) {
            te = data;
            abort = te->err;
            hvfs_debug(mdsl, "Recv txg_end %ld from site %lx, abort %d\n",
                       te->txg, te->site_id, abort);

            /* find the toe now */
            toe = toe_lookup(te->site_id, te->txg);
            if (!toe) {
                hvfs_err(mdsl, "txg_end [%ld,%ld] toe lookup failed\n",
                         te->site_id, te->txg);
                toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_END,
                               te->site_id, te->txg, te);
                goto out;
            }

            /* ok, check the itb_nr now */
            if (unlikely(atomic_read(&toe->itb_nr) < te->itb_nr)) {
                /* Step 1: we should find the missing ITB in the tmp file */
                /* Step 2: if we can find the missing ITBs in the tmp file, we
                 * should just waiting for the  */
                hvfs_err(mdsl, "itb nr mismatch: recv %d vs say %d\n",
                         atomic_read(&toe->itb_nr), te->itb_nr);
                toe_wait(toe, te->itb_nr);
            }

            /* it is ok to commit the TOE--TE to disk now */
            toe->begin.itb_nr = atomic_read(&toe->itb_nr);
            err = mdsl_storage_toe_commit(toe, te);
            if (err) {
                hvfs_err(mdsl, "Commit the toe[%lx,%ld] to disk failed"
                         "w/ %d.\n",
                         toe->begin.site_id, toe->begin.txg, err);
                goto out;
            }
            toe_deactive(toe);
            /* ok, we commit the itb modifications to disk after we logged
             * the infos to TXG file. */
            if (!abort) {
                err = mdsl_storage_update_range(toe);
                if (err) {
                    hvfs_err(mdsl, "Update %ld,%ld range failed w /%d, maybe "
                             "data loss.\n",
                             toe->begin.site_id, toe->begin.txg, err);
                }
            } else {
                hvfs_err(mdsl, "TXG %ld wb aborted by %d from site %lx\n",
                         te->txg, abort, te->site_id);
            }
            put_txg_open_entry(toe);
        }
    }

out:
    xnet_set_auto_free(msg);
    xnet_free_msg(msg);
    return;
}

void mdsl_wdata(struct xnet_msg *msg)
{
}

