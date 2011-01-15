/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-12 16:38:48 macan>
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
#include "mdsl_api.h"
#include "mdsl.h"

static inline
void __mdsl_send_rpy(struct xnet_msg *msg, struct iovec iov[], int nr,
                     int err)
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
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE,
                     hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;
    
    if (err) {
        /* send err reply */
        xnet_msg_set_err(rpy, err);
    } else {
        /* send normal or data reply */
        for (i = 0; i < nr; i++) {
            xnet_msg_add_sdata(rpy, iov[i].iov_base, iov[i].iov_len);
        }
    }

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(mdsl, "xnet_send() failed w/ %d.\n", err);
    }
    xnet_free_msg(rpy);
}

void mdsl_read(struct xnet_msg *msg)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct storage_index *si;
    struct iovec *iov;
    int err = 0, i;
    
    /* ABI:
     * @xm_data: storage_index {
     *           .sic.uuid = puuid (directory uuid)
     *           .sic.arg0 = uuid (NEW API!)
     *           .scd.cnr = # of columns
     *           .scd.cr[x].cno = column number
     *           .scd.cr[x].stored_itbid = itbid (stored itbid)
     *           .scd.cr[x].req_offset = request offset in this file
     *           .scd.cr[x].req_len = request length
     *     }
     */

    /* sanity checking */
    if (msg->tx.len < sizeof(struct storage_index)) {
        hvfs_err(mdsl, "Invalid mdsl read request %d from %lx.\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    if (msg->xm_datacheck) {
        si = msg->xm_data;
    } else {
        hvfs_err(mdsl, "Internal error, data lossing...\n");
        err = -EFAULT;
        goto send_rpy;
    }

    hvfs_debug(mdsl, "Recv read request %lx veclen %d from %lx\n",
               si->sic.uuid, si->scd.cnr, msg->tx.ssite_id);

    /* We should iterate on the client's column_req vector and read each entry
     * to the result buffer */
    iov = xzalloc(sizeof(struct iovec) * si->scd.cnr);
    if (!iov) {
        hvfs_err(mdsl, "xzalloc() iovec failed.\n");
        err = -ENOMEM;
        goto send_rpy;
    }

    for (i = 0; i < si->scd.cnr; i++) {
        /* prepare to get the data file */
        fde = mdsl_storage_fd_lookup_create(si->sic.uuid, MDSL_STORAGE_DATA,
                                            si->scd.cr[i].cno);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create %lx data column %ld failed w/ %ld\n",
                     si->sic.uuid, si->scd.cr[i].cno, PTR_ERR(fde));
            err = PTR_ERR(fde);
            goto cleanup_send_rpy;
        }

        /* prepare the data region */
        iov[i].iov_base = xmalloc(si->scd.cr[i].req_len);
        if (!iov[i].iov_base) {
            hvfs_err(mdsl, "xmalloc data column %ld storage failed.\n",
                     si->scd.cr[i].cno);
            err = -ENOMEM;
            mdsl_storage_fd_put(fde);
            goto cleanup_send_rpy;
        }
        iov[i].iov_len = si->scd.cr[i].req_len;

        /* read the data now */
        msa.offset = si->scd.cr[i].file_offset + si->scd.cr[i].req_offset;
        msa.iov = &iov[i];
        msa.iov_nr = 1;
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "read the dir %lx data column %ld "
                     "offset %ld len %ld failed w/ %d\n",
                     si->sic.uuid, si->scd.cr[i].cno, 
                     si->scd.cr[i].req_offset,
                     si->scd.cr[i].req_len, err);
            mdsl_storage_fd_put(fde);
            goto cleanup_send_rpy;
        }
        /* put the fde */
        mdsl_storage_fd_put(fde);
    }

    /* we have got all the data in the iovec and now it is ok to send the data
     * back :) */
    __mdsl_send_rpy(msg, iov, si->scd.cnr, err);
    
    xnet_free_msg(msg);
    xfree(iov);

    return;
cleanup_send_rpy:
    /* free the iov now */
    for (i = 0; i < si->scd.cnr; i++) {
        if (iov[i].iov_base)
            xfree(iov[i].iov_base);
    }
    xfree(iov);
send_rpy:
    __mdsl_send_rpy(msg, NULL, 0, err);
    
    xnet_free_msg(msg);
    
    return;
}

void mdsl_write(struct xnet_msg *msg)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct storage_index *si;
    struct iovec iov;
    struct proxy_args *pa = NULL;
    void *data;
    u64 offset = 0;
    u64 *location;
    int err = 0, i;

    /* ABI:
     * @xm_data: storage_index {
     *           .sic.uuid = puuid (directory uuid)
     *           .sic.arg0 = uuid (NEW API!)
     *           .scd.cnr = # of columns
     *           .scd.cr[x].cno = column number
     *           .scd.cr[x].stored_itbid = itbid (stored itbid)
     *           .scd.cr[x].req_offset = request offset in this file (ignore)
     *           .scd.cr[x].req_len = request length
     *     }
     */

    /* sanity checking */
    if (unlikely(msg->tx.len < sizeof(struct storage_index))) {
        hvfs_err(mdsl, "Invalid mdsl read request %d from %lx.\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto send_rpy;
    }

    if (likely(msg->xm_datacheck)) {
        si = msg->xm_data;
        /* adjust the data pointer */
        data = msg->xm_data + sizeof(*si) + 
            si->scd.cnr * sizeof(struct column_req);
    } else {
        hvfs_err(mdsl, "Internal error, data lossing...\n");
        err = -EFAULT;
        goto send_rpy;
    }

    hvfs_debug(mdsl, "Recv write request %lx veclen %d from %lx\n",
               si->sic.uuid, si->scd.cnr, msg->tx.ssite_id);

    /* We should iterate on the client's column_req vector and write each
     * entry to the result buffer */
    location = xzalloc(sizeof(u64) * si->scd.cnr);
    if (!location) {
        hvfs_err(mdsl, "xzalloc() location failed.\n");
        err = -ENOMEM;
        goto send_rpy;
    }

    for (i = 0; i < si->scd.cnr; i++) {
        /* prepare to get the data file */
        if (unlikely(si->scd.flag & SCD_PROXY)) {
            pa = xmalloc(sizeof(*pa));
            if (!pa) {
                hvfs_err(mdsl, "alloc proxy args failed\n");
                err = -ENOMEM;
                goto cleanup_send_rpy;
            }
            pa->uuid = si->sic.arg0;
            pa->cno = si->scd.cr[i].cno;
            fde = mdsl_storage_fd_lookup_create(si->sic.uuid,
                                                MDSL_STORAGE_NORMAL,
                                                (u64)pa);
            msa.offset = si->scd.cr[i].file_offset;
        } else {
            fde = mdsl_storage_fd_lookup_create(si->sic.uuid, 
                                                MDSL_STORAGE_DATA,
                                                si->scd.cr[i].cno);
        }
        
        if (unlikely(IS_ERR(fde))) {
            hvfs_err(mdsl, "lookup create %lx data column %ld failed w/ %ld\n",
                     si->sic.uuid, si->scd.cr[i].cno, PTR_ERR(fde));
            err = PTR_ERR(fde);
            if (si->scd.flag & SCD_PROXY)
                xfree(pa);
            goto cleanup_send_rpy;
        }

        /* write the data now */
        iov.iov_base = data + offset;
        iov.iov_len = si->scd.cr[i].req_len;
        offset += iov.iov_len;

        msa.arg = location + i;
        msa.iov = &iov;
        msa.iov_nr = 1;
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "write the dir %ld data column %ld failed w/ %d\n",
                     si->sic.uuid, si->scd.cr[i].cno, err);
            mdsl_storage_fd_put(fde);
            goto cleanup_send_rpy;
        }

        /* put the fde */
        mdsl_storage_fd_put(fde);
    }

    /* we have written all the data region and now it is ok to send the
     * location back :) */
    iov.iov_base = location;
    iov.iov_len = sizeof(u64) * si->scd.cnr;
    __mdsl_send_rpy(msg, &iov, 1, err);

    xnet_free_msg(msg);
    
    return;
cleanup_send_rpy:
    /* free the location array */
    xfree(location);
send_rpy:
    __mdsl_send_rpy(msg, NULL, 0, err);

    xnet_free_msg(msg);
    
    return;
}
