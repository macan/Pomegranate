/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-02 13:13:17 macan>
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

int __mdsl_read_local(struct storage_index *si, 
                      struct iovec **oiov)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct iovec *iov;
    int err = 0, i;

    hvfs_debug(mdsl, "Recv read request %ld veclen %d from self\n",
               si->sic.uuid, si->scd.cnr);

    /* we should iterate on the client's column_req vector and read each entry
     * to the result buffer */
    iov = xzalloc(sizeof(struct iovec) * si->scd.cnr);
    if (!iov) {
        hvfs_err(mdsl, "xzalloc() iovec failed.\n");
        return -ENOMEM;
    }

    for (i = 0; i < si->scd.cnr; i++) {
        /* prepare to get the data file */
        fde = mdsl_storage_fd_lookup_create(si->sic.uuid, MDSL_STORAGE_DATA,
                                            si->scd.cr[i].cno);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create %ld data column %ld failed w/ %ld\n",
                     si->sic.uuid, si->scd.cr[i].cno, PTR_ERR(fde));
            err = PTR_ERR(fde);
            goto out_free;
        }

        /* prepare the data region */
        iov[i].iov_base = xmalloc(si->scd.cr[i].req_len);
        if (!iov[i].iov_base) {
            hvfs_err(mdsl, "xmalloc data column %ld storage failed.\n",
                     si->scd.cr[i].cno);
            mdsl_storage_fd_put(fde);
            err = -ENOMEM;
            goto out_free;
        }
        iov[i].iov_len = si->scd.cr[i].req_len;

        /* read the data now */
        msa.offset = si->scd.cr[i].file_offset + si->scd.cr[i].req_offset;
        msa.iov = &iov[i];
        msa.iov_nr = 1;
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "read the dir %ld data column %ld "
                     "offset %ld len %ld failed w/ %d\n",
                     si->sic.uuid, si->scd.cr[i].cno, 
                     si->scd.cr[i].req_offset,
                     si->scd.cr[i].req_len, err);
            mdsl_storage_fd_put(fde);
            goto out_free;
        }
        /* put the fde */
        mdsl_storage_fd_put(fde);
    }

    *oiov = iov;

    return 0;
out_free:
    for (i = 0; i < si->scd.cnr; i++) {
        if (iov[i].iov_base)
            xfree(iov[i].iov_base);
    }
    xfree(iov);
    return err;
}

int __mdsl_write_local(struct storage_index *si, void *data,
                       u64 **olocation)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct iovec iov;
    u64 offset = 0;
    u64 *location;
    int err = 0, i;

    hvfs_debug(mdsl, "Recv write request %ld veclen %d from self\n",
               si->sic.uuid, si->scd.cnr);

    /* We should iterate on the client's column_req vector and write each
     * entry to the result buffer */
    location = xzalloc(sizeof(u64) * si->scd.cnr);
    if (!location) {
        hvfs_err(mdsl, "xzalloc() location failed.\n");
        return -ENOMEM;
    }
    
    for (i = 0; i < si->scd.cnr; i++) {
        /* prepare to get the data file */
        fde = mdsl_storage_fd_lookup_create(si->sic.uuid, MDSL_STORAGE_DATA,
                                            si->scd.cr[i].cno);
        if (unlikely(IS_ERR(fde))) {
            hvfs_err(mdsl, "lookup create %ld data column %ld failed w/ %ld\n",
                     si->sic.uuid, si->scd.cr[i].cno, PTR_ERR(fde));
            err = PTR_ERR(fde);
            goto out_free;
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
            goto out_free;
        }

        /* put the fde */
        mdsl_storage_fd_put(fde);
        /* accumulate to hmi */
        atomic64_add(iov.iov_len, &hmi.mi_bused);
    }

    *olocation = location;
    
    return 0;
out_free:
    /* free the location array */
    xfree(location);
    
    return err;
}
