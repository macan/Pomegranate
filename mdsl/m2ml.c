/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-27 21:31:50 macan>
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
    struct txg_open_entry *toe;
    range_t *range;
    struct itb *itb;
    void *data = NULL;
    u64 location;
    int master;
    int data_len = 0;
    int err = 0;

    /* API:
     * tx.arg0: puuid
     * tx.arg1: itbid
     */
    hvfs_info(mdsl, "Recv ITB load requst <%ld,%ld> from site %lx\n",
              msg->tx.arg0, msg->tx.arg1, msg->tx.ssite_id);

    itb = xmalloc(sizeof(*itb));
    if (!itb) {
        hvfs_err(mdsl, "xmalloc struct itb failed\n");
        err = -ENOMEM;
        goto out;
    }

    /* first, we should check if there is a opening toe, if there is, we just
     * wait until it is committed to disk */
    toe = toe_lookup_recent(msg->tx.ssite_id);
    if (toe) {
        struct timespec ts;
        
        /* we should wait here */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 60;
        xcond_lock(&toe->wcond);
        if (!toe->state)
            xcond_timedwait(&toe->wcond, &ts);
        xcond_unlock(&toe->wcond);
        toe_put(toe);
    }
    
    /* then, we can safely access the storage file */
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
    if (data_len > 0) {
        data = xmalloc(data_len);
        if (!data) {
            hvfs_err(mdsl, "try to alloc memory for ITB data region (len %d) "
                     "failed\n", data_len);
            err = -EFAULT;
            goto out_put2;
        }
        /* ok, do pread now */
        msa.offset = location + sizeof(*itb);
        msa.iov->iov_base = data;
        msa.iov->iov_len = data_len;
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "fd read failed w/ %d\n", err);
            xfree(data);
            goto out_put2;
        }
    } else if (data_len < 0) {
        hvfs_err(mdsl, "data_len %d is minus, internal error!\n", data_len);
        err = -EFAULT;
        goto out_put2;
    }

out_put2:
    mdsl_storage_fd_put(fde);
out:
    if (err) {
        __mdsl_send_err_rpy(msg, err);
        xfree(itb);
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

static inline
int __bmmap_find_nr(union bmmap_disk *bd, int nr)
{
    u64 entry;
    int i;
    
    for (i = 0; i < bd->bd.used; i++) {
        entry = bd->bd.sarray[i];
        if ((entry >> BMMAP_DISK_NR_SHIFT) == nr) {
            return entry & BMMAP_DISK_INDEX_MASK;
        }
    }

    return -ENOTEXIST;
}

static inline
int __bmmap_find_check_nr(union bmmap_disk *bd, int nr)
{
    u64 entry, max = 0;
    int i, err = -ENOTEXIST;

    for (i = 0; i < bd->bd.used; i++) {
        entry = bd->bd.sarray[i];
        if ((entry >> BMMAP_DISK_NR_SHIFT) > max) {
            max = entry >> BMMAP_DISK_NR_SHIFT;
        }
        if ((entry >> BMMAP_DISK_NR_SHIFT) == nr) {
            err = entry & BMMAP_DISK_INDEX_MASK;
        }
    }

    if (err < 0 && max > nr) {
        err = -EISEMPTY;
    }

    hvfs_debug(mdsl, "find check nr %d w/ err %d max %ld used %d\n", 
               nr, err, max, bd->bd.used);
    return err;
}

static inline
int __bmmap_get_max(union bmmap_disk *bd)
{
    u64 entry, max = 0;
    int i;

    for (i = 0; i < bd->bd.used; i++) {
        entry = bd->bd.sarray[i];
        if ((entry >> BMMAP_DISK_NR_SHIFT) > max) {
            max = entry >> BMMAP_DISK_NR_SHIFT;
        }
    }

    return max;
}

static inline
int __bmmap_add_nr(struct fdhash_entry *fde, struct bc_commit_core *bcc,
                   union bmmap_disk *bd, 
                   int nr, u64 *location, u64 *size)
{
    struct mdsl_storage_access msa;
    void *data;
    struct iovec iov[2] = {
        {.iov_base = NULL, .iov_len = 0,},
        {.iov_base = NULL, .iov_len = 0,},
    };
    u64 rloc;
    int err = 0;

    data = xmalloc(bd->bd.size + fde->bmmap.len);
    if (!data) {
        hvfs_err(mdsl, "xmalloc() slice array failed\n");
        err = -ENOMEM;
        goto out;
    }

    /* Read
     *
     * (mdsl_storage_fd_read does not hold the fde lock) 
     */
    iov[0].iov_base = data;
    iov[0].iov_len = bd->bd.size;
    msa.offset = *location + sizeof(*bd);
    rloc = msa.offset;
    msa.iov = iov;
    msa.iov_nr = 1;
    err = mdsl_storage_fd_read(fde, &msa);
    if (err) {
        hvfs_err(mdsl, "read the dir %ld bitmap %ld location %lx "
                 "failed w/ %d\n",
                 bcc->uuid, bcc->itbid, *location, err);
        xfree(data);
        goto out;
    }

    /* Insert the slice in proper position
     */
    bd->bd.sarray[bd->bd.used] = 
        (((u64)nr) << BMMAP_DISK_NR_SHIFT) | bd->bd.used;
    bd->bd.used++;

    /* memset the new slice now
     */
    memset(data + bd->bd.size, 0, fde->bmmap.len);
    if (nr == 0) {
        /* preset the 0xff in the first bitmap slice */
        memset(data + bd->bd.size, 0xff, 1);
    }

    bd->bd.size += fde->bmmap.len;

    /* Write to file 
     */
    iov[1].iov_base = data;
    iov[1].iov_len = bd->bd.size;
    iov[0].iov_base = bd;
    iov[0].iov_len = sizeof(*bd);
    msa.arg = location;
    msa.iov = iov;
    msa.iov_nr = 2;
    err = mdsl_storage_fd_write(fde, &msa);
    if (err) {
        hvfs_err(mdsl, "write the dir %ld bitmap %ld failed w/ %d\n",
                 bcc->uuid, bcc->itbid, err);
        goto out;
    }

    /* adjust the location and size */
    /* this means we should calculate the new length */
    if (bcc->size != -1UL) {
        *size = (BITMAP_ROUNDUP(bcc->itbid) >> XTABLE_BITMAP_SHIFT >> 3) * 
            fde->bmmap.len;
    } else {
        *size = (__bmmap_get_max(bd) + 1) * fde->bmmap.len;
    }

    err = bd->bd.used - 1;
    hvfs_debug(mdsl, "read location %ld used slice %d(%d) size %ld bdsize %ld\n",
               rloc,
               bd->bd.used, nr, *size, bd->bd.size);
    xfree(data);
    
out:    
    return err;
}

/* this function is for loading the bitmap
 */
void mdsl_bitmap(struct xnet_msg *msg)
{
    u64 uuid, offset, location;
    struct fdhash_entry *fde;
    struct iovec iov;
    struct mdsl_storage_access msa;
    union bmmap_disk *bd;
    int err = 0, nr;

    /* ABI:
       tx.arg0: file location
       tx.arg1: bit offset
    */
    ASSERT(msg->tx.len == 0, mdsl);
    uuid = -1UL;
    location = msg->tx.arg0;
    offset = msg->tx.arg1;

    hvfs_debug(mdsl, "Load bitmap @ location %lx offset %ld\n", 
               location, offset);

    /* Step 1: we should open the default GDT dir/data-default file */
    fde = mdsl_storage_fd_lookup_create(hmi.gdt_uuid, MDSL_STORAGE_BITMAP, 
                                        HVFS_GDT_BITMAP_COLUMN);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create %ld bitmap failed w/ %ld\n",
                 uuid, PTR_ERR(fde));
        goto out;
    }
    /* Step 2: we should read from the offset */
    iov.iov_base = xmalloc(XTABLE_BITMAP_BYTES);
    if (!iov.iov_base) {
        hvfs_err(mdsl, "xmalloc bitmap region failed.\n");
        goto out_put;
    }
    iov.iov_len = XTABLE_BITMAP_BYTES;
    nr = BITMAP_ROUNDDOWN(offset) >> XTABLE_BITMAP_SHIFT >> 3;

    xlock_lock(&fde->bmmap.lock);
    bd = mmap(NULL, sizeof(*bd), PROT_READ | PROT_WRITE,
              MAP_SHARED, fde->fd,
              location);
    if ((void *)bd == MAP_FAILED) {
        xlock_unlock(&fde->bmmap.lock);
        hvfs_err(mdsl, "mmap bitmap header @ %lx failed w/ %d\n",
                 offset, errno);
        goto out_put;
    }
    err = __bmmap_find_check_nr(bd, nr);
    if (err == -ENOTEXIST) {
        xlock_unlock(&fde->bmmap.lock);
        hvfs_err(mdsl, "bitmap slice %d does not exist.\n", nr);
        goto out_put;
    } else if (err == -EISEMPTY) {
        xlock_unlock(&fde->bmmap.lock);
        memset(iov.iov_base, 0, iov.iov_len);
        goto out_reply;
    } else if (err < 0) {
        xlock_unlock(&fde->bmmap.lock);
        hvfs_err(mdsl, "bitmap slice %d find in the header failed w/ %d\n",
                 nr, err);
        goto out_put;
    }
    xlock_unlock(&fde->bmmap.lock);

    msa.iov = &iov;
    msa.iov_nr = 1;
    msa.offset = location + sizeof(*bd) + err * fde->bmmap.len;
    err = mdsl_storage_fd_read(fde, &msa);
    if (err) {
        hvfs_err(mdsl, "read from bitmap file %ld @ %lx failed w/ %d\n",
                 uuid, offset, err);
        goto out_put;
    }
    /* Step 3: prepare the reply and send it */
out_reply:
    __mdsl_send_rpy_data(msg, &iov, 1);
    
out_put:    
    mdsl_storage_fd_put(fde);
out:
    return;
}

static inline
int __customized_send_reply(struct xnet_msg *msg, int err, u64 location, 
                            u64 size)
{
    struct xnet_msg *rpy;

    /* Step 1: prepare the xnet_msg */
    rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!rpy) {
        hvfs_err(mdsl, "xnet_alloc_msg() failed.\n");
        return -ENOMEM;
    }

    /* Step 2: construct the xnet_msg to send it to the destination */
    xnet_msg_set_err(rpy, err);
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0,
                     hmo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, location, size);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(mdsl, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);

    return 0;
}

void mdsl_bitmap_commit(struct xnet_msg *msg)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct bc_commit_core *bcc;
    size_t len;
    u64 location = -1UL;
    u64 size = 0;
    int err = 0;

    len = msg->tx.len;
    if (msg->xm_datacheck)
        bcc = msg->xm_data;
    else
        goto out;

    hvfs_debug(mdsl, "Recv bitmap commit request on %lx %ld %ld %ld\n", 
               bcc->uuid, bcc->itbid, bcc->location, bcc->size);

    /* the uuid/itbid/location is in the bcc */
    /* Step 1: open the GDT dir/data-default file */
    fde = mdsl_storage_fd_lookup_create(hmi.gdt_uuid, MDSL_STORAGE_BITMAP,
                                        HVFS_GDT_BITMAP_COLUMN);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create %ld bitmap failed w/ %ld\n",
                 bcc->uuid, PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out_reply;
    }

    if (bcc->size == -1UL) {
        msa.arg = (void *)bcc->itbid;
        msa.offset = bcc->location;
        msa.iov = NULL;
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "write the dir %ld bitmap %ld @ location %lx "
                     "failed w/ %d\n",
                     bcc->uuid, bcc->itbid, bcc->location, err);
        }
    } else {
        /* First, we should read the whole region of the existed bitmap */
        void *data;
        struct iovec iov[2] = {
            {.iov_base = NULL, .iov_len = 0,},
            {.iov_base = NULL, .iov_len = 0,},
        };
        int nr;

        /* ooo, bug-0000023: the new bitmap slice may be at more longer
         * position, say n times of bmmap.len */
        /* 1. calculate the # of bitmap slices */
        nr = (BITMAP_ROUNDUP(bcc->itbid) >> XTABLE_BITMAP_SHIFT >> 3) -
            (bcc->size >> XTABLE_BITMAP_SHIFT >> 3);
        /* 2. malloc memory */
        data = xmalloc(bcc->size + fde->bmmap.len);
        if (!data) {
            hvfs_err(mdsl, "alloc bitmap slice failed.\n");
            err = -ENOMEM;
            goto out_reply;
        }
        memset(data + bcc->size, 0, fde->bmmap.len);

        if (bcc->size) {
            iov[0].iov_base = data;
            iov[0].iov_len = bcc->size;
            msa.offset = bcc->location;
            msa.iov = iov;
            msa.iov_nr = 1;
            err = mdsl_storage_fd_read(fde, &msa);
            if (err) {
                hvfs_err(mdsl, "read the dir %ld bitmap %ld location %lx "
                         "failed w/ %d\n",
                         bcc->uuid, bcc->itbid, bcc->location, err);
                xfree(data);
                goto out_reply;
            }
        } else {
            /* this means that the bitmap is just INITed */
            if (nr > 1) {
                /* we should setup the first bitmap map slice */
                void *__data;
                
                __data = xrealloc(data, fde->bmmap.len * 2);
                if (!__data) {
                    hvfs_err(mdsl, "realloc bitmap slice failed.\n");
                    err = -ENOMEM;
                    goto out_reply;
                }
                data = __data;

                iov[0].iov_base = data;
                iov[0].iov_len = fde->bmmap.len;
                nr -= 1;
                bcc->size = fde->bmmap.len;
            } else {
                /* ok, nr must be 1 */
                ASSERT(nr == 1, mdsl);
                iov[0].iov_len = 0;
            }
            /* if bcc->size is ZERO, it means that we are writing the first
             * bitmap slice, we should set the default bits */
            memset(data, 0xff, (1 << hmi.itb_depth) >> 3);
        }

        /* FIXME: maybe ftruncate can be used here to minimize the write
         * cost */
        /* Next, we will write the region to disk plus a new slice */
        iov[1].iov_base = data + bcc->size;
        iov[1].iov_len = fde->bmmap.len;
        size = bcc->size + (nr * fde->bmmap.len);
        msa.arg = &location;
        msa.iov = iov;
        msa.iov_nr = 2;
        msa.offset = nr - 1;    /* lseek nr - 1 slices */
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "write the dir %ld bitmap %ld location %lx "
                     "failed w/ %d\n",
                     bcc->uuid, bcc->itbid, bcc->location, err);
            xfree(data);
            goto out_reply;
        }
        xfree(data);
        
        /* Finally, we flip the bit we want to change */
        msa.offset = location;
        msa.arg = (void *)bcc->itbid;
        msa.iov = NULL;
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "write the dir %ld bitmap %ld location %lx "
                     "failed w/ %d\n",
                     bcc->uuid, bcc->itbid, location, err);
            goto out_reply;
        }
    }

    /* We need to send the reply here! reply w/ the errno and new location! */
out_reply:
    mdsl_storage_fd_put(fde);
    __customized_send_reply(msg, err, location, size);
    
out:
    return;
}

/* This is the second version of bitmap commit. The ABI is the same as the
 * first version. We add a header at each bitmap region. There is a sorted
 * (nr) array saving the existed slices. The max slices we support is
 * HVFS_MDSL_MAX_SLICES.
 */
void mdsl_bitmap_commit_v2(struct xnet_msg *msg)
{
    struct fdhash_entry *fde;
    struct mdsl_storage_access msa;
    struct bc_commit_core *bcc;
    union bmmap_disk *bd;
    size_t len;
    u64 location = -1UL, update_location = -1UL;
    u64 size = 0;
    int err = 0, nr;

    len = msg->tx.len;
    if (msg->xm_datacheck)
        bcc = msg->xm_data;
    else
        goto out;

    hvfs_debug(mdsl, "Recv bitmap commit request on %lx %ld %ld %ld\n", 
               bcc->uuid, bcc->itbid, bcc->location, bcc->size);

    location = bcc->location;
    size = bcc->size;

    /* the uuid/itbid/location is in the bcc */
    /* Step 1: open the GDT dir/data-default file */
    fde = mdsl_storage_fd_lookup_create(hmi.gdt_uuid, MDSL_STORAGE_BITMAP,
                                        HVFS_GDT_BITMAP_COLUMN);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create %ld bitmap failed w/ %ld\n",
                 bcc->uuid, PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out_reply;
    }

    /* Step 2: we should confirm that the slice # is in the header, otherwise
     * we have to create a new slice and update it */
    nr = (BITMAP_ROUNDDOWN(bcc->itbid) >> XTABLE_BITMAP_SHIFT >> 3);
    xlock_lock(&fde->bmmap.lock);
    if (bcc->size) {
        bd = mmap(NULL, sizeof(*bd), PROT_READ | PROT_WRITE,
                  MAP_SHARED, fde->fd,
                  bcc->location);
        if (bd == MAP_FAILED) {
            xlock_unlock(&fde->bmmap.lock);
            hvfs_err(mdsl, "mmap bitmap header @ %lx failed w/ %d\n",
                     bcc->location, errno);
            err = -errno;
            goto out_reply;
        }
    } else {
        bd = xzalloc(sizeof(*bd));
        if (!bd) {
            xlock_unlock(&fde->bmmap.lock);
            hvfs_err(mdsl, "xzalloc() failed\n");
            err = -ENOMEM;
            goto out_reply;
        }
    }

    /* bmmap_find_nr() return the in region index */
    err = __bmmap_find_nr(bd, nr);
    if (err == -ENOTEXIST) {
        /* ok, we should create a new bitmap slice now, Read/Copy/Write is
         * needed. */
        err = __bmmap_add_nr(fde, bcc, bd, nr, &location, &size);
        if (err < 0) {
            hvfs_err(mdsl, "bmmap add nr %d failed w/ %d\n", nr, err);
            goto out_unmap;
        }
        update_location = location + sizeof(*bd) + err * fde->bmmap.len;
    } else if (err < 0) {
        hvfs_err(mdsl, "bmmap find nr %d failed w/ %d\n", nr, err);
        goto out_unmap;
    } else {
        /* it is ok to find the location */
        update_location = bcc->location + sizeof(*bd) + err * fde->bmmap.len;
    }

    /* ok, we fall back to update now, the slice location is @ location! */
    msa.offset = update_location;
    msa.arg = (void *)bcc->itbid;
    msa.iov = NULL;
    err = mdsl_storage_fd_write(fde, &msa);
    if (err) {
        hvfs_err(mdsl, "write the dir %ld bitmap %ld location %lx "
                 "failed w/ %d\n",
                 bcc->uuid, bcc->itbid, location, err);
        goto out_unmap;
    }
    hvfs_debug(mdsl, "Commit v2 to location %ld size %ld update %ld\n", 
               location, size, update_location);
    
out_unmap:
    if (bcc->size) {
        err = munmap(bd, sizeof(*bd));
        if (err) {
            xlock_unlock(&fde->bmmap.lock);
            hvfs_err(mdsl, "munmap failed w/ %d\n", errno);
            err = -errno;
            goto out;
        }
    } else {
        xfree(bd);
    }
    xlock_unlock(&fde->bmmap.lock);

    /* We need to send the reply here! reply w/ the errno and new location! */
out_reply:
    mdsl_storage_fd_put(fde);
    __customized_send_reply(msg, err, location, size);
    
out:
    return;
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
                    tb->rdd_nr *
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

                toe_to_tmpfile_N(TXG_OPEN_ENTRY_DISK_DIR_R,
                                 tb->site_id, tb->txg, data, tb->rdd_nr);
                data += tb->rdd_nr * sizeof(struct hvfs_dir_delta);
                len -= tb->rdd_nr * sizeof(struct hvfs_dir_delta);
                
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
            /* the offset of this region is 0 */
            /* FIXME: should we do sth on this region? */
            size_t region_len = 0;

            if (tb && toe && toe->other_region) {
                region_len = tb->dir_delta_nr * sizeof(struct hvfs_dir_delta);
                p = toe->other_region;

                struct hvfs_dir_delta *hdd = (struct hvfs_dir_delta *)p;
                int i;
                for (i = 0; i < tb->dir_delta_nr; i++) {
                    hvfs_err(mdsl, "Dir Delta from site %lx uuid %ld flag %x "
                             "nlink %d\n",
                             hdd->site_id, hdd->duuid, hdd->flag, 
                             atomic_read(&hdd->nlink));
                }
            }
        }
        if (msg->tx.arg0 & HVFS_WBTXG_R_DIR_DELTA) {
            /* FIXME: should we do sth on this region? */
            size_t region_len = 0;
            loff_t offset = tb->dir_delta_nr * sizeof(struct hvfs_dir_delta);

            if (tb && toe && toe->other_region) {
                region_len = tb->rdd_nr * sizeof(struct hvfs_dir_delta);
                p = toe->other_region + offset;
#if 0
                struct hvfs_dir_delta *hdd = (struct hvfs_dir_delta *)p;
                int i;
                for (i = 0; i < tb->rdd_nr; i++) {
                    hvfs_err(mdsl, "HDD site %lx uuid %ld flag %x nlink %d\n",
                             hdd->site_id, hdd->duuid, hdd->flag, hdd->nlink);
                }
#endif
            }
        }
        if (msg->tx.arg0 & HVFS_WBTXG_BITMAP_DELTA) {
            size_t region_len = 0;
            loff_t offset = tb->dir_delta_nr * sizeof(struct hvfs_dir_delta) +
                tb->rdd_nr * sizeof(struct hvfs_dir_delta);
            
            if (tb && toe && toe->other_region) {
                region_len = sizeof(struct bitmap_delta) * tb->bitmap_delta_nr;
                p = toe->other_region + offset;
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
                toe_wait(toe, te->itb_nr);
                hvfs_err(mdsl, "itb <%lx,%lx> nr may mismatch: "
                         "recv %d vs say %d\n", toe->begin.site_id,
                         toe->begin.txg,
                         atomic_read(&toe->itb_nr), te->itb_nr);
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
            xcond_lock(&toe->wcond);
            toe->state = 1;
            xcond_unlock(&toe->wcond);
            xcond_broadcast(&toe->wcond);
            toe_put(toe);
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

