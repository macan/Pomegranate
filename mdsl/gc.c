/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-06-07 00:03:13 macan>
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

/* GC in MDSL is mainly split into two parts: for metadata and for data */

int itb_gc_append(int gen, struct itb *itb, struct itb_info *ii)
{
    int err = 0;

    if (unlikely(hmo.conf.option & HVFS_MDSL_WDROP))
        return 0;

    if (ii) {
        struct fdhash_entry *fde;
        struct iovec itb_iov = {
            .iov_base = itb,
            .iov_len = atomic_read(&itb->h.len),
        };
        struct mdsl_storage_access msa = {
            .iov = &itb_iov,
            .arg = ii,
            .iov_nr = 1,
        };

        /* prepare write to the file: "[target dir]/itb-*" */
        fde = mdsl_storage_fd_lookup_create(itb->h.puuid, MDSL_STORAGE_ITB,
                                            gen);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create failed w/ %ld\n", PTR_ERR(fde));
            goto out;
        }
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "storage_fd_write failed w/ %d\n", err);
            mdsl_storage_fd_put(fde);
            goto out;
        }
        if (unlikely(ii->location == 0)) {
            hvfs_err(mdsl, "Write ITB %ld[%lx] len %d to storage file off "
                   "%ld fde ST %x.\n",
                   itb->h.itbid, itb->h.puuid, 
                   atomic_read(&itb->h.len), ii->location, 
                   fde->state);
            HVFS_BUGON("zero location!");
        }
        mdsl_storage_fd_put(fde);
        /* accumulate to hmi */
        atomic64_add(itb_iov.iov_len, &hmi.mi_bused);
    }

out:
    return err;
}

/* __is_hole() detect holes in ITB file
 *
 * Rational:
 * 1. if itb->h is ALL zero, it is a hole
 * 2. if itb->h is PART zero, and across a page border, it is a hole
 */
int __is_hole(u64 offset, struct itb *itb) 
{
    if (!atomic_read(&itb->h.len) ||
        itb->h.depth == 0 ||
        itb->h.adepth == 0)
        return 1;
    else {
        /* check if the itbheader is INTEGRATED */
        u64 size = offset & (getpagesize() - 1);

        if (size >= sizeof(itb->h))
            return 0;
        
        if (offsetof(struct itbh, len) < size) {
            return 0;
        } else if (offsetof(struct itbh, depth) < size) {
            return 0;
        } else {
            /* blind detect! */
            if (itb->h.flag > ITB_SNAPSHOT)
                return 1;
            if (itb->h.adepth != ITB_DEPTH)
                return 1;
            if (atomic_read(&itb->h.len) > 
                sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE)
                return 1;
        }
    }
    
    return 0;
}

/* do GC-TX on itb file change
 *
 * write the tx_begin in hmo.storage.gc_fd
 * write the tx_end in hmo.storage.gc_fd
 *
 * Rational:
 * 1. for md file, we copy the md-1 file to md-0 (replace the ranges);
 * 2. for range files, we rename Grange-* to range-*;
 * 3. for itb file, we adjust mdisk.master to the new itb file;
 */
int mdsl_gc_tx_itb(u64 duuid, int gen, struct fdhash_entry *omd)
{
    struct fdhash_entry *fde;
    int err = 0, i, j, abort_flag;

    hvfs_info(mdsl, "BEGIN GC-MD transaction on directoy %ld gen %d\n",
              duuid, gen);
    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, gen);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create gc MD file failed w/ %ld\n",
                 PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }
    
    /* Save the old and new md file */
    err = __mdisk_write(omd, NULL);
    if (err) {
        hvfs_err(mdsl, "sync md file failed w/ %d\n", err);
        /* if old md file is failed to be saved, we abort transaction */
        goto out;
    }
    err = __mdisk_write(fde, NULL);
    if (err) {
        hvfs_err(mdsl, "sync gc md file failed w/ %d\n", err);
    }
    
    /* we know the omd file has already been LOCKED, thus we just copy the new
     * md file's range to old md file */
    xfree(omd->mdisk.ranges);
    xfree(omd->mdisk.new_range);
    omd->mdisk.range_nr = fde->mdisk.range_nr;
    omd->mdisk.size = fde->mdisk.size;
    omd->mdisk.new_size = fde->mdisk.new_size;
    omd->mdisk.new_range = fde->mdisk.new_range;
    omd->mdisk.ranges = fde->mdisk.ranges;
    omd->mdisk.range_aid = fde->mdisk.range_aid;

    /* for range files, we do rename */
    if (omd->mdisk.ranges) {
        for (i = 0; i < fde->mdisk.size; i++) {
            char opath[256], npath[256];

            abort_flag = 0;
            sprintf(opath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home, 
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home,
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            err = rename(opath, npath);
            if (err) {
                if (errno == ENOENT) {
                    /* I think it is ok that there is a new range created in
                     * the new metadata file, thus, we just ignore this error */
                    hvfs_warning(mdsl, "Rename '%s' but it doesn't exist!\n",
                                 opath);
                } else {
                    hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d\n",
                             opath, npath, errno);
                    err = -errno;
                    goto rollback_ranges;
                }
            }
            abort_flag = 1;
            
            sprintf(opath, "%s/%lx/%lx/Grange-%ld", hmo.conf.mdsl_home, 
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            err = rename(opath, npath);
            if (err) {
                hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d\n",
                         opath, npath, errno);
                err = -errno;
                goto rollback_ranges;
            }
        }
    }
    if (omd->mdisk.new_range) {
        for (i = 0; i < fde->mdisk.new_size; i++) {
            char opath[256], npath[256];

            abort_flag = 0;
            sprintf(opath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home, 
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home,
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            err = rename(opath, npath);
            if (err) {
                hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d\n",
                         opath, npath, errno);
                err = -errno;
                goto rollback_new_range;
            }
            abort_flag = 1;
            
            sprintf(opath, "%s/%lx/%lx/Grange-%ld", hmo.conf.mdsl_home, 
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            err = rename(opath, npath);
            if (err) {
                hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d\n",
                         opath, npath, errno);
                err = -errno;
                goto rollback_new_range;
            }
        }
    }
    /* final step, atomic change to the new itb file and do cleanups */
    omd->mdisk.itb_master++;
    /* FIXME: cleanup range files(Brange-* and old itb file) */
    err = __mdisk_write(omd, NULL);
    if (err) {
        hvfs_err(mdsl, "sync md file failed w/ %d\n", err);

        i = fde->mdisk.new_size;
        abort_flag = 0;
        goto rollback_new_range;
    }
    /* remove the new md file */
    mdsl_storage_fd_remove(fde);
    close(fde->fd);
    {
        char path[256];

        sprintf(path, "%s/%lx/%lx/md-%d", hmo.conf.mdsl_home,
                hmo.site_id, duuid, gen);
        err = unlink(path);
        if (err) {
            hvfs_err(mdsl, "Unlink '%s' failed w/ %d, need human involving\n", 
                     path, err);
        }
    }
    /* remove the Brange files and old itb file */
    {
        char path[256];

        sprintf(path, "%s/%lx/%lx/itb-%d", hmo.conf.mdsl_home,
                hmo.site_id, duuid, gen - 1);
        err = unlink(path);
        if (err) {
            hvfs_err(mdsl, "Unlink '%s' failed w/ %d, need human involving\n",
                     path, err);
        }
    }
    {
        if (omd->mdisk.ranges) {
            for (i = 0; i < omd->mdisk.size; i++) {
                char path[256];

                sprintf(path, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home,
                        hmo.site_id, duuid, (omd->mdisk.ranges + i)->range_id);
                err = unlink(path);
                if (err) {
                    hvfs_err(mdsl, "Unlink '%s' failed w/ %d, need human "
                             "involving\n",
                             path, err);
                }
            }
        }
        if (omd->mdisk.new_range) {
            for (i = 0; i < omd->mdisk.new_size; i++) {
                char path[256];

                sprintf(path, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home,
                        hmo.site_id, duuid, 
                        (omd->mdisk.new_range + i)->range_id);
                err = unlink(path);
                if (err) {
                    hvfs_err(mdsl, "Unlink '%s' failed w/ %d, need human "
                             "involving\n",
                             path, err);
                }
            }
        }
    }

    hvfs_info(mdsl, "END GC-MD transaction on directory %ld gen %d\n",
              duuid ,gen);
    goto out;
    
out_put:
    mdsl_storage_fd_put(fde);
out:
    return err;
rollback_new_range:
    for (j = 0; j < i; j++) {
        char opath[256], npath[256];
        
        sprintf(opath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/Grange-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }

        sprintf(opath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }
    }
    if (abort_flag) {
        char opath[256], npath[256];
        
        sprintf(opath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }
    }
    /* reset flag and size for rollback of ranges! */
    abort_flag = 0;
    i = fde->mdisk.size;
rollback_ranges:
    for (j = 0; j < i; j++) {
        char opath[256], npath[256];
        
        sprintf(opath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/Grange-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }

        sprintf(opath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }
    }
    if (abort_flag) {
        char opath[256], npath[256];
        
        sprintf(opath, "%s/%lx/%lx/Brange-%ld", hmo.conf.mdsl_home, 
                hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", hmo.conf.mdsl_home,
                hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }
    }
    /* rollback mdisk */
    omd->state = FDE_OPEN;
    err = mdsl_storage_fd_mdisk(omd, NULL);
    if (err) {
        hvfs_err(mdsl, "Reload mdisk from disk failed w/ %d. CRASH is "
                 "nearing\n", err);
    }
    err = -EABORT;
    hvfs_info(mdsl, "ABORT GC-MD transaction on directory %ld gen %d\n",
              duuid, gen);
    goto out_put;
}

/* GC one round of the metadata
 *
 * Return Value: >=0: # of ITBs we handled; <0: error
 */
int mdsl_gc_md_round(u64 duuid, int master, struct fdhash_entry *md, 
                     struct fdhash_entry *fde, u64 *gc_offset)
{
    struct itb_info ii = {
        .duuid = duuid,
    };
    struct itb *itb;
    struct fdhash_entry *nmd;
    range_t *range;
    struct iovec itb_iov;
    struct mdsl_storage_access msa = {
        .iov = &itb_iov,
        .iov_nr = 1,
    };
    struct mmap_args ma;
    u64 offset = *gc_offset, location = 0, copied = 0;
    int err = 0, data_len, compacted = 0, handled = 0, missed = 0;

    if (offset == -1UL) {
        return -EINVAL;
    }
    if (!offset) {
        /* adjust offset to 1! */
        offset = 1;
    }

    if (!md->mdisk.ranges && !md->mdisk.new_range) {
        return -ENOENT;
    }

    itb = xmalloc(sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
    if (!itb) {
        hvfs_err(mdsl, "xzalloc() itb failed.\n");
        return -ENOMEM;
    }
    
    while (1) {
        /* prepare itb */
        //memset(itb, 0, sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
        /* read the header */
        msa.offset = offset;
        itb_iov.iov_base = itb;
        itb_iov.iov_len = sizeof(itb->h);
        if (offset >= fde->abuf.file_offset + fde->abuf.offset) {
            break;
        }
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "fd read failed w/ %d\n", err);
            goto out_free;
        }
        /* BUG-xxx: how to determine the ITB border?
         *
         * The page hole might be in range 1-4095 bytes, we need a always
         * correct way to detect holes.
         */
        if (__is_hole(offset, itb)) {
            /* we should seek to next active page! */
            u64 last_offset;

        reskip:
            last_offset = offset;
            offset = PAGE_ROUNDUP(offset, getpagesize());
            if (offset == last_offset) {
                offset += 1;
                goto reskip;
            }
            continue;
        }

        handled++;
        /* compare this itb with the latest offset */
        ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;

        err = __mdisk_lookup(md, MDSL_MDISK_RANGE, itb->h.itbid, &range);
        if (err == -ENOENT) {
            /* it is ok */
            missed++;
            hvfs_warning(mdsl, "lookup itbid %ld in md file failed w/ %d\n",
                         itb->h.itbid, err);
            goto compact_it;
        } else if (err) {
            hvfs_err(mdsl, "lookup itbid %ld in old md file failed w/ %d\n",
                     itb->h.itbid, err);
            goto out_free;
        }
        ma.foffset = 0;
        ma.range_id = range->range_id;
        ma.range_begin = range->begin;
        ma.flag = MA_OFFICIAL;

        err = __range_lookup(duuid, itb->h.itbid, &ma, &location);
        if (err) {
            goto out_free;
        }
        /* if location is ZERO, it means that the racer has not been update
         * the range file, we just compact this entry to the new itb file to
         * not lose any itb. */
        if (!location) {
            missed++;
            hvfs_warning(mdsl, "lookup itbid %ld in range file "
                         "failed w/ ENOENT, copy it directly!\n",
                         itb->h.itbid);
            goto compact_it;
        }

        if (offset == location) {
            compacted++;
        compact_it:
            copied += atomic_read(&itb->h.len);
            /* read in the data region of itb */
            data_len = atomic_read(&itb->h.len) - sizeof(itb->h);
            if (data_len > 0) {
                msa.offset = offset + sizeof(itb->h);
                msa.iov->iov_base = &itb->lock;
                msa.iov->iov_len = data_len;
                err = mdsl_storage_fd_read(fde, &msa);
                if (err) {
                    hvfs_err(mdsl, "fd read failed w/ %d\n", err);
                    goto out_free;
                }
            } else {
                hvfs_err(mdsl, "data_len %d is minus, internal error!\n", 
                         data_len);
                err = -EFAULT;
                goto out_free;
            }
            /* ok, we should copy this itb entry to the new itb file */
            ii.itbid = itb->h.itbid;
            ASSERT(itb->h.puuid == duuid, mdsl);
            err = itb_gc_append(master + 1, itb, &ii);
            if (err) {
                hvfs_err(mdsl, "GC append itb %ld to new file failed w/ %d\n",
                         itb->h.itbid, err);
                goto out_free;
            }
            /* open the gc_md file and update the gc range region */
            nmd = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, 
                                                master + 1);
            if (IS_ERR(nmd)) {
                hvfs_err(mdsl, "lookup create gc MD file failed w/ %ld\n",
                         PTR_ERR(nmd));
                err = PTR_ERR(nmd);
                goto out_free;
            }
            ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;
        relookup:
            xlock_lock(&nmd->lock);
            err = __mdisk_lookup_nolock(nmd, MDSL_MDISK_RANGE, 
                                        itb->h.itbid, &range);
            if (err == -ENOENT) {
                /* create a new range now */
                u64 i;

                i = MDSL_STORAGE_idx2range(itb->h.itbid);
                __mdisk_add_range_nolock(nmd, i * MDSL_STORAGE_RANGE_SLOTS,
                                         (i + 1) * MDSL_STORAGE_RANGE_SLOTS - 1,
                                         nmd->mdisk.range_aid++);
                __mdisk_range_sort(nmd->mdisk.new_range, nmd->mdisk.new_size);
                xlock_unlock(&nmd->lock);
                goto relookup;
            } else if (err) {
                hvfs_err(mdsl, "mdisk_lookup_nolock failed w/ %d\n", err);
                xlock_unlock(&nmd->lock);
                goto put_fde;
            }
            xlock_unlock(&nmd->lock);

            ma.foffset = 0;
            ma.range_id = range->range_id;
            ma.range_begin = range->begin;
            ma.flag = MA_GC;

            err = __range_write(duuid, itb->h.itbid, &ma, ii.location);
            if (err) {
                hvfs_err(mdsl, "range write failed w/ %d\n", err);
                goto put_fde;
            }
            err = __mdisk_write(nmd, NULL);
            if (err) {
                hvfs_err(mdsl, "sync gc md file failed w/ %d\n", err);
            }
            
        put_fde:
            mdsl_storage_fd_put(nmd);
            if (err) {
                goto out_free;
            }
        }
        /* ok, this itb is done. handle the next one */
        hvfs_warning(mdsl, "Process itb %ld len %d (%s) done. LOC %ld\n", 
                     itb->h.itbid, atomic_read(&itb->h.len), 
                     (offset == location ? "+" : "."),
                     ii.location);
        offset += atomic_read(&itb->h.len);
    }
    err = compacted;
    hvfs_info(mdsl, "This round handled %s%d%s, compacted %s%d%s "
              "and missed %s%d%s ITBs (GC Remain %.2f%% %ld/%ld).\n",
              HVFS_COLOR_RED, handled, HVFS_COLOR_END,
              HVFS_COLOR_GREEN, compacted, HVFS_COLOR_END,
              HVFS_COLOR_YELLOW, missed, HVFS_COLOR_END,
              100 * (double)copied / (double)(offset - *gc_offset), copied, 
              (offset - *gc_offset));
    
out_free:
    xfree(itb);
    *gc_offset = offset;

    return err;
}

/* GC the medata of directory duuid
 */
int mdsl_gc_md(u64 duuid)
{
    struct fdhash_entry *fde, *itbf;
    u64 last_offset, gc_offset;
    int err = 0, round = 0, master;
    
    /* Step 0: prepare: open the md file */
    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, 0);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n", PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }

    /* Step 1: issue one round to scan the itb file */
    master = fde->mdisk.itb_master;
    itbf = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_ITB, master);
    if (IS_ERR(itbf)) {
        hvfs_err(mdsl, "lookup create ITB file failed w/ %ld\n", PTR_ERR(itbf));
        err = PTR_ERR(itbf);
        goto out_put;
    }
    
    gc_offset = fde->mdisk.gc_offset;
    last_offset = gc_offset;

redo_round:
    hvfs_warning(mdsl, "GC directory %lx in round %d from off %lx\n", 
                 duuid, round++, gc_offset);
    err = mdsl_gc_md_round(duuid, master, fde, itbf, &gc_offset);
    if (err < 0) {
        hvfs_err(mdsl, "GC metadata in stage %d's round %d failed w/ %d\n",
                 master, round - 1, err);
        goto out_cleanup;
    } else if (err == 0) {
        /* nothing has been handled, we just stop gc */
        hvfs_warning(mdsl, "Not redundant ITB to be compacted!\n");
        goto out_cleanup;
    }
    
    /* Step 2: do check */
    last_offset = mdsl_storage_fd_max_offset(itbf);
    if (last_offset == -1UL) {
        hvfs_err(mdsl, "get the ITB file offset failed\n");
        err = -EINVAL;
        goto out_cleanup;
    }
    
    if (gc_offset < last_offset) {
        /* we need another gc round! */
        goto redo_round;
    }
    
    /* Step 3: lockup the fde and recheck */
    err = mdsl_storage_fd_lockup(fde);
    if (err) {
        hvfs_err(mdsl, "lockup the MD file failed w/ %d\n",
                 err);
        goto out_cleanup;
    }
    /* wait for the last reference of ITB file */
    while (atomic_read(&itbf->ref) > 1) {
        xsleep(100);
    }
    last_offset = mdsl_storage_fd_max_offset(itbf);
    if (last_offset == -1UL) {
        hvfs_err(mdsl, "get the ITB file offset failed\n");
        err = -EINVAL;
        goto out_unlock;
    }
    if (gc_offset < last_offset) {
        /* we need the final gc round! */
        hvfs_warning(mdsl, "GC directory %lx in round %d(final)\n", 
                     duuid, round++);
        err = mdsl_gc_md_round(duuid, master, fde, itbf, &gc_offset);
        if (err) {
            hvfs_err(mdsl, "GC metadata in stage %d's round %d failed w/ %d\n",
                     master, round, err);
            goto out_unlock;
        }
        ASSERT(gc_offset >= last_offset, mdsl);
    }
    /* ok, we should release the memory resouce of ITB file */
    append_buf_destroy_async(itbf); /* already close the fd */
    /* FIXME: itbf might be referenced by OTHER threads! how to recover from
     * it? */
    mdsl_storage_fd_remove(itbf);
    xfree(itbf);
    mdsl_storage_evict_rangef(duuid);
    
    /* Step 4: do GC-TX */
    err = mdsl_gc_tx_itb(duuid, master + 1, fde);
    if (err) {
        hvfs_err(mdsl, "mdsl_gc_tx_itb(%d) failed w/ %d\n",
                 master, err);
        goto out_release;
    }

    /* finally, release the MD's fde */
    fde->mdisk.gc_offset = 0;
    
out_release:
    mdsl_storage_fd_unlock(fde);
    
out_put:
    mdsl_storage_fd_put(fde);
    
out:
    return err;
out_unlock:
    mdsl_storage_fd_unlock(fde);
out_cleanup:
    /* cleanup the round result? do not do that, we remember the gc_offset */
    fde->mdisk.gc_offset = gc_offset;
    mdsl_storage_fd_put(itbf);
    goto out_put;
}

/* CB on holes
 */
void gc_data_stat_cb(u64 low, u64 high, void *arg)
{
    struct gc_data_stat *gds = arg;

    gds->valid += (high - low);
    if (high > gds->max)
        gds->max = high;
}

int itb_lzo_decompress(struct itb *in)
{
    lzo_uint outlen, inlen;
    int err = 0;
    void *p;

    inlen = atomic_read(&in->h.len) - sizeof(in->h);
    p = xmalloc(inlen);
    if (!p) {
        hvfs_err(mdsl, "Unable to alloc the memory to decompress ITB!\n");
        err = -ENOMEM;
        goto out;
    }
    memcpy(p, (void *)in->lock, inlen);
    
    err = lzo1x_decompress(p, inlen, 
                           (void *)in->lock, &outlen, NULL);
    if (err == LZO_E_OK && 
        outlen == atomic_read(&in->h.zlen) - sizeof(in->h)) {
        err = 0;
    } else {
        hvfs_err(mdsl, "LZO decompress failed w/ %d\n", err);
    }
    /* clear the compress flag */
    in->h.compress_algo = COMPR_NONE;
    /* exchange the len back */
    atomic_set(&in->h.len, outlen + sizeof(in->h));
    xfree(p);
    
out:
    return err;
}

void __add_to_brtree(void **root, struct ite *e, int column)
{
    struct brtnode *n = NULL;

    if (e->column[column].len > 0) {
        n = xmalloc(sizeof(struct brtnode));
        if (n) {
            n->low = e->column[column].offset;
            n->high = e->column[column].offset + e->column[column].len + 1;
            hvfs_info(mdsl, "Add Data Range [%ld,%ld) {%s}\n", 
                      n->low, n->high, e->s.name);
            brt_add(n, root);
        }
    }
}

int mdsl_gc_data_first_round(u64 duuid, int column, void **root, int type,
                             struct fdhash_entry *md, struct fdhash_entry *fde,
                             u64 *begin, u64 *end)
{
    return 0;
}

/* One round on data gc
 *
 * Return value: <0:error; >=0: # of inserted_itbs
 */
int mdsl_gc_data_round(u64 duuid, int column, void **root, int type, 
                       struct fdhash_entry *md, struct fdhash_entry *fde, 
                       u64 *begin, u64 *end)
{
    int err = 0;

#if 0
    if (*begin == 0) {
        /* this is the first round, we use a top-down approach to find valid
         * itbs */
        err = mdsl_gc_data_first_round(duuid, column, root, type, md, fde, 
                                       begin, end);
        if (err) {
            hvfs_err(mdsl, "GC data in first round failed w/ %d\n", err);
            goto out;
        }
    } else {
#else
    {
#endif
        struct itb *itb;
        range_t *range;
        struct iovec itb_iov;
        struct mdsl_storage_access msa = {
            .iov = &itb_iov,
            .iov_nr = 1,
        };
        struct mmap_args ma;
        u64 offset = *begin, location = 0, handled = 0, inserted = 0,
            missed = 0;

        if (offset == -1UL)
            goto out;
        if (!offset) {
            /* adjust offset to 1! */
            offset = 1;
        }

        if (!md->mdisk.ranges && !md->mdisk.new_range)
            return -ENOENT;

        itb = xmalloc(sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
        if (!itb) {
            hvfs_err(mdsl, "xzalloc() itb failed.\n");
            return -ENOMEM;
        }

        while (1) {
            struct ite *ite;
            int nr, data_len = 0, itenr = 0;
        
            /* prepare itb */
            //memset(itb, 0, sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
            /* read the header */
            msa.offset = offset;
            itb_iov.iov_base = itb;
            itb_iov.iov_len = sizeof(itb->h);
            if (offset >= fde->abuf.file_offset + fde->abuf.offset) {
                break;
            }
            err = mdsl_storage_fd_read(fde, &msa);
            if (err) {
                hvfs_err(mdsl, "fd read failed w/ %d\n", err);
                goto out_free;
            }
            if (__is_hole(offset, itb)) {
                /* we should seek to next active page! */
                u64 last_offset;

            reskip:
                last_offset = offset;
                offset = PAGE_ROUNDUP(offset, getpagesize());
                if (offset == last_offset) {
                    offset += 1;
                    goto reskip;
                }
                continue;
            }

            /* compare this itb with the latest offset */
            handled++;
            ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;

            err = __mdisk_lookup(md, MDSL_MDISK_RANGE, itb->h.itbid, &range);
            if (err == -ENOENT) {
                /* it is ok */
                hvfs_warning(mdsl, "lookup itbid %ld in md file failed w/ %d\n",
                             itb->h.itbid, err);
                goto insert_it;
            } else if (err) {
                hvfs_err(mdsl, "lookup itbid %ld in old md file failed w/ %d\n",
                         itb->h.itbid, err);
                goto out_free;
            }
            ma.foffset = 0;
            ma.range_id = range->range_id;
            ma.range_begin = range->begin;
            ma.flag = MA_OFFICIAL;

            err = __range_lookup(duuid, itb->h.itbid, &ma, &location);
            if (err)
                goto out_free;
            /* if location is ZERO, it means that the racer has not been
             * update the range file, we just insert this entry to memory
             * tree. */
            if (!location) {
                missed++;
                hvfs_warning(mdsl, "lookup itbid %ld in range file "
                             "failed w/ ENOENT, insert it directly!\n",
                             itb->h.itbid);
                goto insert_it;
            }

            if (offset == location) {
            insert_it:
                {
                    inserted++;
                    data_len = atomic_read(&itb->h.len) - sizeof(itb->h);

                    if (data_len > 0) {
                        /* read in it */
                        msa.offset = offset + sizeof(itb->h);
                        msa.iov->iov_base = &itb->lock;
                        msa.iov->iov_len = data_len;
                        err = mdsl_storage_fd_read(fde, &msa);
                        if (err) {
                            hvfs_err(mdsl, "fd read failed w/ %d\n", err);
                            goto out_free;
                        }
                        /* uncompress it if needed */
                        switch (itb->h.compress_algo) {
                        case COMPR_NONE:
                            break;
                        case COMPR_LZO:
                            err = itb_lzo_decompress(itb);
                            if (err) {
                                hvfs_err(mdsl, "decompress ITB failed w/ %d\n",
                                         err);
                                goto out_free;
                            }
                            break;
                        default:;
                            hvfs_err(mdsl, "Invalid ITB compress algo %d\n",
                                     itb->h.compress_algo);
                            err = -EINVAL;
                            goto out_free;
                        }
                    } else {
                        hvfs_err(mdsl, "data_len %d is minus, internal error!\n",
                                 data_len);
                        err = -EFAULT;
                        goto out_free;
                    }
                    /* ok, we need analyse each ITE and insert the valid range
                     * into the tree */
                    nr = -1;
                    while (nr < (1 << itb->h.adepth)) {
                        nr = find_next_bit((unsigned long *)itb->bitmap, 
                                           (1 << itb->h.adepth), nr + 1);
                        if (nr < (1 << itb->h.adepth)) {
                            ite = &itb->ite[nr];
                            switch (type) {
                            case GC_DATA_STAT:
                                __add_to_brtree(root, ite, column);
                                break;
                            case GC_DATA:
                                break;
                            default:
                                hvfs_err(mdsl, "Invalid GC type %d\n",
                                         type);
                            }
                            itenr++;
                        }
                    }
                    if (itenr != atomic_read(&itb->h.entries)) {
                        hvfs_warning(mdsl, "Active entries %d, but we only get "
                                     "%d entries\n",
                                     atomic_read(&itb->h.entries), itenr);
                    }
                }
            }
            hvfs_warning(mdsl, "Process itb %ld len %d zlen %ld (%s) done.\n",
                         itb->h.itbid, atomic_read(&itb->h.len), 
                         data_len + sizeof(itb->h), 
                         (offset == location ? "+" : "."));
            offset += data_len + sizeof(itb->h);
        }
        err = inserted;
        hvfs_info(mdsl, "This round handled %s%ld%s, inserted %s%ld%s "
                  "and missed %s%ld%s ITBs.\n",
                  HVFS_COLOR_RED, handled, HVFS_COLOR_END,
                  HVFS_COLOR_GREEN, inserted, HVFS_COLOR_END,
                  HVFS_COLOR_YELLOW, missed, HVFS_COLOR_END);
    out_free:
        xfree(itb);
    }
out:
    return err;
}

/* Get the stat of data GCing
 *
 * Rational: Use the range files and build a memory BINARY tree to detect data
 * file holes.
 */
int mdsl_gc_data_stat(u64 duuid, int column, struct gc_data_stat *gds)
{
    struct fdhash_entry *fde, *itbf;
    void *tree = NULL;
    u64 begin_offset = 0, end_offset;
    int err = 0, master, round = 0;

    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_DATA, column);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create DATA file failed w/ %ld\n",
                 PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }
    gds->total = mdsl_storage_fd_max_offset(fde);
    if (gds->total == -1UL) {
        hvfs_err(mdsl, "get the DATA-%d file offset failed\n", column);
        err = -EINVAL;
    }
    mdsl_storage_fd_put(fde);
    if (err)
        goto out;
    
    /* Read in the ITB file to construct memory range tree */
    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, 0);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n", 
                 PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }

    master = fde->mdisk.itb_master;
    itbf = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_ITB, master);
    if (IS_ERR(itbf)) {
        hvfs_err(mdsl, "lookup create ITB file failed w/ %ld\n", 
                 PTR_ERR(itbf));
        err = PTR_ERR(itbf);
        goto out_put_fde;
    }
    end_offset = mdsl_storage_fd_max_offset(itbf);
    if (end_offset == -1UL) {
        hvfs_err(mdsl, "get the ITB file offset failed\n");
        err = -EINVAL;
        goto out_put_itbf;
    }

redo_round:
    hvfs_info(mdsl, "Constructing memory range tree for DATA file"
              "(%lx/data-%d) ITB [%ld,%ld]B Round %d\n",
              duuid, column, begin_offset, end_offset, round++);
    err = mdsl_gc_data_round(duuid, column, &tree, GC_DATA_STAT, fde, itbf, 
                             &begin_offset, &end_offset);
    if (err < 0) {
        hvfs_err(mdsl, "GC data in round %d faield w/ %d\n",
                 round - 1, err);
        goto out_put_itbf;
    }

    /* do check */
    begin_offset = mdsl_storage_fd_max_offset(itbf);
    if (begin_offset == -1UL) {
        hvfs_err(mdsl, "get the ITB file offset failed\n");
        err = -EINVAL;
        goto out_put_itbf;
    }

    if (begin_offset > end_offset) {
        /* we need another gc round! */
        u64 tmp_offset = begin_offset;
        
        begin_offset = end_offset;
        end_offset = tmp_offset;
        goto redo_round;
    }

out_put_itbf:
    mdsl_storage_fd_put(itbf);
out_put_fde:
    mdsl_storage_fd_put(fde);

    /* we finish getting the hole tree, fill it now */
retry:
    err = brt_loop_on_ranges(&tree, gds, gc_data_stat_cb);
    if (err == -EBUSY) {
        sleep(1);
        goto retry;
    }
    brt_destroy(tree, xfree);
    gds->hole = gds->total - gds->valid;
    
out:
    return err;
}

/* GC the data of directory duuid by TRUNC data file
 */
int mdsl_gc_data_by_trunc(u64 duuid, int column)
{
    struct gc_data_stat gds = {0,};
    int err = 0;
    
    /* First, we compute the holes */
    err = mdsl_gc_data_stat(duuid, column, &gds);
    if (err) {
        hvfs_err(mdsl, "mdsl_gc_data_stat() failed w/ %d\n", err);
        goto out;
    }
    
    /* If the MGC remain ratio is under 50%, we do trunc the file */
    if ((double)gds.max / (double)gds.total <= 0.5) {
        struct fdhash_entry *fde;

        hvfs_info(mdsl, "Data file %lx/data-%d: PGC Remain %.2f%%,"
                  " MGC Remain %.2f%% < 50%%\n",
                  duuid, column,
                  100 * (double)gds.valid / (double)gds.total,
                  100 * (double)gds.max / (double)gds.total);
        
        /* open the data file */
        fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_DATA,
                                            column);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create DATA file failed w/ %ld\n",
                     PTR_ERR(fde));
            err = PTR_ERR(fde);
            goto out;
        }
        /* lockup the file */
        err = mdsl_storage_fd_lockup(fde);
        if (err) {
            hvfs_err(mdsl, "lockup the DATA file failed w/ %d\n", err);
            goto out_put;
        }
        hvfs_info(mdsl, "DO DATA FILE TRUNC NOW!\n");

        xlock_lock(&fde->lock);
        err = append_buf_flush_trunc(fde, gds.max);
        if (err) {
            hvfs_err(mdsl, "append_buf_flush_trunc() failed w/ %d\n", err);
            xlock_unlock(&fde->lock);
            goto out_unlock;
        }
        xlock_unlock(&fde->lock);
        
        hvfs_info(mdsl, "DATA FILE TRUNC DONE!\n");
    out_unlock:
        err = mdsl_storage_fd_unlock(fde);
        if (err) {
            hvfs_err(mdsl, "unlock the DATA file failed w/ %d\n", err);
            goto out_put;
        }
    out_put:
        mdsl_storage_fd_put(fde);
    }
    
out:
    return 0;
}
