/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-02 13:12:00 macan>
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
    omd->mdisk.range_nr[0] = fde->mdisk.range_nr[0];
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
            sprintf(opath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME, 
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME,
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
            
            sprintf(opath, "%s/%lx/%lx/Grange-%ld", HVFS_MDSL_HOME, 
                    hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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
            sprintf(opath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME, 
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME,
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            err = rename(opath, npath);
            if (err) {
                hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d\n",
                         opath, npath, errno);
                err = -errno;
                goto rollback_new_range;
            }
            abort_flag = 1;
            
            sprintf(opath, "%s/%lx/%lx/Grange-%ld", HVFS_MDSL_HOME, 
                    hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
            sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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

        sprintf(path, "%s/%lx/%lx/md-%d", HVFS_MDSL_HOME,
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

        sprintf(path, "%s/%lx/%lx/itb-%d", HVFS_MDSL_HOME,
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

                sprintf(path, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME,
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

                sprintf(path, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME,
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
        
        sprintf(opath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/Grange-%ld", HVFS_MDSL_HOME,
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }

        sprintf(opath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.new_range + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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
        
        sprintf(opath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.new_range + i)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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
        
        sprintf(opath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/Grange-%ld", HVFS_MDSL_HOME,
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        err = rename(opath, npath);
        if (err) {
            hvfs_err(mdsl, "Rename '%s' to '%s' failed w/ %d, request "
                     "for human involving\n",
                     opath, npath, errno);
        }

        sprintf(opath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.ranges + j)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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
        
        sprintf(opath, "%s/%lx/%lx/Brange-%ld", HVFS_MDSL_HOME, 
                hmo.site_id, duuid, (fde->mdisk.ranges + i)->range_id);
        sprintf(npath, "%s/%lx/%lx/range-%ld", HVFS_MDSL_HOME,
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
    u64 offset = *gc_offset, location = 0;
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
        memset(itb, 0, sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
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
        if (!atomic_read(&itb->h.len)) {
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
                         "failed w/ ENOENT\n",
                         itb->h.itbid);
            goto compact_it;
        }

        if (offset == location) {
            compacted++;
        compact_it:
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
              "and missed %s%d%s ITBs.\n",
              HVFS_COLOR_RED, handled, HVFS_COLOR_END,
              HVFS_COLOR_GREEN, compacted, HVFS_COLOR_END,
              HVFS_COLOR_YELLOW, missed, HVFS_COLOR_END);
    
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
    hvfs_warning(mdsl, "GC directory %lx in round %d\n", duuid, round++);
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
