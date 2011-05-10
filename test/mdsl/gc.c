/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-09 11:36:49 macan>
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

#ifdef UNIT_TEST

static int racer_stop = 0;

/* preload_dir() make sure all the files' fde are in cache
 */
void preload_dir(u64 duuid)
{
    struct fdhash_entry *fde, *rangefde;
    struct mmap_args ma;
    int master = -1, i;

    /* open the md file */
    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, 0);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n", PTR_ERR(fde));
    } else {
        master = fde->mdisk.itb_master;
    }

    ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;
    ma.foffset = 0;
    ma.flag = MA_OFFICIAL;

    /* open the range files */
    if (fde->mdisk.ranges) {
        for (i = 0; i < fde->mdisk.size; i++) {
            ma.range_id = (fde->mdisk.ranges + i)->range_id;
            ma.range_begin = (fde->mdisk.ranges + i)->begin;

            rangefde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_RANGE,
                                                     (u64)&ma);
            if (IS_ERR(rangefde)) {
                hvfs_err(mdsl, "lookup create range file failed w/ %ld\n",
                         PTR_ERR(rangefde));
            } else 
                mdsl_storage_fd_put(rangefde);
        }
    }
    if (fde->mdisk.new_range) {
        for (i = 0; i < fde->mdisk.new_size; i++) {
            ma.range_id = (fde->mdisk.new_range + i)->range_id;
            ma.range_begin = (fde->mdisk.new_range + i)->begin;

            rangefde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_RANGE,
                                                     (u64)&ma);
            if (IS_ERR(rangefde)) {
                hvfs_err(mdsl, "lookup create range file failed w/ %ld\n",
                         PTR_ERR(rangefde));
            } else
                mdsl_storage_fd_put(rangefde);
        }
    }
    
    mdsl_storage_fd_put(fde);

    /* open the itb file */
    if (master > 0) {
        fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_ITB, master);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create ITB file failed w/ %ld\n", PTR_ERR(fde));
        } else {
            mdsl_storage_fd_put(fde);
        }
    }
}

/* racer create a new thread and access the metadata/itb file randomizely
 */
void *racer(void *arg)
{
    struct itb *itb;
    struct fdhash_entry *fde;
    struct itb_info ii;
    u64 duuid = (u64)arg;
    struct mmap_args ma = {0, };
    range_t *range;
    int len, range_begin, range_end, err, counter = 0;

    itb = xmalloc(sizeof(*itb) + ITB_SIZE * sizeof(struct ite));
    if (!itb) {
        hvfs_err(mdsl, "xmalloc ITB failed\n");
        racer_stop = 1;
    }
    range_begin = sizeof(itb->h);
    range_end = sizeof(*itb) + ITB_SIZE * sizeof(struct ite);

    while (!racer_stop) {
        xsleep(lib_random(0xffff));
        /* try to append more itb to the itb file */
        len = lib_random(range_end - range_begin) + range_begin;
        atomic_set(&itb->h.len, len);
        itb->h.itbid = lib_random(0xfff);
        itb->h.puuid = duuid;

        err = itb_append(itb, &ii, hmo.site_id, 0);
        if (err) {
            hvfs_err(mdsl, "Append itb <> to disk file failed w/ %d\n",
                     err);
            continue;
        } else {
            hvfs_info(mdsl, "Append (%d) itb %ld len %d to itb file %d\n",
                      (++counter), itb->h.itbid, atomic_read(&itb->h.len),
                      ii.master);
        }
        /* open the md file and try to update the ranges */
        fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_MD, 0);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n",
                     PTR_ERR(fde));
            continue;
        }
        if (ii.master < fde->mdisk.itb_master) {
            hvfs_info(mdsl, "Drop obsolete itb %ld appending %ld\n",
                      itb->h.itbid, ii.location);
            goto put_fde;
        }
        ma.win = MDSL_STORAGE_DEFAULT_RANGE_SIZE;
    relookup:
        xlock_lock(&fde->lock);
        err = __mdisk_lookup_nolock(fde, MDSL_MDISK_RANGE, itb->h.itbid,
                                    &range);
        if (err == -ENOENT) {
            /* create a new range now */
            u64 i;
            
            i = MDSL_STORAGE_idx2range(itb->h.itbid);
            __mdisk_add_range_nolock(fde, i * MDSL_STORAGE_RANGE_SLOTS,
                                     (i + 1) * MDSL_STORAGE_RANGE_SLOTS - 1,
                                     fde->mdisk.range_aid++);
            __mdisk_range_sort(fde->mdisk.new_range, fde->mdisk.new_size);
            xlock_unlock(&fde->lock);
            goto relookup;
        } else if (err) {
            hvfs_err(mdsl, "mdisk_lookup_nolock failed w/ %d\n", err);
            xlock_unlock(&fde->lock);
            goto put_fde;
        }
        xlock_unlock(&fde->lock);

        ma.foffset = 0;
        ma.range_id = range->range_id;
        ma.range_begin = range->begin;
        ma.flag = MA_OFFICIAL;

        err = __range_write(duuid, itb->h.itbid, &ma, ii.location);
        if (err) {
            hvfs_err(mdsl, "range write failed w/ %d\n", err);
            goto put_fde;
        }
        err = __mdisk_write(fde, NULL);
        if (err) {
            hvfs_err(mdsl, "sync md file failed w/ %d\n", err);
        }
    put_fde:
        mdsl_storage_fd_put(fde);
    }

    pthread_exit(0);
}

int main(int argc, char *argv[])
{
    u64 duuid = 1;
    pthread_t racer_thread;
    int err = 0;
    
    hvfs_info(mdsl, "MDSL GC Unit Test ...\n");

    /* got the uuid from user */
    if (argc < 2) {
        hvfs_err(mdsl, "Usage: %s dir_uuid\n", argv[0]);
        return EINVAL;
    } else {
        duuid = atol(argv[1]);
    }
    
    mdsl_init();
    hmo.site_id = HVFS_MDSL(0);
    mdsl_verify();

    preload_dir(duuid);
    /* start a racer */
    err = pthread_create(&racer_thread, NULL, &racer, (void *)duuid);
    if (err)
        goto out_clean;

    sleep(5);
    err = mdsl_gc_md(duuid);
    if (err) {
        hvfs_err(mdsl, "mdsl_gc_md(%lx) failed w/ %d\n",
                 duuid, err);
        goto out_clean;
    }

    racer_stop = 1;
    pthread_join(racer_thread, NULL);
    
out_clean:
    mdsl_destroy();

    return err;
}
#endif
