/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-18 22:51:23 macan>
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

int main(int argc, char *argv[])
{
    u64 duuid = 1;
    char *op;
    struct gc_data_stat gds = {0,};
    int err = 0, sid = 0, column;
    
    hvfs_info(mdsl, "MDSL GC Data Unit Test ...\n");

    /* got the site_id, uuid from user */
    if (argc < 4) {
        hvfs_err(mdsl, "Usage: %s site_id dir_uuid column\n", argv[0]);
        return EINVAL;
    } else {
        sid = atoi(argv[1]);
        duuid = atol(argv[2]);
        column = atoi(argv[3]);
    }

    op = getenv("op");
    if (!op)
        op = "stat";

    hvfs_info(mdsl, "Begin GC Data File %x/%lx/data-%d.\n", HVFS_MDSL(sid),
              duuid, column);
    
    mdsl_init();
    hmo.site_id = HVFS_MDSL(sid);
    mdsl_verify();

    preload_dir(duuid);

    if (strcmp(op, "stat") == 0) {
        err = mdsl_gc_data_stat(duuid, column, &gds);
        if (err) {
            hvfs_err(mdsl, "mdsl_gc_data_stat(%lx) failed w/ %d\n",
                     duuid, err);
            goto out_clean;
        }
        
        hvfs_info(mdsl, "Data File %lx/data-%d: Total %ldB, Valid %ldB, "
                  "Hole %ldB MAX %ldB, PGC Remain %.2f%%, MGC Remain %.2f%%\n",
                  duuid, column, gds.total, gds.valid, gds.hole, gds.max,
                  100 * (double)gds.valid / (double)gds.total,
                  100 * (double)gds.max / (double)gds.total);
    } else if (strcmp(op, "trunc") == 0) {
        err = mdsl_gc_data_by_trunc(duuid, column);
        if (err) {
            hvfs_err(mdsl, "mdsl_gc_data_by_trunc(%lx) faild w/ %d\n",
                     duuid, err);
            goto out_clean;
        }
    }
    
out_clean:
    mdsl_destroy();

    return err;
}
#endif
