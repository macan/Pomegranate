/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-08-22 12:39:05 macan>
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
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "mds.h"
#include "lib.h"

int main(int argc, char *argv[])
{
    int err = 0;
    int offset;
    u64 a = XTABLE_BITMAP_SIZE;
    u8 bitmap[1 << (ITB_DEPTH - 3)];
    long nr;
    atomic_t i;

    hvfs_info(mds, "ITB Size: %ld B\n", 
              sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
    hvfs_info(mds, "ITB Structure Size: %ld B\n", sizeof(struct itb));
    hvfs_info(mds, "ITB Header Size: %ld B\n", sizeof(struct itbh));
    hvfs_info(mds, "ITE Size: %ld B\n",
              sizeof(struct ite));
    hvfs_info(mds, "TXG Size: %ld B\n", sizeof(struct hvfs_tx));
    hvfs_info(mds, "HI  Size: %ld B\n", sizeof(struct hvfs_index));
    hvfs_info(mds, "HMR Size: %ld B\n", sizeof(struct hvfs_md_reply));
    hvfs_info(mds, "MDU Size: %ld B\n", sizeof(struct mdu));
    hvfs_info(mds, "LS  Size: %ld B\n", sizeof(struct link_source));
    hvfs_info(mds, "MD+ Size: %ld B\n", HVFS_MDU_SIZE);
    hvfs_info(mds, "KV+ Size: %d B\n", XTABLE_VALUE_SIZE);
    hvfs_info(mds, "DH  Size: %ld B\n", sizeof(struct dh));
    hvfs_info(mds, "MP  Size: %ld B\n", sizeof(struct mds_prof));
    hvfs_info(mds, "MC  Size: %ld B\n", sizeof(struct mds_conf));
    hvfs_info(mds, "CBD Offt: %ld B\n", offsetof(struct hvfs_mds_object, 
                                                 branch_dispatch));
    hvfs_info(mds, "MTX Size: %ld B\n", sizeof(struct xnet_msg_tx));
    hvfs_info(mds, "MSG Size: %ld B\n", sizeof(struct xnet_msg));

    offset = fls64(a);
    hvfs_info(mds, "[FLS64]: First set bit in 0x%lx is %d.\n", a, offset);
    offset = fls(a);
    hvfs_info(mds, "[FLS  ]: First set bit in 0x%lx is %d.\n", a, offset);

    /* redo region */
    hvfs_info(mds, "RLSD Size %ld B, name offset %ld\n",
              sizeof(struct redo_log_site_disk),
              offsetof(struct redo_log_site_disk, u.rlc.hi.name));

    /* find first zero bit */
    atomic_set(&i, 0);
    memset(bitmap, 0, sizeof(bitmap));
    while (atomic_inc_return(&i) <= 1024) {
    retry:
        nr = find_first_zero_bit((unsigned long *)bitmap, (1 << ITB_DEPTH));
        if (nr < (1 << ITB_DEPTH)) {
            if (lib_bitmap_tas(bitmap, nr)) {
                goto retry;
            }
            if (nr == 0)
                hvfs_info(mds, "nr can be zero.\n");
        } else {
            hvfs_info(mds, "nr %ld\n", nr);
        }
    }

    int j, l;
    char line[1024];
    memset(line, 0, sizeof(line));
    for (j = 0, l = 0; j < (1 << (ITB_DEPTH - 3)); j++) {
        l += sprintf(line + l, "%x", bitmap[j]);
    }
    hvfs_err(mds, "Bitmap [%s]\n", line);

    /* test mds ev */
    mds_pre_init();
    mds_config();
    /* Note, mds_verify() call be called w/o mds_init() */
    /* mds_verify(); */
    hvfs_info(mds, "memlimit is %ld\n", hmo.conf.memlimit);

    /* test bitmap delta */
    u64 oitb = 0, nitb = 0;
    struct hvfs_txg txg = {0, };

    xlock_init(&txg.bdb_lock);
    INIT_LIST_HEAD(&txg.bdb);
    
    for (j = 0; j < 10000; j++) {
        err = mds_add_bitmap_delta(&txg, hmo.site_id, 1, oitb, nitb + j);
        if (err) {
            hvfs_err(mds, "add bitmap delta %ld %ld failed\n", oitb, nitb);
            break;
        }
    }
    mds_init(10);
    hvfs_info(mds, "TXG ddht size: %d\n", hmo.conf.txg_ddht_size);
    hvfs_info(mds, "TXG Size: %ld B\n", sizeof(struct hvfs_tx) + 
              hmo.conf.txg_ddht_size * sizeof(struct regular_hash));

    {
        u64 mask;
        int nr = fls64(XTABLE_BITMAP_SIZE);

        if (nr < 0)
            hvfs_info(mds, "ZERO!\n");

        mask = (1 << nr) - 1;
        hvfs_info(mds, "result %ld \n", 2096896 & mask);
    }

    {
        u64 offset = 1000;
        hvfs_info(mds, "offset %ld roundup %ld\n", offset,
                  BITMAP_ROUNDUP(offset));
        hvfs_info(mds, "offset %ld rounddown %ld\n", offset,
                  BITMAP_ROUNDDOWN(offset));

        offset = XTABLE_BITMAP_SIZE - 1;
        hvfs_info(mds, "offset %ld roundup %ld\n", offset,
                  BITMAP_ROUNDUP(offset));
        hvfs_info(mds, "offset %ld rounddown %ld\n", offset,
                  BITMAP_ROUNDDOWN(offset));

        offset = XTABLE_BITMAP_SIZE;

        hvfs_info(mds, "offset %ld roundup %ld\n", offset,
                  BITMAP_ROUNDUP(offset));
        hvfs_info(mds, "offset %ld rounddown %ld\n", offset,
                  BITMAP_ROUNDDOWN(offset));

        offset = XTABLE_BITMAP_SIZE + 100;
        hvfs_info(mds, "offset %ld roundup %ld\n", offset,
                  BITMAP_ROUNDUP(offset));
        hvfs_info(mds, "offset %ld rounddown %ld\n", offset,
                  BITMAP_ROUNDDOWN(offset));
        offset = 1439283;
        hvfs_info(mds, "offset %ld rounddown %ld\n", offset,
                  BITMAP_ROUNDDOWN(offset));
    }

    {
        u64 offset = 17179869188;
        u64 size = 2147614720;
        int nr = fls64(size << 3) + 1;
        u64 mask = (1UL << nr) - 1;

        hvfs_info(mds, "%lx %lx %lx nr %d\n", offset, size << 3, mask, nr);
        hvfs_info(mds, "CUT OFF %ld to %ld\n", offset,
                  mds_bitmap_cut(offset, size << 3));

        offset = XTABLE_BITMAP_SIZE + 100;
        size = XTABLE_BITMAP_BYTES;
        nr = fls64(size << 3) + 1;
        mask = (1UL << nr) - 1;
        hvfs_info(mds, "%lx %lx %lx nr %d\n", offset, size << 3, mask, nr);
        hvfs_info(mds, "CUT OFF %ld to %ld\n", offset,
                  mds_bitmap_cut(offset, size << 3));

        offset = XTABLE_BITMAP_SIZE - 1;
        size = XTABLE_BITMAP_BYTES;
        hvfs_info(mds, "CUT OFF %ld to %ld\n", offset,
                  mds_bitmap_cut(offset, size << 3));
        
    }

    {
        int nr = 100;
        struct conf_site cs[nr];

        err = conf_parse(NULL, cs, &nr);
        if (err) {
            hvfs_err(mds, "conf_parse failed w/ %d\n", err);
        }
    }

    {
        u64 snr;
        u64 offset = 128 * 1024 * 8 * 3 + 1509;

        snr = BITMAP_ROUNDDOWN(offset) >> 17 >> 3;
        
        hvfs_info(mds, "offset %ld snr %ld refined %ld\n", 
                  offset, snr, offset - XTABLE_BITMAP_SIZE * snr);
    }

    return err;
}
