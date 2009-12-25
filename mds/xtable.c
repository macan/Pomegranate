/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-25 22:52:26 macan>
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
#include "mds.h"

/* ITB split
 *
 * NOTE: 
 */
int itb_split(struct itb *oi, struct itb **ni)
{
    int err = 0;

    return err;
}

/* ITB overflow
 *
 * NOTE:
 */
int itb_overflow(struct itb *oi, struct itb **ni)
{
    int err = 0;

    return err;
}

/* mds_bitmap_lookup()
 *
 * Test the offset in this slice, return the bit!
 */
int mds_bitmap_lookup(struct itbitmap *b, u64 offset)
{
    int index = offset - b->offset;

    ASSERT((index >= 0 && index < XTABLE_BITMAP_SIZE), mds);
    return test_bit(index, b->array);
}

/* mds_bitmap_fallback()
 *
 * Fallback to the next location of ITB
 */
u64 mds_bitmap_fallback(u64 offset)
{
    int nr = ffs(&offset);

    if (!nr)
        return 0;
    __clear_bit(nr, &offset);
    return offset;
}

/* mds_bitmap_load()
 *
 * Return Value: -ENOEXIST means the slice is not exist!
 */
int mds_bitmap_load(struct dh *dh, struct hvfs_index *hi, u64 offset)
{
    struct hvfs_index ghi;
    struct hvfs_md_reply *hmr;
    struct xnet_msg *msg;
    struct chp *p;
    int err;
    
    /* prepare the arguments for GDT lookup */
    ghi.flag = 
}

