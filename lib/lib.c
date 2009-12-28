/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-28 11:05:26 macan>
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

#include "lib.h"
#include "mds_api.h"
#include "ite.h"

#ifdef HVFS_TRACING
//u32 hvfs_lib_tracing_flags = HVFS_DEFAULT_LEVEL | HVFS_DEBUG_ALL;
u32 hvfs_lib_tracing_flags = HVFS_DEFAULT_LEVEL;
#endif

#ifdef HVFS_DEBUG_LOCK
struct list_head glt;           /* global lock table */
#endif

void lib_init(void)
{
    srandom(time(NULL));
}

u64 lib_random(int hint)
{
    return random() % hint;
}

/**
 *  This function should be used for hmr parsing
 *
 * @region: this is the hmr data region
 * @flag: which subregion you want to extract
 * @num: # of entries in this subregion
 * 
 * return the subregion pointer to access
 */
void *hmr_extract(void *region, int flag, int *num)
{
    struct hvfs_md_reply *hmr = (struct hvfs_md_reply *)region;
    int doffset = sizeof(struct hvfs_md_reply);

    if (flag & EXTRACT_HI) {
        if (hmr->flag & MD_REPLY_WITH_HI) {
            *num = 1;
            return region + doffset;
        } else {
            return NULL;
        }
    } else if (flag & EXTRACT_MDU) {
        if (hmr->flag & MD_REPLY_WITH_MDU) {
            *num = hmr->mdu_no;
            if (hmr->flag & MD_REPLY_WITH_HI) {
                doffset += sizeof(struct hvfs_index);
            }
            return region + doffset;
        } else {
            return NULL;
        }
    } else if (flag & EXTRACT_LS) {
        if (hmr->flag & MD_REPLY_WITH_LS) {
            *num = hmr->ls_no;
            if (hmr->flag & MD_REPLY_WITH_HI) {
                doffset += sizeof(struct hvfs_index);
            }
            if (hmr->flag & MD_REPLY_WITH_MDU) {
                doffset += (HVFS_MDU_SIZE * hmr->mdu_no);
            }
            return region + doffset;
        } else {
            return NULL;
        }
    } else if (flag & EXTRACT_BITMAP) {
        if (hmr->flag & MD_REPLY_WITH_BITMAP) {
            *num = hmr->bitmap_no;
            if (hmr->flag & MD_REPLY_WITH_HI) {
                doffset += sizeof(struct hvfs_index);
            }
            if (hmr->flag & MD_REPLY_WITH_MDU) {
                doffset += (HVFS_MDU_SIZE * hmr->mdu_no);
            }
            if (hmr->flag & MD_REPLY_WITH_LS) {
                doffset += (sizeof(struct link_source) * hmr->ls_no);
            }
            return region + doffset;
        } else {
            return NULL;
        }
    }
    return NULL;
}

