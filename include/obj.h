/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-14 10:47:02 macan>
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

#ifndef __HVFS_OSD_H__
#define __HVFS_OSD_H__

struct objid
{
    u64 uuid;
    u32 bid;
    u32 len;
};

#define OBJID_EQUAL(a, b) ({                    \
            int __res;                          \
            if ((a).uuid == (b).uuid &&         \
                (a).bid == (b).bid)             \
                __res = 1;                      \
            else                                \
                __res = 0;                      \
            __res;                              \
        })

struct osd_list
{
    int size;
    u64 site[0];
};

/* OM type in om_init() */
#define HVFS_OM_TYPE_MASTER     0x01
#define HVFS_OM_TYPE_BACKUP     0x02

/* Object report */
struct obj_report_tx
{
    /* 
     * if add_size < 0, then replace the old objids w/ current array
     */
    int add_size, rmv_size;
    struct objid ids[0];
};

#endif
