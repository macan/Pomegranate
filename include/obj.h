/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2013-01-04 14:50:52 macan>
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

#define OBJID_VERSION_BITS      20
#define OBJID_MAX_VERSION       ((1 << OBJID_VERSION_BITS) - 1)
/* check if the new version is valid respect to old version */
#define OBJID_VERSION_CHECK(old, new) ({                            \
            int __res = 0;                                          \
            int __tmp = new - old;                                  \
            if (__tmp >= 0) {                                       \
                if (__tmp <= (1 << (OBJID_VERSION_BITS - 1))) {     \
                    __res = 1;                                      \
                }                                                   \
            } else {                                                \
                if (-__tmp >= (1 << (OBJID_VERSION_BITS - 1))) {    \
                    __res = 1;                                      \
                }                                                   \
            }                                                       \
            __res;                                                  \
        })

#define OBJID_VERSION_NEWER OBJID_VERSION_CHECK

struct objid
{
    u64 uuid;
    u32 bid;                    /* max blocks is 4G */
    u32 len;                    /* max object size is 4GB */
    u32 crc;
    u32 version:20;             /* max version 1M */
#define OBJID_CONSISTENCY_SAFE  0x00
#define OBJID_CONSISTENCY_ONE   0x01
#define OBJID_CONSISTENCY_TWO   0x02
#define OBJID_CONSISTENCY_THREE 0x03
    /* ... up to 14 copy */
#define OBJID_CONSISTENCY_ALL   0x0f
    u32 consistency:4;          /* consistency value */
    u32 sweeped:1;              /* is sweeped region */
    u32 error:1;                /* in error state */
#define OBJID_STATE_NORM        0x00
#define OBJID_STATE_FIX         0x01
#define OBJID_STATE_CONFLICT    0x02
    u32 state:2;
};

struct objid_dev
{
    struct objid id;
    int dev;
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
    struct objid id;            /* this might be an updated objid */
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
