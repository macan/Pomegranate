/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 19:06:45 macan>
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

#ifndef __CBHT_H__
#define __CBHT_H__

/* one segment can hold 1M CBHT buckets */
struct segment
{
    struct list_head list;
    xlock_t lock;
    u64 offset;
    u32 alen;                   /* allocated length */
    u32 len;                    /* current length */
    void *seg[6];               /* allocate exponently, base is 128KB(16K
                                 * entries) */
};

struct bucket_entry 
{
    struct hlist_head h;
    xrwlock_t lock;
};

struct bucket
{
    u32 active;
    u32 conflicts;
    u16 adepth;                 /* allocated depth */
    u16 depth;                  /* current depth */
    u32 pad2;
    struct bucket_entry *content; /* store of bucket_entry */
};

struct eh
{
    struct list_head dir;       /* EH directory */
    xlock_t lock;
    u32 dir_depth;              /* depth of the directory */
    u32 bucket_depth;           /* the size of each bucket */
};

#endif
