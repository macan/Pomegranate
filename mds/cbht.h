/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-14 16:16:07 macan>
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

/* one segment can hold near 1M CBHT buckets */
struct segment
{
    struct list_head list;
    u64 offset;
    u32 alen;                   /* allocated length */
    u32 len;                    /* current length */
    void *seg;                  /* allocate exponently, base is 128KB(16K
                                 * entries) */
};

struct bucket_entry 
{
    struct hlist_head h;
    /*
     * Note: wlock for ITB add/del, rlock for other operations
     */
    xrwlock_t lock;
};

struct bucket
{
    atomic_t active;
    atomic_t conflicts;
#define BUCKET_FREE     0x00
#define BUCKET_SPLIT    0x01
    u16 state;
    u16 adepth;                   /* allocated depth */
    atomic_t depth;               /* current depth */
    u64 id;                       /* bucket id */
    /*
     * Note: wlock for bucket split, rlock for other operations
     */
    xrwlock_t lock;
    struct bucket_entry *content; /* store of bucket_entry */
};

struct eh
{
    struct list_head dir;       /* EH directory */
    /*
     * Note: wlock for segment expanding, rlock for other operations
     */
    xrwlock_t lock;             /* protect segment list */
    u32 dir_depth;              /* depth of the directory */
    u32 bucket_depth;           /* the size of each bucket */
};

#endif
