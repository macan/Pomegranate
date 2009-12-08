/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-08 10:35:40 macan>
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

#ifndef __XTABLE_H__
#define __XTABLE_H__

#ifndef ITB_DEPTH
#warning "You have NOT define the ITB_DEPTH, we default it to 1024 entries."
#define ITB_DEPTH       10
#endif

#ifndef ITB_LOCK_GRANULARITY
#warning "You have NOT define the ITB_LOCK_GRANULARITY, default it to 16."
#define ITB_LOCK_GRANULARITY    16
#endif

#define ITB_SIZE        (1 << ITB_DEPTH)

/* ITB header */
struct itbh 
{
#define ITB_ACTIVE      0x00
#define ITB_SHADOW      0x01
#define ITB_JUST_SPLIT  0x02
#define ITB_SNAPSHOT    0x03
    u8 flag;
#define ITB_STATE_CLEAN 0x00
#define ITB_STATE_DIRTY 0x01
#define ITB_STATE_WBED  0x02
    u8 state;

    u8 depth;                   /* local depth, true depth */
    u8 adepth;                  /* allocated depth, or size of ITB, original
                                 * length */
    atomic_t entries;           /* current used entries */
    atomic_t max_offset;        /* the max offset of ITE, for snip */
    atomic_t conflicts;         /* current conflict entries */
    atomic_t pseudo_conflicts;  /* current pseudo conflict entries */

    /* section for TXG */
    u64 txg;                    /* txg of the latest update */
    xrwlock_t lock;             /* access/evict lock */

    /* section for searching in ITB */
    u64 puuid;
    u64 itbid;
    u64 hash;                   /* hash value of cbht */

    void *be;                   /* bucket_entry myself attatched to */
    struct hlist_node cbht;
    struct list_head list;

    u64 twin;                   /* twin ITB */
    struct list_head overflow;  /* overflow list */

    /* section for compression */
    atomic_t len;               /* the actual total length */
    u16 compress_algo;

    /* section for itb_index allocation */
    u16 inf;            /* index next free */
    u16 itu;            /* index totally used, not including the first half */
};

/* ITB index entry */
#define ITB_INDEX_FREE          0x00
#define ITB_INDEX_UNIQUE        0x01
#define ITB_INDEX_CONFLICT      0x02
#define ITB_INDEX_OVERFLOW      0x03
#if ITB_DEPTH <= 14
struct itb_index 
{
    u32 entry:15;
    u32 conflict:15;
    u32 flag:2;
};
#else
struct itb_index
{
    u64 entry:31;
    u64 conflict:31;
    u64 flag:2;
};
#endif

struct itb_lock 
{
    char l[56];
};

#include "hvfs_common.h"        /* for mdu */
#include "ite.h"                /* for ite */

/* ITB defination */
struct itb 
{
    /* NOTE: do NOT move the struct itbh! */
    struct itbh h;
    u8 bitmap[1 << (ITB_DEPTH - 3)];
    struct itb_lock lock[(1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY];
    struct itb_index index[2 << (ITB_DEPTH)]; /* double size */
    struct ite ite[0];
};

struct checkpoint 
{
    u64 site_id;                /* remote site, virtual */
    u64 txg;                    /* committed/acked remote txg */
    u32 type;                   /* bitmap/metadata */
};

struct bce
{
    struct itbitmap *b;
    u64 uuid;
};

struct bc
{
    struct regular_hash *bcht;
    int size;                   /* size of the hash table */
    int entries;                /* # of itbitmaps */
};

/* saved by changer to MDSL */
struct bitmap_delta
{
    u64 site_id;
    u64 uuid;
    u64 oitb;                   /* piggyback SPLIT/MERGE info in low bits */
    u64 nitb;
};

#endif
