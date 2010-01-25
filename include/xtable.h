/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 20:25:50 macan>
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
/* #warning "You have NOT define the ITB_DEPTH, we default it to 1024 entries." */
#define ITB_DEPTH       10
#endif

#ifndef ITB_LOCK_GRANULARITY
/* #warning "You have NOT define the ITB_LOCK_GRANULARITY, default it to 16." */
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
#define ITB_STATE_COWED 0x03
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
#ifdef _USE_SPINLOCK
    xspinlock_t ilock;          /* index alloc/freelock; max_offset
                                 * changing */
#else
    xlock_t ilock;              /* index alloc/free lock; max_offset
                                 * changing! */
#endif

    /* section for searching in ITB */
    u64 puuid;
    u64 itbid;
    u64 hash;                   /* hash value of cbht */

    void *be;                   /* bucket_entry myself attatched to */
    struct hlist_node cbht;
    struct list_head list;      /* link into the lru list/dirty list */
    struct list_head unlink;    /* link into the unlink list */

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
#define ITB_COW_BITMAP_LEN (sizeof(u8) * (1 << (ITB_DEPTH - 3)))
#define ITB_COW_INDEX_LEN (sizeof(struct itb_index) * (2 << ITB_DEPTH))
struct itb 
{
    /* NOTE: do NOT move the struct itbh! */
    struct itbh h;
    struct itb_lock lock[(1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY];
    u8 bitmap[1 << (ITB_DEPTH - 3)];
    struct itb_index index[2 << (ITB_DEPTH)]; /* double size */
    struct ite ite[0];
};

struct itbitmap
{
    struct list_head list;
    u64 offset:56;
#define BITMAP_END      0x80    /* means there is no slice after this slice */
    u64 flag:8;
    u64 ts;
#define XTABLE_BITMAP_SIZE      (128 * 1024 * 8) /* default is 128K */
    u8 array[XTABLE_BITMAP_SIZE / sizeof(u8)];
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

#include "dh.h"
/* APIs */
int mds_bitmap_lookup(struct itbitmap *, u64);
u64 mds_bitmap_fallback(u64);
void mds_bitmap_update(struct itbitmap *, struct itbitmap *);
int mds_bitmap_load(struct dhe *, u64);
void mds_bitmap_free(struct itbitmap *);
int __mds_bitmap_insert(struct dhe *, struct itbitmap *);

#endif
