/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-31 09:01:11 macan>
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

/* the indirect column for xtable expanding */
#define XTABLE_INDIRECT_COLUMN  (5)

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
    u64 split_rlink;            /* reverse link for COW the spliting ITB */
    struct list_head overflow;  /* overflow list */

    /* section for compression */
    atomic_t len;               /* the actual total length */
    atomic_t zlen;              /* compressed length */
#define COMPR_NONE              (0x00)
#define COMPR_LZO               (0x01)
    u16 compress_algo;

    /* section for itb_index allocation */
    u16 inf;            /* index next free */
    u16 itu;            /* index totally used, not including the first half */

    /* self reference count */
    atomic_t ref;
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
#include "lib.h"

/* region for dtrigger */
#define TRIG_CONTINUE   0
#define TRIG_ABORT      1

typedef int (*DT_MAIN)(u16 where, struct itb *, struct ite *, 
                       struct hvfs_index *, int status, void *dt);

struct dt_ccode
{
    char tmp_file[32];
    void *dlhandle;
    DT_MAIN dtmain;
};

struct dt_python
{
    char tmp_file[32];
    char module[16];
};

struct dir_trigger
{
    /* preconditions
     * Inputs:
     * 1. this itb entry, this ite entry. (So you can get MDU, KV...)
     * 2. the hi index for this operation. (So you can determine whether you
     * should act on it.)
     *
     * Outputs:
     * 1. ABORT or CONTINUE;
     * 2. maybe modified hi index
     * 3. RMU requests
     */
    void *code;

#define DIR_TRIG_NATIVE         0 /* native language */
#define DIR_TRIG_C              1 /* c dynamic binary lib (.so) */
#define DIR_TRIG_PYTHON         2 /* python source code */
    u16 type;

#define DIR_TRIG_NONE           0
#define DIR_TRIG_PRE_FORCE      1
#define DIR_TRIG_POST_FORCE     2
#define DIR_TRIG_PRE_CREATE     3
#define DIR_TRIG_POST_CREATE    4
#define DIR_TRIG_PRE_LOOKUP     5
#define DIR_TRIG_POST_LOOKUP    6
#define DIR_TRIG_PRE_UNLINK     7
#define DIR_TRIG_POST_UNLINK    8
#define DIR_TRIG_PRE_LINKADD    9
#define DIR_TRIG_POST_LINKADD   10
#define DIR_TRIG_PRE_UPDATE     11
#define DIR_TRIG_POST_UPDATE    12
#define DIR_TRIG_PRE_LIST       13
#define DIR_TRIG_POST_LIST      14
#define DIR_TRIG_PRE_ACQUIRE    15
#define DIR_TRIG_POST_ACQUIRE   16
#define DIR_TRIG_PRE_RELEASE    17
#define DIR_TRIG_POST_RELEASE   18
    u16 where;                  /* trigger at where */
    int len;                    /* code length */
};

struct dir_trigger_mgr
{
    int nr;
    struct dir_trigger dt[0];
};

/* APIs */
/* int mds_bitmap_lookup(struct itbitmap *, u64); */
/* u64 mds_bitmap_fallback(u64); */
/* u64 mds_bitmap_cut(u64, u64); */
void mds_bitmap_update(struct itbitmap *, struct itbitmap *);
int mds_bitmap_load(struct dhe *, u64);
void mds_bitmap_refresh(struct hvfs_index *);
void mds_bitmap_refresh_all(u64);
void mds_bitmap_free(struct itbitmap *);
int mds_bitmap_find_next(u64, u64 *);
int __mds_bitmap_insert(struct dhe *, struct itbitmap *);
#define MDS_BITMAP_SET  0x00
#define MDS_BITMAP_CLR  0x01
#define MDS_BITMAP_XOR  0x02
void mds_bitmap_update_bit(struct itbitmap *, u64, u8);
int mds_bitmap_test_bit(struct itbitmap *, u64);
int mds_bitmap_create(struct dhe *, u64, int);

/* Region for fast xtable operations */
/* mds_bitmap_lookup()
 *
 * Test the offset in this slice, return the bit!
 *
 * ABI is the same as test_bit().
 */
static inline
int mds_bitmap_lookup(struct itbitmap *b, u64 offset)
{
    int index = offset - b->offset;

    /* we cant do any ASSERT here :( */
#if 0
    ASSERT((index >= 0 && index < XTABLE_BITMAP_SIZE), mds);
#endif
    return test_bit(index, (u64 *)(b->array));
}

/* mds_bitmap_fallback()
 *
 * Fallback to the next location of ITB
 */
static inline
u64 mds_bitmap_fallback(u64 offset)
{
    int nr = fls64(offset);       /* NOTE: we just use the low 32 bits */

    if (nr < 0)
        return 0;
    __clear_bit(nr, &offset);
    return offset;
}

/* mds_bitmap_cut()
 *
 * Cut the offset to the [0, end_offset) region
 */
static inline
u64 mds_bitmap_cut(u64 offset, u64 end_offset)
{
    u64 mask;
    int nr = fls64(end_offset) + 1;

    if (nr < 0)
        return 0;
    mask = (1UL << nr) - 1;
    offset = offset & mask;

    if (offset < end_offset)
        return offset;
    else {
        return offset - end_offset;
    }
}

#endif
