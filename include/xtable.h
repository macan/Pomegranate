/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 19:21:43 macan>
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

#define ITB_SIZE        (2 << ITB_DEPTH)

/* ITB header */
struct itbh 
{
#define ITB_ACTIVE      0x00
#define ITB_SHADOW      0x01
#define ITB_JUST_SPLIT  0x02
#define ITB_SNAPSHOT    0x03
    u8 flag;
#define ITB_STATE_FREE  0x00
#define ITB_STATE_WB    0x01
#define ITB_STATE_WBED  0x02
#define ITB_STATE_COWED 0x03
    u8 state;
    u8 depth;                   /* local depth, true depth */
    u8 adepth;                  /* allocated depth, or size of ITB, original
                                 * length */
    u16 entries;                /* current used entries */
    u16 max_offset;             /* the max offset of ITE, for snip */
    u16 conflicts;              /* current conflict entries */
    u16 pseudo_conflicts;       /* current pseudo conflict entries */

    /* section for compression */
    u16 compress_algo;
    u32 len;                    /* the actual total length */

    /* section for TXG */
    u64 txg;                    /* txg of the latest update */
    xrwlock_t lock;

    /* section for searching in ITB */
    u64 puuid;
    u64 itbid;
    struct list_head cbht;

    /* section for self index */
    void *storage;
};

/* ITB index entry */
#if ITB_DEPTH <= 16
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
    u8 bitmap[2 << (ITB_DEPTH - 3)];
    struct itb_lock lock[(2 << ITB_DEPTH) / ITB_LOCK_GRANULARITY];
    struct itb_index index[2 << (ITB_DEPTH + 1)];
    struct ite ite[0];
};

#endif
