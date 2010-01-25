/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 08:51:22 macan>
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

#ifndef __HVFS_TXG_H__
#define __HVFS_TXG_H__

#include "hvfs.h"
#include "xtable.h"

struct hvfs_dir_delta 
{
    u64 site_id;
    u64 duuid;
    s32 nlink;                  /* no enough? */
    u64 atime;
    u64 ctime;
};

struct hvfs_dir_delta_buf 
{
    struct list_head list;
    int psize, asize;
    struct hvfs_dir_delta *buf;
};

struct hvfs_rmds_ckpt_buf 
{
    struct list_head list;
    int psize, asize;
    struct checkpoint buf;
};

struct hvfs_txg 
{
    time_t open_time;
    atomic64_t tx_pending;
    mcond_t cond;               /* semaphore for condition wait */
    u64 txg;
    u64 txmax;
#define TXG_STATE_OPEN          0
#define TXG_STATE_WB            1 /* begin WB, waiting for pending TXs */
#define TXG_STATE_WBING         2 /* in WB, all pending TXs are done, ITB are
                                   * free to use */
    u8 state;
    u8 dirty;                   /* whether this txg is dirtied, using in the
                                 * SIGALARM handler to changing txg. */
    xlock_t ckpt_lock, delta_lock, itb_lock, ccb_lock;
    struct hvfs_rmds_ckpt_buf *ckpt;  /* ckpt list */
    struct hvfs_dir_delta_buf *delta; /* dir delta's list */
    struct bitmap_delta *bda;         /* array of bitmap deltas */
    struct list_head dirty_list;      /* dirty list of ITBs */
    struct list_head ccb_list;        /* commit callback list */
};

#define TXG_SET_DIRTY(txg) do { \
        (txg)->dirty = 1;       \
    } while (0)
#define TXG_IS_DIRTY(txg) ((txg)->dirty)

/* the following regions is designed for commit threads */
struct commit_thread_arg
{
    int tid;                    /* thread id */
};

#endif
