/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-02 16:22:16 macan>
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
    struct timeval open_time;
    atomic64_t tx_pending;
    u64 txg;
    u64 txmax;
    u16 state;
    xlock_t ckpt_lock, delta_lock, itb_lock;
    struct hvfs_rmds_ckpt_buf *ckpt; /* ckpt list */
    struct hvfs_dir_delta_buf *delta; /* dir delta's list */
    struct bitmap_delta *bda;         /* array of bitmap deltas */
    struct list_head dirty_list;
};

#endif
