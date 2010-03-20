/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-19 15:30:24 macan>
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
#include "mdsl_api.h"

struct hvfs_dir_delta 
{
    u64 site_id;
    u64 duuid;
    s64 nlink;                  /* not enough? now enough! */
    u64 atime;
    u64 ctime;
};

#define HVFS_MDSL_TXG_BUF_LEN   (512)
struct hvfs_dir_delta_buf 
{
    struct list_head list;
    int psize, asize;
    struct hvfs_dir_delta buf[0];
};

struct hvfs_rmds_ckpt_buf 
{
    struct list_head list;
    int psize, asize;
    struct checkpoint buf[0];
};

struct bitmap_delta_buf
{
    struct list_head list;
    int psize, asize;
    struct bitmap_delta buf[0];
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

    xlock_t ckpt_lock, ddb_lock, bdb_lock, ccb_lock, itb_lock;
    struct list_head ckpt;      /* hvfs_rmds_ckpt_buf list, for ckpt
                                 * entries */
    struct list_head ddb;       /* hvfs_dir_delta_buf list, for dir deltas */
    struct list_head bdb;       /* bitmap_delta_buf list, for bitmap deltas */
    
    struct list_head dirty_list;      /* dirty list of ITBs */
    struct list_head ccb_list;        /* commit callback list */
};

#define TXG_SET_DIRTY(txg) do { \
        (txg)->dirty = 1;       \
    } while (0)
#define TXG_IS_DIRTY(txg) ((txg)->dirty)

/* the following regions is designed for commit threads */
struct txg_wb_slice
{
    struct hlist_node hlist;
    struct list_head list;
    u64 site_id;
    u32 len;                    /* only for the itb length? */
    u32 nr;
#define TWS_NEW         0x0001
    u32 flag;
};

#define HVFS_TXG_WB_SITE_HTSIZE         512
struct commit_thread_arg
{
    int tid;                    /* thread id */
    /* the following region is designed for TXG Write-back */
    struct hvfs_txg *wbt;       /* txg to writeback */
    struct regular_hash siteht[HVFS_TXG_WB_SITE_HTSIZE];
    struct list_head tws_list;
    struct txg_begin begin;
};

static inline
void CTA_INIT(struct commit_thread_arg *cta, struct hvfs_txg *txg)
{
    int i;
    
    cta->wbt = txg;
    INIT_LIST_HEAD(&cta->tws_list);
    for (i = 0; i < HVFS_TXG_WB_SITE_HTSIZE; i++) {
        INIT_HLIST_HEAD(&cta->siteht[i].h);
        xlock_init(&cta->siteht[i].lock);
    }
}

static inline
void CTA_FINA(struct commit_thread_arg *cta)
{
    int i;

    /* free siteht */
    if (!list_empty(&cta->tws_list)) {
        struct txg_wb_slice *pos, *n;
        
        list_for_each_entry_safe(pos, n, &cta->tws_list, list) {
            list_del(&pos->list);
            xfree(pos);
        }
    }

    for (i = 0; i < HVFS_TXG_WB_SITE_HTSIZE; i++) {
        xlock_destroy(&cta->siteht[i].lock);
    }
}

static inline
struct txg_wb_slice *tws_lookup(struct commit_thread_arg *cta, u64 dsite)
{
    struct txg_wb_slice *tws = NULL;
    struct hlist_node *pos;
    u32 i;

    i = hvfs_hash_tws(dsite) % HVFS_TXG_WB_SITE_HTSIZE;
    hlist_for_each_entry(tws, pos, &cta->siteht[i].h, hlist) {
        if (tws->site_id == dsite) {
            break;
        }
    }

    return tws;
}

static inline
void tws_insert(struct commit_thread_arg *cta, struct txg_wb_slice *tws)
{
    u32 i;

    i = hvfs_hash_tws(tws->site_id) % HVFS_TXG_WB_SITE_HTSIZE;
    hlist_add_head(&tws->hlist, &cta->siteht[i].h);
    list_add_tail(&tws->list, &cta->tws_list);
}

static inline
struct txg_wb_slice *tws_create(u64 site)
{
    struct txg_wb_slice *tws = xzalloc(sizeof(*tws));
    if (!tws) {
        HVFS_VV("Create TWS failed.\n");
        return ERR_PTR(-ENOMEM);
    }
    INIT_HLIST_NODE(&tws->hlist);
    INIT_LIST_HEAD(&tws->list);
    tws->site_id = site;
    tws->flag |= TWS_NEW;
    return tws;
}

#define IS_TWS_NEW(tws) ((tws)->flag & TWS_NEW)

static inline
void TWS_CLEAN_NEW(struct txg_wb_slice *tws)
{
    tws->flag &= (~TWS_NEW);
}

static inline
void TWS_SET_NEW(struct txg_wb_slice *tws)
{
    tws->flag |= TWS_NEW;
}

static inline
struct txg_wb_slice *tws_find_create(struct commit_thread_arg *cta, u64 dsite)
{
    struct txg_wb_slice *tws;

    tws = tws_lookup(cta, dsite);
    if (!tws) {
        tws = tws_create(dsite);
        if (IS_ERR(tws)) {
            tws = NULL;
        }
        /* insert in to the hash table */
        tws_insert(cta, tws);
    }
    return tws;
}

#endif
