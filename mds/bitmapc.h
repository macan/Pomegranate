/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-27 22:12:13 macan>
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

#ifndef __MDS_BITMAPC_H__
#define __MDS_BITMAPC_H__

#include "hvfs.h"

struct bitmap_cache
{
    struct regular_hash *bcht;
    struct list_head lru;
    xlock_t lock;
    int hsize;
    atomic_t total;
    atomic_t free;
};

struct bc_entry
{
    struct hlist_node hlist;
    struct list_head list;
    u64 uuid;
    u64 offset;
    atomic_t ref;
    u8 array[XTABLE_BITMAP_SIZE / 8];
};

static inline
struct bc_entry *mds_bc_alloc(void)
{
    struct bc_entry *be;

    be = xzalloc(sizeof(*be));
    if (!be) {
        return NULL;
    }
    INIT_HLIST_NODE(&be->hlist);
    INIT_LIST_HEAD(&be->list);

    return be;
}

static inline
void mds_bc_free(struct bc_entry *be)
{
    xfree(be);
}

#endif
