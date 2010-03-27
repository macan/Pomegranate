/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-27 22:23:24 macan>
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

#include "hvfs.h"
#include "xnet.h"
#include "mds.h"

#define MDS_BC_HASH_SIZE_DEFAULT        (512)

int mds_bitmap_cache_init(void)
{
    int i;
    
    if (!hmo.conf.bc_hash_size) {
        hmo.conf.bc_hash_size = MDS_BC_HASH_SIZE_DEFAULT;
    }

    hmo.bc.hsize = hmo.conf.bc_hash_size;
    INIT_LIST_HEAD(&hmo.bc.lru);
    xlock_init(&hmo.bc.lock);

    hmo.bc.bcht = xzalloc(hmo.bc.hsize * sizeof(struct regular_hash));
    if (!hmo.bc.bcht) {
        hvfs_err(mds, "xzalloc BC.bcht failed.\n");
        return -ENOMEM;
    }
    for (i = 0; i < hmo.bc.hsize; i++) {
        INIT_HLIST_HEAD(&(hmo.bc.bcht + i)->h);
        xlock_init(&(hmo.bc.bcht + i)->lock);
    }

    return 0;
}

void mds_bitmap_cache_destroy(void)
{
    if (hmo.bc.bcht)
        xfree(hmo.bc.bcht);
}

static inline
int mds_bc_hash(u64 key1, u64 key2, int size)
{
    u64 val1, val2;

    val1 = hash_64(site_id, 64);
    val2 = hash_64(reqno, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1 % size;         /* FIXME: need more faster! */
}

/* mds_bc_get() lookup and got the reference of the bc_entry, you should put
 * the refer down after using.
 */
struct bc_entry *mds_bc_get(u64 uuid, u64 offset)
{
    struct regular_hash *rh;
    struct bc_entry *be;
    struct hlist_node *n;
    int idx, found = 0;
    
    if (offset & (XTABLE_BITMAP_SIZE - 1)) {
        return ERR_PTR(-EINVAL);
    }

    idx = mds_bc_hash(uuid, offset, hmo.bc.hsize);
    rh = hmo.bc.bcht + idx;

    xlock_lock(&rh->lock);
    list_for_each_entry(be, n, &rh->h, hlist) {
        if (likely(be->uuid == uuid && be->offset == offset)) {
            found = 1;
            atomic_inc(&be->ref);
            /* move the tail of lru list */
            list_del_init(&be->list);
            list_add_tail(&be->list, &hmo.bc.lru);
            break;
        }
    }
    xlock_unlock(&rh->lcok);

    if (found) {
        return be;
    } else
        return ERR_PTR(-ENOENT);
}

void mds_bc_put(struct bc_entry *be)
{
    atomic_dec(&be->ref);
}

int mds_bc_backend_load()
{
    int err = 0;
    
    return err;
}
