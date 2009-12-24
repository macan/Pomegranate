/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-24 15:39:51 macan>
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
#include "xtable.h"
#include "mds.h"

/* mds_dh_init()
 *
 * NOTE: we do not provide any fast allocation
 */
int mds_dh_init(struct dh *dh, int hsize)
{
    int err, i;
    
    /* regular hash init */
    hsize = (hsize == 0) ? MDS_DH_DEFAULT_SIZE : hsize;
    dh->ht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!dh->ht) {
        hvfs_err(mds, "DH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i <hsize; i++) {
        INIT_HLIST_HEAD(&dh->ht[i].h);
        xlock_init(&dh->ht[i].lock);
    }
out:
    return err;
}

void mds_dh_destroy(struct dh *dh)
{
    if (dh->ht)
        xfree(dh->ht);
}

/* mds_dh_load()
 */
struct dhe *mds_dh_load(struct dh *dh, struct hvfs_index *hi)
{
    struct dhe *e;
    return e;
}

/* mds_dh_search() may block on dh_load
 *
 * Search in the DH(dir hash) to find the dir entry which contains
 * bitmap/salt/... etc
 *
 * NOTE: for now, we do NOT evict any dh entries. If the memory is low, we
 * first try to free the bitmap slices.
 */
struct dhe *mds_dh_search(struct dh *dh, struct hvfs_index *hi)
{
    struct dhe *e;
    struct regular_hash *rh;
    struct hlist_node *l;
    int i, found = 0;

    i = mds_dh_hash(hi->puuid);
    rh = dh->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(e, l, &rh->h, hlist) {
        if (e->uuid == hi->puuid) {
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (unlikely(!found)) {
        /* Hoo, we have not found the directory. We need to request the
         * directory information from the GDT server */
        e = mds_dh_load(dh, hi);
        if (IS_ERR(e)) {
            hvfs_err(mds, "Hoo, loading DH %ld failed\n", hi->puuid);
            goto out;
        }
    }

    /* OK, we have get the dh entry, just return it */
out:
    return e;
}

/* mds_get_itbid() may block on bitmap load
 *
 * Convert the hash to itbid by lookup the bitmap
 */
u64 mds_get_itbid(struct dhe *e, u64 hash)
{
    struct itbitmap *b;
    u64 offset = hash >> ITB_DEPTH;
    int found = 0;

retry:
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
        if (b->offset <= offset && offset < b->offset + XTABLE_BITMAP_SIZE) {
            /* ok, we get the bitmap slice, let us test it */
            if (mds_bitmap_lookup(b, offset)) {
                xlock_unlock(&e->lock);
                return offset;
            } else {
                /* hoo, we should reset the offset and restart the access */
                xlock_unlock(&e->lock);
                offset = mds_bitmap_fallback(offset);
                goto retry;
            }
        } else if (b->offset > offset) {
            /* it means that we need to load the missing slice */
            xlock_unlock(&e->lock);
            b = mds_bitmap_load(dh, hi, offset);
            if (PTR_ERR(b) == -ENOTEXIST) {
                offset = mds_bitmap_fallback(offset);
            } else if (IS_ERR(b)) {
                /* some error occurs, we failed to the 0 position */
                return 0;
            }
            goto retry;
        } else if (offset >= b->offset + XTABLE_BITMAP_SIZE) {
            if (b->flag & BITMAP_END) {
                /* ok, let us just fallbacking */
                xlock_unlock(&e->lock);
                offset = mds_bitmap_fallback(offset);
                goto retry;
            }
        }
    }
    xlock_unlock(&e->lock);

    /* Hoo, we have not found the bitmap slice. We need to request the
     * bitmap slice from the GDT server */
    b = mds_bitmap_load(dh, hi, offset);
    if (IS_ERR(b)) {
        hvfs_err(mds, "Hoo, loading Bitmap %ld failed\n", offset);
        goto out;
    }
    goto retry;
}
