/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-28 20:48:48 macan>
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
#include "xnet.h"
#include "ring.h"

/* mds_dh_init()
 *
 * NOTE: we do not provide any fast allocation
 */
int mds_dh_init(struct dh *dh, int hsize)
{
    int err = 0, i;
    
    /* regular hash init */
    hsize = (hsize == 0) ? MDS_DH_DEFAULT_SIZE : hsize;
    dh->ht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!dh->ht) {
        hvfs_err(mds, "DH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&dh->ht[i].h);
        xlock_init(&dh->ht[i].lock);
    }
    dh->hsize = hsize;
out:
    return err;
}

void mds_dh_destroy(struct dh *dh)
{
    if (dh->ht)
        xfree(dh->ht);
}

/* mds_dh_hash()
 */
static inline
u32 mds_dh_hash(u64 uuid)
{
    return hvfs_hash(uuid, 0, 0, HASH_SEL_DH) % hmo.dh.hsize;
}

/* mds_dh_insert()
 */
struct dhe *mds_dh_insert(struct dh *dh, struct hvfs_index *hi)
{
    struct regular_hash *rh;
    struct dhe *e;
    int i;

    i = mds_dh_hash(hi->uuid);
    rh = dh->ht + i;

    e = xzalloc(sizeof(struct dhe));
    if (!e)
        return ERR_PTR(-ENOMEM);

    INIT_HLIST_NODE(&e->hlist);
    INIT_LIST_HEAD(&e->bitmap);
    xlock_init(&e->lock);
    e->uuid = hi->uuid;
    e->puuid = hi->puuid;
    e->salt = hi->psalt;

    xlock_lock(&rh->lock);
    hlist_add_head(&e->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    return e;
}

/* mds_dh_remove()
 */
int mds_dh_remove(struct dh *dh, u64 uuid)
{
    struct regular_hash *rh;
    struct dhe *e;
    struct hlist_node *pos, *n;
    int i;

    i = mds_dh_hash(uuid);
    rh = dh->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(e, pos, n, &rh->h, hlist) {
        if (e->uuid == uuid) {
            hlist_del(&e->hlist);
            xfree(e);
        }
    }
    xlock_unlock(&rh->lock);

    return 0;
}

/* mds_dh_load()
 *
 * NOTE: load the directory info from the GDT server
 *
 * Error Conversion: kernel err-ptr
 */
struct dhe *mds_dh_load(struct dh *dh, struct hvfs_index *hi)
{
    struct hvfs_md_reply *hmr;
    struct hvfs_index *rhi;
    struct xnet_msg *msg;
    struct chp *p;
    struct dhe *e = ERR_PTR(-ENOTEXIST);
    int err = 0, no;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return ERR_PTR(-ENOMEM);
        }
    }

    /* find the MDS server */
    p = ring_get_point(hi->puuid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        e = (struct dhe *)p;
        goto out_free;
    }
    /* prepare the msg */
    xnet_msg_set_site(msg, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LD, hi->puuid, 0);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
        e = ERR_PTR(err);
        goto out_free;
    }
    /* ok, we get the reply: have the mdu in the reply msg */
    ASSERT(msg->pair, mds);
    hmr = (struct hvfs_md_reply *)(msg->pair->xm_data);
    if (!hmr || hmr->err) {
        hvfs_err(mds, "dh_load request failed %d\n", !hmr ? -ENOTEXIST : 
                 hmr->err);
        e = !hmr ? ERR_PTR(-ENOTEXIST) : ERR_PTR(hmr->err);
        goto out_free;
    }
    rhi = hmr_extract(hmr, EXTRACT_HI, &no);
    if (!rhi) {
        hvfs_err(mds, "hmr_extract MDU failed, not found this subregion.\n");
        goto out_free;
    }
    /* key, we got the mdu, let us insert it to the dh table */
    e = mds_dh_insert(dh, rhi);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out_free;
    }
    
out_free:
    xnet_free_msg(msg);
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
    int err;

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
            err = mds_bitmap_load(e, e->uuid, offset);
            if (err == -ENOTEXIST) {
                offset = mds_bitmap_fallback(offset);
            } else if (err) {
                /* some error occurs, we failed to the 0 position */
                xlock_unlock(&e->lock);
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
    err = mds_bitmap_load(e, e->uuid, offset);
    if (err == -ENOTEXIST) {
        offset = mds_bitmap_fallback(offset);
    } else if (err) {
        hvfs_err(mds, "Hoo, loading Bitmap %ld failed\n", offset);
        goto out;
    }
    goto retry;
out:
    return err;
}
