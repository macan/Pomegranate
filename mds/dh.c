/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-20 15:04:32 macan>
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
    struct dhe *e, *tpos;
    struct hlist_node *pos;
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
    /* NOTE: this is the self salt! */
    e->salt = hi->ssalt;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (e->uuid == tpos->uuid) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&e->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i) {
        xfree(e);
        return ERR_PTR(-EEXIST);
    }
    
    return e;
}

/* mds_dh_remove()
 */
int mds_dh_remove(struct dh *dh, u64 uuid)
{
    struct regular_hash *rh;
    struct dhe *e;
    struct hlist_node *pos, *n;
    struct itbitmap *b, *pos2;
    int i;

    i = mds_dh_hash(uuid);
    rh = dh->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(e, pos, n, &rh->h, hlist) {
        if (e->uuid == uuid) {
            hlist_del(&e->hlist);
            hvfs_debug(mds, "Remove dir:%8ld in DH w/  %p\n", uuid, e);
            /* free the bitmap list */
            list_for_each_entry_safe(b, pos2, &e->bitmap, list) {
                list_del(&b->list);
                mds_bitmap_free(b);
            }
            xlock_destroy(&e->lock);
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
struct dhe *mds_dh_load(struct dh *dh, u64 duuid)
{
    struct hvfs_md_reply *hmr = NULL;
    struct hvfs_index thi, *rhi;
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

    /* check if we are loading the GDT DH */
    if (unlikely(duuid == hmi.gdt_uuid)) {
        /* ok, we should send the request to the ROOT server */
        
        goto send_msg;
    }

    /* prepare the hvfs_index */
    memset(&thi, 0, sizeof(thi));
    thi.flag = INDEX_BY_UUID;
    thi.puuid = hmi.gdt_uuid;
    thi.psalt = hmi.gdt_salt;
    thi.uuid = duuid;
    thi.hash = hvfs_hash(duuid, hmi.gdt_salt, 0, HASH_SEL_GDT);

    e = mds_dh_search(dh, hmi.gdt_uuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "Hoo, we can NOT find the GDT uuid %ld(%ld).\n",
                 hmi.gdt_uuid, duuid);
        hvfs_err(mds, "This is a fatal error %ld! We must die.\n", 
                 PTR_ERR(e));
        ASSERT(0, mds);
    }
    thi.itbid = mds_get_itbid(e, thi.hash);

    /* find the MDS server */
    p = ring_get_point(thi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point(%ld) failed with %ld\n", 
                 thi.itbid, PTR_ERR(p));
        e = ERR_PTR(-ECHP);
        goto out_free;
    }
    if (p->site_id == hmo.site_id) {
        struct hvfs_txg *txg;
        
        hvfs_err(mds, "Load DH (self): uuid %ld itbid %ld, site %lx\n", 
                 thi.uuid, thi.itbid, p->site_id);
        /* the GDT service MDS server is myself, so we just lookup the entry
         * in my CBHT. */
        hmr = get_hmr();
        if (!hmr) {
            hvfs_err(mds, "get_hmr() failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        
        thi.flag |= INDEX_LOOKUP;
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(&thi, hmr, txg, &txg);
        txg_put(txg);
        if (err) {
            hvfs_err(mds, "lookup uuid %ld failed w/ %d.\n",
                     thi.uuid, err);
            goto out_free_hmr;
        }

        /* Note that we should set the salt manually */
        {
            struct gdt_md *m;
            int nr = 0;
            
            m = hmr_extract_local(hmr, EXTRACT_MDU, &nr);
            if (!m) {
                hvfs_err(mds, "Extract MDU failed\n");
                goto out_free_hmr;
            }
            thi.ssalt = m->salt;
        }
        
        e = mds_dh_insert(dh, &thi);
        if (IS_ERR(e) && e != ERR_PTR(-EEXIST)) {
            hvfs_err(mds, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        }
    out_free_hmr:
        xfree(hmr);
    } else {
        /* ok, we should send the request to the remote site now */
        hvfs_err(mds, "Load DH (remote): uuid %ld itbid %ld, site %lx\n", 
                 thi.uuid, thi.itbid, p->site_id);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id, 
                         p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LD, duuid, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_add_sdata(msg, &thi, sizeof(thi));
        
    send_msg:
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
            hvfs_err(mds, "hmr_extract MDU failed, do not found this "
                     "subregion.\n");
            goto out_free;
        }

        /* Note that, we know that the LDH will return the HI with ssalt
         * set. */

        /* key, we got the mdu, let us insert it to the dh table */
        e = mds_dh_insert(dh, rhi);
        if (IS_ERR(e) && e != ERR_PTR(-EEXIST)) {
            hvfs_err(mds, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
            goto out_free;
        }
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
 *
 * Error Conversion: kernel err-ptr
 */
struct dhe *mds_dh_search(struct dh *dh, u64 duuid)
{
    struct dhe *e = ERR_PTR(-EINVAL);
    struct regular_hash *rh;
    struct hlist_node *l;
    int i, found = 0;

    i = mds_dh_hash(duuid);
    rh = dh->ht + i;

retry:
    xlock_lock(&rh->lock);
    hlist_for_each_entry(e, l, &rh->h, hlist) {
        if (e->uuid == duuid) {
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (unlikely(!found)) {
        /* Hoo, we have not found the directory. We need to request the
         * directory information from the GDT server */
        e = mds_dh_load(dh, duuid);
        if (e == ERR_PTR(-EEXIST)) {
            /* this means the entry is load by another thread, it is ok to
             * research in the cache */
            goto retry;
        } else if (IS_ERR(e)) {
            hvfs_err(mds, "Hoo, loading DH %ld failed\n", duuid);
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
            err = mds_bitmap_load(e, offset);
            if (err == -ENOTEXIST) {
                offset = mds_bitmap_fallback(offset);
            } else if (err) {
                /* some error occurs, we failed to the 0 position */
                hvfs_err(mds, "Hoo, loading DHE %ld Bitmap %ld failed\n", 
                         e->uuid, offset);
                goto out;
            }
            goto retry;
        } else if (offset >= b->offset + XTABLE_BITMAP_SIZE) {
            if (b->flag & BITMAP_END) {
                /* ok, let us just fallbacking */
                xlock_unlock(&e->lock);
                offset = mds_bitmap_cut(offset,
                                        b->offset + XTABLE_BITMAP_SIZE);
                goto retry;
            }
        }
    }
    xlock_unlock(&e->lock);

    /* Hoo, we have not found the bitmap slice. We need to request the
     * bitmap slice from the GDT server */
    err = mds_bitmap_load(e, offset);
    if (err == -ENOTEXIST) {
        offset = mds_bitmap_fallback(offset);
    } else if (err) {
        hvfs_err(mds, "Hoo, loading DHE %ld Bitmap %ld failed\n", 
                 e->uuid, offset);
        goto out;
    }
    goto retry;
out:
    return 0;
}

/* mds_dh_bitmap_update()
 *
 * This function only support one bit change on the bitmap region. If the
 * bitmap slice is not loaded in, we will load it automatically
 */
int mds_dh_bitmap_update(struct dh *dh, u64 puuid, u64 itbid, u8 op)
{
    struct itbitmap *b;
    struct dhe *e;
    int err = 0;

    hvfs_debug(mds, "bitmap updating puuid %ld itbid %ld.\n", puuid, itbid);
    e = mds_dh_search(dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "The DHE(%ld) is not exist.\n", puuid);
        return -EINVAL;
    }
retry:
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
        if (b->offset <= itbid && itbid < b->offset + XTABLE_BITMAP_SIZE) {
            /* ok, we get the bitmap slice, just do it */
            mds_bitmap_update_bit(b, itbid, op);
        } else if (b->offset > itbid) {
            /* it means that we need to load the missing slice */
            xlock_unlock(&e->lock);
            err = mds_bitmap_load(e, itbid);
            if (err == -ENOTEXIST) {
                /* we just create the slice now */
                err = mds_bitmap_create(e, itbid);
                if (err == -EEXIST) {
                    /* ok, we just retry */
                    goto retry;
                } else if (err) {
                    goto out;
                }
            } else if (err) {
                hvfs_err(mds, "Hoo, loading DHE %ld Bitmap %ld failed\n",
                         e->uuid, itbid);
                goto out;
            }
            goto retry;
        } else if (itbid >= b->offset + XTABLE_BITMAP_SIZE) {
            if (b->flag & BITMAP_END) {
                /* ok, just create the slice now */
                xlock_unlock(&e->lock);
                err = mds_bitmap_create(e, itbid);
                if (err == -EEXIST) {
                    /* ok, we just retry */
                    goto retry;
                } else if (err) {
                    goto out;
                }
                goto retry;
            }
        }
    }
    xlock_unlock(&e->lock);
out:
    return err;
}

/* mds_dh_bitmap_dump()
 */
void mds_dh_bitmap_dump(struct dh *dh, u64 puuid)
{
    struct itbitmap *b;
    struct dhe *e;
    char line[4096];
    int i, len = 0;

    e = mds_dh_search(dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "The DHE(%ld) is not exist.\n", puuid);
        return;
    }

    memset(line, 0, 4096);
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
/*         for (i = 0; i < XTABLE_BITMAP_SIZE / 8; i++) { */
        for (i = 0; i < 32; i++) {
            len += snprintf(line + len, 4096, "%x", b->array[i]);
        }
        hvfs_plain(mds, "offset: %s\n", line);
    }
    xlock_unlock(&e->lock);
}
