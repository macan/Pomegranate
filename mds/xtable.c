/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-26 22:34:42 macan>
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
#include "xtable.h"
#include "ring.h"
#include "lib.h"
#include "mds.h"

/* ITB split
 *
 * NOTE: this is the local split function, we need to transafer the new itb to
 * the destination MDS.
 *
 * NOTE: we already do the COW, so we do not consider the COWing in ITB
 * spliting.
 *
 * NOTE: holding the bucket.rlock, be.rlock, itb.rlock, ite.wlock
 */
int itb_split_local(struct itb *oi, struct itb **ni, struct itb_lock *l)
{
    struct bucket_entry *be;
    struct itb_index *ii;
    int err = 0, moved = 0, j, offset, done = 0, need_rescan = 0;

    if (*ni)
        return -EINVAL;

    /* we get one new ITB, and increase the itb->h.depth, and select the
     * corresponding ites to the new itb. */
    *ni = get_free_itb(NULL);
    if (unlikely(!*ni)) {
        hvfs_debug(mds, "get_free_itb() failed\n");
        err = -ENOMEM;
        goto out;
    }

    /* we need to get the wlock of the old ITB to prevent any concurrent
     * access */
    be = oi->h.be;
    itb_index_wunlock(l);
    xrwlock_runlock(&oi->h.lock);
    xrwlock_runlock(&be->lock);

    /* reget the wlock */
    xrwlock_wlock(&be->lock);
    xrwlock_wlock(&oi->h.lock);

    /* sanity checking */
    if (atomic_read(&oi->h.entries) < (1 << oi->h.adepth)) {
        /* under the water mark, abort the spliting */
        oi->h.depth--;
        goto out_relock;
    }

retry:
    oi->h.depth++;
    (*ni)->h.depth = oi->h.depth;
    (*ni)->h.itbid = oi->h.itbid + (1 << (oi->h.depth - 1));
    (*ni)->h.puuid = oi->h.puuid;

    /* check and transfer ite between the two ITBs */
    for (j = 0; j < (1 << ITB_DEPTH); j++) {
    rescan:
        ii = &oi->index[j];
        if (ii->flag == ITB_INDEX_FREE)
            continue;
        offset = j;
        done = 0;
        do {
            int conflict = 0;
            
            if (ii->flag == ITB_INDEX_UNIQUE)
                done = 1;
            else if (ii->flag == ITB_INDEX_CONFLICT) {
                conflict = ii->conflict;
                hvfs_debug(mds, "self %d conflict %d\n", offset, conflict);
            }
            if ((oi->ite[ii->entry].hash >> ITB_DEPTH) & 
                (1 << (oi->h.depth - 1))) {
                /* move to the new itb */
                
                hvfs_debug(mds, "offset %d flag %d, %s hash %lx -- bit %d, "
                           "moved %d\n",
                           offset, ii->flag, oi->ite[ii->entry].s.name,
                           oi->ite[ii->entry].hash >> ITB_DEPTH, 
                           (1 << (oi->h.depth - 1)), moved);
                if (ii->flag == 0)
                    ASSERT(0, mds);
                __itb_add_ite_blob(*ni, &oi->ite[ii->entry]);
                itb_del_ite(oi, &oi->ite[ii->entry], offset, j);
                moved++;
                if (offset == j)
                    need_rescan = 1;
            }
            if (done)
                break;
            if (need_rescan) {
                need_rescan = 0;
                goto rescan;
            }
            ii = &oi->index[conflict];
            offset = conflict;
        } while (1);
    }

    /* check if we moved sufficient entries */
    if (moved == 0) {
        /* this means we should split more deeply, however, the itbid of the
         * old ITB can not change, so we just retry our access w/ depth++.
         */
        goto retry;
    }

    hvfs_debug(mds, "moved %d entries from %ld to %ld\n", 
               moved, oi->h.itbid, (*ni)->h.itbid);
    /* commit the changes and release the locks */
    oi->h.state = ITB_JUST_SPLIT;
    mds_dh_bitmap_update(&hmo.dh, oi->h.puuid, oi->h.itbid, MDS_BITMAP_SET);
    /* FIXME: we should connect the two ITBs for write-back */
    oi->h.twin = (u64)(*ni);
    /* FIXME: we should adding the async split update here! */
#if 1
    {
        struct bucket *nb;
        struct bucket_entry *nbe;
        struct itb *ti;

        err = mds_cbht_insert_bbrlocked(&hmo.cbht, (*ni), &nb, &nbe, &ti);
        if (err == -EEXIST) {
            /* someone create the new ITB, we have data lossing */
            hvfs_err(mds, "Someone create ITB %ld, data lossing ...\n",
                     (*ni)->h.itbid);
        } else if (err) {
            hvfs_err(mds, "Internal error.\n");
        } else {
            /* it is ok, we need free the locks */
            xrwlock_runlock(&nbe->lock);
            xrwlock_runlock(&nb->lock);
        }
    }
    mds_dh_bitmap_update(&hmo.dh, oi->h.puuid, (*ni)->h.itbid, MDS_BITMAP_SET);
#endif
    
    xrwlock_wunlock(&oi->h.lock);
    xrwlock_wunlock(&be->lock);

    itb_index_wlock(l);
    xrwlock_rlock(&oi->h.lock);
    xrwlock_rlock(&be->lock);
    
out:
    return err;
out_relock:
    xrwlock_wunlock(&oi->h.lock);
    xrwlock_wunlock(&be->lock);

    /* free the new itb */
    itb_free(*ni);

    itb_index_wlock(l);
    xrwlock_rlock(&oi->h.lock);
    xrwlock_rlock(&be->lock);
    goto out;
}

/* ITB overflow
 *
 * NOTE:
 */
int itb_overflow(struct itb *oi, struct itb **ni)
{
    int err = 0;

    return err;
}

/* mds_bitmap_lookup()
 *
 * Test the offset in this slice, return the bit!
 */
int mds_bitmap_lookup(struct itbitmap *b, u64 offset)
{
    int index = offset - b->offset;

    ASSERT((index >= 0 && index < XTABLE_BITMAP_SIZE), mds);
    return test_bit(index, (u64 *)(b->array));
}

/* mds_bitmap_fallback()
 *
 * Fallback to the next location of ITB
 */
u64 mds_bitmap_fallback(u64 offset)
{
    int nr = fls(offset);       /* NOTE: we just use the low 32 bits */

    if (!nr)
        return 0;
    __clear_bit(nr - 1, &offset);
    return offset;
}

/* mds_bitmap_update()
 *
 * Update the old bitmap with the new bitmap. For now, we just OR the new
 * bitmap to the old bitmap:,(
 */
void mds_bitmap_update(struct itbitmap *o, struct itbitmap *n)
{
    u64 *op = (u64 *)o->array;
    u64 *np = (u64 *)n->array;
    int i;
    
    o->ts = n->ts;
    for (i = 0; i < (XTABLE_BITMAP_SIZE / (8 * sizeof(u64))); i++) {
        *(op + i) |= *(np + i);
    }
}

/* mds_bitmap_update_bit()
 *
 * Update the bit in the bitmap
 */
void mds_bitmap_update_bit(struct itbitmap *b, u64 offset, u8 op)
{
    u64 pos = offset - b->offset;

    __set_bit(pos, (unsigned long *)(b->array));
}

/* mds_bitmap_load()
 *
 * Return Value: -ENOEXIST means the slice is not exist!
 */
int mds_bitmap_load(struct dhe *e, u64 offset)
{
    struct hvfs_md_reply *hmr;
    struct xnet_msg *msg;
    struct chp *p;
    struct itbitmap *bitmap, *b;
    int err, no;
    
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return -ENOMEM;
        }
    }

    /* check if we are loading the GDT bitmap */
    if (unlikely(e->uuid == hmi.gdt_uuid)) {
        /* ok, we should send the request to the ROOT server */
        goto send_msg;
    }
    
    /* find the MDS server */
    p = ring_get_point(e->uuid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        return PTR_ERR(p);
    }
    /* prepare the msg */
    xnet_msg_set_site(msg, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LB, e->uuid, offset);

send_msg:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
        goto out_free;
    }
    /* ok, we get the reply: have the bitmap slice in the reply msg */
    hmr = (struct hvfs_md_reply *)(msg->pair->xm_data);
    if (hmr->err) {
        hvfs_err(mds, "bitmap_load request failed %d\n", hmr->err);
        goto out_free;
    }
    bitmap = hmr_extract(hmr, EXTRACT_BITMAP, &no);
    if (!bitmap) {
        hvfs_err(mds, "hmr_extract BITMAP failed, not found this subregion.\n");
        goto out_free;
    }
    /* hey, we got some bitmap slice, let us insert them to the dhe list */
    xlock_lock(&e->lock);
    if (!list_empty(&e->bitmap)) {
        list_for_each_entry(b, &e->bitmap, list) {
            if (b->offset < offset)
                continue;
            if (b->offset == offset) {
                /* hoo, someone insert the bitmap prior us, we just update our
                 * bitmap to the previous one */
                mds_bitmap_update(b, bitmap);
                break;
            }
            if (b->offset > offset) {
                /* ok, insert ourself prior this slice */
                list_add_tail(&bitmap->list, &b->list);
                /* FIXME: XNET clear the auto free flag */
                xnet_clear_auto_free(msg->pair);
                break;
            }
        }
    } else {
        /* ok, this is an empty list */
        list_add_tail(&bitmap->list, &e->bitmap);
        /* FIXME: XNET clear the auto free flag */
        xnet_clear_auto_free(msg->pair);
    }
    xlock_unlock(&e->lock);

out_free:
    xnet_free_msg(msg);
    return err;
}

/* mds_bitmap_free()
 */
void mds_bitmap_free(struct itbitmap *b)
{
    xfree(b);
}

/* __mds_bitmap_insert()
 *
 * This function is ONLY used by the UNIT TEST program
 */
int __mds_bitmap_insert(struct dhe *e, struct itbitmap *b)
{
    struct itbitmap *pos;
    int err = -EEXIST;

    xlock_lock(&e->lock);
    if (!list_empty(&e->bitmap)) {
        list_for_each_entry(pos, &e->bitmap, list) {
            if (pos->offset < b->offset)
                continue;
            if (pos->offset == b->offset) {
                mds_bitmap_update(pos, b);
                break;
            }
            if (pos->offset > b->offset) {
                list_add_tail(&b->list, &pos->list);
                err = 0;
                break;
            }
        }
    } else {
        /* ok, this is an empty list */
        list_add_tail(&b->list, &e->bitmap);
        err = 0;
    }
    xlock_unlock(&e->lock);

    return err;
}

/* mds_bitmap_create()
 */
int mds_bitmap_create(struct dhe *e, u64 itbid)
{
    struct itbitmap *b;

    b = xzalloc(sizeof(struct itbitmap));
    if (!b) {
        hvfs_err(mds, "xzalloc() itbitmap failed\n");
        return -ENOMEM;
    }
    itbid = (itbid + XTABLE_BITMAP_SIZE - 1) & (~(XTABLE_BITMAP_SIZE - 1));
    INIT_LIST_HEAD(&b->list);
    b->offset = itbid;
    b->ts = 0;                  /* FIXME: set the ts here! */

    return __mds_bitmap_insert(e, b);
}
