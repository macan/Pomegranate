/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-07-08 14:22:40 macan>
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
int itb_split_local(struct itb *oi, int odepth, struct itb_lock *l,
                    struct hvfs_txg *txg)
{
    struct bucket_entry *be;
    struct itb_index *ii;
    struct itb *ni;
    int err = 0, moved = 0, j, offset, done = 0, need_rescan = 0;
    u8 saved_depth = 0;

    /* we get one new ITB, and increase the itb->h.depth, and select the
     * corresponding ites to the new itb. */
    ni = get_free_itb(NULL);
    if (unlikely(!ni)) {
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

    /* NOTE: there may be a COW here! */

    /* reget the wlock */
    xrwlock_wlock(&be->lock);
    xrwlock_wlock(&oi->h.lock);

    /* sanity checking */
    if (unlikely(be != oi->h.be))
        goto out_relock;
    if (unlikely(oi->h.state == ITB_STATE_COWED)) {
        hvfs_debug(mds, "COW -> SPLIT?\n");
        goto out_relock;
    }
    if (unlikely(oi->h.state == ITB_STATE_CLEAN)) {
        /* FIXME: we should redirty the ITB! */
        goto out_relock;
    }
    if (unlikely(odepth < oi->h.depth)) {
        goto out_relock;
    }
    if (unlikely(atomic_read(&oi->h.entries) < (1 << oi->h.adepth))) {
        /* under the water mark, abort the spliting */
        goto out_relock;
    }

    /* make sure this itb will be writen back */
    txg_add_itb(txg, oi);
retry:
    oi->h.depth++;
    (ni)->h.depth = oi->h.depth;
    (ni)->h.itbid = oi->h.itbid | (1 << (oi->h.depth - 1));
    (ni)->h.puuid = oi->h.puuid;

    ASSERT(list_empty(&ni->h.list), mds);
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
            
            if (ii->flag == ITB_INDEX_UNIQUE) {
                hvfs_debug(mds, "self %d UNIQUE\n", offset);
                done = 1;
            } else if (ii->flag == ITB_INDEX_CONFLICT) {
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
                __itb_add_ite_blob(ni, &oi->ite[ii->entry]);
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
        if (!saved_depth)
            saved_depth = oi->h.depth - 1;
        hvfs_err(mds, "HIT untested code-path w/ depth %d.\n", 
                 oi->h.depth);
        if (unlikely(oi->h.depth == 50)) {
            hvfs_err(mds, "We should consider the hash conflicts in "
                     "the same bucket!\n");
            ASSERT(0, mds);
        }
        goto retry;
    }

    if (unlikely(saved_depth))
        oi->h.depth = saved_depth;
    hvfs_debug(mds, "moved %d entries from %ld(%p,%d,%d) to %ld(%p,%d,%d)\n", 
             moved, oi->h.itbid, oi, oi->h.depth, atomic_read(&oi->h.entries),
             (ni)->h.itbid, (ni), (ni)->h.depth, 
               atomic_read(&(ni)->h.entries));
    /* commit the changes and release the locks */
    mds_dh_bitmap_update(&hmo.dh, oi->h.puuid, oi->h.itbid, MDS_BITMAP_SET);

    /* FIXME: we should connect the two ITBs for write-back */
    (ni)->h.twin = (u64)oi;
    itb_get(oi);

    err = mds_add_bitmap_delta(txg, hmo.site_id, oi->h.puuid, oi->h.itbid, 
ni->h.itbid);
    if (err) {
        hvfs_err(mds, "adding bitmap delta failed, lose consistency.\n");
    }
    
    /* FIXME: we should adding the async split update here! */
#if 1
    {
        struct async_update_request *aur = 
            xzalloc(sizeof(struct async_update_request));

        if (!aur) {
            hvfs_err(mds, "xallloc() AU request failed, data lossing.\n");
            err = -ENOMEM;
        } else {
            aur->op = AU_ITB_SPLIT;
            aur->arg = (u64)(ni);
            INIT_LIST_HEAD(&aur->list);
            err = au_submit(aur);
            if (err) {
                hvfs_err(mds, "submit AU request failed, data lossing.\n");
                xfree(aur);
            }
            atomic64_inc(&hmo.prof.itb.split_submit);
        }
    }
#endif
    
    xrwlock_wunlock(&oi->h.lock);
    xrwlock_wunlock(&be->lock);

    /* COW here? */

    xrwlock_rlock(&be->lock);
    xrwlock_rlock(&oi->h.lock);
    itb_index_wlock(l);
    
out:
    /* Recheck the ITB state, if there is a ITB cow occured, we should do
     * what?
     *
     * NOTE: we add one sleep(0) to avoid the corner case clustering, can
     * anyone help me describe what actually should i do here?
     */
    if (oi->h.state == ITB_STATE_COWED ||
        oi->h.state == ITB_STATE_CLEAN) {
        hvfs_debug(mds, "HIT Corner case ITB %p %ld, entries %d, flag %d\n",
                 oi, oi->h.itbid, atomic_read(&oi->h.entries),
                 oi->h.flag);
        err = -ESPLIT;
        sched_yield();
    }
        
    return err;
out_relock:
    xrwlock_wunlock(&oi->h.lock);
    xrwlock_wunlock(&be->lock);

    /* free the new itb */
    itb_free(ni);

    xrwlock_rlock(&be->lock);
    xrwlock_rlock(&oi->h.lock);
    itb_index_wlock(l);
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

/* mds_bitmap_refresh()
 *
 * refresh the bitmap entry
 */
void mds_bitmap_refresh(struct hvfs_index *hi)
{
    struct dhe *e;
    u64 offset;
    int err = 0;
    
    e = mds_dh_search(&hmo.dh, hi->puuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        goto out;
    }
    hvfs_err(mds, "refresh uuid %ld bitmap slice offset %ld.\n",
             hi->puuid, hi->itbid);
    /* try to load the bitmap slice @ hi->itbid */
    offset = BITMAP_ROUNDDOWN(hi->itbid);
    err = mds_bitmap_load(e, offset);
    if (err == -ENOTEXIST) {
        hvfs_err(mds, "uiud %ld Bitmap slice %ld do not exist\n",
                 hi->puuid, offset);
    } else if (err) {
        hvfs_err(mds, "uuid %ld bitmap slice %ld load err w/ %d\n",
                 hi->puuid, offset, err);
    }
    
out:
    return;
}

/* mds_bitmap_load()
 *
 * Return Value: -ENOEXIST means the slice is not exist!
 */
int mds_bitmap_load(struct dhe *e, u64 offset)
{
    struct xnet_msg *msg;
    struct chp *p;
    struct dhe *gdte;
    struct itbitmap *bitmap, *b;
    u64 hash, itbid, tsid;      /* save the target site id */
    int err = 0;
    
    /* round up offset */
    offset = BITMAP_ROUNDDOWN(offset);

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
        /* FIXME: set the dsite_id!!! */
        hvfs_err(mds, "Auto load GDT bitmap from ROOT server is not "
                 "supported yet.\n");
        tsid = HVFS_RING(0);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id,
                         tsid);
        xnet_msg_fill_cmd(msg, HVFS_R2_LBGDT, hmo.xc->site_id, hmo.fsid);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        msg->tx.reserved = offset;
        
        goto send_msg;
    }

    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out_free;
    }
    hash = hvfs_hash_gdt(e->uuid, hmi.gdt_salt);
    itbid = mds_get_itbid(gdte, hash);
    
    /* find the MDS server */
    p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        err = PTR_ERR(p);
        goto out_free;
    }

    /* check if the target MDS server is myself */
    if (p->site_id == hmo.site_id) {
        /* we should lookup the bitmap in my own bitmap cache */
        u64 location, size;
        struct bc_entry *be;
        struct itbitmap *b, *bitmap;
        struct hvfs_index hi;

        memset(&hi, 0, sizeof(hi));
        hi.flag = INDEX_BY_UUID;
        hi.uuid = e->uuid;
        hi.puuid = hmi.gdt_uuid;
        hi.psalt = hmi.gdt_salt;
        hi.hash = hash;
        hi.itbid = itbid;
        
        hvfs_err(mds, "Self bitmap load uuid %ld offset %ld\n",
                 e->uuid, offset);

        /* cut the bitmap to valid range */
        err = mds_bc_dir_lookup(&hi, &location, &size);
        if (err) {
            hvfs_err(mds, "bc_dir_lookup() failed w/ %d\n", err);
            goto out_free;
        }

        if (size == 0) {
            /* this means that offset should be ZERO */
            offset = 0;
        } else {
            /* Caution: we should cut the offset to the valid bitmap range by
             * size! */
            offset = mds_bitmap_cut(offset, size << 3);
            offset = BITMAP_ROUNDDOWN(offset);
        }

        be = mds_bc_get(e->uuid, offset);
        if (IS_ERR(be)) {
            if (be == ERR_PTR(-ENOENT)) {
                struct bc_entry *nbe;

                /* ok, we should create one bc_entry now */
                be = mds_bc_new();
                if (!be) {
                    hvfs_err(mds, "New BC entry failed\n");
                    err = -ENOMEM;
                    goto out_free;
                }
                mds_bc_set(be, e->uuid, offset);

                /* we should load the bitmap from mdsl */
                err = mds_bc_dir_lookup(&hi, &location, &size);
                if (err) {
                    hvfs_err(mds, "bc_dir_lookup failed w/ %d\n", err);
                    goto out_free;
                }

                if (size == 0) {
                    /* this means that we should just return a new default
                     * btimap slice */
                    int i;

                    for (i = 0; i < 1; i++) {
                        be->array[i] = 0xff;
                    }
                } else {
                    /* load the btimap slice from MDSL */
                    err = mds_bc_backend_load(be, hi.itbid, location);
                    if (err) {
                        hvfs_err(mds, "bc_backend_load failed w/ %d\n", err);
                        mds_bc_free(be);
                        goto out_free;
                    }
                }

                /* finally, we insert the bc into the cache, should we check
                 * whether there is a conflice? */
                nbe = mds_bc_insert(be);
                if (nbe != be) {
                    mds_bc_free(be);
                    be = nbe;
                }
                /* we should copy the content of bc_entry to itbitmap */
                bitmap = xmalloc(sizeof(struct itbitmap));
                if (!bitmap) {
                    err = -ENOMEM;
                    goto out_free;
                }
                INIT_LIST_HEAD(&bitmap->list);
                bitmap->offset = be->offset;
                bitmap->flag = ((size - (be->offset >> 3) > XTABLE_BITMAP_BYTES)
                                ? 0 : BITMAP_END);
                bitmap->ts = time(NULL);
                memcpy(bitmap->array, be->array, XTABLE_BITMAP_BYTES);

                xlock_lock(&e->lock);
                if (!list_empty(&e->bitmap)) {
                    list_for_each_entry(b, &e->bitmap, list) {
                        if (b->offset < offset) {
                            continue;
                        }
                        if (b->offset == offset) {
                            /* hoo, someone insert the bitmap prior us, we
                             * just update our bitmap to the previous one */
                            mds_bitmap_update(b, bitmap);
                            break;
                        }
                        if (b->offset > offset) {
                            /* ok, insert ourself prior this slice */
                            list_add_tail(&bitmap->list, &b->list);
                            break;
                        }
                    }
                } else {
                    /* ok, this is an empty list */
                    list_add_tail(&bitmap->list, &e->bitmap);
                }
                xlock_unlock(&e->lock);
            } else {
                hvfs_err(mds, "bc_get() failed w/ %d\n", err);
                goto out_free;
            }
        } else {
            /* we find the entry in the cache, just construct the itbitmap
             * entry and insert it to the dh list */
            bitmap = xmalloc(sizeof(struct itbitmap));
            if (!bitmap) {
                err = -ENOMEM;
                goto out_free;
            }
            bitmap->offset = be->offset;
            bitmap->flag = ((size - (be->offset >> 3) > XTABLE_BITMAP_BYTES)
                            ? 0 : BITMAP_END);
            bitmap->ts = time(NULL);
            memcpy(bitmap->array, be->array, XTABLE_BITMAP_BYTES);

            xlock_lock(&e->lock);
            if (!list_empty(&e->bitmap)) {
                list_for_each_entry(b, &e->bitmap, list) {
                    if (b->offset < offset) {
                        continue;
                    }
                    if (b->offset == offset) {
                        /* hoo, someone insert the bitmap prior us, we just
                         * update our bitmap to the previous one */
                        mds_bitmap_update(b, bitmap);
                        break;
                    }
                    if (b->offset > offset) {
                        /* ok, insert ourself prior this slice */
                        list_add_tail(&bitmap->list, &b->list);
                        break;
                    }
                }
            } else {
                /* ok, this is an empty list */
                list_add_tail(&bitmap->list, &e->bitmap);
            }
            xlock_unlock(&e->lock);
        }
    } else {
        hvfs_err(mds, "Remote bitmap load uuid %ld offset %ld\n",
                 e->uuid, offset);
        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                         hmo.site_id, p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LB, e->uuid, offset);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    send_msg:
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mds, "xnet_send() failed with %d\n", err);
            goto out_free;
        }
        /* ok, we get the reply: have the bitmap slice in the reply msg */
        ASSERT(msg->pair, mds);
        if (msg->pair->tx.err) {
            hvfs_err(mds, "Reply w/ error %d\n", msg->pair->tx.err);
            err = msg->pair->tx.err;
            xnet_set_auto_free(msg->pair);
            goto out_free;
        }
        if (msg->pair->tx.len < sizeof(struct itbitmap)) {
            hvfs_err(mds, "Reply w/ incorrect data length %d vs %ld\n",
                     msg->pair->tx.len, sizeof(struct itbitmap));
            err = -EINVAL;
            xnet_set_auto_free(msg->pair);
            goto out_free;
        }
        
        if (msg->pair->xm_datacheck)
            bitmap = msg->pair->xm_data;
        else {
            hvfs_err(mds, "Wrong xm_datacheck!\n");
            err = -EINVAL;
            xnet_set_auto_free(msg->pair);
            goto out_free;
        }

        INIT_LIST_HEAD(&bitmap->list);
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
                    xnet_set_auto_free(msg->pair);
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
            char line[1024] = {0,};
            int i;
            
            /* ok, this is an empty list */
            list_add_tail(&bitmap->list, &e->bitmap);
            /* FIXME: XNET clear the auto free flag */
            for (i = 0; i < 100; i++) {
                sprintf(line + i, "%x", bitmap->array[i]);
            }
            hvfs_err(mds, "bitmap %s\n", line);
            xnet_clear_auto_free(msg->pair);
        }
        xlock_unlock(&e->lock);
    }

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
    itbid = BITMAP_ROUNDDOWN(itbid);
    INIT_LIST_HEAD(&b->list);
    b->offset = itbid;
    b->ts = 0;                  /* FIXME: set the ts here! */

    return __mds_bitmap_insert(e, b);
}
