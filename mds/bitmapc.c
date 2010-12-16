/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-16 02:09:26 macan>
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
#include "ring.h"
#include "mds.h"

#define MDS_BC_HASH_SIZE_DEFAULT        (512)
#define MDS_BC_ROOF_DEFAULT             (512)

int mds_bitmap_cache_init(void)
{
    int i;
    
    if (!hmo.conf.bc_hash_size) {
        hmo.conf.bc_hash_size = MDS_BC_HASH_SIZE_DEFAULT;
    }
    if (!hmo.conf.bc_roof) {
        hmo.conf.bc_roof = MDS_BC_ROOF_DEFAULT;
    }

    hmo.bc.hsize = hmo.conf.bc_hash_size;
    INIT_LIST_HEAD(&hmo.bc.lru);
    INIT_LIST_HEAD(&hmo.bc.deltas);
    xlock_init(&hmo.bc.delta_lock);
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

    val1 = hash_64(key1, 64);
    val2 = hash_64(key2, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1 % size;         /* FIXME: need more faster! */
}

static inline
void mds_bc_lru_update(struct bc_entry *be)
{
    if (!list_empty(&be->list)) {
        xlock_lock(&hmo.bc.lock);
        list_del_init(&be->list);
    } else {
        xlock_lock(&hmo.bc.lock);
    }
    
    list_add(&be->list, &hmo.bc.lru);
    xlock_unlock(&hmo.bc.lock);
}

static inline
void mds_bc_lru_del(struct bc_entry *be)
{
    if (list_empty(&be->list))
        return;

    xlock_lock(&hmo.bc.lock);
    list_del_init(&be->list);
    xlock_unlock(&hmo.bc.lock);
}

void mds_bitmap_cache_evict(void)
{
    struct regular_hash *rh;
    struct bc_entry *tpos;
    struct hlist_node *pos, *n;
    int err, i;

    /* Step 1: commit the cached bitmaps */
    err = mds_bc_backend_commit();
    if (err) {
        hvfs_err(mds, "mds_bc_backend_commit() failed w/ %d\n", err);
    }

    /* Step 2: free the whole cache */
    for (i = 0; i < hmo.bc.hsize; i++) {
        rh = hmo.bc.bcht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            hlist_del_init(&tpos->hlist);
            mds_bc_lru_del(tpos);
            xfree(tpos);
        }
        xlock_unlock(&rh->lock);
    }
}

/* mds_bc_gc() clean the lru list and shrink the cache size
 */
void mds_bc_gc(void)
{
    struct regular_hash *rh;
    struct bc_entry *be, *n;
    struct hlist_node *l, *m;
    int idx = -1, found = 0;
    
retry:
    xlock_lock(&hmo.bc.lock);
    list_for_each_entry_safe_reverse(be, n, &hmo.bc.lru, list) {
        if (atomic_read(&be->ref) == 0) {
            idx = be->idx;

            list_del_init(&be->list);
            break;
        }
    }
    xlock_unlock(&hmo.bc.lock);

    if (idx != -1) {
        rh = hmo.bc.bcht + idx;

        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(n, l, m, &rh->h, hlist) {
            if (n == be && atomic_read(&n->ref) == 0) {
                hlist_del_init(&n->hlist);
                found = 1;
                break;
            }
        }
        xlock_unlock(&rh->lock);

        if (!found) {
            idx = -1;
            mds_bc_lru_update(be);
            goto retry;
        } else {
            /* free it */
            hvfs_debug(mds, "free %ld %ld\n", be->uuid, be->offset);
            mds_bc_free(be);
            atomic_dec(&hmo.bc.total);
        }
    }
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
    hlist_for_each_entry(be, n, &rh->h, hlist) {
        if (likely(be->uuid == uuid && be->offset == offset)) {
            found = 1;
            if (atomic_inc_return(&be->ref) == 1)
                atomic_dec(&hmo.bc.free);
            /* move the tail of lru list */
            mds_bc_lru_update(be);
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found) {
        return be;
    } else
        return ERR_PTR(-ENOENT);
}

void mds_bc_put(struct bc_entry *be)
{
    if (atomic_dec_return(&be->ref) == 0)
        atomic_inc(&hmo.bc.free);
    if (atomic_read(&hmo.bc.total) > hmo.conf.bc_roof) {
        /* ok, we should release the entries @ the tail of lru list */
        mds_bc_gc();
    }
}

struct bc_entry *mds_bc_replace(void)
{
    struct regular_hash *rh;
    struct bc_entry *be, *n;
    struct hlist_node *l, *m;
    int idx = -1, found = 0;

retry:
    xlock_lock(&hmo.bc.lock);
    list_for_each_entry_safe_reverse(be, n, &hmo.bc.lru, list) {
        if (atomic_read(&be->ref) == 0) {
            idx = be->idx;

            list_del_init(&be->list);
            break;
        }
    }
    xlock_unlock(&hmo.bc.lock);

    if (idx != -1) {
        rh = hmo.bc.bcht + idx;

        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(n, l, m, &rh->h, hlist) {
            if (n == be && atomic_read(&n->ref) == 0) {
                hlist_del_init(&n->hlist);
                found = 1;
                break;
            }
        }
        xlock_unlock(&rh->lock);

        if (!found) {
            idx = -1;
            hvfs_debug(mds, "got %ld %ld failed, retry another\n",
                       be->uuid, be->offset);
            mds_bc_lru_update(be);
            goto retry;
        } else {
            /* find it, and we break this entry from the hash list, you need
             * to re-insert it to the hash table. Be sure to update the free
             * counter */
            hvfs_debug(mds, "replace %ld %ld\n", be->uuid, be->offset);

            ASSERT(atomic_read(&be->ref) == 0, mds);
            atomic_set(&be->ref, 1);
            atomic_dec(&hmo.bc.free);
            atomic_dec(&hmo.bc.total);
            /* re-init the bitmap array */
            memset(be->array, 0, sizeof(be->array));
        }
    } else {
        /* just alloc a new one */
        be = mds_bc_alloc();
    }

    return be;
}

struct bc_entry *mds_bc_insert(struct bc_entry *be)
{
    struct regular_hash *rh;
    struct bc_entry *pos;
    struct hlist_node *n;
    int idx, found = 0;

    idx = mds_bc_hash(be->uuid, be->offset, hmo.bc.hsize);
    rh = hmo.bc.bcht + idx;

    xlock_lock(&rh->lock);
    /* step 1: we should check whether this bc entry is exist */
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (likely(be->uuid == pos->uuid && be->offset == pos->offset)) {
            found = 1;
            if (atomic_inc_return(&pos->ref) == 1)
                atomic_dec(&hmo.bc.free);
            /* move to the tail of lru list */
            mds_bc_lru_update(pos);
            break;
        }
    }
    if (!found) {
        be->idx = idx;
        hlist_add_head(&be->hlist, &rh->h);
    } else {
        xlock_unlock(&rh->lock);
        return pos;
    }
    xlock_unlock(&rh->lock);
    
    mds_bc_lru_update(be);
    atomic_inc(&hmo.bc.total);

    return be;
}

struct bc_entry *mds_bc_new(void)
{
    if (atomic_read(&hmo.bc.total) < hmo.conf.bc_roof) {
        return mds_bc_alloc();
    } else {
        return mds_bc_replace();
    }
}

/*
 * Note: this function is only for MDS2MDS cmd handling!
 */
int mds_bc_dir_check(struct xnet_msg *msg, struct hvfs_index *hi)
{
    struct dhe *e;
    struct chp *p;
    u64 itbid;
    int err = 0;
    
    /* We should lookup the metadata of the directory to get the final file
     * offset of the bitmap slice. */

    /* Step 1: check if we are the right MDS to do this */
    if (!hi->hash)
        hi->hash = hvfs_hash_gdt(hi->uuid, hmi.gdt_salt);

    e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        goto out;
    }
    
    itbid = mds_get_itbid(e, hi->hash);
    mds_dh_put(e);
    if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            err = -ECHP;
            goto out;
        }
        if (hmo.site_id != p->site_id) {
            if (hi->itbid == itbid) {
                /* itbid is correct, but ring changed */
                err = -ERINGCHG;
                goto out;
            }
            hvfs_debug(mds, "NEED FOREARD the reqeust to Site %lx.\n",
                       p->site_id);
            /* do the forward now */
            hi->flag |= INDEX_BIT_FLIP;
            hi->itbid = itbid;
            err = mds_do_forward(msg, p->site_id);
            goto out;
        }
        hi->itbid = itbid;
    }

out:
    return err;
}


/* mds_bc_dir_lookup()
 *
 * find and get the dir bitmap location/size
 */
int mds_bc_dir_lookup(struct hvfs_index *hi, u64 *location, u64 *size)
{
    struct hvfs_md_reply *hmr;
    struct hvfs_txg *txg;
    struct mdu *mdu;
    struct column *column;
    int nr = 0, err = 0;
    
    hvfs_debug(mds, "BC LOOKUP %ld %ld %lx %lx\n",
               hi->puuid, hi->itbid, hi->hash, hi->uuid);
    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        err = -ENOMEM;
        goto out;
    }

    /* search in the CBHT */
    hi->flag |= (INDEX_LOOKUP | INDEX_COLUMN);
    hi->column = HVFS_GDT_BITMAP_COLUMN;
retry:
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);
    if (err) {
        if (err == -EAGAIN || err == -ESPLIT ||
            err == -ERESTART) {
            /* have a breath */
            sched_yield();
            goto retry;
        } else if (err == -EHWAIT) {
            /* deep sleep */
            sleep(1);
            goto retry;
        }
        goto out_free;
    }

    /* get the location and size */
    mdu = hmr_extract_local(hmr, EXTRACT_MDU, &nr);
    if (!mdu) {
        hvfs_err(mds, "extract MDU failed on lookup %ld %ld %lx\n",
                 hi->puuid, hi->itbid, hi->hash);
        err = -EINVAL;
        goto out_free;
    }
    *size = mdu->size;
    column = hmr_extract_local(hmr, EXTRACT_DC, &nr);
    if (!column) {
        hvfs_err(mds, "extract DC failed on lookup %ld %ld %lx\n",
                 hi->puuid, hi->itbid, hi->hash);
        err = -EINVAL;
        goto out_free;
    }
    hvfs_debug(mds, "BC LOOKUP ITE puuid %ld uuid %ld itbid %ld "
               "column offset %ld len %ld itbid %ld size %ld\n",
               hi->puuid, hi->uuid, hi->itbid, 
               column->offset, column->len, column->stored_itbid,
               mdu->size);
    *location = column->offset;

    /* free all the resources */
out_free:
    if (hmr) {
        if (hmr->data)
            xfree(hmr->data);
        xfree(hmr);
    }
out:
    return err;
}

/* mds_bc_backend_load()
 *
 * the uuid and offset should be set in the bc_entry, we just use
 * it. @location is the actual file begin offset.
 */
int mds_bc_backend_load(struct bc_entry *be, u64 itbid, u64 location)
{
    struct xnet_msg *msg;
    struct chp *p;
    int err = 0;

    if (unlikely(hmo.conf.option & HVFS_MDS_MEMONLY))
        return -EINVAL;

    /* Step 1: find the target mdsl site */
    p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto out;
    }

    /* Step 2: prepare the xnet_msg */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }

    hvfs_err(mds, "Load bitmap %lx %ld %ld %ld\n", 
             be->uuid, itbid, location, be->offset);

    /* Step 3: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.site_id, p->site_id);
    /* Note that, be->uuid is NOT used in MDSL, so we change the ABI now */
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_BITMAP, location, be->offset);
    msg->tx.reserved = p->vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Request to load bitmap of %lx location 0x%lx failed\n",
                 be->uuid, location + be->offset);
        goto out_free_msg;
    }

    /* we got the reply now */
    ASSERT(msg->pair, mds);
    if (msg->pair->tx.err) {
        err = msg->pair->tx.err;
        hvfs_err(mds, "Load bitmap from %lx failed w/ %d\n", p->site_id, err);
        goto out_free;
    }

    if (msg->pair->xm_datacheck) {
        memcpy(be->array, msg->pair->xm_data, msg->pair->tx.len);
    } else {
        /* failed w/ invalid reply */
        err = -EFAULT;
        xnet_set_auto_free(msg->pair);
        goto out_free;
    }

out_free:
    xnet_free_msg(msg);
    atomic64_inc(&hmo.prof.mdsl.bitmap);
    
    return err;

out_free_msg:
    xnet_free_msg(msg);
out:
    return err;
}

static inline
int __customized_send_request(struct bc_commit *commit)
{
    struct xnet_msg *msg;
    struct hvfs_md_reply *hmr;
    int err = 0;

    /* Step 1: prepare the xnet_msg */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }

    /* Step 2: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.site_id, commit->dsite_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_BTCOMMIT, commit->core.uuid, 0);
    msg->tx.reserved = commit->vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &commit->core, sizeof(commit->core));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Request to commit the bitmap %ld flip @ location "
                 "0x%lx failed w/ %d\n",
                 commit->core.uuid, commit->core.location, err);
        goto out_free_msg;
    }

    /* we got the reply now */
    ASSERT(msg->pair, mds);
    /* extract the error number */
    err = msg->pair->tx.err;
    /* if the errno is zero, and bcc->core.size is not -1UL, we should got and
     * update the new file location */
    if (!err && msg->pair->tx.arg1 != -1UL) {
        struct hvfs_txg *txg;
        struct dhe *e;
        struct hvfs_index hi = {
            .flag = INDEX_MDU_UPDATE | INDEX_BY_UUID,
            .puuid = hmi.gdt_uuid,
            {.psalt = hmi.gdt_salt, },
        };
        struct mdu_update *mu;
        struct mu_column *mc;
        int retry_nr = 0;

        e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
        if (IS_ERR(e)) {
            /* fatal error */
            hvfs_err(mds, "This is a fatal error, we can not find "
                     "the GDT DHE.\n");
            err = PTR_ERR(e);
            goto out_free_msg;
        }

    realloc0:
        mu = xzalloc(sizeof(struct mdu_update) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(mds, "xzalloc() MU failed.\n");
            goto realloc0;
        }
    realloc:
        hmr = get_hmr();
        if (!hmr) {
            hvfs_err(mds, "get_hmr() failed, fatal error, we must retry\n");
            goto realloc;
        }
        hi.uuid = commit->core.uuid;
        hi.hash = hvfs_hash_gdt(hi.uuid, hmi.gdt_salt);
        hi.itbid = mds_get_itbid(e, hi.hash);
        mds_dh_put(e);
        hi.data = mu;

        /* update the size and the offset in ITE */
        memset(mu, 0, sizeof(mu));
        mu->valid = MU_COLUMN | MU_SIZE;
        mu->size = msg->pair->tx.arg1;
        ASSERT(mu->size >= commit->core.size + XTABLE_BITMAP_BYTES, mds);
        mu->column_no = 1;
        mc = (void *)mu + sizeof(struct mdu_update);
        mc->cno = HVFS_GDT_BITMAP_COLUMN;
        mc->c.stored_itbid = hi.itbid;
        mc->c.len = mu->size;
        mc->c.offset = msg->pair->tx.arg0;
        hvfs_err(mds, "Update puuid %lx uuid %lx itbid %ld column offset %ld "
                 "len %ld itbid %ld\n",
                 hi.puuid, hi.uuid, hi.itbid, mc->c.offset,
                 mc->c.len, mc->c.stored_itbid);
        
        /* search and update in the CBHT */
    retry:
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(&hi, hmr, txg, &txg);
        txg_put(txg);
        if (err) {
            if (err == -EAGAIN || err == -ESPLIT ||
                err == -ERESTART) {
                /* have a breath */
                sched_yield();
                if (++retry_nr < 10000) 
                    goto retry;
            }
            hvfs_err(mds, "FATAL ERROR: update the ITE failed w/ %d\n", err);
        }
        hvfs_debug(mds, "Got reply from MDSL and change bitmap to "
                   "location 0x%lx\n",
                   msg->pair->tx.arg0);
        if (hmr->data)
            xfree(hmr->data);
        xfree(hmr);
    }

    xnet_free_msg(msg);

    return err;
out_free_msg:
    xnet_free_msg(msg);
out:
    return err;
}

static inline
int __customized_send_reply(struct bc_delta *bd)
{
    struct xnet_msg *msg;
    int err = 0;

    /* Step 1: prepare the xnet_msg */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }

    /* Step 2: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hmo.site_id, bd->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_AUBITMAP_R, bd->uuid, bd->itbid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Request to confirm the uuid %ld flip %ld "
                 "failed w/ %d\n",
                 bd->uuid, bd->itbid, err);
        goto out_free_msg;
    }

    xnet_free_msg(msg);
    
    return err;
out_free_msg:
    xnet_raw_free_msg(msg);
out:
    return err;
}

/* mds_bc_backend_commit()
 *
 * the uuid and offset should be set in the bc_entry.
 *
 * If we need to rewrite the whole bitmap region, we should notify the MDSL to
 * do read/modify/write(append).
 */
int mds_bc_backend_commit(void)
{
    LIST_HEAD(deltas);
    LIST_HEAD(errlist);
    LIST_HEAD(commit_list);
    struct bc_delta *pos, *n;
    struct bc_commit *bc;
    struct dhe *gdte;
    struct chp *p;
    struct hvfs_txg *txg;
    struct hvfs_md_reply *hmr;
    struct hvfs_index hi = {
        .namelen = 0,
        {.column = HVFS_GDT_BITMAP_COLUMN,},
        .flag = INDEX_LOOKUP | INDEX_COLUMN | INDEX_BY_UUID,
        .puuid = hmi.gdt_uuid,
    };
    struct mdu *mdu;
    struct column *column;
    u64 size, location;
    int err = 0, nr = 0, deal = 0, error = 0;

    hi.psalt = hmi.gdt_salt;

    /* memonly mode? */
    if (hmo.conf.option & HVFS_MDS_MEMONLY) {
        /* just clean the BC's delta list */
        xlock_lock(&hmo.bc.delta_lock);
        list_add(&deltas, &hmo.bc.deltas);
        list_del_init(&hmo.bc.deltas);
        xlock_unlock(&hmo.bc.delta_lock);

        list_for_each_entry_safe(pos, n, &deltas, list) {
            list_del(&pos->list);
            if (pos->site_id == hmo.site_id) {
                async_aubitmap_cleanup(pos->uuid, pos->itbid);
            } else {
                __customized_send_reply(pos);
            }
            xfree(pos);
        }
        return 0;
    }

    /* alloc hmr */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(mds, "get_hmr() failed\n");
        err = -ENOMEM;
        goto out;
    }
        
    xlock_lock(&hmo.bc.delta_lock);
    /* add the new list head after bc.deltas */
    list_add(&deltas, &hmo.bc.deltas);
    /* delete bc.deltas */
    list_del_init(&hmo.bc.deltas);
    xlock_unlock(&hmo.bc.delta_lock);

    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out;
    }

    list_for_each_entry_safe(pos, n, &deltas, list) {
        deal++;
        hi.uuid = pos->uuid;
        hi.hash = hvfs_hash_gdt(pos->uuid, hmi.gdt_salt);
        
        /* we should get and set the hi.itbid */
        hi.itbid = mds_get_itbid(gdte, hi.hash);
        
        /* actually we should confirm the itb is resident in this MDS,
         * however we know that the BC entry is on this MDS, so the itb
         * should on this MDS either. Refer to mds_aubitmap() please! */
        
        /* search in the CBHT */
    retry:
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(&hi, hmr, txg, &txg);
        txg_put(txg);
        if (err) {
            if (err == -EAGAIN || err == -ESPLIT ||
                err == -ERESTART) {
                /* have a breath */
                sched_yield();
                goto retry;
            }
            /* put the current delta to the error list */
            list_del_init(&pos->list);
            if (err == -ENOENT) {
                /* FIXME: TODO: this directory is gone, ok to ignore the
                 * updates */
                xfree(pos);
                continue;
            }
            list_add(&pos->list, &errlist);
            continue;
        }
        /* get the location and size */
        mdu = hmr_extract_local(hmr, EXTRACT_MDU, &nr);
        if (!mdu) {
            hvfs_err(mds, "extract MDU failed on lookup %ld %ld %lx\n",
                         hi.puuid, hi.itbid, hi.hash);
            list_del_init(&pos->list);
            list_add(&pos->list, &errlist);
            continue;
        }
        size = mdu->size;
        column = hmr_extract_local(hmr, EXTRACT_DC, &nr);
        if (!column) {
            hvfs_err(mds, "extract DC failed on lookup %ld %ld %lx\n",
                     hi.puuid, hi.itbid, hi.hash);
            list_del_init(&pos->list);
            list_add(&pos->list, &errlist);
            continue;
        }
        location = column->offset;
        /* free the hmr resources */
        if (hmr->data)
            xfree(hmr->data);
        memset(hmr, 0, sizeof(*hmr));

        p = ring_get_point(hi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDSL]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            list_del_init(&pos->list);
            list_add(&pos->list, &errlist);
            continue;
        }

        /* Commit the delta info now */
        bc = mds_bc_commit_get();
        if (!bc) {
            hvfs_err(mds, "get the bc_commit failed.\n");
            list_del_init(&pos->list);
            list_add(&pos->list, &errlist);
            continue;
        }
        bc->core.uuid = pos->uuid;
        bc->core.itbid = pos->itbid;
        bc->core.location = location;
        bc->dsite_id = p->site_id;
        bc->vid = p->vid;
        bc->delta = pos;
        list_del_init(&pos->list);

        hvfs_debug(mds, "Construct BCC %ld %ld location %ld size %ld\n", 
                   pos->uuid, pos->itbid, location, size);

        /* Step 1: find if we need to enlarge the bitmap region */
        if (pos->itbid >= (size << 3)) {
            /* we need to enlarge the bitmap region */
            bc->core.size = size;
        } else {
            /* we do not need to enlarge the bitmap region, size is set to
             * -1UL to indicate just a bit change in the data region */
            bc->core.size = -1UL;
        }

        /* Step 2: prepare to write the deltas to the dsite */
        err = __customized_send_request(bc);
        if (err) {
            hvfs_err(mds, "send bitmap commit request to MDS %lx "
                     "failed w/ %d.\n",
                     bc->dsite_id, err);
            list_add(&bc->delta->list, &errlist);
        } else {
            /* before freeing the bc->delta, we should send the reply to the
             * source site now */
            /* if the reply is failed to sent, we just wait for the ssite to
             * resend the request:) */
            if (bc->delta->site_id == hmo.site_id) {
                /* self shortcut */
                async_aubitmap_cleanup(bc->delta->uuid, bc->delta->itbid);
            } else {
                __customized_send_reply(bc->delta);
            }
            /* free the resource */
            xfree(bc->delta);
        }
        mds_bc_commit_put(bc);
    }
    mds_dh_put(gdte);

    /* free hmr */
    xfree(hmr);

    /* checking the errlist to re-insert to hmo.bc.deltas */
    list_for_each_entry_safe(pos, n, &errlist, list) {
        list_del_init(&pos->list);
        xlock_lock(&hmo.bc.delta_lock);
        list_add(&pos->list, &hmo.bc.deltas);
        xlock_unlock(&hmo.bc.delta_lock);
        error++;
    }
    hvfs_warning(mds, "BC deltas deal %d error %d\n", deal, error);
    
out:
    return err;
}

void mds_bc_checking(time_t t)
{
    static time_t last_time = 0;
    int err = 0;
    
    if (!hmo.conf.bitmap_cache_interval)
        return;
    if (last_time == 0)
        last_time = t;
    if (t < last_time + hmo.conf.bitmap_cache_interval) {
        return;
    }
    last_time = t;

    /* check if we should do backend commit */
    if (list_empty(&hmo.bc.deltas)) {
        return;
    }

    err = mds_bc_backend_commit();
    if (err) {
        hvfs_err(mds, "mds_bc_backend_commit failed w/ %d\n", err);
    }
}
