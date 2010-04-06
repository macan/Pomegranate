/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-05 22:06:00 macan>
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
    
    hvfs_debug(mds, "BC LOOKUP %ld %ld %lx\n",
               hi->puuid, hi->itbid, hi->hash);
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
            err == -ERESTART)
            /* have a breath */
            sched_yield();
            goto retry;
        goto out_free;
    }

    /* get the location and size */
    mdu = hmr_extract(hmr, EXTRACT_MDU, &nr);
    if (!mdu) {
        hvfs_err(mds, "extract MDU failed on lookup %ld %ld %lx\n",
                 hi->puuid, hi->itbid, hi->hash);
        err = -EINVAL;
        goto out_free;
    }
    *size = mdu->size;
    column = hmr_extract(hmr, EXTRACT_DC, &nr);
    if (!column) {
        hvfs_err(mds, "extract DC failed on lookup %ld %ld %lx\n",
                 hi->puuid, hi->itbid, hi->hash);
        err = -EINVAL;
        goto out_free;
    }
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

    /* Step 3: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.site_id, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_BITMAP, be->uuid, 
                      location + be->offset);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Request to load bitmap of %ld location 0x%lx failed\n",
                 be->uuid, location + be->offset);
        goto out_free_msg;
    }

    /* we got the reply now */
    ASSERT(msg->pair, mds);
    if (msg->pair->xm_datacheck) {
        memcpy(be->array, msg->pair->xm_data, msg->pair->tx.len);
    } else {
        /* failed w/ invalid reply */
        err = -EFAULT;
        xnet_set_auto_free(msg->pair);
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
 * 
 */
int mds_bc_backend_commit(struct bc_entry *be, u64 itbid, u64 location)
{
}
