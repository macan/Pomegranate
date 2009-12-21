/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-21 23:02:48 macan>
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
#include "mdsl_api.h"
#include "xtable.h"
#include "xnet.h"
#include "mds.h"
#include "lib.h"
#include "ring.h"

inline void itb_index_rlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_rlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_lock((xlock_t *)l);
    }
}

inline void itb_index_wlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_wlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_lock((xlock_t *)l);
    }
}

inline void itb_index_runlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_runlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_unlock((xlock_t *)l);
    }
}

inline void itb_index_wunlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_wunlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_unlock((xlock_t *)l);
    }
}

void ite_create(struct hvfs_index *hi, struct ite *e);

/* mds_read_itb
 *
 * Err convention: Kernel err-ptr convention
 */
struct itb *mds_read_itb(u64 puuid, u64 psalt, u64 itbid)
{
    struct storage_index si;
    struct storage_result *sr;
    struct xnet_msg *msg;
    struct chp *p;
    struct itb *i;
    int ret;

    si.sic.uuid = puuid;
    si.sic.arg0 = itbid;
    si.m.sm.len = 0;            /* no data */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return ERR_PTR(-ENOMEM); /* return the err */
        }
    }
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        return (struct itb *)p;
    }
    /* prepare the msg */
    xnet_msg_set_site(msg, p->site_id);
    xnet_msg_add_data(msg, &si, sizeof(si));
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_ITB, 0);
    
    ret = xnet_send(hmo.xc, msg);
    if (ret) {
        hvfs_err(mds, "xnet_send() failed with %d\n", ret);
        return ERR_PTR(ret);
    }
    /* ok, we get the reply: ITB.len is the length */
    sr = (struct storage_result *)(msg->pair->xm_data);
    if (sr->src.err)
        i = ERR_PTR(sr->src.err);
    else
        i = (struct itb *)(sr->data);
    xnet_free_msg(msg);

    return i;
}

/* __itb_get_free_index
 */
long __itb_get_free_index(struct itb *i)
{
    long nr;
    int c, d;
    
    xlock_lock(&i->h.ilock);
    nr = i->h.inf;
    d = c = (1 << i->h.adepth);

    while (c) {
        if (i->index[nr + d].flag == ITB_INDEX_FREE) {
            i->h.inf = nr + 1;
            i->h.itu++;
            xlock_unlock(&i->h.ilock);
            return nr + d;
        }
        c--;
        nr++;
        if (nr == d)
            nr = 0;
    }
    xlock_unlock(&i->h.ilock);

    /* failed to get a free index, internal error! */
    hvfs_err(mds, "Internal error, failed to get a free index.\n");
    return d + d;
}

/* __itb_add_index()
 *
 * holding the bucket.rlock and be.rlock and itb.rlock AND ite.wlock
 */
void __itb_add_index(struct itb *i, u64 offset, long nr, char *name)
{
    struct itb_index *ii = i->index;
    long f;

    /* check the ENTRY index entry's flag */
    if (ii[offset].flag == ITB_INDEX_FREE) {
        /* ok, this entry is free, and nobody can race w/ me */
        ii[offset].flag = ITB_INDEX_UNIQUE;
        ii[offset].entry = nr;
        hvfs_debug(mds, "FREE     ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_UNIQUE) {
        /* only ONE entry, change flag to CONFLICT */
        /* get a free index entry */
        f = __itb_get_free_index(i);
        ii[offset].flag = ITB_INDEX_CONFLICT;
        ii[offset].conflict = f;
        ii[f].flag = ITB_INDEX_UNIQUE;
        ii[f].entry = nr;
        /* update conflict state */
        atomic_inc(&i->h.pseudo_conflicts);
        hvfs_debug(mds, "UNIQUE   ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_CONFLICT) {
        /* FIXME: have SOME entries, check to see if we need change flag to
         * OVERFLOW */
        /* get a free index entry */
        f = __itb_get_free_index(i);
        /* insert to the head */
        ii[f] = ii[offset];
        ii[offset].entry = nr;
        ii[offset].conflict = f;
        /* it is hard to detemine the precise conflicts */
        atomic_inc(&i->h.pseudo_conflicts);
        hvfs_debug(mds, "CONFLICT ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_OVERFLOW) {
        hvfs_err(mds, "Hoo, this ITB overflowed, for now we can't handle it!\n");
    } else {
        hvfs_err(mds, "Invalid ITE flag 0x%x\n", ii[offset].flag);
    }
    xlock_lock(&i->h.ilock);
    /* NOTE: we use '<=' here for max_offset == 0; because the init value of
     * max_offset is 0, you should update the length when nr is exactly
     * ZERO. */
    if (atomic_read(&i->h.max_offset) <= nr) {
        atomic_set(&i->h.max_offset, nr);
        atomic_set(&i->h.len, sizeof(struct itb) + (nr + 1) * sizeof(struct ite));
    }
    xlock_unlock(&i->h.ilock);
}

/*
 * itb_add_ite()
 *
 * holding the bucket.rlock and be.rlock and itb.rlock AND ite.wlock
 */
int itb_add_ite(struct itb *i, struct hvfs_index *hi, void *data)
{
    u64 offset;
    struct ite *ite;
    long nr;
    int err;

    offset = hi->hash & ((1 << i->h.adepth) - 1);

    /* Step1: get a free ITE entry */
    /* Step1.0: check whether this ITB is full */
    if (atomic_inc_return(&i->h.entries) <= (1 << i->h.adepth)) {
    retry:
        nr = find_first_zero_bit((unsigned long *)i->bitmap, (1 << i->h.adepth));
        if (nr < (1 << i->h.adepth)) {
            /* ok, find one */
            /* test and set the bit now */
            if (lib_bitmap_tas(i->bitmap, nr)) {
                /* someone has set this bit, let us retry */
                goto retry;
            }
            hvfs_verbose(mds, "ITB %p: %ld, %ld, 0x%lx %s, offset %ld, nr %ld\n", 
                         i, i->h.puuid, i->h.itbid, hi->hash, 
                         hi->name, offset, nr);
            /* now we got a free ITE entry at position nr */
            ite = &i->ite[nr];
            memset(ite, 0, sizeof(struct ite));
            ite->hash = hi->hash;
            ite->uuid = atomic64_inc_return(&hmi.mi_uuid);
            if (unlikely(hi->flag & INDEX_CREATE_LINK))
                ite->flag |= ITE_FLAG_LS;
            else
                ite->flag |= ITE_FLAG_NORMAL;
            
            if (hi->flag & INDEX_CREATE_DIR) {
                ite->flag |= ITE_FLAG_SDT;
            } else if (hi->flag & INDEX_CREATE_COPY) {
                ite->flag |= ITE_FLAG_GDT;
            }
            if (likely(hi->flag & INDEX_CREATE_SMALL)) {
                ite->flag |= ITE_FLAG_SMALL;
            } else if (hi->flag & INDEX_CREATE_LARGE) {
                ite->flag |= ITE_FLAG_LARGE;
            }
            /* next step: we try to get a free index entry */
            __itb_add_index(i, offset, nr, hi->name);
            /* set up the mdu base on hi->data */
            ite_create(hi, ite);
            memcpy(data, &(ite->g), HVFS_MDU_SIZE);
        } else {
            /* hoo, there is no zero bit! */
            atomic_dec(&i->h.entries);
            err = -EINVAL;
            goto out;
        }
    } else {
        /* already full, should split */
        /* FIXME: ITB SPLIT! */
        err = -ESPLIT;
        goto out;
    }

    err = 0;
    
out:
    return err;
}

/* 
 * itb_del_ite()
 */
void itb_del_ite(struct itb *i, struct ite *e, u64 offset)
{
    u64 io, head = offset;
    u32 prev;

    io = e - i->ite;

    if (i->index[offset].flag == ITB_INDEX_FREE)
        return;
    if (i->index[offset].flag == ITB_INDEX_UNIQUE) {
        /* just free it */
        i->index[offset].flag = ITB_INDEX_FREE;
        goto clear_bitmap;
    }
    
    prev = offset;
    do {
        if (i->index[offset].entry == io) {
            /* ok, del this entry */
            if (offset == head) {
                /* deleting the head, it cant be the tail */
                /* copy the index reversely */
                u32 next = i->index[offset].conflict;
                do {
                    i->index[offset] = i->index[next];
                    offset = next;
                    next = i->index[next].conflict;
                } while (i->index[offset].flag != ITB_INDEX_UNIQUE);
            } else if (i->index[offset].flag == ITB_INDEX_UNIQUE) {
                /* deleting the tail, it cant be the head */
                /* reset the prev's flag to UNIQUE */
                i->index[prev].flag = ITB_INDEX_UNIQUE;
            } else {
                /* deleting a middle entry */
                i->index[prev].conflict = i->index[offset].conflict;
            }
            i->index[offset].flag = ITB_INDEX_FREE;
            i->h.itu--;
            atomic_dec(&i->h.pseudo_conflicts);
            break;
        }
        prev = offset;
    } while (i->index[offset].flag != ITB_INDEX_UNIQUE);

clear_bitmap:
    /* no need to check the TAC result */
    lib_bitmap_tac(i->bitmap, io);
}

/*
 * ITE unlink
 */
void ite_unlink(struct ite *e, struct itb *i, u64 offset)
{
    if (likely(e->flag & ITE_FLAG_NORMAL)) {
        /* normal file */
        e->s.mdu.nlink--;
        if (!e->s.mdu.nlink)
            e->flag = ((e->flag & ~ITE_STATE_MASK) | ITE_UNLINKED);
        else
            e->flag = ((e->flag & ~ITE_STATE_MASK) | ITE_SHADOW);
    } else if (e->flag & ITE_FLAG_LS) {
        /* FIXME: hard link file, nobody refer it, just delete it */
        itb_del_ite(i, e, offset);
    }
}

/*
 * ITE create with HI
 */
void ite_create(struct hvfs_index *hi, struct ite *e)
{
    /* there is always a struct mdu_update with normal create request */

    memcpy(&e->s.name, hi->name, hi->len);
    if (hi->len < HVFS_MAX_NAME_LEN)
        e->s.name[hi->len] = '\0';
    
    if (unlikely(hi->flag & INDEX_CREATE_COPY)) {
        /* hi->data is MDU */
        memcpy(&e->s.mdu, hi->data, sizeof(struct mdu));
    } else if (unlikely(hi->flag & INDEX_CREATE_LINK)) {
        /* hi->data is LS */
        memcpy(&e->s.ls, hi->data, sizeof(struct link_source));
    } else {
        /* INDEX_CREATE_DIR and non-flag, mdu_update */
        struct mdu_update *mu = (struct mdu_update *)hi->data;
    
        /* default fields */
        e->s.mdu.flags |= HVFS_MDU_IF_NORMAL;
        e->s.mdu.nlink = 1;

        if (!mu->valid)
            return;
        if (mu->valid & MU_MODE)
            e->s.mdu.mode = mu->mode;
        if (mu->valid & MU_UID)
            e->s.mdu.uid = mu->uid;
        if (mu->valid & MU_GID)
            e->s.mdu.gid = mu->gid;
        if (mu->valid & MU_FLAG_ADD)
            e->s.mdu.flags |= mu->flags;
        if (mu->valid & MU_FLAG_CLR)
            e->s.mdu.flags &= ~(mu->flags);
        if (mu->valid & MU_ATIME)
            e->s.mdu.atime = mu->atime;
        if (mu->valid & MU_CTIME)
            e->s.mdu.ctime = mu->ctime;
        if (mu->valid & MU_MTIME)
            e->s.mdu.mtime = mu->mtime;
        if (mu->valid & MU_VERSION)
            e->s.mdu.version = mu->version;
        if (mu->valid & MU_SIZE)
            e->s.mdu.size = mu->size;
        if (unlikely(mu->valid & MU_COLUMN)) {
            struct mu_column *mc = (struct mu_column *)(
                hi->data + sizeof(struct mdu_update));
            int i;

            for (i = 0; i < mu->column_no; i++) {
                /* copy to the dst location */
                e->column[(mc + i)->cno] = (mc + i)->c;
            }
        }
    }
}

/*
 * ITE update with HI
 */
void ite_update(struct hvfs_index *hi, struct ite *e)
{
    if (hi->flag & INDEX_MDU_UPDATE) {
        /* hi->data is mdu_update */
        struct mdu_update *mu = (struct mdu_update *)hi->data;

        if (mu->valid & MU_MODE)
            e->s.mdu.mode = mu->mode;
        if (mu->valid & MU_UID)
            e->s.mdu.uid = mu->uid;
        if (mu->valid & MU_GID)
            e->s.mdu.gid = mu->gid;
        if (mu->valid & MU_FLAG_ADD)
            e->s.mdu.flags |= mu->flags;
        if (mu->valid & MU_FLAG_CLR)
            e->s.mdu.flags &= ~(mu->flags);
        if (mu->valid & MU_ATIME)
            e->s.mdu.atime = mu->atime;
        if (mu->valid & MU_CTIME)
            e->s.mdu.ctime = mu->ctime;
        if (mu->valid & MU_MTIME)
            e->s.mdu.mtime = mu->mtime;
        if (mu->valid & MU_VERSION)
            e->s.mdu.version = mu->version;
        if (mu->valid & MU_SIZE)
            e->s.mdu.size = mu->size;
        if (mu->valid & MU_COLUMN) {
            struct mu_column *mc = (struct mu_column *)(
                hi->data + sizeof(struct mdu_update));
            int i;

            for (i = 0; i < mu->column_no; i++) {
                /* copy to the dst location */
                e->column[(mc + i)->cno] = (mc + i)->c;
            }
        }
    } else if (hi->flag & INDEX_CREATE_COPY) {
        /* hi->data is MDU */
        memcpy(&e->s.mdu, hi->data, sizeof(struct mdu));
    } else if (hi->flag & INDEX_CREATE_LINK) {
        /* hi->data is LS */
        memcpy(&e->s.ls, hi->data, sizeof(struct link_source));
    }
}

/*
 * ITE match
 *
 * Return: ITE_MATCH_MISS/ITE_MATCH_HIT
 */
inline int ite_match(struct ite *e, struct hvfs_index *hi)
{
    /* compare the name or uuid */
    if (unlikely(hi->flag & INDEX_ITE_SHADOW)) { 
        if (((e->flag & ITE_STATE_MASK) != ITE_SHADOW) && 
            ((e->flag & ITE_STATE_MASK) != ITE_UNLINKED))
            return ITE_MATCH_MISS;
    }
    
    if ((hi->flag & INDEX_ITE_ACTIVE) && ((e->flag & ITE_STATE_MASK) != ITE_ACTIVE))
        return ITE_MATCH_MISS;
    
    if (hi->flag & INDEX_BY_UUID) {
        if (e->uuid == hi->uuid && e->hash == hi->hash) {
            return ITE_MATCH_HIT;
        } else
            return ITE_MATCH_MISS;
    } else if (hi->flag & INDEX_BY_NAME) {
        if (strncmp(e->s.name, hi->name, hi->len) == 0) {
            return ITE_MATCH_HIT;
        } else
            return ITE_MATCH_MISS;
    } else {
        return ITE_MATCH_MISS;
    }
}

/* ITB Cache init
 *
 * There may be (< hint_size) memory allocated!
 */
int itb_cache_init(struct itb_cache *ic, int hint_size)
{
    struct itb *i;
    int j;
    
    INIT_LIST_HEAD(&ic->lru);
    atomic_set(&ic->csize, 0);
    xlock_init(&ic->lock);
    if (!hint_size)
        return 0;
    
    /* pre-allocate the ITBs */
    for (j = 0; j < hint_size; j++) {
        i = xzalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
        if (!i) {
            hvfs_info(mds, "xzalloc() ITBs failed, continue ...\n");
            continue;
        }
        atomic_inc(&ic->csize);
    }
    return 0;
}

/* ITB Cache destroy
 */
int itb_cache_destroy(struct itb_cache *ic)
{
    struct itbh *pos, *n;

    list_for_each_entry_safe(pos, n, &ic->lru, list) {
        list_del(&pos->list);
        xfree(pos);
    }

    return 0;
}

/* get_free_itb()
 */
struct itb *get_free_itb(struct hvfs_txg *txg)
{
    struct itb *n;
    struct list_head *l = NULL;
    int i;

    xlock_lock(&hmo.ic.lock);
    if (!list_empty(&hmo.ic.lru)) {
        l = hmo.ic.lru.next;
        ASSERT(l != &hmo.ic.lru, mds);
        list_del_init(l);
    }
    xlock_unlock(&hmo.ic.lock);

    if (l) {
        /* remove from the CBHT */
        n = (struct itb *)(list_entry(l, struct itbh, list));
        if (!hlist_unhashed(&n->h.cbht))
            mds_cbht_del(&hmo.cbht, n);
        memset(n, 0, sizeof(struct itb));
    } else {
        /* try to malloc() one */
        n = xzalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
        if (!n) {
            hvfs_err(mds, "xzalloc() ITB failed\n");
            return NULL;
        }
        atomic_inc(&hmo.ic.csize);
    }

    atomic_set(&n->h.len, sizeof(struct itb));
    n->h.adepth = ITB_DEPTH;
    n->h.flag = ITB_ACTIVE;       /* 0 */
    n->h.state = ITB_STATE_CLEAN; /* 0 */
    n->h.txg = txg->txg;
    xrwlock_init(&n->h.lock);
    xlock_init(&n->h.ilock);
    INIT_HLIST_NODE(&n->h.cbht);
    INIT_LIST_HEAD(&n->h.list);
    INIT_LIST_HEAD(&n->h.overflow);
    /* init the lock region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xrwlock_init((xrwlock_t *)(&n->lock[i]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xlock_init((xlock_t *)(&n->lock[i]));
        }
    }

    return n;
}

/* itb_free()
 */
void itb_free(struct itb *i)
{
    int j;

    /* free the locks */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (j = 0; j < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); j++) {
            xrwlock_destroy((xrwlock_t *)(&i->lock[j]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (j = 0; j < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); j++) {
            xlock_destroy((xlock_t *)(&i->lock[j]));
        }
    }
    xlock_lock(&hmo.ic.lock);
    list_add_tail(&i->h.list, &hmo.ic.lru);
    xlock_unlock(&hmo.ic.lock);
}

/* ITB COW
 */
struct itb *itb_cow(struct itb *itb, struct hvfs_txg *txg)
{
    struct itb *n;

    do {
        n = get_free_itb(txg);
    } while (!n && ({xsleep(10); 1;}));

    memcpy(n, itb, sizeof(struct itb));

    /* init ITB header */
    xrwlock_init(&n->h.lock);
    xlock_init(&n->h.ilock);
    INIT_HLIST_NODE(&n->h.cbht);
    INIT_LIST_HEAD(&n->h.list);
    INIT_LIST_HEAD(&n->h.overflow);
    
    return n;
}

/**
 * ITB COW RECOPY
 *
 * Holding the BE.wlock, and the old ITB has beed removed from the be list.
 *
 * NOTE: in itb_cow() we do not finish copying the ITE region, now let us
 * retry to copy the remain regions.
 */
void itb_cow_recopy(struct itb *oi, struct itb *ni)
{
    int i;
    
    hvfs_debug(mds, "copied max_offset is %d, len %d\n", 
               atomic_read(&oi->h.max_offset),
               atomic_read(&oi->h.len));
    
    memcpy(ni->bitmap, oi->bitmap, ITB_COW_BITMAP_LEN);
    memcpy(ni->index, oi->index, ITB_COW_INDEX_LEN);
    memcpy(ni->ite, oi->ite,
           atomic_read(&oi->h.len) - sizeof(struct itb));

    /* some changes in header region */
    if (atomic_read(&ni->h.len) != atomic_read(&oi->h.len)) {
        atomic_set(&ni->h.len, atomic_read(&oi->h.len));
        ni->h.inf = oi->h.inf;
        ni->h.itu = oi->h.itu;
        atomic_set(&ni->h.entries, atomic_read(&oi->h.entries));
        atomic_set(&ni->h.max_offset, atomic_read(&oi->h.max_offset));
        atomic_set(&ni->h.conflicts, atomic_read(&oi->h.conflicts));
        atomic_set(&ni->h.pseudo_conflicts, atomic_read(&oi->h.pseudo_conflicts));
    }
    
    /* init lock region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xrwlock_init((xrwlock_t *)(&ni->lock[i]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xlock_init((xlock_t *)(&ni->lock[i]));
        }
    }

}

/**
 * ITB Dirty, core function!
 *
 * @itb:ITB
 * @t:  TXG
 * @be: bucket_entry
 *
 * Note: dirty and cow the ITB as needed; return the dirtied ITB for using
 *
 * Note: holding the bucket.rlock and be.rlock and itb.rlock and ite.wlock
 *
 * Note: we should release the ite.wlock when we are doing COW! Lesson of
 * bloods~
 */
struct itb *itb_dirty(struct itb *itb, struct hvfs_txg *t, struct itb_lock *l,
                      struct hvfs_txg **otxg)
{
    *otxg = t;

    if (likely(t->txg == itb->h.txg)) {
        /* ITB accessed in this TXG */
        if (likely(itb->h.state == ITB_STATE_DIRTY))
            return itb;
        else {
            hvfs_debug(mds, "Hoo, ITB state 0x%x in TXG: 0x%lx\n", itb->h.state, 
                       t->txg);
            if (itb->h.state == ITB_STATE_CLEAN) {
                /* init TXG, corner case */
                txg_add_itb(t, itb);
            }
            itb->h.state = ITB_STATE_DIRTY;
        }
    } else if (t->txg == itb->h.txg + 1) {
        /* ITB accessed in the last TXG */
        if (itb->h.state == ITB_STATE_WBED || itb->h.state == ITB_STATE_CLEAN) {
            /* clean or already write-backed, free to use */
            hvfs_debug(mds, "clean or already write-backed, free to use.\n");
            itb->h.txg = t->txg;
            itb->h.state = ITB_STATE_DIRTY;
            txg_add_itb(t, itb);
        } else if (itb->h.state == ITB_STATE_DIRTY) {
            /* need COW */
            struct itb *n;
            struct bucket_entry *be;
            int should_retry = 0;

#if 1
            n = itb_cow(itb, t); /* itb_cow always success */

            /* MAGIC: exchange the old ITB with new ITB */
            /* Step1: release BE.rlock & ITB.rlock */
            be = itb->h.be;
            itb_index_wunlock(l);
            xrwlock_runlock(&itb->h.lock);
            xrwlock_runlock(&be->lock);

            /* Step2: get BE.wlock & ITB.wlock */
            xrwlock_wlock(&be->lock);
            xrwlock_wlock(&itb->h.lock);

            /* Step3: check the ITB txg */

            /* Step3.0: is this ITB deleted or moved? */

            if (itb->h.be != be) /* moved or deleted */
                should_retry = 1;
            else {
                /* not moved/deleted, just COWed */
                if (itb->h.txg == t->txg || itb->h.state == ITB_STATE_COWED) {
                    /* somebody already do cow (win us), we need just retrieve
                     * itb */
                    should_retry = 1;
                } else {
                    /* refresh the pointers, and atomic change the pprev */
                    hlist_del_init(&itb->h.cbht);
                    itb->h.state = ITB_STATE_COWED;
                    itb->h.be = NULL;

                    n->h.txg = t->txg;
                    n->h.state = ITB_STATE_DIRTY;
                    n->h.be = be;
                    hlist_add_head(&n->h.cbht, &be->h);

                    /* ok, recopy the new ITEs */
                    itb_cow_recopy(itb, n);
                    hvfs_debug(mds, "ITB COWing %ld %p to %p\n", 
                               itb->h.itbid, itb, n);
                }
            }
            
            /* Step4: release BE.wlock */
            xrwlock_wunlock(&itb->h.lock);
            xrwlock_wunlock(&be->lock);

            /* Step5: loser should retry the access */
            if (should_retry) {
                itb_free(n);
                hvfs_debug(mds, "loser cow ITB %ld from %p\n", 
                           n->h.itbid, itb);
                itb_index_wlock(l);
                xrwlock_rlock(&be->lock);
                xrwlock_rlock(&itb->h.lock);
                return NULL;
            }
            /* Step6: get BE.rlock */
            xrwlock_rlock(&be->lock);
            xrwlock_rlock(&n->h.lock);

            txg_add_itb(t, n);
            itb = n;
#else
            itb->h.txg = t->txg;
#endif
        }
    } else if (t->txg > itb->h.txg + 1) {
        itb->h.txg = t->txg;
        itb->h.state = ITB_STATE_DIRTY;
        txg_add_itb(t, itb);
    } else if (t->txg == itb->h.txg - 1) {
        /* ITB accessed in the TXG, this can happen on the changing TXG. we
         * should put ourself on the new TXG to diminish the complexity of TXG
         * state machine */
        struct hvfs_txg *nt;
        
        hvfs_debug(mds, "TXG %ld <-- ITB(%ld) %ld, reassign the TXG\n", 
                   t->txg, itb->h.itbid, itb->h.txg);
        nt = mds_get_open_txg(&hmo);
        txg_put(t);
        *otxg = nt;
        itb->h.txg = nt->txg;
        itb->h.state = ITB_STATE_DIRTY;
        txg_add_itb(nt, itb);
    }

    return itb;
}

/**
 * Search ITE in the ITB, matched by hvfs_index
 *
 * Err Convention: 0 means no error, other MINUS number means error
 *
 * Note: holding the bucket.rlock and be.rlock and itb.rlock
 *
 * NOTE: this is the very HOT path for LOOKUP/CREATE/UNLINK/....
 */
int itb_search(struct hvfs_index *hi, struct itb *itb, void *data, 
               struct hvfs_txg *txg, struct itb **oi,
               struct hvfs_txg **otxg)
{
    u64 offset;
    u64 total = 1 << (itb->h.adepth + 1);
    atomic64_t *as;
    struct itb_index *ii;
    struct itb_lock *l;
    int ret = -ENOENT;

    /* NOTE: if we are in retrying, we know that the ITB will not COW
     * again! */
retry:
    offset = hi->hash & ((1 << itb->h.adepth) - 1);
    /* get the ITE lock */
    l = &itb->lock[offset / ITB_LOCK_GRANULARITY];
    if (hi->flag & INDEX_LOOKUP) {
        itb_index_rlock(l);
        as = &hmo.profiling.itb.rsearch_depth;
    } else {
        itb_index_wlock(l);
        as = &hmo.profiling.itb.wsearch_depth;
    }
    
    while (offset < total) {
        ii = &itb->index[offset];
        if (ii->flag == ITB_INDEX_FREE)
            break;
        atomic64_inc(as);
        ret = ite_match(&itb->ite[ii->entry], hi);

        if (ii->flag == ITB_INDEX_UNIQUE) {
            if (ret == ITE_MATCH_MISS) {
                break;
            }
        } else {
            /* CONFLICT & OVERFLOW */
            if (ret == ITE_MATCH_MISS) {
                offset = ii->conflict;
                continue;
            }
        }
        /* OK, found it, already lock it then do xxx on it */
        hvfs_verbose(mds, "OK, the ITE do exist in the ITB.\n");
        if (hi->flag & INDEX_LOOKUP) {
            /* read MDU to buffer */
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
        } else if (unlikely(hi->flag & INDEX_CREATE)) {
            /* already exist, so... */
            if (!hi->flag & INDEX_CREATE_FORCE) {
                /* should return -EEXIST */
                ret = -EEXIST;
                goto out;
            }
            /* FIXME: ok, forcely do it */
            if (hi->flag & INDEX_CREATE_DIR) {
                hvfs_debug(mds, "Forcely create dir now ... should not happen?\n");
            } else if (hi->flag & INDEX_CREATE_COPY) {
                hvfs_debug(mds, "Forcely create with MDU ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (!(*oi)) {
                    ret = -EAGAIN;
                    goto out;
                } else if ((*oi) != itb) {
                    /* this means the itb is cowed, we should refresh ourself */
                    goto refresh;
                }
                ite_update(hi, &itb->ite[ii->entry]);
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            } else if (hi->flag & INDEX_CREATE_LINK) {
                hvfs_verbose(mds, "Forcely create hard link ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (!(*oi)) {
                    ret = -EAGAIN;
                    goto out;
                } else if ((*oi) != itb) {
                    /* this measn the itb is cowed, we should refresh ourself */
                    goto refresh;
                }
                ite_update(hi, &itb->ite[ii->entry]);
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            }
        } else if (hi->flag & INDEX_MDU_UPDATE) {
            /* setattr, no failure */
            hvfs_verbose(mds, "Find the ITE and update the MDU.\n");
            *oi = itb_dirty(itb, txg, l, otxg);
            if (!(*oi)) {
                ret = -EAGAIN;
                goto out;
            } else if ((*oi) != itb) {
                /* this means the itb is cowd, we should refresh ourself */
                goto refresh;
            }
            ite_update(hi, &itb->ite[ii->entry]);
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
        } else if (hi->flag & INDEX_UNLINK) {
            /* unlink */
            hvfs_verbose(mds, "Find the ITE and unlink it.\n");
            *oi = itb_dirty(itb, txg, l, otxg);
            if (!(*oi)) {
                ret = -EAGAIN;
                goto out;
            } else if ((*oi) != itb) {
                /* this means the itb is cowed, we should refresh ourself */
                goto refresh;
            }
            ite_unlink(&itb->ite[ii->entry], itb, offset);
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
        } else if (hi->flag & INDEX_LINK_ADD) {
            /* hard link */
            hvfs_verbose(mds, "Find the ITE and hard link it.\n");
            /* check if this is a hard link ITE */
            if (itb->ite[ii->entry].flag & ITE_FLAG_LS) {
                ret = -EACCES;
                goto out;
            }
            *oi = itb_dirty(itb, txg, l, otxg);
            if (!(*oi)) {
                ret = -EAGAIN;
                goto out;
            } else if ((*oi) != itb) {
                /* this means the itb is cowed, we should refresh ourself */
                goto refresh;
            }
            itb->ite[ii->entry].s.mdu.nlink++;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
        } else if (hi->flag & INDEX_SYMLINK) {
            /* symlink */
            hvfs_err(mds, "Find the ITE and can NOT symlink it.\n");
            ret = -EEXIST;
            goto out;
        } else {
            hvfs_err(mds, "Hooo, what is your type: 0x%x\n", hi->flag);
            ret = -EINVAL;
            goto out;
        }
        ret = 0;
        goto out;
    }
    /* OK, can not find it, so ... */
    hvfs_verbose(mds, "OK, the ITE do NOT exist in the ITB.\n");
    if (likely(hi->flag & INDEX_CREATE || hi->flag & INDEX_SYMLINK)) {
        hvfs_verbose(mds, "Not find the ITE and create/symlink it.\n");
        *oi= itb_dirty(itb, txg, l, otxg);
        if (unlikely((*oi) != itb)) {
            if (!(*oi)) {
                ret = -EAGAIN;  /* w/ itb.rlocked */
                goto out;
            } else {
                /* this means the itb is cowed, we should refresh ourself */
                /* w/ itb.runlocked and oi->rlocked */
                goto refresh;
            }
        }
        ret = itb_add_ite(itb, hi, data);
    } else {
        /* other operations means ENOENT */
        ret = -ENOENT;
    }
out:
    *oi = itb;
    /* put the lock */
    if (hi->flag & INDEX_LOOKUP)
        itb_index_runlock(l);
    else
        itb_index_wunlock(l);
    return ret;
refresh:
    /* already released index.lock */
    itb = *oi;
    goto retry;
}

/* itb_readdir()
 *
 * NOTE: holding the bucket.rlock, be.rlock, itb.rlock
 */
int itb_readdir(struct hvfs_index *hi, struct itb *i, struct hvfs_md_reply *hmr)
{
    return 0;
}

/* itb_dump()
 *
 * NOTE: this function is written for debuging, no locking
 */
void itb_dump(struct itb *i)
{
    char line[4096];
    struct itb_index *ii;
    int j, l;
    
    /* dump the itb header */
    hvfs_info(mds, "Header of ITB %p:\n", i);
    hvfs_info(mds, "flag %x state %x depth %d adepth %d\n",
              i->h.flag, i->h.state, i->h.depth, i->h.adepth);
    hvfs_info(mds, "entries %d, max_offset %d, conflicts %d, "
              "pseudo_conflicts %d\n",
              atomic_read(&i->h.entries), atomic_read(&i->h.max_offset),
              atomic_read(&i->h.conflicts), 
              atomic_read(&i->h.pseudo_conflicts));
    hvfs_info(mds, "txg %ld puuid %ld itbid %ld hash %lx\n",
              i->h.txg, i->h.puuid, i->h.itbid, i->h.hash);
    hvfs_info(mds, "be %p len %d inf %d itu %d\n",
              i->h.be, atomic_read(&i->h.len), i->h.inf, i->h.itu);

    /* dump the bitmap */
    memset(line, 0, sizeof(line));
    for (j = 0, l = 0; j < (1 << (ITB_DEPTH - 3)); j++) {
        l += sprintf(line + l, "%x", i->bitmap[j]);
    }
    hvfs_info(mds, "Bitmap of ITB %p:\n%s\n", i, line);
    /* dump the index region */
    hvfs_info(mds, "Index of ITB %p:\n", i);
    for (j = 0, l = 0; j < (1 << ITB_DEPTH); j++, l = 0) {
        ii = &i->index[j];
        if (ii->flag == ITB_INDEX_FREE)
            continue;
        l += sprintf(line + l, "offset %4d: ", j);
        do {
            l += sprintf(line + l, "<%x,%d,%d,%s>", ii->flag, ii->entry, 
                         ii->conflict, i->ite[ii->entry].s.name);
        } while (ii->flag != ITB_INDEX_UNIQUE && 
                 (ii = &i->index[ii->conflict]));
        line[l] = '\0';
        hvfs_info(mds, "%s\n", line);
    }
    return;
}
