/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-26 09:20:00 macan>
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

#define SEG_BASE (16 * 1024)
#define SEG_TOTAL (SEG_BASE)    /* # of entries */

int mds_seg_alloc(struct segment *s, struct eh *eh)
{
    int err = 0;

    s->seg = xzalloc(s->alen * sizeof(struct bucket *));
    if (!s->seg) {
        hvfs_err(mds, "xzalloc() seg failed\n");
        err = -ENOMEM;
    }

    return 0;
}

void mds_seg_free(struct segment *s)
{
    if (s->seg)
        xfree(s->seg);
    s->len = 0;
    s->seg = NULL;
}

static inline struct segment *mds_segment_alloc()
{
    struct segment *s;
    
    s = xzalloc(sizeof(struct segment));
    if (s) {
        INIT_LIST_HEAD(&s->list);
    }
    return s;
}

int mds_segment_init(struct segment *s, u64 offset, u32 alen, struct eh *eh)
{
    s->offset = offset;
    s->alen = alen;
    s->len = 0;
    return mds_seg_alloc(s, eh);
}

struct bucket *__cbht cbht_bucket_alloc(int depth)
{
    struct bucket *b;
    struct bucket_entry *be;
    int i;

    b = xzalloc(sizeof(struct bucket));
    if (!b) {
        return NULL;
    }
#ifdef UNIT_TEST
    hvfs_debug(mds, "alloc bucket %p, depth %d\n", b, depth);
#endif
    b->content = xzalloc(sizeof(struct bucket_entry) * (1 << depth));
    if (!b->content) {
        return NULL;
    }
    /* init the bucket */
    b->adepth = depth;
    xrwlock_init(&b->lock);

    be = (struct bucket_entry *)(b->content);
    for (i = 0; i < (1 << depth); i++) {
        INIT_HLIST_HEAD(&(be + i)->h);
        xrwlock_init(&(be + i)->lock);
    }

    mds_cbht_prof_buckets_add();
    return b;
}

void __cbht cbht_bucket_free(struct bucket *b)
{
    struct bucket_entry *be;
    int i;
    
    if (!b)
        return;

    xrwlock_destroy(&b->lock);
    be = (struct bucket_entry *)(b->content);
    if (!be)
        goto free_bucket;
    for (i = 0; i < (1 << b->adepth); i++) {
        xrwlock_destroy(&(be + i)->lock);
    }
    xfree(b->content);
free_bucket:
    xfree(b);
    mds_cbht_prof_buckets_del();
}

/*
 * Internal use, not export
 */
int __cbht cbht_bucket_init(struct eh *eh, struct segment *s)
{
    struct bucket *b;

    /* alloc bucket #0 */
    b = cbht_bucket_alloc(eh->bucket_depth);
    if (!b) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        return -ENOMEM;
    }

    b->id = 0;                  /* set bucket id to 0 */
    *((struct bucket **)(s->seg)) = b;
    s->len = 1;
    
    return 0;
}

inline int __cbht segment_update_dir(struct eh *eh, u64 len, struct bucket *b)
{
    /* follow the <b->id> to change all matched dir entries */
    struct segment *s;
    u64 mask = (1 << atomic_read(&b->depth)) - 1;
    int i;
    
    list_for_each_entry(s, &eh->dir, list) {
        for (i = 0; i < s->len; i++) {
            if (((s->offset + i) & mask) == (b->id & mask)) {
                *(((struct bucket **)s->seg) + i) = b;
                hvfs_debug(mds, "D #%d Update @ %d w/ %p %ld\n", 
                           eh->dir_depth, i, b, b->id);
            }
            if (!(--len))
                break;
        }
    }
    
/*     cbht_print_dir(eh); */
    return 0;
}

void cbht_print_dir(struct eh *eh)
{
    struct segment *s;
    int i;

    hvfs_info(mds, "CBHT depth %d\n", eh->dir_depth);
    list_for_each_entry(s, &eh->dir, list) {
        for (i = 0; i < s->len; i++) {
            hvfs_info(mds, "offset %016d %p\n", i,
                      *(((struct bucket **)s->seg) + i));
        }
    }
}

/* cbht_copy_dir()
 */
void __cbht cbht_copy_dir(struct segment *s, u64 offset, u64 len, 
                          struct eh *eh)
{
    u64 clen, cplen = 0;
    struct segment *pos;
    
    /* NOTE: have not check the arguments */
    list_for_each_entry(pos, &eh->dir, list) {
        if (pos->offset <= offset && offset < (pos->offset + pos->len)) {
            clen = min(len, (pos->offset + pos->len - offset));
            hvfs_debug(mds, "copy to [%ld,%ld) from [%ld,%ld), clen %ld\n",
                       s->offset + s->len, s->offset + s->len + clen,
                       offset, offset + len, clen);
            memcpy(((struct bucket **)s->seg) + s->len + cplen, 
                   ((struct bucket **)pos->seg) + (offset - pos->offset), 
                   clen * sizeof(struct bucket **));
            len -= clen;
            cplen += clen;
            offset += clen;
        }
        if (!len)
            break;
    }
}

/* cbht_enlarge_dir()
 *
 * @tdepth: target depth
 *
 * double the directory
 */
int __cbht cbht_enlarge_dir(struct eh *eh, u32 tdepth)
{
    u32 olen = (1 << eh->dir_depth);
    u32 nlen = olen;
    struct segment *s, *ss = NULL;
    u64 offset;
    int err = 0;

    if (tdepth <= eh->dir_depth) {
        /* already enlarged */
        goto out;
    }
    list_for_each_entry(s, &eh->dir, list) {
        if (olen == s->len) {
            /* enlarge from this segment */
            ss = s;
            break;
        } else {
            olen -= s->len;
        }
    }
    /* get the begining segment */
    if (!ss) {
        hvfs_err(mds, "internal error on cbht dir segment.\n");
        err = -EINVAL;
        goto out;
    }
    offset = 0;
    while (nlen > 0) {
        olen = ss->alen - ss->len; /* writable region in this segment */
        olen = min(olen, nlen);
        if (olen) {
            cbht_copy_dir(ss, offset, olen, eh);
            nlen -= olen;
            offset += olen;
            ss->len += olen;
        }
        /* next segment */
        if (nlen && (ss->list.next == &eh->dir)) {
            /* should allocate a new segment */
            s = mds_segment_alloc();
            if (!s) {
                err = -ENOMEM;
                goto out;
            }
            err = mds_segment_init(s, ss->offset + ss->alen, ss->alen, eh);
            if (err)
                goto out;
            ss = s;
            /* add to the dir list */
            list_add_tail(&s->list, &eh->dir);
        }
    }
    /* ok to change the depth */
    eh->dir_depth++;
    mds_cbht_prof_depth(eh->dir_depth);

out:
    return err;
}

/* cbht_update_dir()
 */
int __cbht cbht_update_dir(struct eh *eh, struct bucket *b)
{
    int err;

    /* NOTE THAT:
     *
     * We use timed lock to detect livelock and retry ourself.
     */
    xrwlock_wlock(&eh->lock);

    /* enlarge dir? */
    if (atomic_read(&b->depth) > eh->dir_depth) {
        err = cbht_enlarge_dir(eh, atomic_read(&b->depth));
        if (err)
            goto out;
    }

    err = segment_update_dir(eh, (1 << eh->dir_depth), b);
    
out:
    xrwlock_wunlock(&eh->lock);
    return err;
}

/* cbht_bucket_split()
 *
 * Note: holding the bucket.rlock         (temporary out of date!)
 *
 * NOTE: More high efficiency approach, we need remember the
 * bucket.depth. After spliting, we check the bucket.depth, if it do not match
 * the expected depth, then we need to restart the dir search.
 */
int __cbht cbht_bucket_split(struct eh *eh, struct bucket *ob, u64 criminal,
                             u32 sdepth)
{
#define IN_NEW 0
#define IN_OLD 1
    /* Note that we do not know how many levels should we split, so just
     * repeat spliting until the bucket is all NOT full!
     */
    struct bucket *nb, *tb;
    struct bucket_entry *obe, *nbe;
    struct hlist_node *pos, *n;
    struct itbh *ih;
    int err = 0, i, in;

    xrwlock_runlock(&ob->lock);
    /* change it to wlock */
    xrwlock_wlock(&ob->lock);
    /* recheck if the bucket has been split */
    if (atomic_read(&ob->active) < (2 << ob->adepth)) {
        /* ok, this bucket has been split, release all the lock */
        xrwlock_wunlock(&ob->lock);
        return -EAGAIN;
    }
    /* recheck if the dir depth has changed */
    if (sdepth != eh->dir_depth) {
        xrwlock_wunlock(&ob->lock);
        return -EAGAIN;
    }

    /* ok, we get the bucket.wlock, and the bucket should be split */
retry:
    nb = cbht_bucket_alloc(eh->bucket_depth);
    if (!nb) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        err = -ENOMEM;
        goto out_lock;
    }
    atomic_inc(&ob->depth);
    atomic_set(&nb->depth, atomic_read(&ob->depth));
    /* set bucket id */
    nb->id = ob->id | (1 << (atomic_read(&nb->depth) - 1));

    /* move ITBs */
    obe = ob->content;
    nbe = nb->content;

    /* we know that the bucket has been totally locked, so no be.*lock is
     * needed */
    for (i = 0; i < (1 << eh->bucket_depth); i++) {
        hlist_for_each_entry_safe(ih, pos, n, &(obe + i)->h, cbht) {
            if ((ih->hash >> eh->bucket_depth) & 
                (1 << (atomic_read(&nb->depth) - 1))) {
                hvfs_debug(mds, "hash 0x%lx from ob[%ld] to nb[%ld]\n", 
                           ih->hash, ob->id, nb->id);
                /* move the new ITB */
                hlist_del_init(pos);
                hlist_add_head(pos, &(nbe + i)->h);

                /* no need to lock the itb */
                ih->be = nbe + i;

                atomic_inc(&nb->active);
                atomic_dec(&ob->active);
            }
        }
    }
    /* one-level split has completed, but ... */
    if ((criminal >> eh->bucket_depth) & (1 << (atomic_read(&nb->depth) - 1)))
        in = IN_NEW;
    else
        in = IN_OLD;

    /* pre-locked new bucket, we know the two new buckets are all wlocked */
    xrwlock_wlock(&nb->lock);
    
    /* update the directory */
    err = cbht_update_dir(eh, nb);
    if (err) {
        xrwlock_wunlock(&nb->lock);
        if (err == -EAGAIN) {
            atomic_dec(&ob->depth);
            /* we should re-move the entries from nb to ob! */
        }
        goto out_free;
    }

    hvfs_debug(mds, "%lx, in %d: ob[%ld] %d nb[%ld] %d. eh->depth %d\n", 
               criminal, in, ob->id, atomic_read(&ob->active), 
               nb->id, atomic_read(&nb->active), eh->dir_depth);

    if (!atomic_read(&nb->active) && (in == IN_OLD)) {
        /* old bucket need deeply split */
        /* keep ob not changed and nb unlocked */
        tb = ob;
        xrwlock_wunlock(&nb->lock);
    } else if (!atomic_read(&ob->active) && (in == IN_NEW)) {
        /* new bucket need deeply split */
        /* keep nb locked */
        tb = nb;
        xrwlock_wunlock(&ob->lock);
    } else {
        /* ok, no one need deeply split */
        xrwlock_wunlock(&nb->lock);
        xrwlock_wunlock(&ob->lock);
        tb = NULL;
    }

    mds_cbht_prof_split();

    if (tb) {
        hvfs_debug(mds, "bucket %p need deeply split.\n", tb);
        ob = tb;
        goto retry;
    }

    err = 0;
    return err;

out_free:
    cbht_bucket_free(nb);
out_lock:
    xrwlock_wunlock(&ob->lock);
    return err;
#undef IN_NEW
#undef IN_OLD
}

/* CBHT init
 *
 * @eh:     
 * @bdepth: bucket depth
 */
int mds_cbht_init(struct eh *eh, int bdepth)
{
    struct segment *s;
    int err = 0;
    
    /* do not move this region! */
    /* REGION BEGIN */
    eh->dir_depth = 0;
    eh->bucket_depth = bdepth;
    /* REGION END */

    INIT_LIST_HEAD(&eh->dir);
    xrwlock_init(&eh->lock);

    /* allocate the EH directory */
    s = mds_segment_alloc();
    if (!s) {
        hvfs_err(mds, "mds_segment_alloc() failed\n");
        return -ENOMEM;
    }

    /* init the segment */
    err = mds_segment_init(s, 0, SEG_TOTAL, eh);
    if (err)
        return err;

    /* init the bucket #0 */
    err = cbht_bucket_init(eh, s);
    if (err)
        return err;

    /* add to the dir list */
    xrwlock_wlock(&eh->lock);
    list_add_tail(&s->list, &eh->dir);
    xrwlock_wunlock(&eh->lock);

    return 0;
}

/* CBHT destroy w/o init
 *
 * @eh:
 *
 * Note: do NOT free any ITBs in CBHT, you must free them manually for now 
 */
void mds_cbht_destroy(struct eh *eh)
{
    struct segment *s, *n;
    
    xrwlock_wlock(&eh->lock);
    list_for_each_entry_safe(s, n, &eh->dir, list) {
        list_del(&s->list);
        mds_seg_free(s);
        xfree(s);
    }
    xrwlock_wunlock(&eh->lock);
}

/* CBHT insert with bucket/be rlocked at returning
 *
 * Note: holding nothing
 */
int __cbht mds_cbht_insert_bbrlocked(struct eh *eh, struct itb *i, 
                                     struct bucket **ob, 
                                     struct bucket_entry **oe,
                                     struct itb **oi)
{
    u64 hash, offset;
    struct bucket *b;
    struct bucket_entry *be;
    struct itbh *ih;
    struct hlist_node *pos;
    u32 sdepth;                 /* saved depth to detect changing */
    u32 err;

    hash = hvfs_hash(i->h.puuid, i->h.itbid, sizeof(u64), HASH_SEL_CBHT);
    i->h.hash = hash;
    
retry:
    b = mds_cbht_search_dir(hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", i->h.itbid);
        return -ENOENT;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* holding the bucket.rlock now */

    /* is the bucket will overflow? */
    if (atomic_read(&b->active) >= (2 << b->adepth)) {
        err = cbht_bucket_split(eh, b, hash, sdepth);
        if (!err || err == -EAGAIN) /* already release the bucket.rlock? */
            goto retry;
        else
            goto out;
    }

    hvfs_debug(mds, "%lx, ITB %ld, %ld trying to insert to b[%ld]\n", 
               hash, i->h.puuid, i->h.itbid, b->id);
    xrwlock_wlock(&be->lock);
    /* ok, we should check whether this ITB is existing */
    if (!hlist_empty(&be->h)) {
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == i->h.puuid && ih->itbid == i->h.itbid) {
                /* OK, find the itb in the CBHT, we do NOT need insert
                 * ourself */
                hvfs_debug(mds, "OK, ITB %p find that someone already "
                           "insert the ITB %p.\n",
                           ih, i);
                *oi = (struct itb *)ih;
                *ob = b;
                *oe = be;
                xrwlock_wunlock(&be->lock);
                xrwlock_rlock(&be->lock);
                return -EEXIST;
            }
        }
    }
    xrwlock_rlock(&i->h.lock);
    hlist_add_head(&i->h.cbht, &be->h);
    i->h.be = be;
    xrwlock_runlock(&i->h.lock);
    xrwlock_wunlock(&be->lock);

    atomic_inc(&b->active);
    xrwlock_rlock(&be->lock);
    *ob = b;
    *oe = be;
    return 0;
    
out:
    xrwlock_runlock(&b->lock);
    return err;
}

/* CBHT lookup for existing ITBs, do not modify any content
 *
 * Note: holding nothing
 * Note: holding 
 */
int __cbht mds_cbht_exist_check(struct eh *eh, u64 puuid, u64 itbid)
{
    struct bucket *b;
    struct bucket_entry *be;
    struct itbh *ih;
    struct hlist_node *pos;
    u64 hash, offset;
    u32 sdepth;
    u32 err = 0;

    hash = hvfs_hash(puuid, itbid, sizeof(u64), HASH_SEL_CBHT);

    b = mds_cbht_search_dir(hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No bucket exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", itbid);
        return -ENOENT;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* holding the bucket.rlock now */
    xrwlock_wlock(&be->lock);
    hlist_for_each_entry(ih, pos, &be->h, cbht) {
        if (ih->puuid == puuid && ih->itbid == itbid) {
            /* exist */
            err = -EEXIST;
            break;
        }
    }
    xrwlock_wunlock(&be->lock);
    xrwlock_runlock(&b->lock);

    return err;
}

/* CBHT insert without any lock preservated at returning
 *
 * NOTE: this function do NOT check whether the ITB is already inserted into
 * the CBHT, so you should use this function w/ more care. I strongly
 * suggested that do NOT use this function other than just testing.
 *
 * Note: holding nothing
 */
int __cbht mds_cbht_insert(struct eh *eh, struct itb *i)
{
    u64 hash, offset;
    struct bucket *b;
    struct bucket_entry *be;
    u32 sdepth;                 /* saved depth to detect changing */
    u32 err;
    
    hash = hvfs_hash(i->h.puuid, i->h.itbid, sizeof(u64), HASH_SEL_CBHT);
    i->h.hash = hash;
    
retry:
    b = mds_cbht_search_dir(hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", i->h.itbid);
        return -ENOENT;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* holding the bucket.rlock now */

    /* is the bucket will overflow? */
    if (atomic_read(&b->active) >= (2 << b->adepth)) {
        err = cbht_bucket_split(eh, b, hash, sdepth);
        if (!err || err == -EAGAIN) /* already release the bucket.rlock? */
            goto retry;
        else
            goto out;
    }
    
    xrwlock_wlock(&be->lock);
    xrwlock_rlock(&i->h.lock);
    hlist_add_head(&i->h.cbht, &be->h);
    i->h.be = be;
    xrwlock_runlock(&i->h.lock);
    xrwlock_wunlock(&be->lock);

    atomic_inc(&b->active);
    err = 0;
    
out:
    xrwlock_runlock(&b->lock);
    return err;
}

/* CBHT del
 *
 * Note: holding nothing
 */
int __cbht mds_cbht_del(struct eh *eh, struct itb *i)
{
    struct bucket_entry *be;
    struct bucket *b;
    u64 offset;
    u32 sdepth;

    b = mds_cbht_search_dir(i->h.hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", i->h.itbid);
        return -ENOENT;
    }
    offset = i->h.hash & ((1 << eh->bucket_depth) - 1);
    be = b->content +offset;

    /* holding the bucket.rlock now */

    /* is the bucket will underflow? FIXME: no underflow for now */
    xrwlock_wlock(&be->lock);
    xrwlock_wlock(&i->h.lock);
    /* recheck whether this itb has been moved? */
    if (i->h.be != be) {
        xrwlock_wunlock(&i->h.lock);
        xrwlock_wunlock(&be->lock);
        xrwlock_runlock(&b->lock);
        return 0;
    }
    hlist_del_init(&i->h.cbht);
    i->h.be = NULL;
    xrwlock_wunlock(&i->h.lock);
    xrwlock_wunlock(&be->lock);

    xrwlock_runlock(&b->lock);
    return 0;
}

/* CBHT scaning
 *
 * We try to scan the whole CBHT to execute the specific operations.
 */
void __cbht mds_cbht_scan(struct eh *eh, int op)
{
    static u64 seg_offsets[HVFS_MDS_MAX_OPS] = {0,};
    static u64 bucket_offsets[HVFS_MDS_MAX_OPS] = {0,};
    struct segment *s;
    struct bucket *b = NULL;
    struct bucket_entry *be;
    struct itbh *ih;
    struct hlist_node *pos;
    u64 offset;
    int found = 0, err = 0;

    if (op >= HVFS_MDS_MAX_OPS)
        return;
    
    xrwlock_rlock(&eh->lock);
    list_for_each_entry(s, &eh->dir, list) {
        if (s->offset <= seg_offsets[op] && 
            seg_offsets[op] < (s->offset + s->len)) {
            found = 1;
            break;
        }
    }
    if (found) {
        if (s->seg) {
            for (offset = bucket_offsets[op]; offset < s->len; offset++) {
                b = *(((struct bucket **)s->seg) + offset);
                /* ok, holding the bucket rlock */
                err = xrwlock_tryrlock(&b->lock);
                if (err)
                    continue;
                bucket_offsets[op] = offset + 1;
                break;
            }
            if (offset == s->len) {
                b = NULL;
                seg_offsets[op] = s->offset + s->alen;
                bucket_offsets[op] = 0;
            }
        }
    } else {
        seg_offsets[op] = 0;
        bucket_offsets[op] = 0;
    }
    xrwlock_runlock(&eh->lock);

    /* ok, we holding the bucket rlock now */
    if (b) {
        if (atomic_read(&b->active) == 0)
            goto bypass;
        for (offset = 0; offset < (1 << eh->bucket_depth); offset++) {
            be = b->content + offset;
            xrwlock_rlock(&be->lock);
            hlist_for_each_entry(ih, pos, &be->h, cbht) {
                if (eh->ops) {
                    switch (op) {
                    case HVFS_MDS_OP_EVICT:
                        if (eh->ops->evict)
                            eh->ops->evict(eh, be, ih);
                        break;
                    case HVFS_MDS_OP_CLEAN:
                        if (eh->ops->clean)
                            eh->ops->clean(eh, be, ih);
                        break;
                    default:;
                    }
                }
            }
            xrwlock_runlock(&be->lock);
        }
    bypass:
        xrwlock_runlock(&b->lock);
    }
}

/* CBHT dir search
 *
 * if return value is not error, then the bucket rlock is holding
 *
 * Error Convention: kernel ptr-err!
 */
struct bucket * __cbht mds_cbht_search_dir(u64 hash, u32 *ldepth)
{
    struct eh *eh = &hmo.cbht;
    struct segment *s;
    struct bucket *b = ERR_PTR(-ENOENT); /* ENOENT means can not find it */
    u64 offset;
    int found = 0, err = 0, nr = 0;
    
retry:
    xrwlock_rlock(&eh->lock);
    offset = (hash >> eh->bucket_depth) & ((1 << eh->dir_depth) - 1);
    list_for_each_entry(s, &eh->dir, list) {
        if (s->offset <= offset && offset < (s->offset + s->len)) {
            found = 1;
            break;
        }
    }
    if (likely(found)) {
        offset -= s->offset;
        if (s->seg) {
            b = *(((struct bucket **)s->seg) + offset);
            hvfs_verbose(mds, "hash 0x%lx, offset %ld, b[%ld]\n",
                         hash, offset, b->id);
            /* ok, holding the bucket rlock */
            err = xrwlock_tryrlock(&b->lock);
            if (err == EBUSY || err == EAGAIN) {
                /* EBUSY: somebody wlock the bucket for spliting? */
                /* EAGAIN: max rlock got, retry */
                /* OK: retry myself! */
                xrwlock_runlock(&eh->lock);
                /* NOTE THAT: the eh->lock is under heavy using in a
                 * create-cluster test case, a lot of threads holding the
                 * rlock will block the bucket_split() progressing. What
                 * should we do? */
                sched_yield();  /* do we need this? */
                if (unlikely(hmo.conf.cbht_slow_down)) {
                    if (nr < 12)
                        nr++;
                    xsleep(lib_random(100 << nr));
                }
                found = 0;
                goto retry;
            } else if (err) {
                b = ERR_PTR(-err);
            }
        }
    }
            
    *ldepth = eh->dir_depth;
    xrwlock_runlock(&eh->lock);

    return b;
}

/*
 * Note: holding the bucket.rlock, be.rlock
 */
int __cbht cbht_itb_hit(struct itb *i, struct hvfs_index *hi, 
                        struct hvfs_md_reply *hmr, struct hvfs_txg *txg,
                        struct hvfs_txg **otxg)
{
    struct itb *oi;
    struct mdu *m;
    int err, offset = 0;
    char mdu_rpy[HVFS_MDU_SIZE + sizeof(struct column)];

    xrwlock_rlock(&i->h.lock);
    /* check the ITB state */
    if (unlikely(i->h.state == ITB_STATE_COWED)) {
        xrwlock_runlock(&i->h.lock);
        return -EAGAIN;
    }
    if (unlikely(hi->flag & INDEX_BY_ITB)) {
        /* readdir, read-only */
        err = itb_readdir(hi, i, hmr);
        goto out;
    }
    err = itb_search(hi, i, mdu_rpy, txg, &oi, otxg);
    /* NOTE: we should use the substituted ITB now */
    i = oi;
    if (unlikely(err)) {
        hvfs_debug(mds, "Oh, itb_search() return %d."
                   "(itb [%ld,%ld], hi [%ld,%ld,%s]), itb %p\n", 
                   err, i->h.puuid, i->h.itbid, hi->puuid, 
                   hi->itbid, hi->name, i);
        goto out;
    }
    /* FIXME: fill hmr with mdu_rpy */
    /* determine the flags */
    m = (struct mdu *)(mdu_rpy);
    if (hi->flag & INDEX_BY_ITB)
        hmr->flag |= MD_REPLY_READDIR;

    if (S_ISDIR(m->mode) && hi->puuid != hmi.gdt_uuid)
        hmr->flag |= MD_REPLY_DIR_SDT;
    if (m->flags & HVFS_MDU_IF_LINKT) {
        hmr->flag |= MD_REPLY_WITH_LS;
        hmr->len += sizeof(struct link_source);
    } else {
        hmr->flag |= MD_REPLY_WITH_MDU;
        hmr->len += HVFS_MDU_SIZE;
        hmr->mdu_no = 1;        /* only ONE mdu */
    }

    if (unlikely(hi->flag & INDEX_BIT_FLIP)) {
        hmr->flag |= MD_REPLY_WITH_BFLIP;
    }
    if (unlikely(hi->flag & INDEX_COLUMN)) {
        hmr->flag |= MD_REPLY_WITH_DC;
        hmr->len += sizeof(struct column);
        hmr->dc_no = 1;
    }
    
    hmr->flag |= MD_REPLY_WITH_HI;
    hmr->len += sizeof(*hi);

    hmr->data = xmalloc(hmr->len);
    if (unlikely(!hmr->data)) {
        hvfs_err(mds, "xalloc() hmr->data failed\n");
        /* do not retry myself */
        err = -ENOMEM;
        goto out;
    }
    /* prepare HI */
    memcpy(hmr->data, hi, sizeof(*hi));
    offset += sizeof(*hi);
    /* prepare MDU/LS */
    if (m->flags & HVFS_MDU_IF_LINKT) {
        memcpy(hmr->data + offset, mdu_rpy, sizeof(struct link_source));
        offset += sizeof(struct link_source);
    } else {
        memcpy(hmr->data + offset, mdu_rpy, HVFS_MDU_SIZE);
        offset += HVFS_MDU_SIZE;
    }
    /* prepare BITMAP */
    /* prepare DC */
    if (unlikely(hi->flag & INDEX_COLUMN)) {
        memcpy(hmr->data + offset, mdu_rpy + HVFS_MDU_SIZE, 
               sizeof(struct column));
    }
    
out:
    xrwlock_runlock(&i->h.lock);
    return err;
}

/*
 * Note: holding nothing
 */
int __cbht cbht_itb_miss(struct hvfs_index *hi, 
                         struct hvfs_md_reply *hmr, struct hvfs_txg *txg,
                         struct hvfs_txg **otxg)
{
    struct itb *i, *oi;
    struct bucket *b;
    struct bucket_entry *e;
    int err = 0;

    /* Step1: read the itb from mdsl */
    i = mds_read_itb(hi->puuid, hi->psalt, hi->itbid);
    if (IS_ERR(i)) {
        /* read itb failed, for what? */
        if (i == ERR_PTR(-EAGAIN))
            return -EAGAIN;

        /* FIXME: why this happened? bitmap say this ITB exists! */
        /* FIXME: we should act on ENOENT, other errors should not handle */
        hvfs_debug(mds, "Why this happened? bitmap say this ITB exists!\n");
        if (hi->flag & INDEX_CREATE || hi->flag & INDEX_SYMLINK) {
            /* FIXME: create ITB and ITE */
            i = get_free_itb(txg);
            if (unlikely(!i)) {
                hvfs_debug(mds, "get_free_itb() failed\n");
                err = -ENOMEM;
                goto out;
            }
            i->h.depth = fls64(hi->itbid) + 1;
            if (i->h.depth < hmo.conf.itb_depth_default + 1)
                i->h.depth = hmo.conf.itb_depth_default;
            else {
                /* Note: i->h.depth >= itb_depth_default means that the
                 * splited ITB will be finally routed to this server, we just
                 * wait and retry */
                if (unlikely(!(hmo.conf.option & HVFS_MDS_LIMITED))) {
                    hvfs_err(mds, "want to create itbid %ld depth %d, "
                             "hi psalt %lx\n", 
                             hi->itbid, i->h.depth, hi->psalt);
                    itb_free(i);
                    /* FIXME: we should return EHWAIT actually! */
                    err = -EHWAIT;
                    goto out;
                }
            }

            i->h.itbid = hi->itbid;
            i->h.puuid = hi->puuid;
            err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &b, &e, &oi);
            if (err == -EEXIST) {
                /* free the new ITB */
                itb_free(i);
                i = oi;
            } else if (unlikely(err)) {
                goto out;
            }
            err = cbht_itb_hit(i, hi, hmr, txg, otxg);
            if (err == -EAGAIN) {
                /* release all the locks */
                xrwlock_runlock(&e->lock);
                xrwlock_runlock(&b->lock);
                goto out;
            }
            xrwlock_runlock(&e->lock);
            xrwlock_runlock(&b->lock);
            /* FIXME: */
        } else {
            /* return -ENOENT */
            err = -ENOENT;
            goto out;
        }
    } else {
        /* get it, do search on it */
        /* insert into the cbht */
        err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &b, &e, &oi);
        if (err == -EEXIST) {
            /* it already exists, free this one */
            atomic64_sub(atomic_read(&i->h.entries), &hmo.prof.cbht.aentry);
            itb_free(i);
            i = oi;
        } else if (unlikely(err)) {
            goto out;
        }
        err = cbht_itb_hit(i, hi, hmr, txg, otxg);
        if (err == -EAGAIN) {
            /* release all the lockes */
            xrwlock_runlock(&e->lock);
            xrwlock_runlock(&b->lock);
            goto out;
        }
        xrwlock_runlock(&e->lock);
        xrwlock_runlock(&b->lock);
    }
out:
    return err;
}

/* General search in CBHT
 *
 * @hi: index to search, including flags, refer to "mds_api.h"
 * @hmr:should allocate the data region
 *
 * Search by key(puuid, itbid)
 * FIXME: how about LOCK!
 */
int __cbht mds_cbht_search(struct hvfs_index *hi, struct hvfs_md_reply *hmr,
                           struct hvfs_txg *txg, struct hvfs_txg **otxg)
{
    struct bucket *b;
    struct bucket_entry *be;
    struct itbh *ih;
    struct eh *eh = &hmo.cbht;
    struct hlist_node *pos;
    u64 hash, offset;
    u32 sdepth;
    int err = 0;

    mds_cbht_prof_rw(hi);
    hash = hvfs_hash(hi->puuid, hi->itbid, sizeof(u64), HASH_SEL_CBHT);

retry_dir:
    b = mds_cbht_search_dir(hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", hi->itbid);
        return -ENOENT;
    }
    /* OK, we get the bucket, and holding the bucket.rlock, no bucket spliting
     * can happen!
     */

    /* check the bucket */
    if (likely(atomic_read(&b->active))) {
        offset = hash & ((1 << eh->bucket_depth) - 1);
        be = b->content + offset;
    } else {
        /* the bucket is empty, you can do creating */
        hvfs_debug(mds, "OK, empty bucket!\n");

        /* we support itb loading now, just tring to loead the missed itb */
        xrwlock_runlock(&b->lock);
        err = cbht_itb_miss(hi, hmr, txg, otxg);
        if (err == -EAGAIN)
            goto retry_dir;
        hmr->err = err;
        return err;
    }

    /* always holding the bucket.rlock */
    xrwlock_rlock(&be->lock);
retry:
    if (!hlist_empty(&be->h)) {
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == hi->puuid && ih->itbid == hi->itbid) {
                /* OK, find the itb in the CBHT */
                err = cbht_itb_hit((struct itb *)ih, hi, hmr, txg, otxg);
                if (err == -EAGAIN) {
                    /* no need to release the be.rlock */
                    goto retry;
                }
                xrwlock_runlock(&be->lock);
                goto out;
            }
        }
    }
    xrwlock_runlock(&be->lock);

    /* Can not find it in CBHT, holding the bucket.rlock */
    /* Step1: release the bucket.rlock */
    hvfs_verbose(mds, "hash 0x%lx bucket %p but can not find the ITB in it.\n",
                 hash, b);
    xrwlock_runlock(&b->lock);
    err = cbht_itb_miss(hi, hmr, txg, otxg);
    if (err == -EAGAIN)         /* all locks are released */
        goto retry_dir;
    hmr->err = err;
    return err;

out:
    /* put the bucket lock */
    xrwlock_runlock(&b->lock);
    hmr->err = err;
    if (unlikely(err == -ESPLIT)) {
        /* NOTE THAT: if we get -ESPLIT error, we should check whether there
         * are pending ASYNC UPDATES */
        au_handle_split_sync();
    }
    return err;
}

/* mds_cbht_search_dump_itb()
 *
 * NOTE: this function is written for debuging, no locking
 */
void mds_cbht_search_dump_itb(struct hvfs_index *hi)
{
    struct bucket *b;
    struct bucket_entry *be;
    struct itbh *ih;
    struct eh *eh = &hmo.cbht;
    struct hlist_node *pos;
    u64 hash, offset;
    u32 sdepth;

    hash = hvfs_hash(hi->puuid, hi->itbid, sizeof(u64), HASH_SEL_CBHT);

    b = mds_cbht_search_dir(hash, &sdepth);
    if (unlikely(IS_ERR(b))) {
        hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                 "internal error!\n", hi->itbid);
        return;
    }
    /* OK, we get the bucket, and holding the bucket.rlock, no bucket spliting
     * can happen!
     */

    /* check the bucket */
    if (likely(atomic_read(&b->active))) {
        offset = hash & ((1 << eh->bucket_depth) - 1);
        be = b->content + offset;
    } else {
        /* the bucket is empty, you can do creating */
        hvfs_err(mds, "OK, empty bucket!\n");
        goto out;
    }

    offset = hi->hash & ((1 << ITB_DEPTH) - 1);
    hvfs_info(mds, "criminal: %s hash 0x%lx ITB.id %ld @ offset %ld\n", 
              hi->name, hi->hash, hi->itbid, offset);

    /* always holding the bucket.rlock */
    xrwlock_rlock(&be->lock);
    if (!hlist_empty(&be->h)) {
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == hi->puuid && ih->itbid == hi->itbid) {
                /* OK, find the itb in the CBHT */
                itb_dump((struct itb*)ih);
                break;
            }
        }
    }
    xrwlock_runlock(&be->lock);

out:
    xrwlock_runlock(&b->lock);
    return;
}

/* mds_cbht_itb_del()
 *
 * Just delete the ITB in the CBHT for write-back or reinsert
 *
 * NOTE: holding the bucket.wlock, itb.wlock
 *
 * Return Value: -errno, w/ NO locks hold
 */
int mds_cbht_itb_del(struct bucket_entry *be, struct itb *itb)
{
    struct itbh *ih;
    struct hlist_node *pos;
    int sanity = 0, err = 0;
    
    if (!hlist_empty(&be->h)) {
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == itb->h.puuid && ih->itbid == itb->h.itbid) {
                /* OK, find the itb in the CBHT */
                sanity = 1;
            }
        }
    }
    if (sanity) {
        xrwlock_wunlock(&itb->h.lock);
        hlist_del_init(&itb->h.cbht);
        itb->h.be = NULL;
    } else {
        hvfs_err(mds, "Who is cheating me to detelte ITB %ld.\n",
                 itb->h.itbid);
        err = -EINVAL;
        goto out;
    }

    xrwlock_wunlock(&be->lock);
    return err;
out:
    xrwlock_wunlock(&itb->h.lock);
    xrwlock_wunlock(&be->lock);
    return err;
}

