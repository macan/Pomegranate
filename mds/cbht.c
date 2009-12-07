/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-07 17:03:08 macan>
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
#define SEG0_NO (SEG_BASE << 0)
#define SEG1_NO (SEG_BASE << 1)
#define SEG2_NO (SEG_BASE << 2)
#define SEG3_NO (SEG_BASE << 3)
#define SEG4_NO (SEG_BASE << 4)
#define SEG5_NO (SEG_BASE << 5)
#define SEG_TOTAL (SEG0_NO + SEG1_NO + SEG2_NO + SEG3_NO + SEG4_NO + SEG5_NO)

#define SEG0_TOTAL (SEG0_NO)
#define SEG1_TOTAL (SEG0_NO + SEG1_NO)
#define SEG2_TOTAL (SEG0_NO + SEG1_NO + SEG2_NO)
#define SEG3_TOTAL (SEG0_NO + SEG1_NO + SEG2_NO + SEG3_NO)
#define SEG4_TOTAL (SEG0_NO + SEG1_NO + SEG2_NO + SEG3_NO + SEG4_NO)
#define SEG5_TOTAL (SEG0_NO + SEG1_NO + SEG2_NO + SEG3_NO + SEG4_NO + SEG5_NO)

int mds_seg_alloc(struct segment *s, struct eh *eh)
{
    int err = 0;

    s->seg[0] = xzalloc(s->alen);
    if (!s->seg[0]) {
        hvfs_err(mds, "xzalloc() seg failed\n");
        err = -ENOMEM;
    }

    return 0;
}

void mds_seg_free(struct segment *s)
{
    int i;

    for (i = 0; i < 1; i++) {
        if (s->seg[i])
            xfree(s->seg[i]);
    }
    s->len = 0;
    memset(s->seg, 0, sizeof(void *));
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

struct bucket *cbht_bucket_alloc(int depth)
{
    struct bucket *b;
    struct bucket_entry *be;
    int i;

    b = xzalloc(sizeof(struct bucket));
    if (!b) {
        return NULL;
    }
#ifdef UNIT_TEST
    hvfs_info(mds, "alloc bucket %p\n", b);
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

    return b;
}

/*
 * Internal use, not export
 */
int cbht_bucket_init(struct eh *eh, struct segment *s)
{
    struct bucket *b;

    /* alloc bucket #0 */
    b = cbht_bucket_alloc(eh->bucket_depth);
    if (!b) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        return -ENOMEM;
    }

    b->id = 0;                  /* set bucket id to 0 */
    *((struct bucket **)(s->seg[0])) = b;
    s->len = 1;
    
    return 0;
}

inline int segment_update_dir(struct eh *eh, u64 len, struct bucket *b)
{
    /* follow the <b->id> to change all matched dir entries */
    struct segment *s;
    u64 mask = (1 << atomic_read(&b->depth)) - 1;
    int i;
    
    xrwlock_rlock(&eh->lock);
    list_for_each_entry(s, &eh->dir, list) {
        for (i = 0; i < s->len; i++) {
            if (((s->offset + i) & mask) == b->id)
                *((struct bucket **)(s->seg[0] + i)) = b;
            if (!(--len))
                break;
        }
    }
    xrwlock_runlock(&eh->lock);

    return 0;
}

void cbht_print_dir(struct eh *eh)
{
    struct segment *s;
    int i;

    list_for_each_entry(s, &eh->dir, list) {
        for (i = 0; i < s->len; i++) {
            hvfs_info(mds, "offset %016d %p\n", i,
                      *(struct bucket **)(s->seg[0] + i));
        }
    }
}

/* cbht_copy_dir()
 */
void cbht_copy_dir(struct segment *s, u64 offset, u64 len, struct eh *eh)
{
    u64 clen;
    struct segment *pos;
    
    /* NOTE: have not check the arguments */
    list_for_each_entry(pos, &eh->dir, list) {
        if (pos->offset <= offset && offset < (pos->offset + pos->len)) {
            clen = min(len, (pos->offset + pos->len - offset));
            memcpy(s->seg[0] + s->len, s->seg[0] + (offset - s->offset), clen);
            len -= clen;
            offset += clen;
        }
        if (!len)
            break;
    }
}

/* cbht_enlarge_dir()
 *
 * double the directory
 */
int cbht_enlarge_dir(struct eh *eh)
{
    u32 olen = (1 << eh->dir_depth);
    u32 nlen = olen;
    struct segment *s, *ss = NULL;
    u64 offset;
    int err = 0;

    xrwlock_rlock(&eh->lock);
    list_for_each_entry(s, &eh->dir, list) {
        if (olen == s->len) {
            /* enlarge from this segment */
            ss = s;
        } else {
            olen -= s->len;
        }
    }
    xrwlock_runlock(&eh->lock);
    /* get the begining segment */
    if (!ss) {
        hvfs_err(mds, "internal error on cbht dir segment.\n");
        return -EINVAL;
    }
    offset = 0;
    while (nlen > 0) {
        olen = ss->alen - ss->len; /* writable region in this segment */
        olen = min(olen, nlen);
        cbht_copy_dir(ss, offset, olen, eh);
        nlen -= olen;
        offset += olen;
        /* next segment */
        if (ss->list.next == &eh->dir) {
            /* should allocate a new segment */
            s = mds_segment_alloc();
            if (!s) {
                return -ENOMEM;
            }
            err = mds_segment_init(s, ss->offset + ss->alen, ss->alen, eh);
            if (err)
                return err;
            ss = s;
            /* add to the dir list */
            xrwlock_wlock(&eh->lock);
            list_add_tail(&s->list, &eh->dir);
            xrwlock_wunlock(&eh->lock);
        }
    }
    /* ok to change the depth */
    eh->dir_depth++;

    return err;
}

/* cbht_update_dir()
 */
int cbht_update_dir(struct eh *eh, struct bucket *b)
{
    int err;
    /* enlarge dir? */
    if (atomic_read(&b->depth) > eh->dir_depth) {
        err = cbht_enlarge_dir(eh);
        if (err)
            return err;
    }

    return segment_update_dir(eh, (1 << eh->dir_depth), b);
}

/* cbht_bucket_split()
 *
 * Note: holding the bucket.rlock
 */
int cbht_bucket_split(struct eh *eh, struct bucket *ob, u64 criminal,
                      struct bucket **out)
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

    /* ok, we get the bucket.wlock, and the bucket should be split */
retry:
    nb = cbht_bucket_alloc(eh->bucket_depth);
    if (!nb) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        err = -ENOMEM;
        goto out;
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
            if (ih->hash & (1 << (atomic_read(&nb->depth) - 1))) {
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
    if (criminal & (1 << (atomic_read(&nb->depth) - 1)))
        in = IN_NEW;
    else
        in = IN_OLD;
    
    /* pre-locked new bucket, we know the two new buckets are all locked */
    xrwlock_wlock(&nb->lock);
    
    /* update the directory */
    err = cbht_update_dir(eh, nb);
    if (err) {
        goto out;
    }

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
        tb = NULL;
    }

    if (tb) {
        ob = tb;
        goto retry;
    }

    if (in == IN_NEW)
        *out = nb;
    else
        *out = ob;

    err = 0;
out:
    xrwlock_wunlock(&ob->lock);
    xrwlock_rlock(&ob->lock);
    return err;
#undef IN_NEW
#undef IN_OLD
}

/* CBHT init
 *
 * @eh:     
 * @ddepth: depth of the directory, can't exceed one segment!
 * @bdepth: bucket depth
 */
int mds_cbht_init(struct eh *eh, int bdepth)
{
    struct segment *s;
    int err = 0;
    
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

    eh->dir_depth = 0;
    eh->bucket_depth = bdepth;
    return 0;
}

/* CBHT destroy w/o init
 *
 * @eh: 
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
int mds_cbht_insert_bbrlocked(struct eh *eh, struct itb *i, struct bucket **ob,
                              struct bucket_entry **oe)
{
    u64 hash, offset;
    struct bucket *b, *sb;
    struct bucket_entry *be;
    u32 err;

    hash = hvfs_hash(i->h.puuid, i->h.itbid, sizeof(u64), HASH_SEL_CBHT);
    i->h.hash = hash;
    
retry:
    b = mds_cbht_search_dir(hash);
    if (!b) {
        hvfs_err(mds, "Internal error, can not find 0x%lx in the EH dir\n", 
                 i->h.itbid);
        return -EINVAL;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* holding the bucket.rlock now */

    /* is the bucket will overflow? */
    if (atomic_read(&b->active) >= (2 << b->adepth)) {
        err = cbht_bucket_split(eh, b, hash, &sb);
        if (err == -EAGAIN)     /* already release the bucket.rlock? */
            goto retry;
        else if (err)
            goto out;
        b = sb;
    }
    
    xrwlock_wlock(&be->lock);
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

/* CBHT insert without any lock preservated at returning
 *
 * Note: holding nothing
 */
int mds_cbht_insert(struct eh *eh, struct itb *i)
{
    u64 hash, offset;
    struct bucket *b, *sb;
    struct bucket_entry *be;
    u32 err;
    
    hash = hvfs_hash(i->h.puuid, i->h.itbid, sizeof(u64), HASH_SEL_CBHT);
    i->h.hash = hash;
    
retry:
    b = mds_cbht_search_dir(hash);
    if (!b) {
        hvfs_err(mds, "Internal error, can not find 0x%lx in the EH dir\n", 
                 i->h.itbid);
        return -EINVAL;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* holding the bucket.rlock now */

    /* is the bucket will overflow? */
    if (atomic_read(&b->active) >= (2 << b->adepth)) {
        err = cbht_bucket_split(eh, b, hash, &sb);
        if (err == -EAGAIN)     /* already release the bucket.rlock? */
            goto retry;
        else if (err)
            goto out;
        b = sb;
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
int mds_cbht_del(struct eh *eh, struct itb *i)
{
    struct bucket_entry *be;
    struct bucket *b;
    u64 offset;

retry:
    b = mds_cbht_search_dir(i->h.hash);
    if (!b) {
        hvfs_err(mds, "Internal error, can not find 0x%lx in the EH dir.\n",
                 i->h.itbid);
        return -EINVAL;
    }
    offset = i->h.hash & ((1 << eh->bucket_depth) - 1);
    be = b->content +offset;

    /* holding the bucket.rlock now */

    /* is the bucket will underflow? FIXME: no underflow for now */
    xrwlock_wlock(&be->lock);
    xrwlock_rlock(&i->h.lock);
    /* recheck whether this itb has been moved? */
    if (i->h.be != be) {
        xrwlock_runlock(&i->h.lock);
        xrwlock_wunlock(&be->lock);
        xrwlock_runlock(&b->lock);
        goto retry;
    }
    hlist_del_init(&i->h.cbht);
    i->h.be = NULL;
    xrwlock_runlock(&i->h.lock);
    xrwlock_wunlock(&be->lock);

    xrwlock_runlock(&b->lock);
    return 0;
}

/* CBHT dir search
 *
 * if return value is not null, then the bucket rlock is holding
 */
struct bucket *mds_cbht_search_dir(u64 hash)
{
    struct eh *eh = &hmo.cbht;
    struct segment *s;
    struct bucket *b = ERR_PTR(-ENOENT); /* ENOENT means can not find it */
    u64 offset;
    int found = 0;
    
    offset = (hash >> eh->bucket_depth) & ((1 << eh->dir_depth) - 1);
    xrwlock_rlock(&eh->lock);
    list_for_each_entry(s, &eh->dir, list) {
        if (s->offset <= offset && offset < (s->offset + s->len)) {
            found = 1;
            break;
        }
    }
    if (found) {
        offset -= s->offset;
        if (s->seg[0]) {
            b = *((struct bucket **)(s->seg[0] + offset));
            /* ok, holding the bucket rlock */
            if (xrwlock_tryrlock(&b->lock) == EBUSY) {
                /* somebody wlock the bucket for spliting? */
                b = ERR_PTR(-EAGAIN);
            }
        }
    }
            
    xrwlock_runlock(&eh->lock);

    return b;
}

/*
 * Note: holding the bucket.rlock, be.rlock
 */
int cbht_itb_hit(struct itb *i, struct hvfs_index *hi, 
                 struct hvfs_md_reply *hmr, struct hvfs_txg *txg)
{
    struct mdu *m;
    int err;
    char mdu_rpy[HVFS_MDU_SIZE];

    xrwlock_rlock(&i->h.lock);
    if (unlikely(hi->flag & INDEX_BY_ITB)) {
        /* readdir, read-only */
        err = itb_readdir(hi, i, hmr);
        return err;
    }
    err = itb_search(hi, i, mdu_rpy, txg);
    if (err) {
        hvfs_debug(mds, "Oh, itb_search() return %d.\n", err);
        goto out;
    }
    /* FIXME: fill hmr with mdu_rpy */
    /* determine the flags */
    m = (struct mdu *)(mdu_rpy);
    if (S_ISDIR(m->mode) && hi->puuid != hmi.gdt_uuid)
        hmr->flag |= MD_REPLY_DIR_SDT;
    if (hi->flag & INDEX_BY_ITB)
        hmr->flag |= MD_REPLY_READDIR;
    if (m->flags & HVFS_MDU_IF_LINKT) {
        hmr->flag |= MD_REPLY_WITH_LS;
        hmr->len += sizeof(struct link_source);
    } else {
        hmr->flag |= MD_REPLY_WITH_MDU;
        hmr->len += HVFS_MDU_SIZE;
        hmr->mdu_no = 1;        /* only ONE mdu */
    }
    
    hmr->flag |= MD_REPLY_WITH_HI;
    hmr->len += sizeof(*hi);

    hmr->data = xmalloc(hmr->len);
    if (!hmr->data) {
        hvfs_err(mds, "xalloc() hmr->data failed\n");
        /* do not retry myself */
        err = -ENOMEM;
        goto out;
    }
    memcpy(hmr->data, hi, sizeof(*hi));
    if (m->flags & HVFS_MDU_IF_LINKT) {
        memcpy(hmr->data + sizeof(*hi), mdu_rpy, sizeof(struct link_source));
    } else
        memcpy(hmr->data + sizeof(*hi), mdu_rpy, HVFS_MDU_SIZE);
out:
    xrwlock_runlock(&i->h.lock);
    return err;
}

/*
 * Note: holding the bucket.rlock
 */
int cbht_itb_miss(struct hvfs_index *hi, 
                  struct hvfs_md_reply *hmr, struct hvfs_txg *txg)
{
    struct itb *i;
    struct bucket *b;
    struct bucket_entry *e;
    int err = 0;

    /* Step1: read the itb from mdsl */
    i = mds_read_itb(hi->puuid, hi->psalt, hi->itbid);
    if (IS_ERR(i)) {
        /* read itb failed, for what? */
        /* FIXME: why this happened? bitmap say this ITB exists! */
        if (hi->flag & INDEX_CREATE || hi->flag & INDEX_SYMLINK) {
            /* FIXME: create ITB and ITE */
            i = get_free_itb();
            if (!i) {
                hvfs_debug(mds, "get_free_itb() failed\n");
                err = -ENOMEM;
                goto out;
            }
            i->h.itbid = hi->itbid;
            i->h.puuid = hi->puuid;
            err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &b, &e);
            if (err) {
                goto out;
            }
            err = cbht_itb_hit(i, hi, hmr, txg);
            if (err == -EAGAIN) {
                /* release all the locks */
                xrwlock_runlock(&b->lock);
                xrwlock_runlock(&e->lock);
                goto out;
            }
            /* FIXME: */
        } else {
            /* return -ENOENT */
            err = -ENOENT;
            goto out;
        }
    } else {
        /* get it, do search on it */
        /* insert into the cbht */
        err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &b, &e);
        if (err) {
            goto out;
        }
        err = cbht_itb_hit(i, hi, hmr, txg);
        if (err == -EAGAIN) {
            /* release all the lockes */
            xrwlock_runlock(&b->lock);
            xrwlock_runlock(&e->lock);
            goto out;
        }
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
int mds_cbht_search(struct hvfs_index *hi, struct hvfs_md_reply *hmr,
                    struct hvfs_txg *txg)
{
    struct bucket *b;
    struct bucket_entry *be;
    struct itbh *ih;
    struct eh *eh = &hmo.cbht;
    struct hlist_node *pos;
    u64 hash, offset;
    int err = 0;

    hash = hvfs_hash(hi->puuid, hi->itbid, sizeof(u64), HASH_SEL_CBHT);

retry_dir:
    b = mds_cbht_search_dir(hash);
    if (IS_ERR(b)) {
        if (PTR_ERR(b) == -EAGAIN)
            goto retry_dir;
        else {
            hvfs_err(mds, "No buckets exist? Find 0x%lx in the EH dir, "
                     "internal error!\n", hi->itbid);
            return -ENOENT;
        }
    }
    /* OK, we get the bucket, and holding the bucket.rlock, no bucket spliting
     * can happen!
     */

    /* check the bucket */
    if (atomic_read(&b->active)) {
        offset = hash & ((1 << eh->bucket_depth) - 1);
        be = b->content + offset;
    } else {
        /* the bucket is empty, you can do creating */
        if (hi->flag & INDEX_CREATE) {
            /* FIXME: */
            xrwlock_runlock(&b->lock);
            err = cbht_itb_miss(hi, hmr, txg);
            if (err == -EAGAIN)
                goto retry_dir;
            return err;
        } else {
            err = -ENOENT;
            goto out;
        }
    }

    /* always holding the bucket.rlock */
    xrwlock_rlock(&be->lock);
retry:
    if (!hlist_empty(&be->h)) {
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == hi->puuid && ih->itbid == hi->itbid) {
                /* OK, find the itb in the CBHT */
                err = cbht_itb_hit((struct itb *)ih, hi, hmr, txg);
                if (err == -EAGAIN) {
                    /* no need to release the be.rlock */
                    goto retry;
                }
                goto out;
            }
        }
    }
    xrwlock_runlock(&be->lock);

    /* Can not find it in CBHT, holding the bucket.rlock */
    /* Step1: release the bucket.rlock */
    xrwlock_runlock(&b->lock);
    err = cbht_itb_miss(hi, hmr, txg);
    if (err == -EAGAIN)         /* all locks are released */
        goto retry_dir;
    return err;

out:
    /* put the bucket lock */
    xrwlock_runlock(&b->lock);
    return err;
}

#ifdef UNIT_TEST
int main(int argc, char *argv[])
{
    struct itb *i;
    struct timeval begin, end;
    struct hvfs_index hi = {0,};
    struct hvfs_md_reply hmr;
    struct hvfs_txg txg = {.txg = 5,};
    int err;

    hvfs_info(mds, "CBHT UNIT TESTing...\n");
    err = mds_cbht_init(&hmo.cbht, 4);
    if (err) {
        hvfs_err(mds, "mds_cbht_init failed %d\n", err);
        goto out;
    }
    /* print the init cbht */
    cbht_print_dir(&hmo.cbht);
    /* init hte itb cache */
    itb_cache_init(&hmo.ic, 100);
    
    /* alloc one ITB */
    i = get_free_itb();
    i->h.puuid = 9999;
    i->h.itbid = 909009;
    i->h.txg = 5;
    i->h.state = ITB_STATE_CLEAN;


    lib_timer_start(&begin);
    err = mds_cbht_insert(&hmo.cbht, i);
    if (err) {
        hvfs_err(mds, "mds_cbht_insert() failed %d\n", err);
        goto out;
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end);

    /* search the itb! */
    hi.puuid = 9999;
    hi.itbid = 909009;
    hi.flag |= (INDEX_LOOKUP | INDEX_BY_UUID_F);
    err = mds_cbht_search(&hi, &hmr, &txg);
    if (err) {
        hvfs_err(mds, "mds_cbht_search() failed %d\n", err);
    }
    
    itb_free(i);

    itb_cache_destroy(&hmo.ic);
    mds_cbht_destroy(&hmo.cbht);
out:
    return err;
}
#endif
