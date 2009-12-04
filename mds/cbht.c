/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-04 22:07:52 macan>
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
        xrwlock_init(&s->lock);
    }
    return s;
}

int mds_segment_init(struct segment *s, u64 offset, u32 alen, struct eh *eh)
{
    s->offset = offset;
    s->alen = alen;
    s->len = 1;
    return mds_seg_alloc(s, eh);
}

struct bucket *cbht_bucket_alloc(int depth)
{
    struct bucket *b;
    struct bucket_entry *be;

    b = xzalloc(struct bucket);
    if (!b) {
        return NULL;
    }
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
    int err;
    struct segment *s;
    struct bucket *b;

    /* alloc bucket #0 */
    b = cbht_bucket_alloc(eh->bucket_depth);
    if (!b) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        return -ENOMEM;
    }

    b->id = 0;                  /* set bucket id to 0 */
    ((struct bucket *)(*(s->seg[0]))) = b;
    
    return 0;
}

inline segment_update_dir(struct eh *eh, u64 len, struct bucket *b)
{
    /* follow the <b->id> to change all matched dir entries */
    struct segment *s;
    u64 mask = 1 << atomic_read(&b->depth) - 1;
    
    xrwlock_rlock(&eh->lock);
    hlist_for_each_entry(s, &eh->dir, list) {
        int k = 0;
        for (i = 0; i < s->len; i++) {
            if ((s->offset + i) & mask == b->id)
                    *(s->seg[0]) = b;
            if (!(--len))
                break;
        }
    }
    xrwlock_runlock(&eh->lock);
}

/* cbht_copy_dir()
 */
void cbht_copy_dir(struct segment *s, u64 offset, u64 len, struct eh *eh)
{
    struct segment *s;
    u64 clen;
    
    /* NOTE: have not check the arguments */
    hlist_for_each_entry(s, &eh->dir, list) {
        if (s->offset <= offset && offset < (s->offset + s->len)) {
            clen = min((s->alen - s->len), len);
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

    xrwlock_rlock(&eh->lock);
    hlist_for_each_entry(s, &eh->dir, list) {
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
        cbht_copy_dir(ss, offset, olen);
        nlen -= olen;
        offset += olen;
        /* next segment */
        if (ss->next == &eh->dir) {
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
}

/* cbht_update_dir()
 */
int cbht_update_dir(struct eh *eh, struct bucket *b)
{
    /* enlarge dir? */
    if (atomic_read(b->depth) > eh->dir_depth) {
        err = cbht_enlarge_dir(eh);
        if (err)
            return err;
    }

    return segment_update_dir(eh, (1 << eh->dir_depth), b);
}

/* cbht_bucket_split()
 */
int cbht_bucket_split(struct eh *eh, struct bucket *ob, u64 criminal,
                      struct bucket **out)
{
    /* Note that we do not know how many levels should we split, so just
     * repeat spliting until the bucket is all NOT full!
     */
    struct bucket *nb, *tb;
#define IN_NEW  0x00
#define IN_OLD  0x01
    int in, err;

    if (cmpxchg(&ob->state, BUCKET_FREE, BUCKET_SPLIT) == BUCKET_SPLIT) {
        /* somebody is spliting now */
        return -ELOCKED;
    }

retry:
    nb = cbht_bucket_alloc(eh->bucket_depth);
    if (!nb) {
        hvfs_err(mds, "cbht_bucket_alloc() failed\n");
        ob->state = BUCKET_FREE;
        return -ENOMEM;
    }
    atomic_inc(&ob->depth);
    atomic_set(&nb->depth, atomic_read(&ob->depth));
    /* set bucket id */
    nb->id = ob->id | (1 << (atomic_read(&nb->depth) - 1));

    /* move ITBs */
    obe = ob->content;
    nbe = nb->content;

    for (i = 0; i < (1 << eh->bucket_depth); i++) {
        xrwlock_wlock(&(obe + i)->lock);
        hlist_for_each_entry_safe(ih, pos, n, &(obe + i)->h, cbht) {
            if (ih->hash & (1 << (atomic_read(&nb->depth) - 1))) {
                /* move the new ITB */
                hlist_del_init(pos);
                hlist_add_head(pos, &(nbe + i)->h);

                /* wlock the ITB for ih->be access */
                xrwlock_wlock(&ih->lock);
                ih->be = nbe + i;
                xrwlock_wunlock(&ih->lock);

                atomic_add(&nb->active);
                atomic_dec(&ob->active);
            }
        }
        xrwlock_wunlock(&(obe + i)->lock);
    }
    /* one-level split has completed, but ... */
    if (criminal & (1 << (atomic_read(&nb->depth) - 1)))
        in = IN_NEW;
    else
        in = IN_OLD;
    
    if (!atomic_read(&nb->active) && (in == IN_OLD)) {
        /* old bucket need deeply split */
        /* keep ob not changed and nb FREE */
        tb = ob;
    } else if (!atomic_read(&ob->active) && (in == IN_NEW)) {
        /* new bucket need deeply split */
        /* change ob->state to FREE and lock the new ITB */
        ob->state = BUCKET_FREE;
        nb->state = BUCKET_SPLIT;
        tb = nb;
    } else {
        ob->state = BUCKET_FREE;
        tb = NULL;
    }

    /* update the directory */
    err = cbht_update_dir(eh, nb);
    if (err)
        return err;

    if (tb) {
        ob = tb;
        goto retry;
    }

    if (in == IN_NEW)
        *out = nb;
    else
        *out = ob;

    return 0;
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
    
    INIT_LIST_HEAD(&eh->list);
    xlock_init(&eh->lock);

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
    xlock_lock(&eh->lock);
    list_add_tail(&s->list, &eh->dir);
    xlock_unlock(&eh->lock);

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
        xlock_destroy(&s->lock);
        mds_seg_free(s);
        xfree(s);
    }
    xrwlock_wunlock(&eh->lock);
}

/* CBHT insert
 */
int mds_cbht_insert(struct eh *eh, struct itb *i)
{
    u64 hash;
    struct bucket *b, *sb;
    u32 err;

    hash = hvfs_hash(i->puuid, i->itbid, sizeof(u64), HASH_SEL_CBHT);
    i->h.hash = hash;
    
retry:
    b = mds_cbht_search_dir(hash);
    if (!b) {
        hvfs_err(mds, "Internal error, can not find 0x%lx in the EH dir\n", 
                 i->itbid);
        return -EINVAL;
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

    /* is the bucket will overflow? */
    if (atomic_read(&b->active) >= (2 << b->adepth)) {
        err = cbht_bucket_split(eh, b, hash, &sb);
        if (err == -ELOCKED)
            goto retry;
        else if (err)
            return err;
        b = *sb;
    }
    
    xrwlock_wlock(&be->lock);
    xrwlock_wlock(&i->h.lock);
    hlist_add_head(&i->h.cbht, &be->h);
    i->h.be = be;
    xrwlock(wunlock(&i->h.lock));
    xrwlock_wunlock(&be->lock);
    atomic_inc(&b->active);

    return 0;
}

/* CBHT del
 */
void mds_cbht_del(struct eh *eh, struct itb *i)
{
    struct bucket_entry *be = i->h.be;

    xrwlock_wlock(&be->lock);
    xrwlock_wlock(&i->h.lock);
    hlist_del(&i->h.cbht, &be->h);
    
}

/* CBHT dir search
 *
 * if return value is not null, then the bucket rlock is holding
 */
struct bucket *mds_cbht_search_dir(u64 hash)
{
    u64 offset, ioff;
    struct eh *eh = &hmo.eh;
    struct segment *s;
    struct bucket *b = ERR_PTR(-ENOENT); /* ENOENT means can not find it */
    int found = 0, seg;
    
    offset = (hash >> eh->bucket_depth) & ((1 << eh->dir_depth) - 1);
    xrwlock_rlock(eh->lock);
    list_for_each_entry(s, &eh->dir, list) {
        if (s->offset <= offset && offset < (s->offset + s->len)) {
            found = 1;
            break;
        }
    }
    if (found) {
        offset -= s->offset;
        VALUE_TO_SEG(offset, seg, ioff);
        if (s->seg[seg]) {
            b = (struct bucket *)(*(s->seg[seg] + (offset - ioff)));
            /* ok, holding the bucket rlock */
            if (xrwlock_tryrlock(&b->lock) == EBUSY) {
                /* somebody wlock the bucket for spliting? */
                b = ERR_PTR(-EAGAIN);
            }
        }
    }
            
    xrwlock_runlock(eh->lock);

    return b;
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
    struct itb *i;
    struct mdu *m;
    struct hlist_node *pos;
    char mdu_rpy[HVFS_MDU_SIZE];
    u64 hash;
    int err = 0;

    hash = hvfs_hash(hi->puuid, hi->itbid, sizeof(u64), HASH_SEL_CBHT);

research:
    b = mds_cbht_search_dir(hash);
    if (IS_ERR(b)) {
        if (PTR_ERR(b) == -EAGAIN)
            goto research;
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
    if (unlikely(b->state == BUCKET_SPLIT))
        goto research;

    if (b->active) {
        offset = hash & ((1 << eh->bucket_depth) - 1);
        be = b->content + offset;
    } else {
        /* the bucket is empty, you can do creating */
        if (hi->flag & INDEX_CREATE) {
            /* FIXME: */
        } else {
            return -ENOENT;
        }
    }

retry:
    if (!hlist_empty(&be->h)) {
        xrwlock_rlock(&be->lock);
        hlist_for_each_entry(ih, pos, &be->h, cbht) {
            if (ih->puuid == hi->puuid && ih->itbid == hi->itbid) {
                found = 1;
                err = xrwlock_tryrlock(&ih->lock); /* always get a read lock */
                if (err == EBUSY)
                    goto retry;
                break;
            }
        }
        xrwlock_runlock(&be->lock);
    }
    /* OK, we find the ITB or can find it */
    if (found) {
        hvfs_debug(mds, "Find ITB 0x%lx in CBHT.\n", hi->itbid);
        i = (struct itb *)(ih);
        if (unlikely(hi->flag & INDEX_BY_ITB)) {
            /* readdir */
            return itb_readdir(i, hi, hmr);
        }
        err = itb_search(hi, i, mdu_rpy, txg);
        if (err == -EAGAIN) {
            goto retry;
        } else if (err) {
            hvfs_debug(mds, "Oh, itb_search() return %d.\n", err);
            goto out;
        }
        /* fill hmr with mdu_rpy, fall through */
        xrwlock_runlock(&ih->lock);
    } else {
        if (unlikely(b->state == BUCKET_SPLIT)) {
            /* spliting some time before, retry ourself? */
            goto research;
        }
        hvfs_debug(mds, "Can not find ITB 0x%lx in CBHT, retrieve it ...\n", 
                   hi->itbid);
        i = mds_read_itb(hi->puuid, hi->psalt, hi->itbid);
        if (IS_ERR(i)) {
            hvfs_debug(mds, "Oh, this ITB do not exist, WHY?.\n");
            /* FIXME: why this happened? */
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
                mds_cbht_insert(hi, i);
                itb_search(hi, i, mdu_rpy), ;
                /* fall through */
            } else {
                /* return -ENOENT */
                err = -ENOENT;
                goto out;
            }
        } else {
            /* get it, so find in ITB */
            if (unlikely(hi->flag & INDEX_BY_ITB)) {
                /* readdir */
                return itb_readdir(i, hi, hmr);
            }
            xrwlock_rlock(&i->h.lock);
            mds_cbht_insert(hi, i); /* alter? */
            err = itb_search(hi, i, mdu_rpy, txg, be);
            if (err == -EAGAIN) {
                goto retry;
            } else if (err) {
                hvfs_debug(mds, "Oh, itb_search() return %d.\n", err);
                goto out;
            }
            /* fall through */
            xrwlock_runlock(&i->h.lock);
        }
    }
    /* fill hmr with mdu_rpy */
    if (err)
        goto out;
    /* determine the flags */
    m = (struct mdu *)(mdu_rpy);
    if (S_ISDIR(m->mode) && hi->puuid != hmo.gdt_uuid)
        hmr->flag |= MD_REPLY_DIR_SDT;
    if (hi->flag & INDEX_BY_ITB)
        hmr->flag |= MD_REPLY_READDIR;
    if (m->flags & HVFS_MDU_IF_LINKT) {
        hmr->flag |= MD_REPLY_WITH_LS;
        hmr->len += sizeof(struct link_source);
    } else {
        hmr->flag |= MD_REPLY_WIHT_MDU;
        hmr->len += HVFS_MDU_SIZE;
        hmr->mdu_no = 1;        /* only ONE mdu */
    }
    
    hmr->flag |= MD_REPLY_WITH_HI;
    hmr->len += sizeof(*hi);

    hmr->data = xalloc(hmr->len);
    if (!hmr->data) {
        hvfs_err(mds, "xalloc() hmr->data failed\n");
        /* do not retry myself */
        err = -ENOMEM;
        goto out;
    }
    memcpy(hmr->data, hi, sizeof(*hi));
    if (m->flags & HVFS_MDU_IF_LINKT) {
        memcpy(hmi->data + sizeof(*hi), mdu_rpy, sizeof(struct link_source));
    } else
        memcpy(hmi->data + sizeof(*hi), mdu_rpy, HVFS_MDU_SIZE);
out:
    return err;
}
