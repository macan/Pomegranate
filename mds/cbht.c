/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-02 21:37:24 macan>
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

#define ALLOC_SEG(s, i, err) do {                   \
        s->seg[i] = zalloc(SEG##i##_NO);            \
        if (!s->seg[i]) {                           \
            hvfs_err(mds, "zalloc() seg failed\n"); \
            err = -ENOMEM;                          \
        }                                           \
        s->len += SEG##i##_NO;                      \
    } while (0)

#define VALUE_TO_SEG(v, seg, ioff)  do {         \
        int seg = -1;                            \
        if (v < SEG0_TOTAL) {                    \
            seg = 0;                             \
            ioff = 0;                            \
        } else if (v < SEG1_TOTAL) {             \
            seg = 1;                             \
            ioff = SEG0_TOTAL;                   \
        } else if (v < SEG2_TOTAL) {             \
            seg = 2;                             \
            ioff = SEG1_TOTAL;                   \
        } else if (v < SEG3_TOTAL) {             \
            seg = 3;                             \
            ioff = SEG2_TOTAL;                   \
        } else if (v < SEG4_TOTAL) {             \
            seg = 4;                             \
            ioff = SEG3_TOTAL;                   \
        } else if (v < SEG5_TOTAL) {             \
            seg = 5;                             \
            ioff = SEG4_TOTAL;                   \
        }                                        \
    } while (0)

int mds_seg_alloc(struct segment *s, struct eh *eh)
{
    int err = 0;
    
    switch (s->len) {
    case 0:
        ALLOC_SEG(s, 0, err);
        break;
    case SEG0_NO:
        ALLOC_SEG(s, 1, err);
        break;
    case SEG1_NO:
        ALLOC_SEG(s, 2, err);
        break;
    case SEG2_NO:
        ALLOC_SEG(s, 3, err);
        break;
    case SEG3_NO:
        ALLOC_SEG(s, 4, err);
        break;
    case SEG4_NO:
        ALLOC_SEG(s, 5, err);
        break;
    case SEG5_NO:
        /* alloc another segment */
        ns = mds_segment_alloc();
        if (!ns) {
            hvfs_err(mds, "mds_segment_alloc() failed\n");
            return -ENOMEM;
        }
        mds_segment_init(s, s->alen, SEG_TOTAL, eh);

        xlock_lock(&eh->lock);
        list_add(&ns->list, &eh->dir);
        xlock_unlock(&eh->lock);
        break;
    default:
        hvfs_err(mds, "Invalid segment length %d\n", s->len);
    }
    return 0;
}

void mds_seg_free(struct segment *s)
{
    int i;

    for (i = 0; i < 6; i++) {
        if (s->seg[i])
            xfree(s->seg[i]);
    }
    s->len = 0;
    memset(s->seg, 0, sizeof(void *) * 6);
}

static inline struct segment *mds_segment_alloc()
{
    struct segment *s;
    
    s = zalloc(sizeof(struct segment));
    if (s) {
        INIT_LIST_HEAD(&s->list);
        xlock_init(&s->lock);
    }
    return s;
}

int mds_segment_init(struct segment *s, u64 offset, u32 alen, u32 len, 
                     struct eh *eh)
{
    s->offset = offset;
    s->alen = alen;
    s->len = len;
    return mds_seg_alloc(s, eh);
}

struct bucket *cbht_bucket_alloc(int depth)
{
    struct bucket *b;

    b = zalloc(struct bucket);
    if (!b) {
        return NULL;
    }
    b->content = zalloc(sizeof(struct bucket_entry) * (1 << depth));
    if (!b->content) {
        return NULL;
    }
    return b;
}

int cbht_bucket_init(struct eh*eh, int max)
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

    s = list_entry(eh->dir.next, struct segment, list);
    for (i = 0; i < 6; i++) {
        for (j = 0; j < (SEG_BASE << i); j++) {
            if (!max)
                break;
            *(s->seg[i] + j) = b;
            max--;
        }
    }
}

/* CBHT init
 *
 * @eh:     
 * @ddepth: depth of the directory, can't exceed one segment!
 * @bdepth: bucket depth
 */
int mds_cbht_init(struct eh* eh, int ddepth, int bdepth)
{
    struct segment *s;
    u64 max = (1 << ddepth) - 1;
    
    INIT_LIST_HEAD(&eh->list);
    xlock_init(&eh->lock);

    /* allocate the EH directory */
    s = mds_segment_alloc();
    if (!s) {
        hvfs_err(mds, "mds_segment_alloc() failed\n");
        return -ENOMEM;
    }

    /* init the segment */
    err = mds_segment_init(s, 0, SEG_TOTAL, max, eh);
    if (err)
        return err;

    /* init the bucket based on ddepth */
    err = cbht_bucke_init(eh, max);
    if (err)
        return err;

    /* add to the dir list */
    xlock_lock(&eh->lock);
    list_add(&s->list, &eh->dir);
    xlock_unlock(&eh->lock);

    eh->dir_depth = ddepth;
    eh->bucket_depth = bdepth;
    return 0;
}

/* CBHT destroy w/o init
 *
 * @eh: 
 */
void mds_cbht_destroy(struct *eh)
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
int mds_cbht_insert(struct *eh, struct itb *i)
{
    u64 hash;
    struct bucket *b;

    hash = hvfs_hash(i->puuid, i->itbid, sizeof(u64), HASH_SEL_CBHT);
    
    b = mds_cbht_search_dir(hash);
    if (!b) {
        hvfs_err(mds, "Sorry, can not find 0x%lx in the EH dir\n", i->itbid);
    }
    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;
    
}

/* CBHT del
 */
void mds_cbht_del(struct *eh, struct itb *i)
{
}

/* CBHT dir search
 *
 *
 */
struct bucket *mds_cbht_search_dir(u64 hash)
{
    u64 offset, ioff;
    struct eh *eh = &hmo.eh;
    struct segment *s;
    struct bucket *b = NULL;
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
        if (s->seg[seg])
            b = (struct bucket *)(*(s->seg[seg] + (offset - ioff)));
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
    struct hlist_node *pos, *n;
    char mdu_rpy[HVFS_MDU_SIZE];
    u64 hash;
    int err = 0;

    hash = hvfs_hash(hi->puuid, hi->itbid, sizeof(u64), HASH_SEL_CBHT);

    b = mds_cbht_search_dir(hash);
    if (!b) {
        hvfs_err(mds, "Sorry ,can not find 0x%lx in the EH dir\n", hi->itbid);
        return -ENOENT;
    }

    offset = hash & ((1 << eh->bucket_depth) - 1);
    be = b->content + offset;

retry:
    if (!hlist_empty(&be->h)) {
        xrwlock_rlock(&be->lock);
        hlist_for_each_entry_safe(ih, pos, n, &be->h, cbht) {
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
        err = itb_search(hi, i, mdu_rpy, txg, be);
        if (err == -EAGAIN) {
            goto retry;
        } else if (err) {
            hvfs_debug(mds, "Oh, itb_search() return %d.\n", err);
            goto out;
        }
        /* fill hmr with mdu_rpy, fall through */
        xrwlock_runlock(&ih->lock);
    } else {
        hvfs_debug(mds, "Can not find ITB 0x%lx in CBHT, retrieve it ...\n", 
                   hi->itbid);
        i = mds_read_itb(hi->puuid, hi->psalt, hi->itbid);
        if (!i) {
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
