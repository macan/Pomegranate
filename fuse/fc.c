/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-16 16:03:36 macan>
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
#include "pfs.h"
#include "branch.h"
#include <fuse.h>

/* we only accept this format: "/path/to/name" */
#define SPLIT_PATHNAME(pathname, path, name) do {                       \
        int __len = strlen(pathname);                                   \
        char *__tmp = (char *)pathname + __len - 1;                     \
        while (*__tmp != '/')                                           \
            __tmp--;                                                    \
        if (__tmp == pathname) {                                        \
            path = "/";                                                 \
        } else {                                                        \
            path = pathname;                                            \
            *__tmp = '\0';                                              \
        }                                                               \
        if ((__tmp + 1) == (pathname + __len)) {                        \
            name = "";                                                  \
        } else {                                                        \
            name = __tmp + 1;                                           \
        }                                                               \
    } while (0)

/* We construct a Stat-Oneshot-Cache (SOC) to boost the performance of VFS
 * create. By saving the mdu info in SOC, we can eliminate one network rtt for
 * the stat-after-create. */
struct __pfs_soc_mgr
{
#define PFS_SOC_HSIZE_DEFAULT   (8192)
    struct regular_hash *ht;
    u32 hsize;
    atomic_t nr;
} pfs_soc_mgr;

struct soc_entry
{
    struct hlist_node hlist;
    char *key;
    struct hstat hs;
};

static int __soc_init(int hsize)
{
    int i;

    if (hsize)
        pfs_soc_mgr.hsize = hsize;
    else
        pfs_soc_mgr.hsize = PFS_SOC_HSIZE_DEFAULT;

    pfs_soc_mgr.ht = xmalloc(pfs_soc_mgr.hsize * sizeof(struct regular_hash));
    if (!pfs_soc_mgr.ht) {
        hvfs_err(xnet, "Stat Oneshot Cache(SOC) hash table init failed\n");
        return -ENOMEM;
    }

    /* init the hash table */
    for (i = 0; i < pfs_soc_mgr.hsize; i++) {
        INIT_HLIST_HEAD(&pfs_soc_mgr.ht[i].h);
        xlock_init(&pfs_soc_mgr.ht[i].lock);
    }
    atomic_set(&pfs_soc_mgr.nr, 0);

    return 0;
}

static void __soc_destroy(void)
{
    xfree(pfs_soc_mgr.ht);
}

static inline
int __soc_hash(const char *key)
{
    return __murmurhash64a(key, strlen(key), 0xf467eaddaf9) %
        pfs_soc_mgr.hsize;
}

static inline
struct soc_entry *__se_alloc(const char *key, struct hstat *hs)
{
    struct soc_entry *se;

    se = xzalloc(sizeof(*se));
    if (!se) {
        hvfs_err(xnet, "xzalloc() soc_entry failed\n");
        return NULL;
    }
    se->key = strdup(key);
    se->hs = *hs;

    return se;
}

static inline
void __soc_insert(struct soc_entry *new)
{
    struct regular_hash *rh;
    struct soc_entry *se;
    struct hlist_node *pos, *n;
    int idx, found = 0;

    idx = __soc_hash(new->key);
    rh = pfs_soc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(se, pos, n, &rh->h, hlist) {
        if (strcmp(new->key, se->key) == 0) {
            /* already exist, then update the hstat */
            se->hs = new->hs;
            found = 1;
            break;
        }
    }
    if (!found) {
        hlist_add_head(&new->hlist, &rh->h);
    }
    xlock_unlock(&rh->lock);
    atomic_inc(&pfs_soc_mgr.nr);
}

static inline
struct soc_entry *__soc_lookup(const char *key)
{
    struct regular_hash *rh;
    struct soc_entry *se;
    struct hlist_node *pos, *n;
    int idx, found = 0;

    if (atomic_read(&pfs_soc_mgr.nr) <= 0)
        return NULL;
    
    idx = __soc_hash(key);
    rh = pfs_soc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(se, pos, n, &rh->h, hlist) {
        if (strcmp(se->key, key) == 0) {
            hlist_del(&se->hlist);
            atomic_dec(&pfs_soc_mgr.nr);
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found)
        return se;
    else
        return NULL;
}

/* We construct a write buffer cache to absorb user's write requests and flush
 * them as a whole to disk when the file are closed. Thus, we have
 * close-to-open consistency.
 */
size_t g_pagesize = 0;
static void *zero_page = NULL;
struct __pfs_fuse_mgr pfs_fuse_mgr = {.inited = 0,};

#define PFS_FUSE_CONFIG_UUID            0xffff000000000000

/* We are sure that there is no page hole! */
struct __pfs_odc_mgr
{
#define PFS_ODC_HSIZE_DEFAULT   (8191)
    struct regular_hash *ht;
    u32 hsize;
} pfs_odc_mgr;

struct bhhead
{
    struct hlist_node hlist;
    struct list_head bh;
    size_t size;                /* total buffer size */
    size_t asize;               /* actually size for release use */
    struct hstat hs;
    xrwlock_t clock;
    u64 uuid;                   /* who am i? */
#define BH_CLEAN        0x00
#define BH_DIRTY        0x01
#define BH_CONFIG       0x80
    u32 flag;
    atomic_t ref;
    void *ptr;                  /* private pointer */
};

struct bh
{
    struct list_head list;
    off_t offset;               /* buffer offset */
    void *data;                 /* this is always a page */
};

static int __odc_init(int hsize)
{
    int i;

    if (hsize)
        pfs_odc_mgr.hsize = hsize;
    else
        pfs_odc_mgr.hsize = PFS_ODC_HSIZE_DEFAULT;

    pfs_odc_mgr.ht = xmalloc(pfs_odc_mgr.hsize * sizeof(struct regular_hash));
    if (!pfs_odc_mgr.ht) {
        hvfs_err(xnet, "OpeneD Cache(ODC) hash table init failed\n");
        return -ENOMEM;
    }

    /* init the hash table */
    for (i = 0; i < pfs_odc_mgr.hsize; i++) {
        INIT_HLIST_HEAD(&pfs_odc_mgr.ht[i].h);
        xlock_init(&pfs_odc_mgr.ht[i].lock);
    }

    return 0;
}

static void __odc_destroy(void)
{
    xfree(pfs_odc_mgr.ht);
}

static inline
int __odc_hash(u64 uuid)
{
    return __murmurhash64a(&uuid, sizeof(uuid), 0xfade8419edfa) %
        pfs_odc_mgr.hsize;
}

/* Return value: 0: not really removed; 1: truely removed
 */
static inline
int __odc_remove(struct bhhead *del)
{
    struct regular_hash *rh;
    struct bhhead *bhh;
    struct hlist_node *pos, *n;
    int idx;

    idx = __odc_hash(del->uuid);
    rh = pfs_odc_mgr.ht + idx;

    idx = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(bhh, pos, n, &rh->h, hlist) {
        if (del == bhh && del->uuid == bhh->uuid) {
            if (atomic_dec_return(&bhh->ref) <= 0) {
                idx = 1;
                hlist_del(&bhh->hlist);
            }
            break;
        }
    }
    xlock_unlock(&rh->lock);

    return idx;
}

static struct bhhead *__odc_insert(struct bhhead *new)
{
    struct regular_hash *rh;
    struct bhhead *bhh;
    struct hlist_node *pos, *n;
    int idx, found = 0;

    idx = __odc_hash(new->uuid);
    rh = pfs_odc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(bhh, pos, n, &rh->h, hlist) {
        if (new->uuid == bhh->uuid) {
            /* already exist */
            atomic_inc(&bhh->ref);
            found = 1;
            break;
        }
    }
    if (!found) {
        hlist_add_head(&new->hlist, &rh->h);
        bhh = new;
    }
    xlock_unlock(&rh->lock);

    return bhh;
}

/* Return value: NULL: miss; other: hit
 */
static inline
struct bhhead *__odc_lookup(u64 uuid)
{
    struct regular_hash *rh;
    struct bhhead *bhh;
    struct hlist_node *n;
    int idx, found = 0;

    idx = __odc_hash(uuid);
    rh = pfs_odc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(bhh, n, &rh->h, hlist) {
        if (bhh->uuid == uuid) {
            atomic_inc(&bhh->ref);
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found)
        return bhh;
    else
        return NULL;
}

static inline
struct bhhead* __get_bhhead(struct hstat *hs)
{
    struct bhhead *bhh, *tmp_bhh;

    bhh = __odc_lookup(hs->uuid);
    if (!bhh) {
        /* create it now */
        bhh = xzalloc(sizeof(struct bhhead));
        if (unlikely(!bhh)) {
            return NULL;
        }
        INIT_LIST_HEAD(&bhh->bh);
        xrwlock_init(&bhh->clock);
        bhh->hs = *hs;
        bhh->uuid = hs->uuid;
        bhh->asize = hs->mc.c.len;
        atomic_set(&bhh->ref, 1);

        /* try to insert into the table */
        tmp_bhh = __odc_insert(bhh);
        if (tmp_bhh != bhh) {
            /* someone ahead me, free myself */
            xfree(bhh);
            bhh = tmp_bhh;
        }
    }

    return bhh;
}

static inline void __set_bhh_dirty(struct bhhead *bhh)
{
    bhh->flag = BH_DIRTY;
}
static inline void __clr_bhh_dirty(struct bhhead *bhh)
{
    bhh->flag &= ~BH_DIRTY;
}

static inline void __set_bhh_config(struct bhhead *bhh)
{
    bhh->flag = BH_CONFIG;
}

static int __prepare_bh(struct bh *bh, int alloc)
{
    if (!bh->data || bh->data == zero_page) {
        if (alloc) {
            bh->data = xzalloc(g_pagesize);
            if (!bh->data) {
                return -ENOMEM;
            }
        } else
            bh->data = zero_page;
    }

    return 0;
}

static struct bh* __get_bh(off_t off, int alloc)
{
    struct bh *bh;

    bh = xzalloc(sizeof(struct bh));
    if (!bh) {
        return NULL;
    }
    INIT_LIST_HEAD(&bh->list);
    bh->offset = off;
    if (__prepare_bh(bh, alloc)) {
        xfree(bh);
        bh = NULL;
    }

    return bh;
}

static void __put_bh(struct bh *bh)
{
    if (bh->data && bh->data != zero_page)
        xfree(bh->data);

    xfree(bh);
}

static void __put_bhhead(struct bhhead *bhh)
{
    struct bh *bh, *n;

    if (__odc_remove(bhh)) {
        list_for_each_entry_safe(bh, n, &bhh->bh, list) {
            list_del(&bh->list);
            __put_bh(bh);
        }

        xfree(bhh);
    }
}

/* __bh_fill() will fill the buffer cache w/ buf. if there are holes, it will
 * fill them automatically.
 */
static int __bh_fill(struct hstat *hs, int column, struct column *c,
                     struct bhhead *bhh, void *buf, off_t offset,
                     size_t size)
{
    /* round down the offset */
    struct bh *bh;
    off_t off_end = PAGE_ROUNDUP((offset + size), g_pagesize);
    off_t loff = 0;
    ssize_t rlen;
    size_t _size = 0;
    int err = 0;

    xrwlock_wlock(&bhh->clock);
    /* should we loadin the middle holes */
    if (offset >= bhh->size) {
        while (bhh->size < off_end) {
            bh = __get_bh(bhh->size, 0);
            if (!bh) {
                err = -ENOMEM;
                goto out;
            }
            if (offset == bhh->size && size >= g_pagesize) {
                /* just copy the buffer, prepare true page */
                __prepare_bh(bh, 1);
                _size = min(size, bh->offset + g_pagesize - offset);
                if (buf)
                    memcpy(bh->data + offset - bh->offset,
                           buf + loff, _size);
                size -= _size;
                loff += _size;
                offset = bh->offset + g_pagesize;
            } else {
                /* read in the page now */
                if (bhh->size <= hs->mc.c.len || 
                    hs->mdu.flags & HVFS_MDU_IF_LZO) {
                    __prepare_bh(bh, 1);
                }
                rlen = __hvfs_fread(hs, 0, &bh->data, &hs->mc.c,
                                    bhh->size, g_pagesize);
                if (rlen == -EFBIG) {
                    /* it is ok, we just zero the page */
                    err = 0;
                } else if (rlen < 0) {
                    hvfs_err(xnet, "bh_fill() read the file range [%ld, %ld] "
                             "failed w/ %ld\n",
                             bhh->size, bhh->size + g_pagesize, rlen);
                    err = rlen;
                    goto out;
                }
                /* should we fill with buf? */
                if (size && offset < bh->offset + g_pagesize) {
                    __prepare_bh(bh, 1);
                    _size = min(size, bh->offset + g_pagesize - offset);
                    if (buf)
                        memcpy(bh->data + offset - bh->offset,
                               buf + loff, _size);
                    size -= _size;
                    loff += _size;
                    offset = bh->offset + g_pagesize;
                }
            }
            list_add_tail(&bh->list, &bhh->bh);
            bhh->size += g_pagesize;
        }
    } else {
        /* update the cached content */
        list_for_each_entry(bh, &bhh->bh, list) {
            if (offset >= bh->offset && offset < bh->offset + g_pagesize) {
                __prepare_bh(bh, 1);
                _size = min(size, bh->offset + g_pagesize - offset);
                if (buf)
                    memcpy(bh->data + offset - bh->offset,
                           buf + loff, _size);
                size -= _size;
                loff += _size;
                offset = bh->offset + g_pagesize;
                if (size <= 0)
                    break;
            }
        }
        if (size) {
            /* fill the last holes */
            while (bhh->size < off_end) {
                bh = __get_bh(bhh->size, 1);
                if (!bh) {
                    err = -ENOMEM;
                    goto out;
                }
                if (offset == bhh->size && size >= g_pagesize) {
                    /* just copy the buffer */
                    _size = min(size, bh->offset + g_pagesize - offset);
                    if (buf)
                        memcpy(bh->data + offset - bh->offset,
                               buf + loff, _size);
                    size -= _size;
                    loff += _size;
                    offset = bh->offset + g_pagesize;
                } else {
                    /* read in the page now */
                    rlen = __hvfs_fread(hs, 0, &bh->data, &hs->mc.c,
                                       bhh->size, g_pagesize);
                    if (rlen == -EFBIG) {
                        /* it is ok, we just zero the page */
                        err = 0;
                    } else if (rlen < 0) {
                        hvfs_err(xnet, "bh_fill() read the file range [%ld, %ld] "
                                 "failed w/ %ld",
                                 bhh->size, bhh->size + g_pagesize, rlen);
                        err = rlen;
                        goto out;
                    }
                    /* should we fill with buf? */
                    if (size && offset < bh->offset + g_pagesize) {
                        _size = min(size, bh->offset + g_pagesize - offset);
                        if (buf)
                            memcpy(bh->data + offset - bh->offset,
                                   buf + loff, _size);
                        size -= _size;
                        loff += _size;
                        offset = bh->offset + g_pagesize;
                    }
                    list_add_tail(&bh->list, &bhh->bh);
                    bhh->size += g_pagesize;
                }
            }
        }
    }

out:
    xrwlock_wunlock(&bhh->clock);
    
    return err;
}

/* Return the cached bytes we can read or minus errno
 */
static int __bh_read(struct bhhead *bhh, void *buf, off_t offset, 
                     size_t size)
{
    struct bh *bh;
    off_t loff = 0, saved_offset = offset;
    size_t _size, saved_size = size;
    
    if (offset + size > bhh->size || list_empty(&bhh->bh)) {
        return -EFBIG;
    }
    
    xrwlock_rlock(&bhh->clock);
    list_for_each_entry(bh, &bhh->bh, list) {
        if (offset >= bh->offset && offset < bh->offset + g_pagesize) {
            _size = min(size, bh->offset + g_pagesize - offset);
            memcpy(buf + loff, bh->data + offset - bh->offset,
                   _size);
            /* adjust the offset and size */
            size -= _size;
            loff += _size;
            offset = bh->offset + g_pagesize;
            if (size <= 0)
                break;
        }
    }
    xrwlock_runlock(&bhh->clock);

    size = saved_size - size;
    /* adjust the return size to valid file range */
    if (saved_offset + size > bhh->asize) {
        size = bhh->asize - saved_offset;
        if ((ssize_t)size < 0)
            size = 0;
    }
    
    return size;
}

static int __bh_sync(struct bhhead *bhh)
{
    struct hstat hs;
    struct bh *bh;
    struct iovec *iov = NULL;
    off_t offset = 0;
    void *data = NULL;
    size_t size, _size;
    u64 hash;
    int err = 0, i;

    if (bhh->asize > bhh->size) {
        /* oh, we have to fill the remain pages */
        err = __bh_fill(&bhh->hs, 0, &bhh->hs.mc.c, bhh, NULL, 
                        bhh->asize, 0);
        if (err < 0) {
            hvfs_err(xnet, "fill the buffer cache failed w/ %d\n",
                     err);
            goto out;
        }
    }

    hs = bhh->hs;

    xrwlock_wlock(&bhh->clock);
    size = bhh->asize;
    i = 0;
    list_for_each_entry(bh, &bhh->bh, list) {
        _size = min(size, g_pagesize);
        i++;
        size -= _size;
        if (size <= 0)
            break;
    }

    if (i > IOV_MAX - 5) {
        /* sadly fallback to memcpy approach */
        data = xmalloc(bhh->asize);
        if (!data) {
            hvfs_err(xnet, "xmalloc(%ld) data buffer failed\n", 
                     bhh->asize);
            xrwlock_wunlock(&bhh->clock);
            return -ENOMEM;
        }

        size = bhh->asize;
        list_for_each_entry(bh, &bhh->bh, list) {
            _size = min(size, g_pagesize);
            memcpy(data + offset, bh->data, _size);
            offset += _size;
            size -= _size;
            if (size <= 0)
                break;
        }
    } else {
        iov = xmalloc(sizeof(*iov) * i);
        if (!iov) {
            hvfs_err(xnet, "xmalloc() iov buffer failed\n");
            xrwlock_wunlock(&bhh->clock);
            return -ENOMEM;
        }
        
        size = bhh->asize;
        i = 0;
        list_for_each_entry(bh, &bhh->bh, list) {
            _size = min(size, g_pagesize);
            
            (iov + i)->iov_base = bh->data;
            (iov + i)->iov_len = _size;
            i++;
            size -= _size;
            if (size <= 0)
                break;
        }
    }
    __clr_bhh_dirty(bhh);
    xrwlock_wunlock(&bhh->clock);

    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hs.puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out_free;
        }
        hash = hs.hash;
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }

    /* write out the data now */
    if (data) {
        err = __hvfs_fwrite(&hs, 0 /* ZERO */, 0, data, bhh->asize, 
                             &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on ino'%lx' failed w/ %d\n",
                     hs.uuid, err);
            goto out_free;
        }
    } else {
        err = __hvfs_fwritev(&hs, 0 /* ZERO */, 0, iov, i, 
                             &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on ino'%lx' failed w/ %d\n",
                     hs.uuid, err);
            goto out_free;
        }
    }

    /* update the file attributes */
    {
        struct mdu_update *mu;
        struct mu_column *mc;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        mc = (void *)mu + sizeof(*mu);
        mu->valid = MU_COLUMN | MU_SIZE;
        {
            mu->valid |= MU_FLAG_CLR;
            mu->flags |= (HVFS_MDU_IF_PROXY | HVFS_MDU_IF_LZO);
        }
        mu->size = bhh->asize;
        mu->column_no = 1;
        mc->cno = 0;            /* zero column */
        mc->c = hs.mc.c;
        hs.hash = hash;

        err = __hvfs_update(hs.puuid, hs.psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on ino<%lx,%lx> failed w/ %d\n",
                     hs.uuid, hs.hash, err);
            xfree(mu);
            goto out_free;
        }
        /* finally, update bhh->hs */
        hs.mc = *mc;
        bhh->hs = hs;
        xfree(mu);
    }

    err = size;

out_free:
    xfree(iov);
    xfree(data);

out:
    return err;
}

/* We have a LRU translate cache to resolve file system pathname(only
 * directory) to uuid and salt pair.
 */
static time_t *g_pfs_tick = NULL; /* file system tick */
struct __pfs_ltc_mgr
{
    struct regular_hash *ht;
    struct list_head lru;
    xlock_t lru_lock;
#define PFS_LTC_HSIZE_DEFAULT   (8191)
    u32 hsize:16;               /* hash table size */
    u32 ttl:8;                  /* valid ttl. 0 means do not believe the
                                 * cached value (cache disabled) */
} pfs_ltc_mgr;

struct ltc_entry
{
    struct hlist_node hlist;
    struct list_head list;
    char *fullname;             /* full pathname */
    u64 uuid, salt;
    u64 born;
};

static int __ltc_init(int ttl, int hsize)
{
    int i;
    
    if (hsize)
        pfs_ltc_mgr.hsize = hsize;
    else
        pfs_ltc_mgr.hsize = PFS_LTC_HSIZE_DEFAULT;

    pfs_ltc_mgr.ttl = ttl;

    pfs_ltc_mgr.ht = xmalloc(pfs_ltc_mgr.hsize * sizeof(struct regular_hash));
    if (!pfs_ltc_mgr.ht) {
        hvfs_err(xnet, "LRU Translate Cache hash table init failed\n");
        return -ENOMEM;
    }

    /* init the hash table */
    for (i = 0; i < pfs_ltc_mgr.hsize; i++) {
        INIT_HLIST_HEAD(&pfs_ltc_mgr.ht[i].h);
        xlock_init(&pfs_ltc_mgr.ht[i].lock);
    }
    INIT_LIST_HEAD(&pfs_ltc_mgr.lru);
    xlock_init(&pfs_ltc_mgr.lru_lock);

    /* init file system tick */
    g_pfs_tick = &hmo.tick;

    return 0;
}

static void __ltc_destroy(void)
{
    xfree(pfs_ltc_mgr.ht);
}

#define LE_LIFE_FACTOR          (4)
#define LE_IS_OLD(le) (                                                 \
        ((*g_pfs_tick - (le)->born) >                                   \
         LE_LIFE_FACTOR * pfs_ltc_mgr.ttl)                              \
        )
#define LE_IS_VALID(le) (*g_pfs_tick - (le)->born <= pfs_ltc_mgr.ttl)

static inline
int __ltc_hash(const char *key)
{
    return __murmurhash64a(key, strlen(key), 0xfead31435df3) % 
        pfs_ltc_mgr.hsize;
}

static void __ltc_remove(struct ltc_entry *del)
{
    struct regular_hash *rh;
    struct ltc_entry *le;
    struct hlist_node *pos, *n;
    int idx;

    idx = __ltc_hash(del->fullname);
    rh = pfs_ltc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(le, pos, n, &rh->h, hlist) {
        if (del == le && strcmp(del->fullname, le->fullname) == 0) {
            hlist_del(&le->hlist);
            break;
        }
    }
    xlock_unlock(&rh->lock);
}

static struct ltc_entry *
__ltc_new_entry(char *pathname, void *arg0, void *arg1)
{
    struct ltc_entry *le = NULL;

    /* find the least recently used entry */
    if (!list_empty(&pfs_ltc_mgr.lru)) {
        xlock_lock(&pfs_ltc_mgr.lru_lock);
        le = list_entry(pfs_ltc_mgr.lru.prev, struct ltc_entry, list);
        /* if it is born long time ago, we reuse it! */
        if (LE_IS_OLD(le)) {
            /* remove from the tail */
            list_del_init(&le->list);

            xlock_unlock(&pfs_ltc_mgr.lru_lock);
            /* remove from the hash table */
            __ltc_remove(le);

            /* install new values */
            xfree(le->fullname);
            le->fullname = strdup(pathname);
            if (!le->fullname) {
                /* failed with not enough memory! */
                xfree(le);
                le = NULL;
                goto out;
            }
            le->uuid = (u64)arg0;
            le->salt = (u64)arg1;
            le->born = *g_pfs_tick;
        } else {
            xlock_unlock(&pfs_ltc_mgr.lru_lock);
            goto alloc_one;
        }
    } else {
    alloc_one:
        le = xmalloc(sizeof(*le));
        if (!le) {
            goto out;
        }
        le->fullname = strdup(pathname);
        if (!le->fullname) {
            xfree(le);
            le = NULL;
            goto out;
        }
        le->uuid = (u64)arg0;
        le->salt = (u64)arg1;
        le->born = *g_pfs_tick;
    }

out:
    return le;
}

/* Return value: 1 => hit and up2date; 2 => miss, alloc and up2date; 
 *               0 => not up2date
 */
static int __ltc_update(char *pathname, void *arg0, void *arg1)
{
    struct regular_hash *rh;
    struct ltc_entry *le;
    struct hlist_node *n;
    int found = 0, idx;

    /* ABI: arg0, and arg1 is uuid and salt value */
    idx = __ltc_hash(pathname);
    rh = pfs_ltc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(le, n, &rh->h, hlist) {
        if (strcmp(le->fullname, pathname) == 0) {
            /* ok, we update the entry */
            le->uuid = (u64)arg0;
            le->salt = (u64)arg1;
            le->born = *g_pfs_tick;
            found = 1;
            /* move to the head of lru list */
            xlock_lock(&pfs_ltc_mgr.lru_lock);
            list_del_init(&le->list);
            list_add(&le->list, &pfs_ltc_mgr.lru);
            xlock_unlock(&pfs_ltc_mgr.lru_lock);
            break;
        }
    }
    if (unlikely(!found)) {
        le = __ltc_new_entry(pathname, arg0, arg1);
        if (likely(le)) {
            found = 2;
        }
        /* insert to this hash list */
        hlist_add_head(&le->hlist, &rh->h);
        /* insert to the lru list */
        xlock_lock(&pfs_ltc_mgr.lru_lock);
        list_add(&le->list, &pfs_ltc_mgr.lru);
        xlock_unlock(&pfs_ltc_mgr.lru_lock);
    }
    xlock_unlock(&rh->lock);
    
    return found;
}

/* Return value: 0: miss; 1: hit; <0: error
 */
static inline
int __ltc_lookup(char *pathname, void *arg0, void *arg1)
{
    struct regular_hash *rh;
    struct ltc_entry *le;
    struct hlist_node *n;
    int found = 0, idx;

    idx = __ltc_hash(pathname);
    rh = pfs_ltc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(le, n, &rh->h, hlist) {
        if (LE_IS_VALID(le) && 
            strcmp(pathname, le->fullname) == 0
            ) {
            *(u64 *)arg0 = le->uuid;
            *(u64 *)arg1 = le->salt;
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    return found;
}

static inline
void __ltc_invalid(const char *pathname)
{
    struct regular_hash *rh;
    struct ltc_entry *le;
    struct hlist_node *pos, *n;
    int idx;

    idx = __ltc_hash(pathname);
    rh = pfs_ltc_mgr.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(le, pos, n, &rh->h, hlist) {
        if (strcmp(pathname, le->fullname) == 0) {
            le->born -= pfs_ltc_mgr.ttl;
            break;
        }
    }
    xlock_unlock(&rh->lock);
}

/* FUSE config support
 *
 * Using this dynamic config service, user can change the behaivers
 * on-the-fly.
 */

struct pfs_config_entry
{
    char *name;
#define PCE_STRING      0x00
#define PCE_U64         0x01
#define PCE_U64X        0x02
#define PCE_BOOL        0x03
    u32 flag;
    union 
    {
        char *svalue;
        u64 uvalue;
    };
};

#define PFS_CONFIG_ACTIVE_ENTRY         (5)
struct pfs_config_entry pfs_ce_default[PFS_CONFIG_ACTIVE_ENTRY] = {
#define PC_DATA_ZIP                     0
    {
        .name = "data_zip", 
        .flag = PCE_BOOL, 
        {
            .uvalue = 0,
        },
    },
#define PC_LRU_TRANSLATE_CACHE_TTL      1
    {
        .name = "lru_translate_cache_ttl",
        .flag = PCE_U64,
        {
            .uvalue = 0,
        },
    },
#define PC_SYNC_WRITE                   2
    {
        .name = "pfs_fuse_sync_write",
        .flag = PCE_BOOL,
        {
            .uvalue = 0,
        },
    },
#define PC_NOATIME                      3
    {
        .name = "noatime",
        .flag = PCE_BOOL,
        {
            .uvalue = 0,
        },
    },
#define PC_NODIRATIME                   4
    {
        .name = "nodiratime",
        .flag = PCE_BOOL,
        {
            .uvalue = 0,
        },
    },
};

struct pfs_config_mgr
{
#define PCM_BUF_SIZE    4096
    char buf[PCM_BUF_SIZE];
    int asize, psize;
    struct pfs_config_entry pce[0];
};

static inline
int hvfs_config_check(const char *pathname, struct stat *stbuf)
{
    if (likely(!pfs_fuse_mgr.use_config))
        return 0;
    
    if (unlikely(memcmp(pathname, ".@.$.pfs.conf", 13) == 0)) {
        stbuf->st_ino = -1UL;
        stbuf->st_mode = S_IFREG;
        stbuf->st_nlink = 1;
        stbuf->st_ctime = 
            stbuf->st_mtime = 
            stbuf->st_atime = time(NULL);
        stbuf->st_size = 4096;

        return 1;
    } else
        return 0;
}

/* config_open check if this is the magic file :) */
static inline
int hvfs_config_open(const char *pathname, struct fuse_file_info *fi)
{
    struct hstat hs = {
        .uuid = PFS_FUSE_CONFIG_UUID, /* special uuid */
        .mc.c.len = 0,
    };
    struct bhhead *bhh;
    struct pfs_config_mgr *pcm = NULL;
    
    if (likely(!pfs_fuse_mgr.use_config))
        return 0;

    if (unlikely(memcmp(pathname, ".@.$.pfs.conf", 13) == 0)) {
        bhh = __get_bhhead(&hs);
        if (!bhh)
            return 0;

        pcm = xzalloc(sizeof(*pcm) + 
                      sizeof(struct pfs_config_entry) * 16);
        if (!pcm) {
            xfree(bhh);
            return 0;
        }

        memcpy(pcm->pce, pfs_ce_default, sizeof(pfs_ce_default));
        pcm->psize = 16;
        pcm->asize = PFS_CONFIG_ACTIVE_ENTRY;
        
        __set_bhh_config(bhh);
        bhh->ptr = pcm;
        fi->fh = (u64)bhh;

        return 1;
    }

    return 0;
}

static inline
void hvfs_config_release(struct pfs_config_mgr *pcm)
{
    if (likely(!pfs_fuse_mgr.use_config))
        return;

    xfree(pcm);
}

/* config_read dump the current configs */
static int hvfs_config_read(struct pfs_config_mgr *pcm, char *buf,
                            size_t size, off_t offset)
{
    char *p;
    size_t bl, bs;
    int i;
    
    if (likely(!pfs_fuse_mgr.use_config))
        return 0;

    /* re-generate the buffer now */
    p = pcm->buf;
    bl = PCM_BUF_SIZE;
    
    bs = snprintf(p, bl, 
                  "PomegranateFS FUSE Client Configurations:\n\n"
                  "# Defaults\n");
    p += bs;
    bl -= bs;
    
    for (i = 0; i < pcm->asize; i++) {
        switch (pcm->pce[i].flag) {
        case PCE_STRING:
            bs = snprintf(p, bl, "%s:%s\n", pcm->pce[i].name,
                          pcm->pce[i].svalue);
            break;
        case PCE_U64:
            bs = snprintf(p, bl, "%s:%ld\n", pcm->pce[i].name,
                          pcm->pce[i].uvalue);
            break;
        case PCE_U64X:
            bs = snprintf(p, bl, "%s:%lx\n", pcm->pce[i].name,
                          pcm->pce[i].uvalue);
            break;
        case PCE_BOOL:
            bs = snprintf(p, bl, "%s:%s\n", pcm->pce[i].name,
                          (pcm->pce[i].uvalue == 0 ? "false" :
                           "true"));
            break;
        default:
            bs = snprintf(p, bl, "INVALID ENTRY\n");
        }
        p += bs;
        bl -= bs;
        if (bl <= 0)
            break;
    }

    /* check the offset */
    if (offset >= (PCM_BUF_SIZE - bl))
        return 0;
    memcpy(buf, pcm->buf + offset, min(size, 
                                       PCM_BUF_SIZE - bl 
                                       - offset));

    return min(size, PCM_BUF_SIZE - bl - offset);
}

/* GETATTR: 
 * Use xnet to send the request to server
 */
static int hvfs_getattr(const char *pathname, struct stat *stbuf)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    {
        struct soc_entry *se = __soc_lookup(pathname);

        if (unlikely(se)) {
            hs = se->hs;
            xfree(se);
            goto pack;
        }
    }

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    if (unlikely(hvfs_config_check(name, stbuf))) {
        goto out;
    }

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (unlikely(err)) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* lookup the file in the parent directory now */
    if (strlen(name) > 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_debug(xnet, "do internal file stat (SDT) on '%s'"
                       " failed w/ %d puuid %lx psalt %lx (%s RT %lx %lx)\n", 
                       name, err, puuid, psalt,
                       path, hmi.root_uuid, hmi.root_salt);
            goto out;
        }
        if (S_ISDIR(hs.mdu.mode)) {
            hs.hash = 0;
            err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 1, &hs);
            if (err) {
                hvfs_err(xnet, "do last dir stat (GDT) on '%s'<%lx,%lx> "
                         "failed w/ %d\n",
                         name, hs.uuid, hs.hash, err);
                goto out;
            }
        }
    } else {
        /* check if it the root directory */
        if (puuid == hmi.root_uuid) {
            /* stat root w/o any file name, it is ROOT we want to state */
            err = __hvfs_fill_root(&hs);
            if (err) {
                hvfs_err(xnet, "fill root entry failed w/ %d\n", err);
                goto out;
            }
        }
    }

    /* update hs w/ local ODC cached hstat */
    {
        struct bhhead *bhh = __odc_lookup(hs.uuid);

        if (unlikely(bhh)) {
#if 0
            hvfs_err(xnet, "<%lx,%lx> new %lx %ld %d old %lx %ld %d\n", 
                     hs.uuid, hs.hash,
                     hs.mdu.mtime, hs.mdu.size, hs.mdu.version,
                     bhh->hs.mdu.mtime, bhh->hs.mdu.size, 
                     bhh->hs.mdu.version);
#endif
            if (MDU_VERSION_COMPARE(hs.mdu.version, bhh->hs.mdu.version)) {
                bhh->hs.mdu = hs.mdu;
                bhh->hs.mc = hs.mc;
            } else {
                hs.mdu = bhh->hs.mdu;
                hs.mc = bhh->hs.mc;
                hs.mdu.size = bhh->asize;
            }
            __put_bhhead(bhh);
        }
    }

pack:
    /* pack the result to stat buffer */
    stbuf->st_ino = hs.uuid;
    stbuf->st_mode = hs.mdu.mode;
    stbuf->st_rdev = hs.mdu.dev;
    stbuf->st_nlink = hs.mdu.nlink;
    stbuf->st_uid = hs.mdu.uid;
    stbuf->st_gid = hs.mdu.gid;
    stbuf->st_ctime = (time_t)hs.mdu.ctime;
    stbuf->st_atime = (time_t)hs.mdu.atime;
    stbuf->st_mtime = (time_t)hs.mdu.mtime;
    if (unlikely(S_ISDIR(hs.mdu.mode))) {
        stbuf->st_size = 0;
        stbuf->st_blocks = 1;
    } else {
        stbuf->st_size = hs.mdu.size;
        /* FIXME: use column size instead! */
        stbuf->st_blocks = (hs.mdu.size + 511) >> 9;
    }
    /* the blksize is always 4KB */
    stbuf->st_blksize = 4096;
    
out:
    xfree(dup);
    xfree(spath);

    return err;
}

/* At this moment, we only support reading the symlink content from the mdu
 * fields.
 */
static int hvfs_readlink(const char *pathname, char *buf, size_t size)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    ssize_t rlen;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* lookup the file in the parent directory now */
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        if (S_ISDIR(hs.mdu.mode)) {
            hs.hash = 0;
            err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 1, &hs);
            if (err) {
                hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
        }
    } else {
        hvfs_err(xnet, "Readlink from a directory is not allowed\n");
        err = -EINVAL;
        goto out;
    }

    /* ok to parse the symname */
    if (hs.mdu.size > sizeof(hs.mdu.symname)) {
        /* read the symname from storage server */
        rlen = __hvfs_fread(&hs, 0 /* column is ZERO */, (void **)&buf, 
                            &hs.mc.c, 0, min(hs.mdu.size, size));
        if (rlen < 0) {
            hvfs_err(xnet, "do internal fread on '%s' failed w/ %ld\n",
                     name, rlen);
            err = rlen;
            goto out;
        }
        err = 0;
    } else {
        memcpy(buf, hs.mdu.symname, min(hs.mdu.size, size));
    }
    buf[min(hs.mdu.size, size)] = '\0';

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_mknod(const char *pathname, mode_t mode, dev_t rdev)
{
    struct hstat hs;
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* create the file or dir in the parent directory now */
    hs.name = name;
    hs.uuid = 0;
    /* FIXME: should we not drop rdev? */
    mu.valid = MU_MODE;
    mu.mode = mode;
    err = __hvfs_create(puuid, psalt, &hs, 0, &mu);
    if (err) {
        hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_mkdir(const char *pathname, mode_t mode)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt, duuid;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* create the file or dir in the parent directory now */
    hs.name = name;
    hs.uuid = 0;
    mu.valid = MU_MODE;
    mu.mode = mode | S_IFDIR;
    err = __hvfs_create(puuid, psalt, &hs, INDEX_CREATE_DIR, &mu);
    if (err) {
        hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    duuid = hs.uuid;

    /* create the gdt entry now */
    err = __hvfs_create(hmi.gdt_uuid, hmi.gdt_salt, &hs, 
                        INDEX_CREATE_GDT, NULL);
    if (err) {
        hvfs_err(xnet, "do internal create (GDT) on '%s' faild w/ %d\n",
                 name, err);
        goto out;
    }
    __ltc_update((char *)pathname, (void *)hs.uuid, (void *)hs.ssalt);

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_unlink(const char *pathname)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        saved_psalt = psalt;
        saved_puuid = puuid;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        saved_hash = hs.hash;
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* finally, do delete now */
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_unlink(puuid, psalt, &hs);
    if (err) {
        hvfs_err(xnet, "do internal delete (SDT) on '%s' "
                 "failed w/ %d\n",
                 name, err);
        goto out;
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_rmdir(const char *pathname)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        saved_psalt = psalt;
        saved_puuid = puuid;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        saved_hash = hs.hash;
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* finally, do delete now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        /* what we want to delete is the root directory, reject it */
        hvfs_err(xnet, "Reject root directory removal!\n");
        err = -ENOTEMPTY;
        goto out;
    } else {
        /* confirm what it is firstly! */
        struct hstat tmp_hs;
        u64 duuid, dsalt;
        
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat (SDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }
        if (!S_ISDIR(hs.mdu.mode)) {
            hvfs_err(xnet, "not a directory, we expect dir here\n");
            err = -ENOTDIR;
            goto out;
        }
        duuid = hs.uuid;

        tmp_hs = hs;
        tmp_hs.hash = 0;
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &tmp_hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (SDT) on '%s' "
                     "failed w/ %d\n", name, err);
            goto out;
        }
        dsalt = tmp_hs.ssalt;
        
        /* is this directory empty? */
        if (!__hvfs_is_empty_dir(duuid, dsalt, NULL)) {
            err = -ENOTEMPTY;
            goto out;
        }

        /* delete a normal file or dir, it is easy */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_unlink(puuid, psalt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete (SDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }

        /* ok, delete the GDT entry */
        hs.hash = 0;
        err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete (GDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }
        __ltc_invalid(pathname);
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_symlink(const char *from, const char *to)
{
    struct hstat hs;
    struct mdu_update *mu;
    char *dup = strdup(to), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, namelen;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* create the file or dir in the parent directory now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        hvfs_err(xnet, "Create zero-length named file or root directory?\n");
        err = -EINVAL;
        goto out;
    }
    
    hs.name = name;
    hs.uuid = 0;
    /* switch here for 16B symname */
    namelen = strlen(from);

    if (namelen <= sizeof(hs.mdu.symname)) {
        mu = xzalloc(sizeof(*mu) + namelen);
        if (unlikely(!mu)) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mu->valid = MU_SYMNAME | MU_SIZE;
        mu->namelen = namelen;
        mu->size = namelen;
        memcpy((void *)mu + sizeof(*mu), from, namelen);

        err = __hvfs_create(puuid, psalt, &hs, INDEX_SYMLINK, mu);
        if (err) {
            hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                     name, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    } else {
        struct column saved_c;

        /* write to the MDSL and create symlink file with the column info */
        hs.puuid = puuid;
        hs.psalt = psalt;
        hs.hash = 0;            /* default to zero itb */
        err = __hvfs_fwrite(&hs, 0 /* ZERO */, 0, (void *)from, 
                            namelen, &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on '%s' failed w/ %d\n",
                     to, err);
            goto out;
        }
        saved_c = hs.mc.c;
        mu = xzalloc(sizeof(*mu) + 4);
        if (unlikely(!mu)) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mu->valid = MU_SYMNAME;
        mu->namelen = 4;
        sprintf((char *)mu + sizeof(*mu), "NaN");

        hs.uuid = 0;
        err = __hvfs_create(puuid, psalt, &hs, INDEX_SYMLINK, mu);
        if (err) {
            hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                     name, err);
            xfree(mu);
            goto out;
        }

        /* finally, update the newly created symlink file */
        mu->valid = MU_SIZE | MU_COLUMN;
        mu->size = namelen;
        mu->column_no = 1;
        hs.mc.c = saved_c;

        err = __hvfs_update(puuid, psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     to, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

/* Rational for (atomic) rename:
 *
 * Basically, we stat and copy the file info to the target location; and
 * finally, unlink the original entry.
 */
static int hvfs_rename(const char *from, const char *to)
{
    struct link_source ls;
    struct hstat hs, saved_hs, deleted_hs = {.uuid = 0, .mdu.mode = 0,};
    char *dup = strdup(from), *dup2 = strdup(from), 
        *path, *name, *spath = NULL, *sname;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, create_link = 0;

    /* Step 1: get the stat info of 'from' file */
    path = dirname(dup);
    name = basename(dup2);
    sname = strdup(name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat_ext(puuid, psalt, 0, INDEX_SUPERFICIAL |
                              INDEX_ITE_ACTIVE, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else {
        /* rename a directory, it is ok */
        if (!S_ISDIR(hs.mdu.mode) ||
            hs.puuid == hmi.root_uuid) {
            hvfs_err(xnet, "directory or not-directory, it is a question!\n");
            err = -EPERM;
            goto out;
        }
    }

    /* if the source file has been opened, we should use the latest hstat info
     * cached in it */
    {
        struct bhhead *bhh = __odc_lookup(hs.uuid);
        
        if (bhh) {
            hs = bhh->hs;
            hs.name = name;
            /* if the 'from' file is dirty, we should sync it */
            if (bhh->flag & BH_DIRTY) {
                __bh_sync(bhh);
            }
            __put_bhhead(bhh);
        }
    }

    if (hs.mdu.flags & HVFS_MDU_IF_LINKT) {
        /* this is a link target, just copy it to the new location */
        ls = *(struct link_source *)&hs.mdu;
        create_link = 1;
        saved_hs = hs;
    } else {
        /* for other types (file or dir), we increase the nlink and unlink
         * them */
        struct mu_column saved_mc;
        
        hs.name = name;
        hs.uuid = 0;
        saved_mc = hs.mc;
        err = __hvfs_linkadd(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file linkadd (SDT) on '%s' "
                     "failed w/ %d\n", name, err);
            goto out;
        }
        saved_hs = hs;

        /* for dir, the puuid and psalt is not always correct */
        saved_hs.puuid = puuid;
        saved_hs.psalt = psalt;
        saved_hs.mdu.nlink -= 1;
        saved_hs.mc = saved_mc;

        if (!S_ISDIR(saved_hs.mdu.mode) && saved_hs.mdu.nlink > 1) {
            /* we are a link source, somebody refer to me, we should pretend
             * to be a link target? */
            create_link = 1;
            ls.flags = 0;
            ls.uid = hs.mdu.uid;
            ls.gid = hs.mdu.gid;
            ls.mode = hs.mdu.mode;
            ls.nlink = hs.mdu.nlink;
            ls.s_puuid = hs.puuid;
            ls.s_psalt = hs.psalt;
            ls.s_uuid = hs.uuid;
            ls.s_hash = hs.hash;
        }
    }

    /* cleanup */
    xfree(dup);
    xfree(dup2);
    xfree(spath);

    /* do new create now */
    dup = strdup(to);
    dup2 = strdup(to);
    puuid = hmi.root_uuid;
    psalt = hmi.root_salt;

    path = dirname(dup);
    name = basename(dup2);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit2;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out_rollback;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit2:
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* final stat on target */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat_ext(puuid, psalt, 0, INDEX_SUPERFICIAL |
                              INDEX_ITE_ACTIVE, &hs);
        if (err == -ENOENT) {
            /* it is ok to continue */
        } else if (err) {
            hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                     name, err);
            goto out_rollback;
        } else {
            /* target file or directory do exist */
            if (S_ISDIR(hs.mdu.mode)) {
                struct hstat tmp_hs;
                u64 duuid, dsalt;
                
                if (!S_ISDIR(saved_hs.mdu.mode)) {
                    err = -EISDIR;
                    goto out_rollback;
                }
                /* stat GDT to get the salt value */
                duuid = hs.uuid;
                tmp_hs = hs;
                err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &tmp_hs);
                if (err) {
                    hvfs_err(xnet, "do last dir stat (GDT) on '%s'"
                             " failed w/ %d\n",
                             name, err);
                    goto out_rollback;
                }
                dsalt = tmp_hs.ssalt;
                
                /* check if it is empty */
                if (__hvfs_is_empty_dir(duuid, dsalt, &hs)) {
                    /* FIXME: delete the directory now, only SDT entry. SAVED
                     * it to deleted_hs */
                    deleted_hs = hs;
                    err = __hvfs_unlink(puuid, psalt, &hs);
                    if (err) {
                        hvfs_err(xnet, "do internal unlink (SDT) "
                                 "on uuid<%lx,%lx> failed w/ %d\n",
                                 hs.uuid, hs.hash, err);
                        goto out_rollback;
                    }
                } else {
                    err = -ENOTEMPTY;
                    goto out_rollback;
                }
            } else {
                if (S_ISDIR(saved_hs.mdu.mode)) {
                    err = -ENOTDIR;
                    goto out_rollback;
                }
                /* FIXME: delete the file now */
                deleted_hs = hs;
                err = __hvfs_unlink(puuid, psalt, &hs);
                if (err) {
                    hvfs_err(xnet, "do internal unlink (SDT) on "
                             "uuid<%lx,%lx> failed w/ %d\n",
                             hs.uuid, hs.hash, err);
                    goto out_rollback;
                }
            }
        }
    } else {
        /* this means the target is a directory and do exist */
        if (S_ISDIR(hs.mdu.mode)) {
            /* check if it is empty */
            if (__hvfs_is_empty_dir(puuid, psalt, &hs)) {
                /* FIXME: delete the directory now, only SDT entry. SAVED it
                 * to deleted_hs */
                deleted_hs = hs;
                err = __hvfs_unlink(puuid, psalt, &hs);
                if (err) {
                    hvfs_err(xnet, "do internal unlink (SDT) on "
                             "uuid<%lx,%lx> failed w/ %d\n",
                             hs.uuid, hs.hash, err);
                    goto out_rollback;
                }
            } else {
                err = -ENOTEMPTY;
                goto out_rollback;
            }
        } else {
            hvfs_err(xnet, "directory or not-directory, it is a question\n");
            goto out_rollback;
        }
    }
    
    hs.name = name;
    hs.uuid = 0;
    if (create_link) {
        err = __hvfs_create(puuid, psalt, &hs, INDEX_CREATE_LINK,
                            (struct mdu_update *)&ls);
        if (err) {
            hvfs_err(xnet, "do internal create link (SDT) on '%s' "
                     "failed w/ %d\n", name, err);
            goto out_rollback2;
        }
    } else {
        hs.uuid = saved_hs.uuid;
        err = __hvfs_create(puuid, psalt, &hs, INDEX_CREATE_COPY,
                            (struct mdu_update *)&saved_hs.mdu);
        if (err) {
            hvfs_err(xnet, "do internal create link (SDT) on '%s' "
                     "failed w/ %d\n", name, err);
            goto out_rollback2;
        }

        /* update the column info */
        if (!S_ISDIR(saved_hs.mdu.mode)) {
            struct mdu_update mu = {
                .valid = MU_COLUMN,
                .column_no = 1,
            };
            hs.mc = saved_hs.mc;
            
            err = __hvfs_update(puuid, psalt, &hs, &mu);
            if (err) {
                hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                         name, err);
                goto out_rollback3;
            }
        }
        /* if the target file has been opened, we should update the ODC
         * cached info */
        {
            struct bhhead *bhh = __odc_lookup(hs.uuid);
            
            if (bhh) {
                bhh->hs.puuid = puuid;
                bhh->hs.psalt = psalt;
                /* new name means a new hash value */
                bhh->hs.hash = hs.hash;
                __put_bhhead(bhh);
            }
        }

        /* revert the linkadd operation for the source file */
        {
            u64 saved_psalt = saved_hs.psalt;
            
            err = __hvfs_linkadd(saved_hs.puuid, saved_hs.psalt, -1, &saved_hs);
            if (err) {
                hvfs_err(xnet, "do internal linkadd -1 on uuid<%lx,%lx> "
                         "failed w/ %d\n",
                         saved_hs.uuid, saved_hs.hash, err);
                /* should we ignore this error? */
                goto out_rollback3;
            }
            saved_hs.psalt = saved_psalt;
        }
    }
    /* unlink the old file or directory now */
    err = __hvfs_unlink_ext(saved_hs.puuid, saved_hs.psalt, INDEX_SUPERFICIAL |
                            INDEX_ITE_ACTIVE, 
                            &saved_hs);
    if (err) {
        hvfs_err(xnet, "do internal unlink (SDT) on uuid<%lx,%lx> "
                 "failed w/ %d\n",
                 saved_hs.uuid, saved_hs.hash, err);
        goto out_rollback4;
    }

    /* FIXME: remove the deleted_hs's GDT entry */
    if (S_ISDIR(deleted_hs.mdu.mode)) {
        /* for GDT operations, set hash to ZERO */
        deleted_hs.hash = 0;
        err = __hvfs_unlink(deleted_hs.puuid, deleted_hs.psalt,
                            &deleted_hs);
        if (err) {
            hvfs_err(xnet, "do internal unlink (GDT) on uuid<%lx,%lx> "
                     "failed w/ %d\n",
                     deleted_hs.uuid, deleted_hs.hash, err);
            /* ignore this error */
        }
    }

    hvfs_err(xnet, "rename from %s(%lx,%lx) to %s(%lx,%lx)\n",
             from, saved_hs.uuid, saved_hs.hash, to, hs.uuid, hs.hash);
out:
    xfree(sname);
    xfree(dup);
    xfree(dup2);
    xfree(spath);

    return err;
out_rollback4:
    /* reverse the linkadd -1 */
    create_link = 1;
out_rollback3:
    /* remove the new created entry */
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_unlink(puuid, psalt, &hs);
    if (err) {
        hvfs_err(xnet, "do internal unlink on '%s' failed w/ %d\n",
                 name, err);
    }
out_rollback2:
    /* re-create the deleted_hs SDT entry */
    if (S_ISDIR(deleted_hs.mdu.mode)) {
        deleted_hs.name = name;
        err = __hvfs_create(deleted_hs.puuid, deleted_hs.psalt, &deleted_hs,
                            INDEX_CREATE_COPY,
                            (struct mdu_update *)&deleted_hs.mdu);
        if (err) {
            hvfs_err(xnet, "do internal re-create on '%s' failed w/ %d\n",
                     name, err);
        }
    }
out_rollback:
    /* reverse-linkadd for saved_hs */
    if (!create_link) {
        err = __hvfs_linkadd(saved_hs.puuid, saved_hs.psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file linkadd (SDT) on uuid<%lx,%lx> "
                     "failed w/ %d\n",
                     saved_hs.uuid, saved_hs.hash, err);
        }
    }
    goto out;
}

static int hvfs_link(const char *from, const char *to)
{
    struct link_source ls;
    struct hstat hs;
    char *dup = strdup(from), *dup2 = strdup(from), 
        *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    /* Step 1: get the stat info of 'from' file */
    path = dirname(dup);
    name = basename(dup2);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_linkadd(puuid, psalt, 0, &hs);
        if (err == -EACCES) {
            /* we should stat hard and retry! */
            hs.uuid = 0;
            err = __hvfs_stat(puuid, psalt, 0, &hs);
            if (err) {
                hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
            err = __hvfs_linkadd(hs.puuid, hs.psalt, 0, &hs);
            if (err) {
                hvfs_err(xnet, "do internal file linkadd (SDT) on '%s'"
                         " failed w/ %d\n", name, err);
                goto out;
            }
        } else if (err) {
            hvfs_err(xnet, "do internal file linkadd (SDT) on '%s'"
                     " failed w/ %d\n", name, err);
            goto out;
        }
        if (S_ISDIR(hs.mdu.mode)) {
            hvfs_err(xnet, "hard link on directory is not allowed\n");
            err = -EPERM;
            goto out;
        }
    } else {
        hvfs_err(xnet, "hard link on directory is not allowed\n");
        err = -EPERM;
        goto out;
    }

    ls.flags = 0;
    ls.uid = hs.mdu.uid;
    ls.gid = hs.mdu.gid;
    ls.mode = hs.mdu.mode;
    ls.nlink = hs.mdu.nlink;
    ls.s_puuid = hs.puuid;
    ls.s_psalt = hs.psalt;
    ls.s_uuid = hs.uuid;
    ls.s_hash = hs.hash;

    /* cleanup */
    xfree(dup);
    xfree(dup2);
    xfree(spath);

    /* Step 2: construct the new LS entry */
    dup = strdup(to);
    dup2 = strdup(to);
    puuid = hmi.root_uuid;
    psalt = hmi.root_salt;
    
    path = dirname(dup);
    name = basename(dup2);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit2;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit2:
    /* create the file or dir in the parent directory now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        hvfs_err(xnet, "Create zero-length named file or root directory?\n");
        err = -EINVAL;
        goto out;
    }
    
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_create(puuid, psalt, &hs, INDEX_CREATE_LINK, 
                        (struct mdu_update *)&ls);
    if (err) {
        hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

out:
    xfree(dup);
    xfree(dup2);
    xfree(spath);
    
    return err;
}

static int hvfs_chmod(const char *pathname, mode_t mode)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }
    
    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    mu.valid = MU_MODE;
    mu.mode = mode;

    /* finally, do update now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        /* update the final directory by uuid */
        hs.name = NULL;
        hs.hash = 0;
        err = __hvfs_update(hmi.gdt_uuid, hmi.gdt_salt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else {
        /* update the final file by name */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_update(puuid, psalt, &hs, &mu);
        if (err == -EACCES) {
            hs.uuid = 0;
            err = __hvfs_stat(puuid, psalt, 0, &hs);
            if (err) {
                hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
            err = __hvfs_update(hs.puuid, hs.psalt, &hs, &mu);
            if (err) {
                hvfs_err(xnet, "do internal update on uuid<%lx,%lx> "
                         "failed w/ %d\n",
                         hs.uuid, hs.hash, err);
                goto out;
            }
        } else if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;    
}

static int hvfs_chown(const char *pathname, uid_t uid, gid_t gid)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;
    
    mu.valid = MU_UID | MU_GID;
    mu.uid = uid;
    mu.gid = gid;

    /* finally, do update now */
    if (!name || strlen(name) == 0 || strcmp(name, "/") == 0) {
        /* update the final directory by uuid */
        hs.name = NULL;
        hs.hash = 0;
        err = __hvfs_update(hmi.gdt_uuid, hmi.gdt_salt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else {
        /* update the final file by name */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_update(puuid, psalt, &hs, &mu);
        if (err == -EACCES) {
            hs.uuid = 0;
            err = __hvfs_stat(puuid, psalt, 0, &hs);
            if (err) {
                hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
            err = __hvfs_update(hs.puuid, hs.psalt, &hs, &mu);
            if (err) {
                hvfs_err(xnet, "do internal update on uuid<%lx,%lx> "
                         "failed w/ %d\n",
                         hs.uuid, hs.hash, err);
                goto out;
            }
        } else if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

out:
    xfree(dup);
    
    return err;    
}

static int hvfs_truncate(const char *pathname, off_t size)
{
    struct hstat hs = {0,};
    struct mdu_update mu = {.valid = 0,};
    char *dup = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    ssize_t rlen;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        saved_psalt = psalt;
        saved_puuid = puuid;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        saved_hash = hs.hash;
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* lookup the file in the parent directory now */
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else {
        hvfs_err(xnet, "truncate directory is not allowed\n");
        err = -EINVAL;
        goto out;
    }
    if (S_ISDIR(hs.mdu.mode)) {
        hvfs_err(xnet, "truncate directory is not allowed\n");
        err = -EINVAL;
        goto out;
    }

    /* check the file length now */
    if (size > hs.mdu.size) {
        void *data;

        data = xmalloc(size);
        if (!data) {
            hvfs_err(xnet, "Expanding the file content w/ xmalloc failed\n");
            err = -ENOMEM;
            goto out;
        }

        rlen = __hvfs_fread(&hs, 0 /* column is ZERO */, &data, &hs.mc.c,
                            0, hs.mdu.size);
        if (rlen < 0) {
            hvfs_err(xnet, "do internal fread on '%s' failed w/ %ld\n",
                     name, rlen);
            err = rlen;
            goto local_out;
        }
        memset(data + hs.mdu.size, 0, size - hs.mdu.size);

        /* calculate the new itbid */
        {
            struct dhe *e;
            
            e = mds_dh_search(&hmo.dh, puuid);
            if (IS_ERR(e)) {
                hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
                err = PTR_ERR(e);
                goto local_out;
            }
            hs.hash = mds_get_itbid(e, hs.hash);
            mds_dh_put(e);
        }

        err = __hvfs_fwrite(&hs, 0 /* column is ZERO */, 0, data, size, 
                            &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on '%s' failed w/ %d\n",
                     name, err);
            goto local_out;
        }
        mu.valid = MU_COLUMN;
        mu.column_no = 1;
    local_out:
        xfree(data);
        if (err < 0)
            goto out;
    } else if (size == hs.mdu.size) {
        goto out;
    }
    /* finally update the metadata */
    mu.valid |= MU_SIZE | MU_COLUMN;
    mu.size = size;
    mu.column_no = 1;
    hs.mc.c.len = size;
    hs.name = name;
    hs.uuid = 0;
    /* use INDEX_BY_UUID to got the entry */
    err = __hvfs_update(puuid, psalt, &hs, &mu);
    if (err == -EACCES) {
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        err = __hvfs_update(puuid, psalt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on uuid<%lx,%lx> "
                     "failed w/ %d\n",
                     hs.uuid, hs.hash, err);
            goto out;
        }
    } else if (err) {
        hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
out:
    xfree(dup);

    return err;
}

static int hvfs_ftruncate(const char *pathname, off_t size, 
                          struct fuse_file_info *fi)
{
    struct hstat hs;
    struct mdu_update mu = {.valid = 0,};
    struct bhhead *bhh = (struct bhhead *)fi->fh;
    u64 saved_hash = 0;
    ssize_t rlen;
    int err = 0;

    if (unlikely(!bhh))
        return -EBADF;

    if (unlikely(bhh->flag & BH_CONFIG)) {
        return -EINVAL;
    }

    hs = bhh->hs;

    /* check the file length now */
    if (size > hs.mdu.size) {
        void *data;

        data = xmalloc(size);
        if (!data) {
            hvfs_err(xnet, "Expanding the file content w/ xmalloc failed\n");
            err = -ENOMEM;
            goto out;
        }

        rlen = __hvfs_fread(&hs, 0 /* column is ZERO */, &data, &hs.mc.c,
                            0, hs.mdu.size);
        if (rlen < 0) {
            hvfs_err(xnet, "do internal fread on uuid<%lx,%lx> "
                     "failed w/ %ld\n",
                     hs.uuid, hs.hash, rlen);
            err = rlen;
            goto local_out;
        }
        memset(data + hs.mdu.size, 0, size - hs.mdu.size);

        /* calculate the new itbid */
        {
            struct dhe *e;
            
            e = mds_dh_search(&hmo.dh, hs.puuid);
            if (IS_ERR(e)) {
                hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
                err = PTR_ERR(e);
                goto local_out;
            }
            saved_hash = hs.hash;
            hs.hash = mds_get_itbid(e, hs.hash);
            mds_dh_put(e);
        }

        err = __hvfs_fwrite(&hs, 0 /* column is ZERO */, 0, data, size, 
                            &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on uuid<%lx,%lx> failed w/ %d\n",
                     hs.uuid, hs.hash, err);
            goto local_out;
        }
        mu.valid = MU_COLUMN;
        mu.column_no = 1;
    local_out:
        xfree(data);
        if (err < 0)
            goto out;
    } else if (size == hs.mdu.size) {
        goto out;
    } else {
        saved_hash = hs.hash;
    }
    /* finally update the metadata */
    mu.valid |= MU_SIZE | MU_COLUMN;
    mu.size = size;
    mu.column_no = 1;
    hs.mc.c.len = size;
    hs.hash = saved_hash;
    /* use INDEX_BY_UUID to got the entry */
    err = __hvfs_update(hs.puuid, hs.psalt, &hs, &mu);
    if (err == -EACCES) {
        hs.uuid = 0;
        err = __hvfs_stat(hs.puuid, hs.psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat on uuid<%lx,%lx> failed w/ %d\n",
                     hs.uuid, hs.hash, err);
            goto out;
        }
        err = __hvfs_update(hs.puuid, hs.psalt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on uuid<%lx,%lx> "
                     "failed w/ %d\n",
                     hs.uuid, hs.hash, err);
            goto out;
        }
    } else if (err) {
        hvfs_err(xnet, "do internal update on uuid<%lx,%lx> failed w/ %d\n",
                 hs.uuid, hs.hash, err);
        goto out;
    }
out:

    return err;
}

static int hvfs_utime(const char *pathname, struct utimbuf *buf)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    
    mu.valid = MU_ATIME | MU_MTIME;
    mu.atime = buf->actime;
    mu.mtime = buf->modtime;

    /* finally, do update now */
    if (strlen(name) > 0) {
        /* update the final file by name */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_update(puuid, psalt, &hs, &mu);
        if (err == -EACCES) {
            /* this means that we have hit a link target, stat harder! */
            hs.uuid = 0;
            err = __hvfs_stat(puuid, psalt, 0, &hs);
            if (err) {
                hvfs_err(xnet, "do internal stat on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
            err = __hvfs_update(hs.puuid, hs.psalt, &hs, &mu);
            if (err) {
                hvfs_err(xnet, "do internal update on uuid<%lx,%lx> "
                         "failed w/ %d\n",
                         hs.uuid, hs.hash, err);
                goto out;
            }
        } else if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else {
        /* update the final directory by uuid */
        hs.name = NULL;
        hs.hash = 0;
        err = __hvfs_update(hmi.gdt_uuid, hmi.gdt_salt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;    
}

static int hvfs_open(const char *pathname, struct fuse_file_info *fi)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    /* check if it is the config file */
    if (hvfs_config_open(name, fi))
        goto out;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }
    
    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* eh, we have to lookup this file now. Otherwise, what we want to lookup
     * is the last directory, just return a result string now */
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    if (S_ISDIR(hs.mdu.mode)) {
        err = -EISDIR;
        goto out;
    }

    fi->fh = (u64)__get_bhhead(&hs);
    /* we should restat the file to detect any new file syncs */
#ifdef FUSE_SAFE_OPEN
    {
        struct bhhead *bhh = (struct bhhead *)fi->fh;

        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file 2rd stat (SDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }
        if (MDU_VERSION_COMPARE(hs.mdu.version, bhh->hs.mdu.version)) {
            bhh->hs.mdu = hs.mdu;
            bhh->hs.mc = hs.mc;
        }
    }
#endif

out:
    xfree(dup);
    xfree(spath);

    return err;
}

static int hvfs_read(const char *pathname, char *buf, size_t size, 
                     off_t offset, struct fuse_file_info *fi)
{
    struct hstat hs;
    struct bhhead *bhh = (struct bhhead *)fi->fh;
    ssize_t rlen;
    int err = 0, bytes = 0;

    /* is config_read() ? */
    if (unlikely(bhh->flag & BH_CONFIG)) {
        return hvfs_config_read((struct pfs_config_mgr *)
                                bhh->ptr, buf, size, offset);
    }

    hs = bhh->hs;

    err = __bh_read(bhh, buf, offset, size);
    if (err == -EFBIG) {
        /* read in the data now */
        rlen = __hvfs_fread(&hs, 0 /* column is ZERO */, (void **)&buf, 
                            &hs.mc.c, offset, size);
        if (rlen < 0) {
            if (rlen == -EFBIG) {
                /* translate EFBIG to OK */
                err = 0;
            } else {
                hvfs_err(xnet, "do internal fread on '%s' failed w/ %ld\n",
                         pathname, rlen);
                err = rlen;
            }
            goto out;
        }
        bytes = rlen;
        err = __bh_fill(&hs, 0, &hs.mc.c, bhh, buf, offset, rlen);
        if (err < 0) {
            hvfs_err(xnet, "fill the buffer cache failed w/ %d\n",
                     err);
            goto out;
        }
        /* restore the bytes */
        err = bytes;
    } else if (err < 0) {
        hvfs_err(xnet, "buffer cache read '%s' failed w/ %d\n", 
                 pathname, err);
        goto out;
    }
    /* return the # of bytes we read */
    if (!pfs_fuse_mgr.noatime && err > 0) {
        /* update the atime now */
        struct mdu_update mu;
        struct timeval tv;
        u64 puuid = hs.puuid, psalt = hs.psalt;
        int __err;

        gettimeofday(&tv, NULL);

        mu.valid = MU_ATIME;
        mu.atime = tv.tv_sec;
        __err = __hvfs_update(puuid, psalt, &hs, &mu);
        if (__err == -EACCES) {
            /* this means that we have hit a link target, it should not
             * happen! */
            hvfs_err(xnet, "internal fault: in open() we stat hard, but "
                     "the result lost?\n");
        } else if (__err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     pathname, err);
            goto out;
        }
    }
    
out:
    return err;
}

static int hvfs_sync_write(const char *pathname, const char *buf, 
                           size_t size, off_t offset, 
                           struct fuse_file_info *fi)
{
    struct hstat hs;
    struct bhhead *bhh = (struct bhhead *)fi->fh;
    void *data = NULL;
    u64 len, hash;
    ssize_t rlen;
    int err = 0, flag = 0;

    if (unlikely(bhh->flag & BH_CONFIG))
        return -EINVAL;

    hs = bhh->hs;

    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hs.puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        hash = hs.hash;
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }

    /* calculate whether we should read the original data content */
    if (offset + size > hs.mc.c.len) {
        /* well, we need buffer expanding */
        data = xmalloc(offset + size);
        if (!data) {
            hvfs_err(xnet, "xmalloc() buffer failed\n");
            err = -ENOMEM;
            goto out;
        }
        len = offset + size;
    } else {
        /* ok, we read the original buffer */
        len = hs.mc.c.len;
    }
    rlen = __hvfs_fread(&hs, 0 /* ZERO */, &data, &hs.mc.c, 0, len);
    if (rlen < 0) {
        hvfs_err(xnet, "read in the original data content failed w/ %ld\n",
                 rlen);
        err = rlen;
        goto out;
    }

    /* prepare the write out buffer */
    memcpy(data + offset, buf, size);
    
    /* write out the data now */
    err = __hvfs_fwrite(&hs, 0 /* ZERO */, flag, data, len, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fwrite on '%s' failed w/ %d\n",
                 pathname, err);
        goto out;
    }

    /* update the file attributes */
    {
        struct mdu_update *mu;
        struct mu_column *mc;
        u32 redo_flag = 0;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mc = (void *)mu + sizeof(*mu);
        mu->valid = MU_COLUMN | MU_SIZE;
        if (flag) {
            mu->valid |= MU_FLAG_ADD;
            if (flag & SCD_PROXY)
                mu->flags |= HVFS_MDU_IF_PROXY;
            else {
                redo_flag |= HVFS_MDU_IF_PROXY;
            }
            if (flag & SCD_LZO) {
                if (len != hs.mc.c.len)
                    mu->flags |= HVFS_MDU_IF_LZO;
            } else {
                redo_flag |= HVFS_MDU_IF_LZO;
            }
        } else {
            mu->valid |= MU_FLAG_CLR;
            mu->flags |= (HVFS_MDU_IF_PROXY | HVFS_MDU_IF_LZO);
        }
        mu->size = len;
        mu->column_no = 1;
        mc->cno = 0;            /* zero column */
        mc->c = hs.mc.c;

    retry:
        hs.hash = hash;
        err = __hvfs_update(hs.puuid, hs.psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     pathname, err);
            xfree(mu);
            goto out;
        }
        if (redo_flag) {
            mu->valid = MU_FLAG_CLR;
            mu->flags = redo_flag;
            redo_flag = 0;
            goto retry;
        }
        xfree(mu);
    }

    err = size;
out:
    xfree(data);
    
    return err;
}

static int hvfs_cached_write(const char *pathname, const char *buf,
                             size_t size, off_t offset,
                             struct fuse_file_info *fi)
{
    struct hstat hs;
    struct bhhead *bhh = (struct bhhead *)fi->fh;
    int err = 0;

    if (unlikely(bhh->flag & BH_CONFIG))
        return -EINVAL;

    hs = bhh->hs;
    __set_bhh_dirty(bhh);
    if (offset + size > bhh->asize)
        bhh->asize = offset + size;

    err = __bh_fill(&hs, 0, &hs.mc.c, bhh, (void *)buf, offset, size);
    if (err < 0) {
        hvfs_err(xnet, "fill the buffer cache failed w/ %d\n",
                 err);
        goto out;
    }
    err = size;

out:
    return err;
}

static int hvfs_write(const char *pathname, const char *buf,
                      size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    if (pfs_fuse_mgr.sync_write) {
        return hvfs_sync_write(pathname, buf, size, offset, fi);
    } else {
        return hvfs_cached_write(pathname, buf, size, offset, fi);
    }
}

static int hvfs_statfs_plus(const char *pathname, struct statvfs *stbuf)
{
    struct statfs s;
    struct xnet_group *xg = NULL;
    int err = 0, i;

    memset(&s, 0, sizeof(s));
    
    xg = cli_get_active_site(hmo.chring[CH_RING_MDS]);
    if (!xg) {
        hvfs_err(xnet, "cli_get_active_site() failed\n");
        err = -ENOMEM;
        goto out;
    }

    for (i = 0; i < xg->asize; i++) {
        err = __hvfs_statfs(&s, xg->sites[i].site_id);
        if (err) {
            hvfs_err(xnet, "Statfs from %lx failed /w %d\n",
                     xg->sites[i].site_id, err);
        }
    }
    xfree(xg);
    
    xg = cli_get_active_site(hmo.chring[CH_RING_MDSL]);
    if (!xg) {
        hvfs_err(xnet, "cli_get_active_site() failed\n");
        err = -ENOMEM;
        goto out;
    }

    for (i = 0; i < xg->asize; i++) {
        err = __hvfs_statfs(&s, xg->sites[i].site_id);
        if (err) {
            hvfs_err(xnet, "Statfs from %lx failed /w %d\n",
                     xg->sites[i].site_id, err);
        }
    }
    xfree(xg);

    s.f_type = HVFS_SUPER_MAGIC;
    s.f_namelen = HVFS_MAX_NAME_LEN;
    
    /* construct the result buffer */
    stbuf->f_bsize = s.f_bsize;
    stbuf->f_frsize = 4096;
    stbuf->f_blocks = s.f_blocks;
    stbuf->f_bfree = s.f_bfree;
    stbuf->f_bavail = s.f_bavail;
    stbuf->f_files = s.f_files;
    stbuf->f_ffree = s.f_ffree;
    stbuf->f_fsid = hmo.fsid;
    stbuf->f_flag = ST_NOSUID;
    stbuf->f_namemax = s.f_namelen;
    
out:
    return err;
}

static int hvfs_release(const char *pathname, struct fuse_file_info *fi)
{
    struct bhhead *bhh = (struct bhhead *)fi->fh;

    if (unlikely(bhh->flag & BH_CONFIG)) {
        hvfs_config_release((struct pfs_config_mgr *)bhh->ptr);
        xfree(bhh);

        return 0;
    }

    if (bhh->flag & BH_DIRTY) {
        __bh_sync(bhh);
    }

    __put_bhhead(bhh);

    return 0;
}

typedef struct __hvfs_dir
{
    u64 itbid;                  /* current no. of this ITB */
    u64 goffset, loffset;
    int csize;                  /* current size of this ITB */
    struct dentry_info *di;
} hvfs_dir_t;

static inline
u64 SELECT_SITE(u64 itbid, u64 psalt, int type, u32 *vid)
{
    struct chp *p;

    p = ring_get_point(itbid, psalt, hmo.chring[type]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -1UL;
    }
    *vid = p->vid;
    return p->site_id;
}

/* Note: attr namespace of pomegranate file system: prefix => pfs
 *
 * Format: pfs.class.column.op
 *
 * There are mainly two classes: native and tag. Class native is used to
 * access raw column data, while class tag is used to access tag orient
 * attributes.
 *
 * Table:
 *        class    column    op      [other region]
 *        native    [0-5]    read    .offset.len
 *                           write   [.len]
 *                           lookup  {return column info}
 *
 *        dt        ignore   create  .pfs_path.type.where.priority.local_path
 *                           cat     .pfs_path
 *
 *        branch    ignore   create  .name.tag.level.op_list
 *                           delete  .name
 *
 *        tag       [0-5]    set     .B.kv_list <key=value;key2=value2;...>
 *                           delete  .B.key
 *                           update  .B.key.value
 *                           test    .B.key
 *                           search  .B.dbname.prefix.search_expr 
 *                                            {trigger BDB search}
 *
 * DT can only be attached to a directory
 *
 * B is a position holder for Branch descriptor.
 *
 * B = B[:branch_name[:key1[:key2:....]]] {key1, key2 is a list of tags we
 *                                         should index}
 *
 * Avaliable columns are:
 * for file => 0 -> XTABLE_INDIRECT_COLUMN
 * for dir  => HVFS_DIR_FF_COLUMN -> XTABLE_INDIRECT_COLUMN
 */
#define HVFS_XATTR_CLASS_NATIVE         0
#define HVFS_XATTR_CLASS_DT             1
#define HVFS_XATTR_CLASS_BRANCH         2
#define HVFS_XATTR_CLASS_TAG            3

#define HVFS_XATTR_NATIVE_READ          0
#define HVFS_XATTR_NATIVE_WRITE         1
#define HVFS_XATTR_NATIVE_LOOKUP        2

#define HVFS_XATTR_DT_CREATE            0
#define HVFS_XATTR_DT_CAT               1

#define HVFS_XATTR_BRANCH_CREATE        0
#define HVFS_XATTR_BRANCH_DELETE        1

#define HVFS_XATTR_TAG_SET              0
#define HVFS_XATTR_TAG_DELETE           1
#define HVFS_XATTR_TAG_UPDATE           2
#define HVFS_XATTR_TAG_TEST             3
#define HVFS_XATTR_TAG_SEARCH           4

/* get next xattr token */
#define HVFS_XATTR_NT(key, p, s, err, out) do { \
        char *__in = NULL;                      \
        if (!p) {                               \
            __in = key;                         \
        }                                       \
        p = strtok_r(__in, ". ", (s));          \
        if (!p) {                               \
            err = -EINVAL;                      \
            goto out;                           \
        }                                       \
    } while (0)

/* get next B token */
#define HVFS_B_NT(key, p, s, err, out) do {     \
        char *__in = NULL;                      \
        if (!p) {                               \
            __in = key;                         \
        }                                       \
        p = strtok_r(__in, ": ", (s));          \
        if (!p) {                               \
            err = -EINVAL;                      \
            goto out;                           \
        }                                       \
    } while (0)

/* get next KVL token */
#define HVFS_KVL_NT(key, p, s, err, out) do {   \
        char *__in = NULL;                      \
        if (!p) {                               \
            __in = key;                         \
        }                                       \
        p = strtok_r(__in, "; ", (s));          \
        if (!p) {                               \
            err = -EINVAL;                      \
            goto out;                           \
        }                                       \
    } while (0)

/* Convention:
 *
 * Return value: >0 => size; <0 => error: =0 => ok
 */
static
ssize_t __hvfs_xattr_native_read(char *key, char *p, char **s, 
                                 struct hstat *hs, int column, 
                                 char *value, size_t size)
{
    off_t offset;
    ssize_t len, rlen;
    ssize_t err = 0;
    
    /* Note: for native read, we have to parse the offset and length from key
     * string */

    /* get offset */
    HVFS_XATTR_NT(key, p, s, err, out);
    offset = atol(p);

    /* get length */
    HVFS_XATTR_NT(key, p, s, err, out);
    len = atol(p);

    /* check column size */
    ASSERT(column == hs->mc.cno, xnet);
    if (hs->mc.c.len < len) {
        len = hs->mc.c.len;
    }

    /* sanity check */
    if (!size) {
        return len;
    } else if (size < len) {
        return -ERANGE;
    }

    /* ok, issue a read request to MDSL */
    rlen = __hvfs_fread(hs, column, (void **)&p, &hs->mc.c, offset, len);
    if (rlen < 0) {
        hvfs_err(xnet, "__hvfs_fread() offset %ld len %ld failed w/ %ld\n",
                 offset, len, rlen);
        err = rlen;
        goto out;
    }

    err = rlen;
    
out:
    return err;
}

static
ssize_t __hvfs_xattr_native_write(char *key, char *p, char **s,
                                  struct hstat *hs, int column,
                                  char *value, size_t size)
{
    ssize_t len = size;
    u64 hash;
    ssize_t err = 0;

    /* Note: for native write, we just write the value buffer to MDSL */

    /* get optional length */
    HVFS_XATTR_NT(key, p, s, err, default_len);
    len = atol(p);
default_len:
    if (len > size)
        len = size;
    if (!len)
        return 0;
    
    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hs->puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        hash = hs->hash;
        hs->hash = mds_get_itbid(e, hs->hash);
        mds_dh_put(e);
    }

    if (value) {
        err = __hvfs_fwrite(hs, column, 0, value, len, &hs->mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on uuid'%lx,%lx' "
                     "failed w/ %ld\n",
                     hs->uuid, hash, err);
            goto out;
        }
    } else {
        hvfs_err(xnet, "No data region found\n");
        err = -EINVAL;
        goto out;
    }

    /* update the file attributes */
    {
        struct mdu_update mu;

        mu.valid = MU_COLUMN;
        mu.column_no = 1;
        hs->mc.cno = column;
        hs->hash = hash;

        err = __hvfs_update(hs->puuid, hs->psalt, hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on ino<%lx,%lx> "
                     "failed w/ %ld\n",
                     hs->uuid, hs->hash, err);
            goto out;
        }
    }
    err = len;

out:
    return err;
}

/* Return a buffer as:
 *
 * ".stored_itbid.length.offset"
 */
static
ssize_t __hvfs_xattr_native_lookup(char *key, char *p, char **s,
                                   struct hstat *hs, int column,
                                   char *value, size_t size)
{
    char buf[256];
    ssize_t err = 0;
    int len;

    /* check column size */
    ASSERT(column == hs->mc.cno, xnet);

    /* pack the result to buffer */
    len = snprintf(buf, 256, "%ld.%ld.%ld", hs->mc.c.stored_itbid,
                   hs->mc.c.len, hs->mc.c.offset);
    if (!size)
        return len;
    else if (size < len) {
        return -ERANGE;
    }

    memcpy(value, buf, len);
    err = len;

    return err;
}

/* tag_set() read in several other regions: B and KV list
 */
static
ssize_t __hvfs_xattr_tag_set(char *key, char *p, char **s,
                             struct hstat *hs, int column,
                             char *value, size_t size)
{
    ssize_t err = 0;
    char **B_kl = NULL, *B_name = NULL;
    u8 no_B = 0, B_index_all = 0;
    short kl_size = 0, kl_off = 0;

    /* get B */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* parse B */
    {
        char *b = NULL, *t;

        /* get header */
        HVFS_B_NT(p, b, &t, err, out);
        if (*b != 'B') {
            hvfs_err(xnet, "TAG add: Invalid B header '%s'\n", b);
            err = -EINVAL;
            goto out;
        }

        /* get name */
        HVFS_B_NT(p, b, &t, err, no_branch);
        B_name = strdup(b);

        /* get key list */
        do {
            HVFS_B_NT(p, b, &t, err, next_token);
            /* add this key to list, enlarge the array if needed */
            if (strcmp(b, "@all") == 0) {
                B_index_all = 1;
                goto next_token;
            }
            if (kl_off >= kl_size) {
                B_kl = xrealloc(B_kl, kl_size + 8);
                if (!B_kl) {
                    hvfs_err(xnet, "xrealloc() key list failed\n");
                    err = -ENOMEM;
                    goto out;
                }
                kl_size += 8;
            }
            B_kl[kl_off++] = strdup(b);
        } while (b);
        
    no_branch:
        no_B = 1;
    }
next_token:

    /* get kv_list */
    HVFS_XATTR_NT(key, p, s, err, out_free);

    /* write this kv_list to MDSL and update metadata */
    {
        u64 hash;
        
        /* calculate which itbid we should stored it in */
        {
            struct dhe *e;

            e = mds_dh_search(&hmo.dh, hs->puuid);
            if (IS_ERR(e)) {
                hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
                err = PTR_ERR(e);
                goto out;
            }
            hash = hs->hash;
            hs->hash = mds_get_itbid(e, hs->hash);
            mds_dh_put(e);
        }

        err = __hvfs_fwrite(hs, column, 0, p, strlen(p), &hs->mc.c);
        if (err) {
            hvfs_err(xnet, "do internal fwrite on uuid'%lx,%lx' "
                     "failed w/ %ld\n",
                     hs->uuid, hash, err);
            goto out_free;
        }

        /* update the file attributes */
        {
            struct mdu_update mu;
            
            mu.valid = MU_COLUMN;
            mu.column_no = 1;
            hs->mc.cno = column;
            hs->hash = hash;
            
            err = __hvfs_update(hs->puuid, hs->psalt, hs, &mu);
            if (err) {
                hvfs_err(xnet, "do internal update on ino<%lx,%lx> "
                         "failed w/ %ld\n",
                         hs->uuid, hs->hash, err);
                goto out_free;
            }
        }
    }

    /* send the selected key list to branch system */
    if (!no_B) {
        char primary_key[256];
        
        if (B_index_all) {
            /* index the whole kv list */
            snprintf(primary_key, 256, "+%lx::%lx:%lx", hs->puuid,
                     hs->uuid, hs->hash);
            err = branch_publish(hs->puuid, hs->uuid, B_name, primary_key,
                                 1, p, strlen(p));
            if (err) {
                hvfs_err(xnet, "publish kv_list '%s' to B'%s' failed w/ %ld",
                         p, B_name, err);
                goto out_free;
            }
        } else if (!kl_off) {
            /* no active kv pairs */
            goto out_free;
        } else {
            /* filter the kv list */
            char *kvl = alloca(strlen(p)), *k = NULL, *t = NULL;
            int offset = 0, i;

            do {
                HVFS_KVL_NT(p, k, &t, err, kvl_ok);
                for(i = 0; i < kl_off; i++) {
                    if (strcmp(k, B_kl[i]) == 0) {
                        /* match */
                        offset += sprintf(kvl + offset, "%s;", k);
                    }
                }
            } while (k);
        kvl_ok:
            if (offset > 0) {
                /* construct primary key */
                snprintf(primary_key, 256, "+%lx::%lx:%lx", hs->puuid, 
                         hs->uuid, hs->hash);
                err = branch_publish(hs->puuid, hs->uuid, B_name, primary_key,
                                     1, kvl, strlen(kvl));
                if (err) {
                    hvfs_err(xnet, "publish kv_list '%s' to B'%s' "
                             "failed w/ %ld\n",
                             kvl, B_name, err);
                    goto out_free;
                }
            }
        }
    }

out_free:
    if (kl_off) {
        while (kl_off >= 0) {
            xfree(B_kl[kl_off]);
            kl_off--;
        }
    }
    xfree(B_kl);
    
out:
    return err;
}

static
ssize_t __hvfs_xattr_tag_delete(char *key, char *p, char **s,
                                struct hstat *hs, int column,
                                char *value, size_t size)
{
    ssize_t err = 0;
    char *B_name = NULL;
    char *buf = NULL;
    u8 no_B = 0;

    /* get B */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* parse B */
    {
        char *b = NULL, *t;

        /* get header */
        HVFS_B_NT(p, b, &t, err, out);
        if (*b != 'B') {
            hvfs_err(xnet, "TAG del: Invalid B header '%s'\n", b);
            err = -EINVAL;
            goto out;
        }

        /* get name */
        HVFS_B_NT(p, b, &t, err, no_branch);
        B_name = strdup(b);
        goto next_token;

    no_branch:
        no_B = 1;
    }
next_token:

    /* get key */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* read in the column data */
    buf = xzalloc(hs->mc.c.len + 1);
    if (!buf) {
        hvfs_err(xnet, "xzalloc() column data buffer failed\n");
        goto out;
    }
    
    err = __hvfs_fread(hs, column, (void **)buf, &hs->mc.c, 0, 
                       hs->mc.c.len);
    if (err < 0) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld failed w/ %ld\n",
                 hs->mc.c.len, err);
        goto out;
    } else if (err != hs->mc.c.len) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld but return %ldB\n",
                 hs->mc.c.len, err);
        err = -EAGAIN;
        goto out;
    }

    /* remove the key */
    {
        char *f = NULL, *fe, needle[strlen(p) + 2];

        memset(needle, 0, sizeof(needle));
        sprintf(needle, "%s=", p);
        
        f = strstr(buf, needle);
        if (!f) {
            hvfs_err(xnet, "Find key'%s' in column data failed, no such key\n",
                     p);
            err = -ENOENT;
            goto out_free;
        }

        fe = f;
        while (*fe != ';') {
            if (fe >= buf + hs->mc.c.len)
                break;
            fe++;
        }

        memmove(f, fe, (buf + hs->mc.c.len - fe));

        /* write the data back to MDSL and update metadata */
        {
            u64 hash;
            
            /* calculate which itbid we should stored it in */
            {
                struct dhe *e;
                
                e = mds_dh_search(&hmo.dh, hs->puuid);
                if (IS_ERR(e)) {
                    hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", 
                             PTR_ERR(e));
                    err = PTR_ERR(e);
                    goto out;
                }
                hash = hs->hash;
                hs->hash = mds_get_itbid(e, hs->hash);
                mds_dh_put(e);
            }
            
            err = __hvfs_fwrite(hs, column, 0, buf, 
                                hs->mc.c.len - (fe - f), &hs->mc.c);
            if (err) {
                hvfs_err(xnet, "do internal fwrite on uuid'%lx,%lx' "
                         "failed w/ %ld\n",
                         hs->uuid, hash, err);
                goto out_free;
            }
            
            /* update the file attributes */
            {
                struct mdu_update mu;
                
                mu.valid = MU_COLUMN;
                mu.column_no = 1;
                hs->mc.cno = column;
                hs->hash = hash;
                
                err = __hvfs_update(hs->puuid, hs->psalt, hs, &mu);
                if (err) {
                    hvfs_err(xnet, "do internal update on ino<%lx,%lx> "
                             "failed w/ %ld\n",
                             hs->uuid, hs->hash, err);
                    goto out_free;
                }
            }
        }
    }

    /* update the index using the buffer we got
     *
     * Describe why we do the following operations:
     *
     * We want to delete a secondary index entry. In BDB, if you push a KV
     * pair with an exist key, then you actually update the original KV
     * pair. Thus, if we want to delete a secondary index entry, we just
     * update the old KV pair.
     */
    if (!no_B) {
        char primary_key[256];

        snprintf(primary_key, 256, "+%lx::%lx:%lx", hs->puuid,
                 hs->uuid, hs->hash);
        err = branch_publish(hs->puuid, hs->uuid, B_name, primary_key,
                             1, buf, hs->mc.c.len);
        if (err) {
            hvfs_err(xnet, "publish kv_list '%s' to B'%s' failed w/ %ld",
                     buf, B_name, err);
            goto out_free;
        }
    }

out_free:    
    xfree(buf);
out:
    return err;
}

static
ssize_t __hvfs_xattr_tag_update(char *key, char *p, char **s,
                                struct hstat *hs, int column,
                                char *value, size_t size)
{
    ssize_t err = 0;
    char *B_name = NULL;
    char *buf = NULL, *ukey = NULL, *uvalue = NULL;
    u8 no_B = 0;

    /* get B */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* parse B */
    {
        char *b = NULL, *t;

        /* get header */
        HVFS_B_NT(p, b, &t, err, out);
        if (*b != 'B') {
            hvfs_err(xnet, "TAG update: Invalid B header '%s'\n", b);
            err = -EINVAL;
            goto out;
        }

        /* get name */
        HVFS_B_NT(p, b, &t, err, no_branch);
        B_name = strdup(b);
        goto next_token;

    no_branch:
        no_B = 1;
    }
next_token:

    /* get key */
    HVFS_XATTR_NT(key, p, s, err, out);
    ukey = strdup(p);

    /* get value */
    HVFS_XATTR_NT(key, p, s, err, out);
    uvalue = strdup(p);

    /* read in the column data */
    buf = xzalloc(hs->mc.c.len + strlen(ukey) + strlen(uvalue) + 
                  3 /* ';' ';' '\0'*/);
    if (!buf) {
        hvfs_err(xnet, "xzalloc() column data buffer failed\n");
        goto out;
    }

    err = __hvfs_fread(hs, column, (void **)buf, &hs->mc.c, 0,
                       hs->mc.c.len);
    if (err < 0) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld failed w/ %ld\n",
                 hs->mc.c.len, err);
        goto out;
    } else if (err != hs->mc.c.len) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld but return %ldB\n",
                 hs->mc.c.len, err);
        err = -EAGAIN;
        goto out;
    }

    /* update the key */
    {
        off_t noff;
        char *f = NULL, *fe, needle[strlen(ukey) + 2];

        memset(needle, 0, sizeof(needle));
        sprintf(needle, "%s=", ukey);

        f = strstr(buf, needle);
        if (!f) {
            hvfs_warning(xnet, "Find key'%s' in column data failed, "
                         "no such key\n",
                     ukey);
            f = fe = buf;
            goto append_new;
        }

        fe = f;
        while (*fe != ';') {
            if (fe >= buf + hs->mc.c.len)
                break;
            fe++;
        }

        /* overwrite the old KV pair */
        memmove(f, fe, (buf + hs->mc.c.len - fe));
        
    append_new:
        /* write a new KV pair */
        noff = hs->mc.c.len - (fe - f);
        if (buf[noff - 1] != ';')
            buf[noff++] = ';';
        noff += sprintf(buf + noff, "%s=%s;", ukey, uvalue);
        buf[noff] = '\0';

        /* write the data back to MDSL and update metadata */
        {
            u64 hash;
            
            /* calculate which itbid we should stored it in */
            {
                struct dhe *e;
                
                e = mds_dh_search(&hmo.dh, hs->puuid);
                if (IS_ERR(e)) {
                    hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", 
                             PTR_ERR(e));
                    err = PTR_ERR(e);
                    goto out;
                }
                hash = hs->hash;
                hs->hash = mds_get_itbid(e, hs->hash);
                mds_dh_put(e);
            }
            
            err = __hvfs_fwrite(hs, column, 0, buf, 
                                noff, &hs->mc.c);
            if (err) {
                hvfs_err(xnet, "do internal fwrite on uuid'%lx,%lx' "
                         "failed w/ %ld\n",
                         hs->uuid, hash, err);
                goto out;
            }
            
            /* update the file attributes */
            {
                struct mdu_update mu;
                
                mu.valid = MU_COLUMN;
                mu.column_no = 1;
                hs->mc.cno = column;
                hs->hash = hash;
                
                err = __hvfs_update(hs->puuid, hs->psalt, hs, &mu);
                if (err) {
                    hvfs_err(xnet, "do internal update on ino<%lx,%lx> "
                             "failed w/ %ld\n",
                             hs->uuid, hs->hash, err);
                    goto out;
                }
            }
        }
    }

    /* Update the index using the buffer we got
     *
     * Describe why we do the following operations:
     *
     * We want to delete a secondary index entry. In BDB, if you push a KV
     * pair with an exist key, then you actually update the original KV
     * pair. Thus, if we want to delete a secondary index entry, we just
     * update the old KV pair.
     */
    if (!no_B) {
        char primary_key[256];

        snprintf(primary_key, 256, "+%lx::%lx:%lx", hs->puuid,
                 hs->uuid, hs->hash);
        err = branch_publish(hs->puuid, hs->uuid, B_name, primary_key,
                             1, buf, hs->mc.c.len);
        if (err) {
            hvfs_err(xnet, "publish kv_list '%s' to B'%s' failed w/ %ld",
                     buf, B_name, err);
            goto out;
        }
    }
    err = 0;
    
out:
    xfree(ukey);
    xfree(uvalue);
    xfree(buf);
    
    return err;
}

/* tag_test() return the value and value length if the specific key exists,
 * otherwise return -ENOENT.
 */
static
ssize_t __hvfs_xattr_tag_test(char *key, char *p, char **s,
                              struct hstat *hs, int column,
                              char *value, size_t size)
{
    ssize_t err = 0;
    char *B_name = NULL;
    char *buf = NULL, *ukey = NULL;
    u8 no_B = 0;

    /* get B */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* parse B */
    {
        char *b = NULL, *t;

        /* get header */
        HVFS_B_NT(p, b, &t, err, out);
        if (*b != 'B') {
            hvfs_err(xnet, "TAG test: Invalid B header '%s'\n", b);
            err = -EINVAL;
            goto out;
        }

        /* get name */
        HVFS_B_NT(p, b, &t, err, no_branch);
        B_name = strdup(b);
        goto next_token;

    no_branch:
        no_B = 1;
    }
next_token:

    /* get key */
    HVFS_XATTR_NT(key, p, s, err, out);
    ukey = p;
    
    /* readin the column data */
    buf = xzalloc(hs->mc.c.len + 1);
    if (!buf) {
        hvfs_err(xnet, "xzalloc() column data buffer failed\n");
        goto out;
    }

    err = __hvfs_fread(hs, column, (void **)&buf, &hs->mc.c, 0,
                       hs->mc.c.len);
    if (err < 0) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld failed w/ %ld\n",
                 hs->mc.c.len, err);
        goto out;
    } else if (err != hs->mc.c.len) {
        hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld but return %ldB\n",
                 hs->mc.c.len, err);
        err = -EAGAIN;
        goto out;
    }

    /* find the key */
    {
        int klen = strlen(p);
        char *f = NULL, *fe, needle[klen + 2];

        memset(needle, 0, sizeof(needle));
        sprintf(needle, "%s=", p);

        f = strstr(buf, needle);
        if (!f) {
            /* key not found */
            err = -ENOENT;
            goto out;
        }

        /* find it, copy the value out */
        fe = f;
        while (*fe != ';') {
            if (fe >= buf + hs->mc.c.len)
                break;
            fe++;
        }
        
        if (!size) {
            err = fe - f - klen - 1;
            goto out;
        }

        if (size < fe - f - klen - 1) {
            err = -ERANGE;
            goto out;
        }

        /* return length */
        err = fe - f - klen - 1;
        memcpy(value, f + klen + 1, err);
    }

out:
    xfree(buf);
    
    return err;
}

/* tag_search() get a query string from key, and return value (and length)
 */
static
ssize_t __hvfs_xattr_tag_search(char *key, char *p, char **s,
                                struct hstat *hs, int column,
                                char *value, size_t size)
{
    ssize_t err = 0;
    char *B_name = NULL;
    char *buf = NULL, *dbname = NULL, *prefix = NULL, *sexpr = NULL;
    u8 no_B = 0;

    /* get B */
    HVFS_XATTR_NT(key, p, s, err, out);

    /* parse B */
    {
        char *b = NULL, *t;

        /* get header */
        HVFS_B_NT(p, b, &t, err, out);
        if (*b != 'B') {
            hvfs_err(xnet, "TAG search: Invalid B header '%s'\n", b);
            err = -EINVAL;
            goto out;
        }

        /* get name */
        HVFS_B_NT(p, b, &t, err, no_branch);
        B_name = strdup(b);
        goto next_token;

    no_branch:
        no_B = 1;
    }
next_token:

    /* get dbname */
    HVFS_XATTR_NT(key, p, s, err, out);
    dbname = strdup(p);

    /* get prefix */
    HVFS_XATTR_NT(key, p, s, err, out);
    prefix = strdup(p);
    
    /* get search_expr */
    HVFS_XATTR_NT(key, p, s, err, out);
    sexpr = p;

    /* seach in the branch, send the request to all the bp sites */
    {
        struct xnet_group *xg = NULL;
        struct iovec *iov;
        size_t tsize = 0, bsize;
        off_t offset = 0;
        int i;

        xg = cli_get_active_site(hmo.chring[CH_RING_BP]);

        if (!xg) {
            hvfs_err(xnet, "get active BP site failed, ENOMEM?\n");
            goto out;
        }
        
        iov = alloca(sizeof(struct iovec) * xg->asize);
        memset(iov, 0, sizeof(struct iovec) * xg->asize);

        for (i = 0; i < xg->asize; i++) {
            buf = NULL;
            bsize = 0;

            err = branch_search(B_name, xg->sites[i].site_id, dbname, prefix, 
                                sexpr, (void **)&buf, &bsize);
            if (err) {
                hvfs_err(xnet, "Search query '%s' in site %lx failed w/ %ld\n",
                         sexpr, xg->sites[i].site_id, err);
            }
            /* set the flag */
            xg->sites[i].flags |= XNET_GROUP_RECVED;
            
            /* alloc an iov and save our buffer in it */
            iov[i].iov_base = buf;
            iov[i].iov_len = bsize;

            tsize += bsize;
        }

        if (!size) {
            /* return current buffer size */
            err = tsize;
            goto out_free;
        } else if (size < tsize) {
            err = -ERANGE;
            goto out_free;
        }

        /* pack the result in the large buffer */
        for (i = 0; i < xg->asize; i++) {
            if (xg->sites[i].flags & XNET_GROUP_RECVED) {
                memcpy(value + offset, iov[i].iov_base, iov[i].iov_len);
                offset += iov[i].iov_len;
            } else {
                hvfs_warning(xnet, "Site %lx responds error for this search\n",
                             xg->sites[i].site_id);
            }
        }
        err = tsize;
        
    out_free:
        for (i = 0; i < xg->asize; i++) {
            if (xg->sites[i].flags & XNET_GROUP_RECVED) {
                xfree(iov[i].iov_base);
            }
        }
        xfree(xg);
    }

out:
    xfree(dbname);
    xfree(prefix);
    
    return err;
}

static 
ssize_t __hvfs_xattr_main(char *key, char *value, size_t size, int flags, 
                          int column, struct hstat *hs)
{
    char *dup = strdup(key), *p = NULL, *s = NULL;
    ssize_t err = 0;
    int class, op, __col;
    
    /* get namespace */
    HVFS_XATTR_NT(dup, p, &s, err, out);
    if (strcmp(p, "pfs") != 0) {
        hvfs_err(xnet, "Request for unsupport namespace: %s\n",
                 p);
        err = -ENOTSUP;
        goto out;
    }
    
    /* get class */
    HVFS_XATTR_NT(dup, p, &s, err, out);
    if (strcmp(p, "native") == 0) {
        class = HVFS_XATTR_CLASS_NATIVE;
    } else if (strcmp(p, "tag") == 0) {
        class = HVFS_XATTR_CLASS_TAG;
    } else if (strcmp(p, "dt") == 0) {
        class = HVFS_XATTR_CLASS_DT;
    } else if (strcmp(p, "branch") == 0) {
        class = HVFS_XATTR_CLASS_BRANCH;
    } else {
        hvfs_err(xnet, "Request for unknown class: %s\n",
                 p);
        err = -ENOTSUP;
        goto out;
    }
    
    /* get column */
    HVFS_XATTR_NT(dup, p, &s, err, out);
    __col = atoi(p);
    if (column + __col > XTABLE_INDIRECT_COLUMN) {
        hvfs_err(xnet, "Request for column %d overflow level 0\n",
                 __col);
        err = -EINVAL;
        goto out;
    }
    column += __col;
    
    /* get op */
    HVFS_XATTR_NT(dup, p, &s, err, out);
    switch (class) {
    case HVFS_XATTR_CLASS_NATIVE:
        if (strcmp(p, "read") == 0) {
            op = HVFS_XATTR_NATIVE_READ;
        } else if (strcmp(p, "write") == 0) {
            op = HVFS_XATTR_NATIVE_WRITE;
        } else if (strcmp(p, "lookup") == 0) {
            op = HVFS_XATTR_NATIVE_LOOKUP;
        } else {
            hvfs_err(xnet, "Request for unknown native op: %s\n",
                     p);
            err = -ENOTSUP;
            goto out;
        }
        break;
    case HVFS_XATTR_CLASS_TAG:
        if (strcmp(p, "set") == 0) {
            op = HVFS_XATTR_TAG_SET;
        } else if (strcmp(p, "delete") == 0) {
            op = HVFS_XATTR_TAG_DELETE;
        } else if (strcmp(p, "update") == 0) {
            op = HVFS_XATTR_TAG_UPDATE;
        } else if (strcmp(p, "test") == 0) {
            op = HVFS_XATTR_TAG_TEST;
        } else if (strcmp(p, "search") == 0) {
            op = HVFS_XATTR_TAG_SEARCH;
        } else {
            hvfs_err(xnet, "Request for unknown tag op: %s\n",
                     p);
            err = -ENOTSUP;
            goto out;
        }
        break;
    case HVFS_XATTR_CLASS_DT:
        if (strcmp(p, "create") == 0) {
            op = HVFS_XATTR_DT_CREATE;
        } else if (strcmp(p, "cat") == 0) {
            op = HVFS_XATTR_DT_CAT;
        } else {
            hvfs_err(xnet, "Request for unknown dtrigger op: %s\n",
                     p);
            err = -ENOTSUP;
            goto out;
        }
        break;
    case HVFS_XATTR_CLASS_BRANCH:
        if (strcmp(p, "create") == 0) {
            op = HVFS_XATTR_BRANCH_CREATE;
        } else if (strcmp(p, "delete") == 0) {
            op = HVFS_XATTR_BRANCH_DELETE;
        } else {
            hvfs_err(xnet, "Request for unknown branch op: %s\n",
                     p);
            err = -ENOTSUP;
            goto out;
        }
        break;
    default:
        hvfs_err(xnet, "Invalid class, internal error!\n");
        err = -EFAULT;
        goto out;
    }
    
    /* prepare column info  */
    err = __hvfs_stat(hs->puuid, hs->psalt, column, hs);
    if (err) {
        hvfs_err(xnet, "do internal file state (SDT) on uuid'%lx,%lx' "
                 "faield w/ %ld\n",
                 hs->uuid, hs->hash, err);
        goto out;
    }

    /* ok, call handlers now */
    switch (class) {
    case HVFS_XATTR_CLASS_NATIVE:
        switch (op) {
        case HVFS_XATTR_NATIVE_READ:
            err = __hvfs_xattr_native_read(dup, p, &s, hs, column, 
                                           value, size);
            break;
        case HVFS_XATTR_NATIVE_WRITE:
            err = __hvfs_xattr_native_write(dup, p, &s, hs, column,
                                            value, size);
            break;
        case HVFS_XATTR_NATIVE_LOOKUP:
            err = __hvfs_xattr_native_lookup(dup, p, &s, hs, column,
                                             value, size);
            break;
        default:
            hvfs_err(xnet, "Request for unknown op: %d\n", op);
            err = -ENOTSUP;
            goto out;
        }
        break;
    case HVFS_XATTR_CLASS_TAG:
        switch (op) {
        case HVFS_XATTR_TAG_SET:
            err = __hvfs_xattr_tag_set(dup, p, &s, hs, column,
                                       value, size);
            break;
        case HVFS_XATTR_TAG_DELETE:
            err = __hvfs_xattr_tag_delete(dup, p, &s, hs, column,
                                          value, size);
            break;
        case HVFS_XATTR_TAG_UPDATE:
            err = __hvfs_xattr_tag_update(dup, p, &s, hs, column,
                                          value, size);
            break;
        case HVFS_XATTR_TAG_TEST:
            err = __hvfs_xattr_tag_test(dup, p, &s, hs, column,
                                        value, size);
            break;
        case HVFS_XATTR_TAG_SEARCH:
            err = __hvfs_xattr_tag_search(dup, p, &s, hs, column,
                                          value, size);
            break;
        default:
            hvfs_err(xnet, "Request for unknown op: %d\n", op);
            err = -ENOTSUP;
            goto out;
        }
        break;
    case HVFS_XATTR_CLASS_DT:
        break;
    case HVFS_XATTR_CLASS_BRANCH:
        break;
    default:
        hvfs_err(xnet, "Request for unknown class: %d\n", class);
        err = -ENOTSUP;
        goto out;
    }
out:
    return err;
}

static int hvfs_setxattr(const char *pathname, const char *key,
                         const char *value, size_t size, int flags)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, column = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }
    
    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    if (S_ISDIR(hs.mdu.mode)) {
        /* We want to manipulate dir xattr, be carefull on reserved columns.
         * The first free column we can use start from HVFS_DIR_FF_COLUMN */
        column = HVFS_DIR_FF_COLUMN;
    }

    /* manipulate the columns and update the metadata */
    err = __hvfs_xattr_main((char *)key, (char *)value, size, flags, 
                            column, &hs);
    if (err) {
        hvfs_err(xnet, "__hvfs_xattr_main() failed w/ %d\n", err);
        goto out;
    }

out:
    return err;
}

static int hvfs_getxattr(const char *pathname, const char *key,
                         char *value, size_t size)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, column = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }
    
    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    if (S_ISDIR(hs.mdu.mode)) {
        /* We want to manipulate dir xattr, be carefull on reserved columns.
         * The first free column we can use start from HVFS_DIR_FF_COLUMN */
        column = HVFS_DIR_FF_COLUMN;
    }

    /* manipulate the columns and update the metadata */
    err = __hvfs_xattr_main((char *)key, (char *)value, size, 0, 
                            column, &hs);
    if (err) {
        hvfs_err(xnet, "__hvfs_xattr_main() failed w/ %d\n", err);
        goto out;
    }

out:
    return err;
}

/* Return an array of NULL-terminated strings, but now we just return a blob
 * of column data.
 */
static int hvfs_listxattr(const char *pathname, char *list, size_t size)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, column = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }
    
    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    if (S_ISDIR(hs.mdu.mode)) {
        /* We want to manipulate dir xattr, be carefull on reserved columns.
         * The first free column we can use start from HVFS_DIR_FF_COLUMN */
        column = HVFS_DIR_FF_COLUMN;
    }

    /* iterate on avaliable columns, and retrieve their content */
    {
        struct iovec *iov = NULL;
        char *buf = NULL;
        size_t tsize = 0;
        off_t offset = 0;
        int i;

        iov = alloca(sizeof(struct iovec) * XTABLE_INDIRECT_COLUMN);
        memset(iov, 0, sizeof(struct iovec) * XTABLE_INDIRECT_COLUMN);
        
        for (i = column; i < XTABLE_INDIRECT_COLUMN; i++) {
            buf = NULL;
            err = __hvfs_stat(puuid, psalt, i, &hs);
            if (err) {
                hvfs_err(xnet, "do internal file stat (SDT) on '%s' "
                         "failed w/ %d\n",
                         name, err);
                goto out_free;
            }
            
            if (hs.mc.c.len > 0) {
                err = __hvfs_fread(&hs, i, (void **)&buf, &hs.mc.c, 0,
                                   hs.mc.c.len);
                if (err < 0) {
                    hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld "
                             "failed w/ %d\n",
                             hs.mc.c.len, err);
                    goto out_free;
                } else if (err != hs.mc.c.len) {
                    hvfs_err(xnet, "__hvfs_fread() offset 0 len %ld "
                             "but return %dB\n",
                             hs.mc.c.len, err);
                    /* ignore this mismatch */
                }
                iov[i].iov_base = buf;
                iov[i].iov_len = hs.mc.c.len;
                tsize += hs.mc.c.len;
            }
        }

        if (!size) {
            /* return current buffer size */
            err = tsize + 1;
            goto out_free;
        } else if (size < tsize + 1) {
            err = -ERANGE;
            goto out_free;
        }

        /* pack the result in the large buffer */
        for (i = column; i < XTABLE_INDIRECT_COLUMN; i++) {
            if (iov[i].iov_len) {
                memcpy(list + offset, iov[i].iov_base, iov[i].iov_len);
                offset += iov[i].iov_len;
            }
        }
        err = tsize + 1;

    out_free:
        for (i = column; i < XTABLE_INDIRECT_COLUMN; i++) {
            if (iov[i].iov_base)
                xfree(iov[i].iov_base);
        }
    }
out:
    
    return err;
}

static int hvfs_removexattr(const char *pathname, const char *key)
{
    int err = -ENOTSUP;

    hvfs_err(xnet, "Remove xattr is not supported, please refer doc to "
             "remove a xattr key/value pairs in Pomegranate.\n");

    return err;
}

static int hvfs_opendir(const char *pathname, struct fuse_file_info *fi)
{
    hvfs_dir_t *dir;

    dir = xzalloc(sizeof(*dir));
    if (!dir) {
        hvfs_err(xnet, "xzalloc() hvfs_dir_t failed\n");
        return -ENOMEM;
    }
    
    fi->fh = (u64)dir;

    return 0;
}

/* If we have read some dirents, we return 0; otherwise, we should return 1 to
 * indicate a error.
 */
static int __hvfs_readdir_plus(u64 duuid, u64 salt, void *buf,
                               fuse_fill_dir_t filler, off_t off,
                               hvfs_dir_t *dir)
{
    char name[256];
    struct xnet_msg *msg;
    struct dentry_info *tdi;
    struct hvfs_index hi;
    u64 dsite;
    off_t saved_offset = off;
    u32 vid;
    int err = 0, retry_nr, res = 0;

    /* Step 1: we should refresh the bitmap of the directory */
    if (!(dir->goffset + dir->loffset))
        mds_bitmap_refresh_all(duuid);

    /* check if the cached entries can serve the request */
    if (off < dir->goffset) {
        /* seek backward, just zero out our brain */
        xfree(dir->di);
        memset(dir, 0, sizeof(*dir));
    }
    hvfs_debug(xnet, "readdir_plus itbid %ld off %ld goff %ld csize %d\n", 
               dir->itbid, off, dir->goffset, dir->csize);

    if (dir->csize > 0 && 
        off <= dir->goffset + dir->csize) {
        /* ok, easy to fill the dentry */
        struct stat st;
        int idx;
        
        tdi = dir->di;
        for (idx = 0; idx < dir->csize; idx++) {
            if (dir->goffset + idx == off) {
                /* fill in */
                memcpy(name, tdi->name, tdi->namelen);
                name[tdi->namelen] = '\0';
                memset(&st, 0, sizeof(st));
                st.st_ino = tdi->uuid;
                st.st_mode = tdi->mode;
                res = filler(buf, name, &st, off + 1);
                if (res)
                    break;
                /* update offset */
                dir->loffset = idx + 1;
                off++;
            }
            tdi = (void *)tdi + sizeof(*tdi) + tdi->namelen;
        }

        if (res)
            return 0;
        else
            dir->itbid++;
    }
    
    do {
        dir->goffset += dir->csize;
        dir->loffset = 0;
        dir->csize = 0;
        xfree(dir->di);
        dir->di = NULL;
        res = 0;

        err = mds_bitmap_find_next(duuid, &dir->itbid);
        if (err < 0) {
            hvfs_err(xnet, "mds_bitmap_find_next() failed @ %ld w/ %d\n",
                     dir->itbid, err);
            break;
        } else if (err > 0) {
            /* this means we can safely stop now */
            break;
        } else {
            /* ok, we can issue the request to the dest site now */
            hvfs_debug(xnet, "Issue request %ld to site ...\n",
                       dir->itbid);
            /* Step 3: we print the results to the console */
            memset(&hi, 0, sizeof(hi));
            hi.puuid = duuid;
            hi.psalt = salt;
            hi.hash = -1UL;
            hi.itbid = dir->itbid;
            hi.flag = INDEX_BY_ITB;

            dsite = SELECT_SITE(dir->itbid, hi.psalt, CH_RING_MDS, &vid);
            msg = xnet_alloc_msg(XNET_MSG_NORMAL);
            if (!msg) {
                hvfs_err(xnet, "xnet_alloc_msg() failed\n");
                err = -ENOMEM;
                goto out;
            }
            xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                             hmo.xc->site_id, dsite);
            xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LIST, 0, 0);
#ifdef XNET_EAGER_WRITEV
            xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
            xnet_msg_add_sdata(msg, &hi, sizeof(hi));

            retry_nr = 0;
        retry:
            err = xnet_send(hmo.xc, msg);
            if (err) {
                hvfs_err(xnet, "xnet_send() failed\n");
                xnet_free_msg(msg);
                goto out;
            }

            ASSERT(msg->pair, xnet);
            if (msg->pair->tx.err) {
                /* Note that, if the itbid is less than 8, then we ignore the
                 * ENOENT error */
                if (dir->itbid < 8 && msg->pair->tx.err == -ENOENT) {
                    xnet_free_msg(msg);
                    dir->itbid++;
                    continue;
                }
                if (msg->pair->tx.err == -EHWAIT) {
                    if (retry_nr < 60) {
                        retry_nr++;
                        sleep(1);
                        goto retry;
                    }
                }
                hvfs_err(mds, "list dir %lx slice %ld failed w/ %d\n",
                         duuid, dir->itbid, msg->pair->tx.err);
                err = msg->pair->tx.err;
                xnet_free_msg(msg);
                goto out;
            }
            if (msg->pair->xm_datacheck) {
                /* ok, dump the entries */

                /* alloc the buffer */
                if (msg->pair->tx.len - sizeof(struct hvfs_md_reply) == 0) {
                    xnet_free_msg(msg);
                    dir->itbid++;
                    continue;
                } else {
                    hvfs_debug(xnet, "From ITB %ld, len %ld\n", 
                               dir->itbid,
                               msg->pair->tx.len - 
                               sizeof(struct hvfs_md_reply));
                    dir->di = xmalloc(msg->pair->tx.len - 
                                      sizeof(struct hvfs_md_reply));
                    if (!dir->di) {
                        hvfs_err(xnet, "xmalloc() dir->di buffer failed\n");
                        err = -ENOMEM;
                        xnet_free_msg(msg);
                        goto out;
                    }
                    dir->csize = ((struct hvfs_md_reply *)
                                  msg->pair->xm_data)->dnum;
                    memcpy(dir->di, msg->pair->xm_data + 
                           sizeof(struct hvfs_md_reply),
                           (msg->pair->tx.len - 
                            sizeof(struct hvfs_md_reply)));
                }
                
                /* check if we should stop */
                if (off <= dir->goffset + dir->csize) {
                    struct stat st;
                    int idx;

                    tdi = dir->di;
                    for (idx = 0; idx < dir->csize; idx++) {
                        if (dir->goffset + idx == off) {
                            /* fill in */
                            memcpy(name, tdi->name, tdi->namelen);
                            name[tdi->namelen] = '\0';
                            st.st_ino = tdi->uuid;
                            st.st_mode = tdi->mode;
                            res = filler(buf, name, &st, off + 1);
                            if (res)
                                break;
                            dir->loffset = idx + 1;
                            off++;
                        }
                        tdi = (void *)tdi + sizeof(*tdi) + tdi->namelen;
                    }
                    if (res)
                        break;
                }
            } else {
                hvfs_err(xnet, "Invalid LIST reply from site %lx.\n",
                         msg->pair->tx.ssite_id);
                err = -EFAULT;
                xnet_free_msg(msg);
                goto out;
            }
            xnet_free_msg(msg);
        }
        dir->itbid += 1;
    } while (1);

    if (off > saved_offset)
        err = 0;
    else
        err = 1;
    
out:
    return err;
}

static int hvfs_readdir_plus(const char *pathname, void *buf, 
                             fuse_fill_dir_t filler, off_t off,
                             struct fuse_file_info *fi)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        /* Step 1: find in the SDT */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    if (name && strlen(name) > 0 && strcmp(name, "/") != 0) {
        /* stat the last dir */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        psalt = hs.ssalt;
    } else {
        /* check if it is the root directory */
        if (puuid == hmi.root_uuid) {
            err = __hvfs_fill_root(&hs);
            if (err) {
                hvfs_err(xnet, "fill root entry failed w/ %d\n", err);
                goto out;
            }
        }
    }

    err = __hvfs_readdir_plus(puuid, psalt, buf, filler, off, 
                              (hvfs_dir_t *)fi->fh);
    if (err < 0) {
        hvfs_err(xnet, "do internal readdir on '%s' failed w/ %d\n",
                 (name ? name : p), err);
        goto out;
    } else if (err == 1) {
        /* stop loudly */
        err = -ENOENT;
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static int hvfs_release_dir(const char *pathname, struct fuse_file_info *fi)
{
    hvfs_dir_t *dir = (hvfs_dir_t *)fi->fh;

    xfree(dir->di);
    xfree(dir);

    return 0;
}

/* use user defined configs
 */
static void *hvfs_init(struct fuse_conn_info *conn)
{
    int err = 0;

    if (!g_pagesize)
        g_pagesize = getpagesize();
realloc:
    err = posix_memalign(&zero_page, g_pagesize, g_pagesize);
    if (err || !zero_page) {
        goto realloc;
    }
    if (mprotect(zero_page, g_pagesize, PROT_READ) < 0) {
        hvfs_err(xnet, "mprotect ZERO page failed w/ %d\n", errno);
    }

    if (!pfs_fuse_mgr.inited) {
        /* disable dynamic magic config/atime/diratime */
        pfs_fuse_mgr.inited = 1;
        pfs_fuse_mgr.sync_write = 0;
        pfs_fuse_mgr.use_config = 0;
        pfs_fuse_mgr.use_dstore = 0;
        pfs_fuse_mgr.noatime = 1;
        pfs_fuse_mgr.nodiratime = 1;
        pfs_fuse_mgr.ttl = 5;
    }
    
    /* setup dynamic config values */
    pfs_ce_default[PC_SYNC_WRITE].uvalue = pfs_fuse_mgr.use_config;

    /* increase this ttl value can increase performance greatly (5->60 +~20%)
     */
    pfs_ce_default[PC_LRU_TRANSLATE_CACHE_TTL].uvalue = pfs_fuse_mgr.ttl;
    pfs_ce_default[PC_SYNC_WRITE].uvalue = pfs_fuse_mgr.sync_write;
    pfs_ce_default[PC_NOATIME].uvalue = pfs_fuse_mgr.noatime;
    pfs_ce_default[PC_NODIRATIME].uvalue = pfs_fuse_mgr.nodiratime;
    
    if (__ltc_init(pfs_fuse_mgr.ttl, 0)) {
        hvfs_err(xnet, "LRU Translate Cache init failed. Cache DISABLED!\n");
    }

    if (__odc_init(0)) {
        hvfs_err(xnet, "OpeneD Cache(ODC) init failed. FATAL ERROR!\n");
        HVFS_BUGON("ODC init failed!");
    }

    if (__soc_init(0)) {
        hvfs_err(xnet, "Stat Oneshot Cache(SOC) init failed. FATAL ERROR!\n");
        HVFS_BUGON("SOC init failed!");
    }

    return NULL;
}

/* Introduced in fuse version 2.5. Create and open a file, thus we drag mknod
 * and open in it!
 */
static int hvfs_create_plus(const char *pathname, mode_t mode, 
                            struct fuse_file_info *fi)
{
    struct hstat hs = {.mc.c.len = 0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *path, *name, *spath = NULL;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    SPLIT_PATHNAME(dup, path, name);
    n = path;

    spath = strdup(path);
    err = __ltc_lookup(spath, &puuid, &psalt);
    if (err > 0) {
        goto hit;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err) {
        goto out;
    }

    __ltc_update(spath, (void *)puuid, (void *)psalt);
hit:
    /* create the file or dir in the parent directory now */
    hs.name = name;
    hs.uuid = 0;
    /* FIXME: should we not drop rdev? */
    mu.valid = MU_MODE;
    mu.mode = mode;
    err = __hvfs_create(puuid, psalt, &hs, 0, &mu);
    if (unlikely(err)) {
        hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

    fi->fh = (u64)__get_bhhead(&hs);
    /* Save the hstat in SOC cache */
    {
        struct soc_entry *se = __se_alloc(pathname, &hs);

        __soc_insert(se);
    }

out:
    xfree(dup);
    xfree(spath);
    
    return err;
}

static void hvfs_destroy(void *arg)
{
    __ltc_destroy();
    __odc_destroy();
    __soc_destroy();
    
    hvfs_info(xnet, "Exit the PomegranateFS fuse client now.\n");
}

struct fuse_operations pfs_ops = {
    .getattr = hvfs_getattr,
    .readlink = hvfs_readlink,
    .getdir = NULL,
    .mknod = hvfs_mknod,
    .mkdir = hvfs_mkdir,
    .unlink = hvfs_unlink,
    .rmdir = hvfs_rmdir,
    .symlink = hvfs_symlink,
    .rename = hvfs_rename,
    .link = hvfs_link,
    .chmod = hvfs_chmod,
    .chown = hvfs_chown,
    .truncate = hvfs_truncate,
    .utime = hvfs_utime,
    .open = hvfs_open,
    .read = hvfs_read,
    .write = hvfs_write,
    .statfs = hvfs_statfs_plus,
    .flush = NULL,
    .release = hvfs_release,
    .fsync = NULL,
    .setxattr = hvfs_setxattr,
    .getxattr = hvfs_getxattr,
    .listxattr = hvfs_listxattr,
    .removexattr = hvfs_removexattr,
    .opendir = hvfs_opendir,
    .readdir = hvfs_readdir_plus,
    .releasedir = hvfs_release_dir,
    .init = hvfs_init,
    .destroy = hvfs_destroy,
    .create = hvfs_create_plus,
    .ftruncate = hvfs_ftruncate,
};
