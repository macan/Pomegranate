/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-27 16:26:50 macan>
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
#include <fuse.h>

/* We construct a write buffer cache to absort user's write requests and flush
 * them as a whole to disk when the file are closed. Thus, we have
 * close-to-open consistency.
 */
static size_t g_pagesize = 0;
struct __pfs_fuse_mgr
{
    u32 sync_write:1;
} pfs_fuse_mgr;

/* We are sure that there is no page hole! */
struct bhhead
{
    struct list_head bh;
    size_t size;                /* total buffer size */
    size_t asize;               /* actually size for release use */
    struct hstat hs;
    xrwlock_t clock;
#define BH_CLEAN        0x00
#define BH_DIRTY        0x01
    u32 flag;
};

struct bh
{
    struct list_head list;
    off_t offset;               /* buffer offset */
    void *data;                 /* this is always a page */
};

static struct bhhead* __get_bhhead(struct hstat *hs)
{
    struct bhhead *bhh;

    bhh = xzalloc(sizeof(struct bhhead));
    if (!bhh) {
        return NULL;
    }
    INIT_LIST_HEAD(&bhh->bh);
    xrwlock_init(&bhh->clock);
    bhh->hs = *hs;

    return bhh;
}

static void __set_bhh_dirty(struct bhhead *bhh)
{
    bhh->flag = BH_DIRTY;
}

static int __prepare_bh(struct bh *bh)
{
    if (bh->data)
        return 0;
    
    bh->data = xzalloc(g_pagesize);
    if (!bh->data) {
        return -ENOMEM;
    }

    return 0;
}

static struct bh* __get_bh(off_t off)
{
    struct bh *bh;

    bh = xzalloc(sizeof(struct bh));
    if (!bh) {
        return NULL;
    }
    INIT_LIST_HEAD(&bh->list);
    bh->offset = off;
    if (__prepare_bh(bh)) {
        xfree(bh);
        bh = NULL;
    }

    return bh;
}

static void __put_bh(struct bh *bh)
{
    if (bh->data)
        xfree(bh->data);

    xfree(bh);
}

static void __put_bhhead(struct bhhead *bhh)
{
    struct bh *bh, *n;

    list_for_each_entry_safe(bh, n, &bhh->bh, list) {
        list_del(&bh->list);
        __put_bh(bh);
    }
    
    xfree(bhh);
}

static int __bh_read(struct bhhead *bhh, void *buf, off_t offset, 
                     size_t size)
{
    struct bh *bh;
    off_t loff = 0;
    size_t _size;
    
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

    if (size)
        size = -EFAULT;
    
    return size;
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
    size_t _size = 0;
    int err = 0;

    xrwlock_wlock(&bhh->clock);
    /* should we loadin the middle holes */
    if (offset >= bhh->size) {
        while (bhh->size < off_end) {
            bh = __get_bh(bhh->size);
            if (!bh) {
                err = -ENOMEM;
                goto out;
            }
            if (offset == bhh->size && size >= g_pagesize) {
                /* just copy the buffer */
                _size = min(size, bh->offset + g_pagesize - offset);
                memcpy(bh->data + offset - bh->offset,
                       buf + loff, _size);
                size -= _size;
                loff += _size;
                offset = bh->offset + g_pagesize;
            } else {
                /* read in the page now */
                err = __hvfs_fread(hs, 0, &bh->data, &hs->mc.c,
                                   bhh->size, g_pagesize);
                if (err == -EFBIG) {
                    /* it is ok, we just zero the page */
                    err = 0;
                } else if (err < 0) {
                    hvfs_err(xnet, "bh_fill() read the file range [%ld, %ld] "
                             "failed w/ %d\n",
                             bhh->size, bhh->size + g_pagesize, err);
                    goto out;
                }
                /* should we fill with buf? */
                if (size && offset < bh->offset + g_pagesize) {
                    _size = min(size, bh->offset + g_pagesize - offset);
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
                _size = min(size, bh->offset + g_pagesize - offset);
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
                bh = __get_bh(bhh->size);
                if (!bh) {
                    err = -ENOMEM;
                    goto out;
                }
                /* read in the page now */
                err = __hvfs_fread(hs, 0, &bh->data, &hs->mc.c,
                                   bhh->size, g_pagesize);
                if (err < 0) {
                    hvfs_err(xnet, "bh_fill() read the file range [%ld, %ld] "
                             "failed w/ %d",
                             bhh->size, bhh->size + g_pagesize, err);
                    goto out;
                }
                /* should we fill with buf? */
                if (size && offset < bh->offset + g_pagesize) {
                    _size = min(size, bh->offset + g_pagesize - offset);
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

out:
    xrwlock_wunlock(&bhh->clock);
    
    return err;
}

static int __bh_sync(struct bhhead *bhh)
{
    struct bh *bh;
    void *data = NULL;
    off_t offset = 0;
    size_t size, _size;
    u64 hash;
    int err = 0;

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

    data = xmalloc(bhh->asize);
    if (!data) {
        hvfs_err(xnet, "xmalloc() data buffer failed\n");
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

    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, bhh->hs.puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out_free;
        }
        hash = bhh->hs.hash;
        bhh->hs.hash = mds_get_itbid(e, bhh->hs.hash);
        mds_dh_put(e);
    }

    /* write out the data now */
    err = __hvfs_fwrite(&bhh->hs, 0 /* ZERO */, 0, data, bhh->asize, 
                        &bhh->hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fwrite on ino'%lx' failed w/ %d\n",
                 bhh->hs.uuid, err);
        goto out_free;
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
        mc->c = bhh->hs.mc.c;

    retry:
        bhh->hs.hash = hash;
        err = __hvfs_update(bhh->hs.puuid, bhh->hs.psalt, &bhh->hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on ino'%lx' failed w/ %d\n",
                     bhh->hs.uuid, err);
            xfree(mu);
            goto out_free;
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
out_free:
    xfree(data);

out:
    return err;
}

/* GETATTR: 
 * Use xnet to send the request to server
 */
static int hvfs_getattr(const char *pathname, struct stat *stbuf)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname || !stbuf)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
    n = path;

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

    hs.puuid = puuid;
    hs.psalt = psalt;

    /* pack the result to stat buffer */
    stbuf->st_ino = hs.uuid;
    stbuf->st_mode = hs.mdu.mode;
    stbuf->st_rdev = hs.mdu.dev;
    stbuf->st_nlink = hs.mdu.nlink;
    stbuf->st_uid = hs.mdu.uid;
    stbuf->st_gid = hs.mdu.gid;
    stbuf->st_ctime = max(hs.mdu.ctime, hs.mdu.mtime);
    stbuf->st_atime = (time_t)hs.mdu.atime;
    stbuf->st_mtime = (time_t)hs.mdu.mtime;
    if (S_ISDIR(hs.mdu.mode)) {
        stbuf->st_size = 0;
        stbuf->st_blocks = 1;
    } else {
        stbuf->st_size = hs.mdu.size;
        stbuf->st_blocks = (hs.mdu.size + 511) >> 9;
    }
    /* the blksize is always 4KB */
    stbuf->st_blksize = 4096;
    
out:
    xfree(dup);
    xfree(dup2);
    return err;
}

/* At this moment, we only support reading the symlink content from the mdu
 * fields.
 */
static int hvfs_readlink(const char *pathname, char *buf, size_t size)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname || !buf)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
    n = path;

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

    hs.puuid = puuid;
    hs.psalt = psalt;

    /* ok to parse the symname */
    if (hs.mdu.size > sizeof(hs.mdu.symname)) {
        hvfs_err(xnet, "Long SYMLINK not supported yet!\n");
        err = -EINVAL;
    } else {
        memcpy(buf, hs.mdu.symname, size);
        buf[size] = '\0';
    }

out:
    xfree(dup);
    xfree(dup2);
    
    return err;
}

static int hvfs_mknod(const char *pathname, mode_t mode, dev_t rdev)
{
    struct hstat hs;
    struct mdu_update mu;
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* create the file or dir in the parent directory now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        hvfs_err(xnet, "Create zero-length named file or root directory?\n");
        err = -EINVAL;
        goto out;
    }
    
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

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;
}

static int hvfs_mkdir(const char *pathname, mode_t mode)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* create the file or dir in the parent directory now */
    if (strlen(name) == 0 || strcmp(name, "/") == 0) {
        hvfs_err(xnet, "Create zero-length named or root directory?\n");
        err = -EINVAL;
        goto out;
    }

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

    /* create the gdt entry now */
    err = __hvfs_create(hmi.gdt_uuid, hmi.gdt_salt, &hs, 
                        INDEX_CREATE_GDT, NULL);
    if (err) {
        hvfs_err(xnet, "do internal create (GDT) on '%s' faild w/ %d\n",
                 name, err);
        goto out;
    }
    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;
}

static int hvfs_unlink(const char *pathname)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, is_dir = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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

    /* finally, do delete now */
    if (!name || strlen(name) == 0 || strcmp(name, "/") == 0) {
        /* what we want to delete is a directory, double check it */
        if (!S_ISDIR(hs.mdu.mode) || !is_dir) {
            hvfs_err(xnet, "It is a dir you want to delete, isn't it?\n");
            err = -EINVAL;
            goto out;
        }
        /* FIXME: check if it is a empty directory? Yup, but how? */
        hs.name = NULL;
        /* Step 1: delete the SDT entry by UUID */
        hs.uuid = puuid;
        hs.hash = saved_hash;
        err = __hvfs_unlink(saved_puuid, saved_psalt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
        /* Step 2: delete the GDT entry */
        hs.uuid = puuid;
        hs.hash = 0;
        err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
    } else {
        /* confirm what it is firstly! */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat (SDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }
        if ((S_ISDIR(hs.mdu.mode) && !is_dir) ||
            (!S_ISDIR(hs.mdu.mode) && is_dir)) {
            hvfs_err(xnet, "is directory or file but not "
                     "matched with your argument\n");
            err = -EINVAL;
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
        if (is_dir) {
            /* ok, delete the GDT entry */
            hs.hash = 0;
            err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
            if (err) {
                hvfs_err(xnet, "do internal delete (GDT) on '%s' "
                         "failed w/ %d\n",
                         name, err);
                goto out;
            }
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;
}

static int hvfs_rmdir(const char *pathname)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0, is_dir = 1;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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

    /* finally, do delete now */
    if (!name || strlen(name) == 0 || strcmp(name, "/") == 0) {
        /* what we want to delete is a directory, double check it */
        if (!S_ISDIR(hs.mdu.mode) || !is_dir) {
            hvfs_err(xnet, "It is a dir you want to delete, isn't it?\n");
            err = -EINVAL;
            goto out;
        }
        /* FIXME: check if it is a empty directory? Yup, but how? */
        hs.name = NULL;
        /* Step 1: delete the SDT entry by UUID */
        hs.uuid = puuid;
        hs.hash = saved_hash;
        err = __hvfs_unlink(saved_puuid, saved_psalt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
        /* Step 2: delete the GDT entry */
        hs.uuid = puuid;
        hs.hash = 0;
        err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
    } else {
        /* confirm what it is firstly! */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal stat (SDT) on '%s' "
                     "failed w/ %d\n",
                     name, err);
            goto out;
        }
        if ((S_ISDIR(hs.mdu.mode) && !is_dir) ||
            (!S_ISDIR(hs.mdu.mode) && is_dir)) {
            hvfs_err(xnet, "is directory or file but not "
                     "matched with your argument\n");
            err = -EINVAL;
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
        if (is_dir) {
            /* ok, delete the GDT entry */
            hs.hash = 0;
            err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
            if (err) {
                hvfs_err(xnet, "do internal delete (GDT) on '%s' "
                         "failed w/ %d\n",
                         name, err);
                goto out;
            }
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;
}

static int hvfs_symlink(const char *from, const char *to)
{
    return -ENOSYS;
}

static int hvfs_rename(const char *from, const char *to)
{
    return -ENOSYS;
}

static int hvfs_link(const char *from, const char *to)
{
    return -ENOSYS;
}

static int hvfs_chmod(const char *pathname, mode_t mode)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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
    
    mu.valid = MU_MODE;
    mu.mode = mode;

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
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;    
}

static int hvfs_chown(const char *pathname, uid_t uid, gid_t gid)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;    
}

static int hvfs_truncate(const char *pathname, off_t size)
{
    struct hstat hs = {0,};
    struct mdu_update mu = {.valid = 0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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

        err = __hvfs_fread(&hs, 0 /* column is ZERO */, &data, &hs.mc.c,
                           0, hs.mdu.size);
        if (err < 0) {
            hvfs_err(xnet, "do internal fread on '%s' failed w/ %d\n",
                     name, err);
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
    if (err) {
        hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
out:
    xfree(dup);
    xfree(dup2);

    return err;
}

static int hvfs_utime(const char *pathname, struct utimbuf *buf)
{
    struct hstat hs = {0,};
    struct mdu_update mu;
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname || !buf)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
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
    
    mu.valid = MU_ATIME | MU_MTIME;
    mu.atime = buf->actime;
    mu.mtime = buf->modtime;

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
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

out:
    xfree(dup);
    xfree(dup2);
    
    return err;    
}

static int hvfs_open(const char *pathname, struct fuse_file_info *fi)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
    n = path;

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

    fi->fh = (u64)__get_bhhead(&hs);
    
out:
    xfree(dup);
    xfree(dup2);

    return err;
}

static int hvfs_read(const char *pathname, char *buf, size_t size, 
                     off_t offset, struct fuse_file_info *fi)
{
    struct hstat hs;
    struct bhhead *bhh = (struct bhhead *)fi->fh;
    int err = 0, bytes = 0;

    if (!pathname || !buf || !bhh)
        return -EINVAL;

    hs = bhh->hs;

    err = __bh_read(bhh, buf, offset, size);
    if (err == -EFBIG) {
        /* read in the data now */
        err = __hvfs_fread(&hs, 0 /* column is ZERO */, (void **)&buf, 
                           &hs.mc.c, offset, size);
        if (err < 0) {
            hvfs_err(xnet, "do internal fread on '%s' failed w/ %d\n",
                     pathname, err);
            goto out;
        }
        bytes = err;
        err = __bh_fill(&hs, 0, &hs.mc.c, bhh, buf, offset, err);
        if (err < 0) {
            hvfs_err(xnet, "fill the buffer cache failed w/ %d\n",
                     err);
            goto out;
        }
        /* restore the bytes */
        err = bytes;
    } else if (err) {
        hvfs_err(xnet, "buffer cache read '%s' failed w/ %d\n", 
                 pathname, err);
        goto out;
    } else {
        err = size;
    }
    /* return the # of bytes we read */
    
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
    int err = 0, flag = 0;

    if (!buf)
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
    err = __hvfs_fread(&hs, 0 /* ZERO */, &data, &hs.mc.c, 0, len);
    if (err < 0) {
        hvfs_err(xnet, "read in the original data content failed w/ %d\n",
                 err);
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

    if (!pathname || !buf)
        return -EINVAL;

    hs = bhh->hs;
    __set_bhh_dirty(bhh);
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

static int __hvfs_readdir_plus(u64 duuid, u64 salt, void *buf,
                               fuse_fill_dir_t filler, off_t off,
                               hvfs_dir_t *dir)
{
    char name[256];
    struct xnet_msg *msg;
    struct dentry_info *tdi;
    struct hvfs_index hi;
    u64 dsite;
    u32 vid;
    int err = 0, retry_nr, res = 0;

    /* Step 1: we should refresh the bitmap of the directory */
    if (!(dir->goffset + dir->loffset))
        mds_bitmap_refresh_all(duuid);

    /* check if the cached entries can serve the request */
    if (off < dir->goffset) {
        /* seek backward is not allowed */
        return -EINVAL;
    }
    hvfs_debug(xnet, "readdir_plus itbid %ld off %ld goff %ld csize %d\n", 
               dir->itbid, off, dir->goffset, dir->csize);

    if (dir->goffset + dir->csize > 0 && 
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

    err = 0;
out:
    return err;
}

static int hvfs_readdir_plus(const char *pathname, void *buf, 
                             fuse_fill_dir_t filler, off_t off,
                             struct fuse_file_info *fi)
{
    struct hstat hs = {0,};
    char *dup = strdup(pathname), *dup2 = strdup(pathname), *path, *name;
    char *p = NULL, *n, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!pathname || !buf)
        return -EINVAL;
    path = dirname(dup);
    name = basename(dup2);
    n = path;

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

    if (err)
        goto out;

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
    if (err) {
        hvfs_err(xnet, "do internal readdir on '%s' failed w/ %d\n",
                 (name ? name : p), err);
        goto out;
    }

out:
    return err;
}

static int hvfs_release_dir(const char *pathname, struct fuse_file_info *fi)
{
    hvfs_dir_t *dir = (hvfs_dir_t *)fi->fh;

    xfree(dir->di);
    xfree(dir);

    return 0;
}

static void *hvfs_init(struct fuse_conn_info *conn)
{
    g_pagesize = getpagesize();
    pfs_fuse_mgr.sync_write = 0;

    return NULL;
}

static void hvfs_destroy(void *arg)
{
    hvfs_info(xnet, "Exit the fuse client now.\n");
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
    .opendir = hvfs_opendir,
    .readdir = hvfs_readdir_plus,
    .releasedir = hvfs_release_dir,
    .init = hvfs_init,
    .destroy = hvfs_destroy,
};
