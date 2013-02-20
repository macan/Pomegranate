/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2013-02-19 14:32:53 macan>
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
#include "osd.h"
#include "lib.h"
#include <dirent.h>

static u32 g_session = 0;
static xlock_t g_version_lock;

int osd_storage_dir_make_exist(char *path)
{
    int err;

    err = mkdir(path, 0755);
    if (err) {
        err = -errno;
        if (errno == EEXIST) {
            err = 0;
        } else if (errno == EACCES) {
            hvfs_err(osd, "Failed to create the dir %s, no permission.\n",
                     path);
        } else {
            hvfs_err(osd, "mkdir %s failed w/ %d\n", path, errno);
        }
    }

    return err;
}

static inline
char *osd_storage_selector(int *dev)
{
    char *p = hoo.storage.am.store_array[hoo.storage.am.sa.rra.cur];

    if (dev)
        *dev = hoo.storage.am.sa.rra.cur;
    if (++hoo.storage.am.sa.rra.cur >= hoo.storage.am.array_size)
        hoo.storage.am.sa.rra.cur = 0;

    return p;
}

static inline
char *osd_storage_iterator(int pos)
{
    if (unlikely(pos >= hoo.storage.am.array_size))
        return NULL;
    else {
        return hoo.storage.am.store_array[pos];
    }
}

static inline
int osd_storage_array_size()
{
    return hoo.storage.am.array_size;
}

/* calculate the prefix from objid
 */
void osd_get_prefix(struct objid oid, char *prefix)
{
    MD5_CTX mdContext;
    int idx[OSD_DEFAULT_PREFIX_LEN] = {1, 7, 11, 13, }, i;
    
    MD5Init (&mdContext);
    MD5Update (&mdContext, &oid, sizeof(oid.uuid) + sizeof(oid.bid));
    MD5Final (&mdContext);

    for (i = 0; i < OSD_DEFAULT_PREFIX_LEN; i++) {
        snprintf(&prefix[i << 1], 3, "%02x", mdContext.digest[idx[i]]);
    }
    prefix[OSD_DEFAULT_PREFIX_LEN << 1] = '\0';
}

void osd_get_obj_path(struct objid oid, char *store, char *path)
{
    char prefix[2 * OSD_DEFAULT_PREFIX_LEN + 1];

    memset(prefix, 0, sizeof(prefix));
    osd_get_prefix(oid, prefix);
    /* NOTE:
     *
     * if OSD_DEFAULT_PREFIX_LEN != 4, then fail! (HOW TO FIX: change 0.4s to
     * sth else)
     */
    ASSERT(OSD_DEFAULT_PREFIX_LEN == 4, osd);
    sprintf(path, "%s/%lx/%.4s/%s/%lx.%x", store, hoo.site_id, 
            prefix, &prefix[OSD_DEFAULT_PREFIX_LEN],
            oid.uuid, oid.bid);
}

void osd_obj_path_valid(char *oldpath)
{
    /* alloc a level 0/1 path array */
    char paths[2][256];
    char *path = strdup(oldpath);
    int len, i, level = 1;

    if (!path)
        return;
    len = strlen(path);
    for (i = len; i >= 0; i--) {
        if (path[i] == '/') {
            path[i] = '\0';
            strcpy(paths[level], path);
            level--;
        }
        if (level < 0)
            break;
    }
    if (level >= 0) {
        hvfs_err(osd, "Invalid obj path: %s\n", path);
        return;
    }
    /* ok, we have to valid the directories */
    for (i = 0; i < 2; i++) {
        hvfs_info(osd, "make exist: %s\n", paths[i]);
        osd_storage_dir_make_exist(paths[i]);
    }
}

int osd_log_integrated(void)
{
    struct log_entry le;
    loff_t offset = 0;
    u64 begin_session = 0, end_session = 0;
    int err = -ENOENT, bl, br;

    /* read in the content from last checkpoint position */
    do {
        /* get the log_entry */
        bl = 0;
        do {
            br = pread(hoo.storage.objlog_fd, (void *)&le + bl,
                       sizeof(le) - bl, offset + bl);
            if (br < 0) {
                hvfs_err(osd, "read objlog file failed w/ %d offset %ld\n", 
                         errno, offset + bl);
                err = -errno;
                goto out;
            } else if (br == 0) {
                /* it is ok to break here */
                goto out_check;
            }
            bl += br;
        } while (bl < sizeof(le));

        if (le.magic == LOG_BEGIN_MAGIC) {
            begin_session = le.session;
        } else if (le.magic == LOG_END_MAGIC) {
            end_session = le.session;
        }
        offset += sizeof(le);
    } while (1);

out_check:
    if (begin_session == end_session) {
        if (end_session) 
            err = 0;
        else if (!begin_session) {
            /* there is no session pair */
            err = 0;
        } else {
            err = -ENOENT;
        }
    }
out:
    if (err) {
        hvfs_warning(osd, "OSD objlog integrated check failed w/ %d(%s)\n",
                     err, strerror(-err));
    }

    return err;
}

int osd_log_redo(void)
{
    struct log_entry le;
    loff_t offset = 0;
    int err = -ENOENT, bl, br;

    /* read in the content from last checkpoint position */
    do {
        /* get the log_entry */
        bl = 0;
        do {
            br = pread(hoo.storage.objlog_fd, (void *)&le + bl,
                       sizeof(le) - bl, offset + bl);
            if (br < 0) {
                hvfs_err(osd, "read objlog file failed w/ %d offset %ld\n", 
                         errno, offset + bl);
                err = -errno;
                goto out;
            } else if (br == 0) {
                /* it is ok to break here */
                err = 0;
                goto out;
            }
            bl += br;
        } while (bl < sizeof(le));

        if (le.magic == LOG_ENTRY_MAGIC) {
            /* check if the ENTRY exists */
            /* FIXME: 
             * construct two lists: one for add, the other for del.
             */
        }
        offset += sizeof(le);
    } while (1);

out:
    if (err) {
        hvfs_warning(osd, "OSD objlog redo failed w/ %d\n", err);
    }

    return err;
}

int osd_storage_is_clean()
{
    char path[256] = {0,};
    int err = 0;

    /* try to open the log file */
    sprintf(path, "%s/%lx/objlog", hoo.conf.osd_home, hoo.site_id);

    hoo.storage.objlog_fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (hoo.storage.objlog_fd < 0) {
        hvfs_err(osd, "open() objlog file %s failed %d (%s)\n",
                 path, errno, strerror(errno));
        err = -errno;
        goto out;
    }

    /* check if the log file is integrated */
    err = osd_log_integrated();
    if (err) {
        hvfs_err(osd, "objlog file %s is NOT integrated.\n",
                 path);
    }

    hvfs_info(osd, "Begin redo the logs ...\n");
    err = osd_log_redo();
    if (err) {
        hvfs_err(osd, "objlog file %s redo failed w/ %d\n",
                 path, err);
        goto out;
    }
    
    hvfs_info(osd, "objlog file is CLEAN!\n");

out:
    return err;
}

void __osd_log_rename(void)
{
    char opath[256], npath[256];
    int err = 0;

    sprintf(opath, "%s/%lx/objlog", hoo.conf.osd_home, hoo.site_id);
    sprintf(npath, "%s/%lx/last-objlog", hoo.conf.osd_home, hoo.site_id);

    err = rename(opath, npath);
    if (err) {
        hvfs_err(osd, "rename objlog to last-objlog failed w/ %d\n",
                 errno);
        goto out;
    }

    /* close old file and open new file */
    err = open(opath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(osd, "open file '%s' failed w/ %d\n", opath, errno);
    }
    close(hoo.storage.objlog_fd);
    hoo.storage.objlog_fd = err;
    
out:
    return;
}

void __osd_log_pair_write(struct log_entry *le)
{
    loff_t offset;
    long bw, bl;
    
    xlock_lock(&hoo.storage.objlog_fd_lock);
    offset = lseek(hoo.storage.objlog_fd, 0, SEEK_END);
    if (offset < 0) {
        hvfs_err(osd, "lseek to end of fd %d failed w/ %d\n",
                 hoo.storage.objlog_fd, errno);
        goto out_unlock;
    }
    /* write the LOG_ENTRY */
    bl = 0;
    do {
        bw = pwrite(hoo.storage.objlog_fd, (void *)le + bl,
                    sizeof(*le) - bl, offset + bl);
        if (bw <= 0) {
            hvfs_err(osd, "pwrite to fd %d failed w/ %d\n",
                     hoo.storage.objlog_fd, errno);
            goto out_unlock;
        }
        bl += bw;
    } while (bl < sizeof(*le));
    offset += sizeof(*le);

out_unlock:    
    xlock_unlock(&hoo.storage.objlog_fd_lock);
}

/* write a magic pair begin in log file */
void osd_startup_normal(void)
{
    struct log_entry lb;

    memset(&lb, 0, sizeof(lb));
    lb.magic = LOG_BEGIN_MAGIC;

    /* set up specific info */
    lb.ts = (u64)time(NULL);
    lb.session = g_session;

    /* change to a new log file */
    __osd_log_rename();

    /* do write */
    __osd_log_pair_write(&lb);
}

/* Write a magic pair end in log file
 */
void osd_exit_normal(void)
{
    struct log_entry le;

    memset(&le, 0, sizeof(le));
    le.magic = LOG_END_MAGIC;
    le.session = g_session;

    /* set up session info */
    le._end.addnr = atomic_read(&hoo.storage.lm.addnr);
    le._end.delnr = atomic_read(&hoo.storage.lm.delnr);
    le.ts = (u64)time(NULL);

    __osd_log_pair_write(&le);
}

int osd_storage_init(void)
{
    char path[256] = {0,};
    int err = 0, i;

    /* set the fd limit firstly */
    struct rlimit rli = {
        .rlim_cur = 65536,
        .rlim_max = 70000,
    };
    err = setrlimit(RLIMIT_NOFILE, &rli);
    if (err) {
        hvfs_err(osd, "setrlimit failed w/ %s\n", strerror(errno));
        hvfs_warning(osd, "%sStorage Server has FD limit! To overcome "
                     "this limit, please use a powerful UID to run this"
                     " process.%s\n", 
                     HVFS_COLOR_RED, HVFS_COLOR_END);
    }

    /* check the OSD site directory */
    sprintf(path, "%s/%lx", hoo.conf.osd_home, hoo.site_id);
    err = osd_storage_dir_make_exist(path);
    if (err) {
        hvfs_err(osd, "dir %s do not exist.\n", path);
        return -ENOTEXIST;
    }

    xlock_init(&g_version_lock);

    /* setup the session id */
    g_session = lib_random(INT_MAX);

    /* setup the storage manager */
    xlock_init(&hoo.storage.objlog_fd_lock);
    atomic_set(&hoo.storage.lm.addnr, 0);
    atomic_set(&hoo.storage.lm.delnr, 0);
    INIT_LIST_HEAD(&hoo.storage.lm.add);
    INIT_LIST_HEAD(&hoo.storage.lm.del);
    xlock_init(&hoo.storage.lm.add_lock);
    xlock_init(&hoo.storage.lm.del_lock);

    INIT_LIST_HEAD(&hoo.storage.sm.head);
    xlock_init(&hoo.storage.sm.lock);

    hoo.storage.am.store_array = hoo.conf.osd_storages_array;
    hoo.storage.am.array_size = hoo.conf.osd_storages_array_size;
    hoo.storage.am.sa.rra.cur = 0;

    /* setup the OGA manager */
    if (!hoo.om.hsize) {
        hoo.om.hsize = HVFS_OSD_OM_HSIZE;
    }
    INIT_LIST_HEAD(&hoo.om.changed);
    INIT_LIST_HEAD(&hoo.om.changed_saving);
    hoo.om.ht = xzalloc(hoo.om.hsize * sizeof(struct regular_hash));
    if (!hoo.om.ht) {
        hvfs_err(osd, "xzalloc() OGA hash table failed.\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hoo.om.hsize; i++) {
        INIT_HLIST_HEAD(&(hoo.om.ht + i)->h);
        xlock_init(&(hoo.om.ht + i)->lock);
    }

    /* check whether this storage is clean */
    err = osd_storage_is_clean();
    if (err) {
        hvfs_err(osd, "storage '%s' is_clean() failed w/ %d\n",
                 path, err);
        goto out;
    }

out:
    return err;
}

void osd_storage_destroy(void)
{
    /* close the files */
    if (hoo.conf.lf_file)
        fclose(hoo.conf.lf_file);
    if (hoo.conf.pf_file)
        fclose(hoo.conf.pf_file);
}

/* Document for OGA manager.
 *
 * We only need oga hash entry add, delete, and update!
 */
static inline
u32 __om_hash(struct objid id)
{
    u32 u1 = JSHash((char *)&id.uuid, sizeof(id.uuid));
    u32 u2 = RSHash((char *)&id.bid, sizeof(id.bid));

    return (u1 ^ u2) % hoo.om.hsize;
}

static
int __om_add2changed(struct om_entry *oe, int upd_or_del)
{
    struct om_changed_entry *oce;

    xlock_lock(&hoo.om.changed_lock);
    if (hoo.om.report_type == OM_REPORT_ALL){
        xlock_unlock(&hoo.om.changed_lock);
        return 0;
    }
    xlock_unlock(&hoo.om.changed_lock);
    
    oce = xzalloc(sizeof(*oce));
    if (!oce) {
        hvfs_err(osd, "xzalloc() om_changed_entry failed\n");
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&oce->list);
    oce->id = oe->id;
    oce->upd_or_del = upd_or_del;

    /* add to the changed list unless for the 1st scan */
    if (hoo.state < HOO_STATE_RUNNING) 
        return 0;
    xlock_lock(&hoo.om.changed_lock);
    list_add_tail(&oce->list, &hoo.om.changed);
    xlock_unlock(&hoo.om.changed_lock);
    hvfs_info(osd, "ADD obj %lx.%x to changed list for '%s'\n",
              oe->id.uuid, oe->id.bid, (upd_or_del ? "DELETE" : "UPDATE"));
    osd_reporter_schedule();

    return 0;
}

static
int __om_insert_entry(struct om_entry *oe)
{
    struct regular_hash *rh;
    struct om_entry *tpos;
    struct hlist_node *pos;
    int i;

    i = __om_hash(oe->id);
    rh = hoo.om.ht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (OBJID_EQUAL(tpos->id, oe->id)) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&oe->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i)
        return -EEXIST;

    return 0;
}

/* Return value: >= 0 means valid dev, -1 means invalid dev
 */
static
int __om_find_dev(struct objid id)
{
    struct regular_hash *rh;
    struct om_entry *oe = NULL;
    struct hlist_node *pos;
    int i, dev = -1;

    i = __om_hash(id);
    rh = hoo.om.ht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(oe, pos, &rh->h, hlist) {
        if (OBJID_EQUAL(oe->id, id)) {
            /* get the dev */
            dev = oe->dev;
            hvfs_info(osd, "FIND obj %lx.%x => DEV %d\n",
                      id.uuid, id.bid, dev);
            i = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    return dev;
}

static
int __om_add_entry(struct objid id, int dev)
{
    struct om_entry *oe;
    int err = 0;

    oe = xzalloc(sizeof(*oe));
    if (!oe) {
        hvfs_err(osd, "unable to allocate a new object entry.\n");
        return -ENOMEM;
    }

    INIT_HLIST_NODE(&oe->hlist);
    oe->id = id;
    oe->dev = dev;

    /* try to add it to the hash table */
    err = __om_insert_entry(oe);
    if (err == -EEXIST) {
        xfree(oe);
    } else {
        /* FIXME ERR: generate a update log entry here */
        __om_add2changed(oe, OM_UPDATE);
    }

    return err;
}

/* Return value: 0=> ok, otherwise=>fail
 */
int __om_del_entry(struct objid id)
{
    struct regular_hash *rh;
    struct om_entry *tpos = NULL;
    struct hlist_node *pos, *n;
    int i;

    i = __om_hash(id);
    rh = hoo.om.ht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (OBJID_EQUAL(tpos->id, id)) {
            hlist_del_init(&tpos->hlist);
            i = 1;
            /* FIXME ERR: generate a update log entry here */
            __om_add2changed(tpos, OM_DELETE);
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (i)
        xfree(tpos);

    return !i;
}

/* drop all the active entries
 */
void __om_clear()
{
    struct regular_hash *rh;
    struct om_entry *tpos = NULL;
    struct hlist_node *pos, *n;
    int i;

    for (i = 0; i < hoo.om.hsize; i++) {
        rh = hoo.om.ht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            hlist_del_init(&tpos->hlist);
            xfree(tpos);
        }
        xlock_unlock(&rh->lock);
    }
}

/* __om_update_entry() will add the entry if it doesn't exist
 */
int __om_update_entry(struct objid id, int dev)
{
    struct regular_hash *rh;
    struct om_entry *oe = NULL;
    struct hlist_node *pos;
    int i, err = 0;

    i = __om_hash(id);
    rh = hoo.om.ht + i;

retry:
    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(oe, pos, &rh->h, hlist) {
        if (OBJID_EQUAL(oe->id, id)) {
            /* update it! */
            if (oe->id.len != id.len ||
                oe->id.error != id.error ||
                oe->id.sweeped != id.sweeped) {
                oe->id = id;
                oe->dev = dev;
                /* generate a update log entry here */
                err = __om_add2changed(oe, OM_UPDATE);
            }
            i = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);
    if (!i) {
        /* this means we should insert a new entry now */
        int err2 = __om_add_entry(id, dev);
        if (err2 == -EEXIST)
            goto retry;
    }
    if (err) {
        hvfs_err(osd, "OGA manager update entry %lx.%x failed w/ %d\n",
                 id.uuid, id.bid, err);
    }

    return err;
}

/* user must set id.uuid, id.bid!
 */
int osd_update_objid(char *fpath, int fd, struct objid *id, int length)
{
    OSD_FH rfh;
    int err = 0, bl, bw, br;

    /* read the FH from disk */
    bl = 0;
    do {
        br = pread(fd, (void *)&rfh + bl, OSD_FH_SIZE - bl, bl);
        if (br < 0) {
            hvfs_err(osd, "read OSD_FH failed w/ %d offset %d\n",
                     errno, bl);
            err = -errno;
            goto out;
        } else if (br == 0) {
            break;
        }
        bl += br;
    } while (bl < OSD_FH_SIZE);
    
    if (!rfh.uuid) {
        rfh.uuid = id->uuid;
        rfh.bid = id->bid;
        rfh.version = id->version;
        rfh.consistency = id->consistency;
    }

    rfh.len = id->len = length;
    xlock_lock(&g_version_lock);
    rfh.version++;
    xlock_unlock(&g_version_lock);
    id->version = rfh.version;
    /* update CRC/digest? */
    
    /* write the FH to disk */
    bl = 0;
    do {
        bw = pwrite(fd, (void *)&rfh + bl, OSD_FH_SIZE - bl, bl);
        if (bw < 0) {
            hvfs_err(osd, "pwrite to fd %d failed w/ %d\n",
                     fd, errno);
            err = -errno;
            break;
        }
        bl += bw;
    } while (bl < OSD_FH_SIZE);

out:
    return err;
}

/* osd_storage_write() write thte data region to device
 */
int osd_storage_write(struct objid *obj, void *data, u32 offset, 
                      int length, int *dev)
{
    char path[PATH_MAX];
    int fd, err = 0, bl, bw;

    /* Step 1: get the target obj file path */
    *dev = __om_find_dev(*obj);
    if (*dev < 0) {
        osd_get_obj_path(*obj, osd_storage_selector(dev), path);
        osd_obj_path_valid(path);
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(*dev), path);
    }

    /* Step 2: try to open the file */
    fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
checkit:
    if (fd < 0) {
        if (errno == EEXIST) {
            /* this file does exist, just open it */
            fd = open(path, O_RDWR);
            goto checkit;
        }
        hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                 path, errno, strerror(errno));
        err = -errno;
        goto out;
    }

    /* Step 3: try to write the data region */
    bl = 0;
    do {
        bw = pwrite(fd, data + bl, length - bl, OSD_FH_SIZE + offset + bl);
        if (bw < 0) {
            hvfs_err(osd, "pwrite to fd %d failed w/ %d\n",
                     fd, errno);
            err = -errno;
            goto out_close;
        }
        bl += bw;
    } while (bl < length);

    /* Step 3.5: update the objid */
    osd_update_objid(path, fd, obj, length);

    /* Step 4: close the file now */
    atomic64_inc(&hoo.prof.storage.wreq);
    atomic64_add(length, &hoo.prof.storage.wbytes);

out_close:
    close(fd);
out:
    return err;
}

/* osd_storage_read() read the data region from device
 *
 * Return value: >=0 means valid read, <0 means error
 */
static inline 
int __osd_storage_read(struct objid *obj, void **data, u32 offset, int length, 
                       int version)
{
    char path[PATH_MAX];
    int fd = -1, err = 0, bl, br;

    /* Step 1: get the target obj file path */
    err = __om_find_dev(*obj);
    if (err < 0) {
#ifdef HVFS_OSD_STORE_DETECT_SLOW
        int i;
        
        for (i = 0; i < hoo.storage.am.array_size; i++) {
            osd_get_obj_path(*obj, osd_storage_iterator(i), path);
            
            /* Step 2: try to open the file */
            fd = open(path, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT)
                    continue;
                hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                         path, errno, strerror(errno));
                err = -errno;
                goto out;
            } else {
                break;
            }
        }

        if (fd < 0) {
            hvfs_err(osd, "No valid storage directory?\n");
            err = -ENOENT;
            goto out;
        }
#else
        err = -ENOENT;
        goto out;
#endif
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(err), path);

        /* Step 2: try to open the file */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                     path, errno, strerror(errno));
            err = -errno;
            goto out;
        }
    }

    if (version != -1) {
        OSD_FH rfh;

        /* read the FH from disk */
        bl = 0;
        do {
            br = pread(fd, (void *)&rfh + bl, OSD_FH_SIZE - bl, bl);
            if (br < 0) {
                hvfs_err(osd, "read OSD_FH failed w/ %d offset %d\n",
                         errno, bl);
                err = -errno;
                goto out_close;
            } else if (br == 0) {
                break;
            }
            bl += br;
        } while (bl < OSD_FH_SIZE);

        if (rfh.version != version) {
            err = -EBADV;
            goto out_close;
        }
        if (length < 0)
            length = rfh.len;
    }
    
    /* prepare the data region if needed */
    if (length < 0) {
        /* probe the file length */
        struct stat buf;
        if (stat(path, &buf) < 0) {
            hvfs_err(osd, "Failed to stat file '%s' w/ %s(%d)\n",
                     path, strerror(errno), errno);
            err = -errno;
            goto out_close;
        }
        length = buf.st_size - OSD_FH_SIZE;
        
        /* alloc the data region */
        if (*data)
            xfree(*data);
        *data = xmalloc(length);
        if (!*data) {
            hvfs_err(osd, "xmalloc() data region %d bytes failed\n",
                     length);
            err = -ENOMEM;
            goto out_close;
        }
    }

    /* Step 3: try to read the data region */
    bl = 0;
    do {
        br = pread(fd, *data + bl, length - bl, OSD_FH_SIZE + offset + bl);
        if (br < 0) {
            hvfs_err(osd, "pread failed w/ %d (%s)\n", 
                     errno, strerror(errno));
            err = -errno;
            goto out_close;
        } else if (br == 0) {
            hvfs_warning(osd, "pread to EOF w/ offset %d\n", offset + bl);
            break;
        }
        bl += br;
    } while (bl < length);

    /* the total valid data length is in bl */
    err = bl;

    /* Step 4: close the file now */
    atomic64_inc(&hoo.prof.storage.rreq);
    atomic64_add(length, &hoo.prof.storage.rbytes);
out_close:
    close(fd);
out:
    return err;
}

/* Return Any Version */
int osd_storage_read(struct objid *obj, void **data, u32 offset, int length)
{
    hvfs_err(osd, "ANY MATCH read\n");
    return __osd_storage_read(obj, data, offset, length, -1);
}

/* Return Strict Version
 */
int osd_storage_read_strict(struct objid *obj, void **data, u32 offset, int length,
                            int version)
{
    hvfs_err(osd, "STRICT read\n");
    return __osd_storage_read(obj, data, offset, length, version);
}

/* osd_storage_sync() sync the data region or the whole file
 */
int osd_storage_sync(struct objid *obj, u32 offset, u32 length)
{
    char path[PATH_MAX];
    int fd = -1, err = 0;

    /* Step 1: get the target obj file path */
    err = __om_find_dev(*obj);
    if (err < 0) {
#ifdef HVFS_OSD_STORE_DETECT_SLOW
        int i;
        
        for (i = 0; i < hoo.storage.am.array_size; i++) {
            osd_get_obj_path(*obj, osd_storage_iterator(i), path);
            
            /* Step 2: try to open the file */
            fd = open(path, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT)
                    continue;
                hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                         path, errno, strerror(errno));
                err = -errno;
                goto out;
            } else {
                break;
            }
        }

        if (fd < 0) {
            hvfs_err(osd, "No valid storage directory?\n");
            err = -ENOENT;
            goto out;
        }
#else
        err = -ENOENT;
        goto out;
#endif
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(err), path);

        /* Step 2: try to open the file */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                     path, errno, strerror(errno));
            err = -errno;
            goto out;
        }
    }

    /* Step 3: try to sync the data region
     * At now, we just sync the whole obj file
     */
    err = fsync(fd);
    if (err) {
        hvfs_err(osd, "fsync() file '%s' failed w/ %d (%s)\n",
                 path, errno, strerror(errno));
        err = -errno;
        goto out_close;
    }

    atomic64_inc(&hoo.prof.storage.wreq);
out_close:
    close(fd);

out:
    return err;
}

/* osd_storage_trunc() truncate the file w/o considering OSD_FH_SIZE, caller
 * should not add OSD_FH_SIZE
 */
int osd_storage_trunc(struct objid *obj, off_t length, int *dev)
{
    char path[PATH_MAX];
    int fd = -1, err = 0;

    /* Step 1: get the target obj file path */
    *dev = __om_find_dev(*obj);
    if (*dev < 0) {
#ifdef HVFS_OSD_STORE_DETECT_SLOW
        int i;
        
        for (i = 0; i < hoo.storage.am.array_size; i++) {
            osd_get_obj_path(*obj, osd_storage_iterator(i), path);
            
            /* Step 2: try to open the file */
            fd = open(path, O_RDWR);
            if (fd < 0) {
                if (errno == ENOENT)
                    continue;
                hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                         path, errno, strerror(errno));
                err = -errno;
                goto out;
            } else {
                *dev = i;
                break;
            }
        }

        if (fd < 0) {
            hvfs_err(osd, "No valid storage directory?\n");
            err = -ENOENT;
            goto out;
        }
#else
        err = -ENOENT;
        goto out;
#endif
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(*dev), path);

        /* Step 2: try to open the file */
        fd = open(path, O_RDWR);
        if (fd < 0) {
            hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                     path, errno, strerror(errno));
            err = -errno;
            goto out;
        }
    }

    /* Step 3: try to truncate the file
     */
    err = ftruncate(fd, length + OSD_FH_SIZE);
    if (err) {
        hvfs_err(osd, "ftruncate() file '%s' to %ld bytes failed w/ %d (%s)\n",
                 path, length, errno, strerror(errno));
        err = -errno;
        goto out_close;
    }

    /* Step 3.5: update the objid */
    osd_update_objid(path, fd, obj, length);

    atomic64_inc(&hoo.prof.storage.wreq);
out_close:
    close(fd);

out:
    return err;
}

int osd_storage_del(struct objid *obj)
{
    char path[PATH_MAX];
    int fd = -1, err = 0;

    /* Step 1: get the target obj file path */
    err = __om_find_dev(*obj);
    if (err < 0) {
#ifdef HVFS_OSD_STORE_DETECT_SLOW
        int i;
        
        for (i = 0; i < hoo.storage.am.array_size; i++) {
            osd_get_obj_path(*obj, osd_storage_iterator(i), path);
            
            /* Step 2: try to open the file */
            fd = open(path, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT)
                    continue;
                hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                         path, errno, strerror(errno));
                err = -errno;
                goto out;
            } else {
                break;
            }
        }

        if (fd < 0) {
            hvfs_err(osd, "No valid storage directory?\n");
            err = -ENOENT;
            goto out;
        }
#else
        err = -ENOENT;
        goto out;
#endif
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(err), path);

        /* Step 2: try to open the file */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                     path, errno, strerror(errno));
            err = -errno;
            goto out;
        }
    }

    /* close the file, begin unlink */
    close(fd);
    err = unlink(path);
    if (err) {
        hvfs_err(osd, "unlink() file '%s' failed w/ %d (%s)\n",
                 path, errno, strerror(errno));
        err = -errno;
        goto out;
    }

    atomic64_inc(&hoo.prof.storage.wreq);

out:
    return err;
}

int osd_storage_getlen(struct objid *obj)
{
    char path[PATH_MAX];
    struct stat buf;
    int fd = -1, err = 0;

    /* Step 1: get the target obj file path */
    err = __om_find_dev(*obj);
    if (err < 0) {
#ifdef HVFS_OSD_STORE_DETECT_SLOW
        int i;
        
        for (i = 0; i < hoo.storage.am.array_size; i++) {
            osd_get_obj_path(*obj, osd_storage_iterator(i), path);
            
            /* Step 2: try to open the file */
            fd = open(path, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT)
                    continue;
                hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                         path, errno, strerror(errno));
                err = -errno;
                goto out;
            } else {
                break;
            }
        }

        if (fd < 0) {
            hvfs_err(osd, "No valid storage directory?\n");
            err = -ENOENT;
            goto out;
        }
#else
        err = -ENOENT;
        goto out;
#endif
    } else {
        osd_get_obj_path(*obj, osd_storage_iterator(err), path);

        /* Step 2: try to open the file */
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            hvfs_err(osd, "open() file '%s' failed w/ %d (%s)\n",
                     path, errno, strerror(errno));
            err = -errno;
            goto out;
        }
    }
    
    /* probe the file length */
    if (stat(path, &buf) < 0) {
        hvfs_err(osd, "Failed to stat file '%s' w/ %s(%d)\n",
                 path, strerror(errno), errno);
        err = -errno;
        goto out_close;
    }
    err = buf.st_size;

out_close:
    close(fd);

out:
    return err;
}

static inline
struct obj_gather *__enlarge_og(struct obj_gather *in)
{
#define OG_DEFAULT_SIZE         (512)
    void *out = NULL;
    
    if (!in) {
        return NULL;
    } else if (in->psize == 0) {
        /* totally new alloc */
        out = xzalloc(OG_DEFAULT_SIZE * sizeof(struct objid));
        if (!out) {
            hvfs_err(osd, "Failed to alloc new OG region\n");
            return NULL;
        }
        in->psize = OG_DEFAULT_SIZE;
        in->ids = out;
    } else {
        /* realloc a region */
        out = xrealloc(in->ids, (in->psize + OG_DEFAULT_SIZE) * 
                       sizeof(struct objid));
        if (!out) {
            hvfs_err(osd, "Failed to realloc new OG region\n");
            return NULL;
        }
        in->psize += OG_DEFAULT_SIZE;
        in->ids = out;
    }

    return in;
}

static inline
void __free_og(struct obj_gather *og)
{
    if (og->psize > 0)
        xfree(og->ids);
}

typedef void (*__osd_dir_iterate_func)(char *path, char *name, void *data);

void __gather_statfs(char *path, char *name, void *data)
{
    struct statfs *s = (struct statfs *)data;

    s->f_spare[0]++;
    hvfs_debug(osd, "statfs: %s %ld\n", name, s->f_spare[0]);
}

void __gather_blocks(char *path, char *name, void *data)
{
    struct obj_gather_all *oga = (struct obj_gather_all *)data;
    char pathname[PATH_MAX];
    char *n, *s = NULL, *p;
    OSD_FH rfh;
    int fd, bl = 0, br;

    if (!oga)
        return;
    if (oga->add.asize >= oga->add.psize) {
        void *out = __enlarge_og(&oga->add);
        if (!out) {
            hvfs_err(osd, "enlarge OG region failed, block %s leaking\n",
                     name);
            return;
        }
    }
    /* parse name to objid */
    n = strdup(name);
    if (!n) {
        hvfs_err(osd, "duplicate the block NAME failed\n");
        return;
    }
    p = strtok_r(n, ".\n", &s);
    if (!p) {
        hvfs_err(osd, "no objid.uuid find in NAME: %s\n", n);
        goto out;
    }
    oga->add.ids[oga->add.asize].id.uuid = strtoul(p, NULL, 16);
    p = strtok_r(NULL, ".\n", &s);
    if (!p) {
        hvfs_err(osd, "no objid.bid find in NAME: %s\n", n);
        goto out;
    }
    oga->add.ids[oga->add.asize].id.bid = strtoul(p, NULL, 16);

    /* FIXME: get block length */
    sprintf(pathname, "%s/%s", path, name);
    fd = open(pathname, O_RDONLY);
    if (fd < 0) {
        hvfs_err(osd, "open() file %s failed w/ %d (%s)\n",
                 pathname, errno, strerror(errno));
        goto out;
    }
    
    do {
        br = pread(fd, (void *)&rfh + bl, OSD_FH_SIZE - bl, bl);
        if (br < 0) {
            hvfs_err(osd, "read OSD_FH failed w/ %d offset %d\n",
                     errno, bl);
            goto out;
        } else if (br == 0) {
            break;
        }
        bl += br;
    } while (bl < OSD_FH_SIZE);

    if (!rfh.uuid) {
        /* uninitialized FH? */
        hvfs_err(osd, "Invalid OSD_FH for %ld.%d\n",
                 oga->add.ids[oga->add.asize].id.uuid,
                 oga->add.ids[oga->add.asize].id.bid);
        oga->add.ids[oga->add.asize].id.error = 1;
    }
    oga->add.ids[oga->add.asize].id.version = rfh.version;
    oga->add.ids[oga->add.asize].id.len = rfh.len;
    oga->add.ids[oga->add.asize].dev = oga->cur;
    
    oga->add.asize++;
    
out:
    xfree(n);
}

static inline 
int __ignore_self_parent(char *dir)
{
    if ((strcmp(dir, ".") == 0) ||
        (strcmp(dir, "..") == 0)) {
        return 0;
    }
    return 1;
}

/* iterate over the directory tree and trigger the func on each REG file
 */
int __osd_dir_iterate(char *oldpath, char *name, __osd_dir_iterate_func func, 
                      void *data)
{
    char path[PATH_MAX];
    struct dirent entry;
    struct dirent *result;
    DIR *d;
    int err = 0;

    sprintf(path, "%s/%s", oldpath, name);
    d = opendir(path);
    if (!d) {
        hvfs_err(osd, "opendir(%s) failed w/ %s(%d)\n",
                 path, strerror(errno), errno);
        goto out;
    }

    for (err = readdir_r(d, &entry, &result);
         err == 0 && result != NULL;
         err = readdir_r(d, &entry, &result)) {
        /* ok, we should iterate over the dirs */
        if (entry.d_type == DT_DIR && __ignore_self_parent(entry.d_name)) {
            err = __osd_dir_iterate(path, entry.d_name, func, data);
            if (err) {
                hvfs_err(osd, "Dir %s: iterate to func failed w/ %d\n",
                         entry.d_name, err);
            }
        } else if (entry.d_type == DT_REG) {
            /* call the function now */
            func(path, entry.d_name, data);
        } else if (entry.d_type == DT_UNKNOWN) {
            hvfs_warning(osd, "File %s with unknown file type?\n",
                         entry.d_name);
        }
    }
    closedir(d);

out:
    return err;
}

/* osd_storage_statfs() scan the storage directory and count the file number,
 * block number, etc
 *
 * FIXME: add another level directory for DIFFERENT DEVICEs.
 */
int osd_storage_statfs(struct statfs *s)
{
    char path[PATH_MAX];
    struct dirent entry;
    struct dirent *result;
    DIR *d;
    int err = 0;

    /* Step 1: open the home directory, get the first-level entries */
    sprintf(path, "%s/%lx", hoo.conf.osd_home, hoo.site_id);
    d = opendir(path);
    if (!d) {
        hvfs_err(osd, "opendir(%s) failed w/ %s(%d)\n",
                 path, strerror(errno), errno);
        goto out;
    }
    /* Step 2: iterate over the first-level entries */
    for (err = readdir_r(d, &entry, &result);
         err == 0 && result != NULL;
         err = readdir_r(d, &entry, &result)) {
        if (entry.d_type == DT_DIR && __ignore_self_parent(entry.d_name)) {
            /* ok, we should iterate over the second-level entries */
            err = __osd_dir_iterate(path, entry.d_name, __gather_statfs,
                                    (void *)s);
            if (err) {
                hvfs_err(osd, "Dir %s: iterated to statfs failed w/ %d\n",
                         entry.d_name, err);
            }
        } else if (entry.d_type == DT_UNKNOWN) {
            hvfs_warning(osd, "File %s with unknown file type?\n", 
                         entry.d_name);
        }
    }
    closedir(d);

out:
    return err;
}

/* Return value: 1 => ok ; 0 => no_change
 */
int osd_om_state_change(u8 target_state, u8 target_send)
{
    int ok = 0, do_report = 0;
    
    hvfs_debug(osd, "from %d.%d to %d.%d\n", hoo.om.report_type, hoo.om.should_send,
               target_state, target_send);
    xlock_lock(&hoo.om.changed_lock);
    switch (hoo.om.report_type) {
    case OM_REPORT_ALL:
        ASSERT(hoo.om.should_send == OM_REPORT_PAUSE, osd);
        if (target_state == OM_REPORT_BEGIN_SCAN &&
            target_send == OM_REPORT_PAUSE) {
            hoo.om.report_type = OM_REPORT_BEGIN_SCAN;
            ok = 1;
        } else {
            hvfs_err(osd, "Invalid state change from %d.%d to %d.%d, rejected!\n",
                     hoo.om.report_type, hoo.om.should_send,
                     target_state, target_send);
        }
        break;
    case OM_REPORT_BEGIN_SCAN:
        if (target_state == OM_REPORT_END_SCAN) {
            ASSERT(hoo.om.should_send == OM_REPORT_PAUSE, osd);
            hoo.om.report_type = OM_REPORT_END_SCAN;
            hoo.om.should_send = target_send;
            ok = 1;
        } else {
            hvfs_warning(osd, "There is an active OBJ report scan process! "
                         "Back-off!\n");
        }
        break;
    case OM_REPORT_END_SCAN:
        if (target_state == OM_REPORT_DIFF) {
            ASSERT(hoo.om.should_send == OM_REPORT_ACTIVE, osd);
            ASSERT(target_send == OM_REPORT_ACTIVE, osd);
            hoo.om.report_type = OM_REPORT_DIFF;
            ok = 1;
        } else if (target_state == OM_REPORT_END_SCAN) {
            hoo.om.should_send = target_send;
        } else {
            hvfs_err(osd, "Invalid state change from %d.%d to %d.%d, rejected!\n",
                     hoo.om.report_type, hoo.om.should_send,
                     target_state, target_send);
        }
        break;
    case OM_REPORT_DIFF:
        if (target_state == OM_REPORT_BEGIN_SCAN &&
            target_send == OM_REPORT_PAUSE) {
            hoo.om.report_type = OM_REPORT_BEGIN_SCAN;
            hoo.om.should_send = OM_REPORT_PAUSE;
            /* move changed list to saving list */
            list_replace_init(&hoo.om.changed, &hoo.om.changed_saving);
            do_report = 1;
            ok = 1;
        } else {
            hvfs_err(osd, "Invalid state change from %d.%d to %d.%d, rejected!\n",
                     hoo.om.report_type, hoo.om.should_send,
                     target_state, target_send);
        }
        break;
    default:
        hvfs_err(osd, "Invalid state change from %d.%d to %d.%d, rejected!\n",
                 hoo.om.report_type, hoo.om.should_send,
                 target_state, target_send);
    }

    xlock_unlock(&hoo.om.changed_lock);

    if (do_report) {
        __do_obj_diff_report();
    }

    return ok;
}

/* osd_storage_process_report() scan the storage directory and generate the
 * obj_gather_all structure.
 */
struct obj_gather_all *osd_storage_process_report()
{
    char path[PATH_MAX];
    struct dirent entry;
    struct dirent *result;
    struct obj_gather_all *oga;
    DIR *d;
    int err = 0, i;

    /* Change the OM state now */
    if (osd_om_state_change(OM_REPORT_BEGIN_SCAN, OM_REPORT_PAUSE)) {
        hvfs_info(osd, "OSD store BEGIN fully scan ...\n");
    } else {
        return ERR_PTR(-EFAULT);
    }

    /* Step 0: alloc the block info array */
    oga = xzalloc(sizeof(*oga));
    if (!oga) {
        hvfs_err(osd, "Alloc obj_gather_all failed!\n");
        err = -ENOMEM;
        goto out;
    }

    /* Step 1: open the home directory, get the first-level entries */
    for (i = 0; i < osd_storage_array_size(); i++) {
        /* set the current dev */
        oga->cur = i;
        /* select a active store */
        sprintf(path, "%s/%lx", osd_storage_iterator(i), hoo.site_id);
        hvfs_err(osd, "PROBE dev path: %s\n", path);
        d = opendir(path);
        if (!d) {
            hvfs_err(osd, "opendir(%s) failed w/ %s(%d)\n",
                     path, strerror(errno), errno);
            err = -errno;
            goto out;
        }
        /* Step 2: iterate over the first-level entries */
        for (err = readdir_r(d, &entry, &result);
             err == 0 && result != NULL;
             err = readdir_r(d, &entry, &result)) {
            if (entry.d_type == DT_DIR && __ignore_self_parent(entry.d_name)) {
                /* ok, we should iterate over the second-level entries */
                err = __osd_dir_iterate(path, entry.d_name, __gather_blocks,
                                        (void *)oga);
                if (err) {
                    hvfs_err(osd, "Dir %s: iterated to gather blocks failed w/ %d\n",
                             entry.d_name, err);
                }
            } else if (entry.d_type == DT_UNKNOWN) {
                hvfs_warning(osd, "File %s with unknown file type?\n", 
                             entry.d_name);
            }
        }
        closedir(d);
    }

out:
    if (osd_om_state_change(OM_REPORT_END_SCAN, OM_REPORT_PAUSE)) {
        hvfs_info(osd, "OSD store END fully scan (still PAUSE) ...\n");
    }
    if (err) {
        if (oga) {
            __free_og(&oga->add);
            __free_og(&oga->rmv);
            xfree(oga);
        }
        return ERR_PTR(err);
    }
    
    return oga;
}
