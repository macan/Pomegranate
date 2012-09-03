/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-14 17:26:42 macan>
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

static u32 g_session = 0;

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

void osd_get_obj_path(struct objid oid, char *path)
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
    sprintf(path, "%s/%.4s/%s/%lx.%x", hoo.conf.osd_home, prefix, 
            &prefix[OSD_DEFAULT_PREFIX_LEN],
            oid.uuid, oid.bid);
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
    int err = 0;

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

