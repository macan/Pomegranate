/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-13 20:57:00 macan>
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
#include "mdsl.h"

struct fdhash_entry
{
    struct hlist_node list;
    u64 uuid;
    u64 arg;
    int type;
    int fd;
};

int mdsl_storage_init(void)
{
    if (!hmo.conf.storage_fdhash_size) {
        hmo.conf.storage_fdhash_size = MDSL_STORAGE_FDHASH_SIZE;
    }

    hmo.storage.fdhash = xmalloc(hmo.conf.storage_fdhash_size *
                                 sizeof(struct regular_hash));
    if (!hmo.storage.fdhash) {
        hvfs_err(mdsl, "alloc fd hash table failed.\n");
        return -ENOMEM;
    }
    /* init the hash table */
    for (i = 0; i < hmo.conf.storage_fdhash_size; i++) {
        INIT_HLIST_HEAD(&(hmo.storage.fdhash + i)->h);
        xlock_init(&(hmo.storage.fdhash + i)->lock);
    }

    return 0;
}

int mdsl_storage_fd_lookup(u64 duuid, int ftype, u64 arg)
{
    struct fdhash_entry *fde;
    struct hlist_node *pos;
    int idx;
    
    idx = hvfs_hash_fdht(duuid, ftype);
    xlock_lock(&(hmo.storage.fdhash + idx)->lock);
    hlist_for_each_entry(fde, pos, &(hmo.storage.fdhash + idx)->h, list) {
        if (duuid == fde->uuid && ftype == fde->type && arg == fde->arg) {
            xlock_unlock(&(hmo.storage.fdhash + idx)->lock);
            return fde->fd;
        }
    }
    xlock_unlock(&(hmo.storage.fdhash + idx)->lock);

    return -1;
}

int mdsl_storage_fd_lookup_create(u64 duuid, int fdtype, u64 arg)
{
    struct fdhash_entry *fde;
    int fd;
    
    fd = mdsl_storage_fd_lookup(duuid, fdtype, arg);
    if (fd > 0)
        return fd;

    /* we should open the file now */
    switch (fdtype) {
    case MDSL_STORAGE_MD:
        sprintf(path, "%s/%ld/md", HVFS_MDSL_HOME, duuid);
        break;
    case MDSL_STORAGE_ITB:
        sprintf(path, "%s/%ld/itb-%ld", HVFS_MDSL_HOME, duuid, arg);
        break;
    case MDSL_STORAGE_RANGE:
        sprintf(path, "%s/%ld/range-%ld", HVFS_MDSL_HOME, duuid, arg);
        break;
    case MDSL_STORAGE_DATA:
        sprintf(path, "%s/%ld/data-%ld", HVFS_MDSL_HOME, duuid, arg);
        break;
    case MDSL_STORAGE_DIRECTW:
        sprintf(path, "%s/%ld/directw", HVFS_MDSL_HOME, duuid);
        break;
    case MDSL_STORAGE_LOG:
        sprintf(path, "%s/log", HVFS_MDSL_HOME);
        break;
    case MDSL_STORAGE_SPLIT_LOG:
        sprintf(path, "%s/split_log", HVFS_MDSL_HOME);
        break;
    case MDSL_STORAGE_TXG:
        sprintf(path, "%s/txg", HVFS_MDSL_HOME);
        break;
    case MDSL_STORAGE_TMP_TXG:
        sprintf(path, "%s/tmp_txg", HVFS_MDSL_HOME);
        break;
    default:
        hvfs_err(mdsl, "Invalid file type provided, check your codes.\n");
    }

    /* NOTE:
     *
     * 1. itb/data file should be written with self buffering through the mem
     *    window
     *
     * 2. itb/data file should be read through the mem window
     *
     * 3. md/range file should be read/written with mem window
     */

    return 0;
    
}
