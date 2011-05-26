/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-24 05:56:33 macan>
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

#ifndef __FUSE_STORE_H__
#define __FUSE_STORE_H__

#include "hvfs.h"

/* hvfs_datastore refer to a local directory as a storage
 */
struct hvfs_datastore
{
    struct list_head list;
    
#define LLFS_TYPE_FREE          0x00
#define LLFS_TYPE_EXT3          0x01
#define LLFS_TYPE_EXT4          0x02
#define LLFS_TYPE_NFS           0x03
#define LLFS_TYPE_NFS4          0x04
#define LLFS_TYPE_CEPH          0x05
#define LLFS_TYPE_ORANGEFS      0x06

#define LLFS_TYPE_ANY           0x40
#define LLFS_TYPE_ERR           0x80

#define HVFS_DSTORE_FREE        0x00
#define HVFS_DSTORE_VALID       0x01
    u32 type, state;
    char pathname[HVFS_MAX_NAME_LEN];
};

struct hvfs_datastore_mgr
{
    struct list_head g_dstore_list;
    int nr;                     /* # of config-ed data store */
};

static inline
char *hvfs_type_convert(u32 type)
{
    switch (type) {
    case LLFS_TYPE_FREE:
        return "nofs";
    case LLFS_TYPE_EXT3:
        return "ext3";
    case LLFS_TYPE_EXT4:
        return "ext4";
    case LLFS_TYPE_NFS:
        return "nfs";
    case LLFS_TYPE_NFS4:
        return "nfs4";
    case LLFS_TYPE_CEPH:
        return "ceph";
    case LLFS_TYPE_ORANGEFS:
        return "orangefs";
    case LLFS_TYPE_ANY:
        return "anyfs";
    default:
        return "errfs";
    }
}

static inline
u32 hvfs_type_revert(char *type)
{
    if (!strcmp(type, "ext3")) {
        return LLFS_TYPE_EXT3;
    } else if (!strcmp(type, "ext4")) {
        return LLFS_TYPE_EXT4;
    } else if (!strcmp(type, "nfs")) {
        return LLFS_TYPE_NFS;
    } else if (!strcmp(type, "nfs4")) {
        return LLFS_TYPE_NFS4;
    } else if (!strcmp(type, "ceph")) {
        return LLFS_TYPE_CEPH;
    } else if (!strcmp(type, "orangefs")) {
        return LLFS_TYPE_ORANGEFS;
    } else if (!strcmp(type, "anyfs")) {
        return LLFS_TYPE_ANY;
    } else if (!strcmp(type, "nofs")) {
        return LLFS_TYPE_FREE;
    } else {
        return LLFS_TYPE_ERR;
    }
}

/* APIs */
void hvfs_datastore_init(void);
int hvfs_datastore_adding(char *conf_filename);
struct hvfs_datastore *hvfs_datastore_add_new(u32 type, char *pathname);
u64 hvfs_datastore_fsid(char *name);
struct hvfs_datastore *hvfs_datastore_add_new(u32 type, char *pathname);
struct hvfs_datastore *hvfs_datastore_get(u32 type, u64 fsid);
char *hvfs_datastore_getone(u32 type, u64 fsid, char *entry);
void hvfs_datastore_free(struct hvfs_datastore *hd);
void hvfs_datastore_exit(void);

#endif
