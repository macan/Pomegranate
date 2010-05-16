/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-16 10:07:50 macan>
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

#ifndef __HVFS_ADDR_H__
#define __HVFS_ADDR_H__

#include "hvfs_u.h"

struct hvfs_sock_addr
{
    struct sockaddr sa;
};

/* hvfs_sock_addr_tx for NET transfer */
struct hvfs_sock_addr_tx
{
    struct sockaddr sa;
};

struct hvfs_addr
{
    struct list_head list;
    /* stable flag, saved */
#define HVFS_SITE_PROTOCOL_TCP  0x80000000
    u32 flag;
    union 
    {
        struct hvfs_sock_addr sock;
    };
};

struct hvfs_addr_tx
{
    u32 flag;
    union 
    {
        struct hvfs_sock_addr_tx sock;
    };
};

struct hvfs_site
{
    /* caller flag, not saved */
#define HVFS_SITE_REPLACE       0x00008000 /* replace all the addr */
#define HVFS_SITE_ADD           0x00004000
#define HVFS_SITE_DEL           0x00002000
    u32 flag;
    u32 nr;
    struct list_head addr;      /* addr list */
};

/* hvfs_site_tx for NET transfer */
struct hvfs_site_tx
{
    u64 site_id;
    u32 flag;
    u32 nr;
    struct hvfs_addr_tx addr[0];
};

/* The following is the region for HXI exchange ABI */
/*
 * Read(open) from the r2 manager. If reopen an opened one, r2 should initiate
 * the recover process to get the newest values from the MDSLs.
 */
#define HMI_STATE_CLEAN         0x01
#define HMI_STATE_LASTOPEN      0x02
#define HMI_STATE_LASTMIG       0x03
#define HMI_STATE_LASTPAUSE     0x04

struct hvfs_mds_info 
{
    u32 state;
    u64 gdt_salt;
    u64 gdt_uuid;               /* special UUID for GDT */
    u64 root_salt;
    u64 root_uuid;
    u64 group;
    u64 uuid_base;              /* the base value of UUID allocation */
    u64 session_id;
    atomic64_t mi_tx;           /* next tx # */
    atomic64_t mi_txg;          /* next txg # */
    atomic64_t mi_uuid;         /* next file and dir uuid */
    atomic64_t mi_fnum;         /* total allocated file number */
    atomic64_t mi_dnum;         /* total allocated dir number */
};

struct hvfs_mdsl_info
{
    u32 state;
    u32 itb_depth;
    u64 gdt_salt;
    u64 gdt_uuid;
    u64 root_salt;
    u64 root_uuid;
    u64 group;
    u64 uuid_base;
    atomic64_t mi_tx;           /* next tx # */
    atomic64_t mi_txg;          /* next txg # */
    atomic64_t mi_uuid;         /* next file uuid */
    atomic64_t mi_fnum;         /* total allocated file # */
};

/*
 * Note: we just saving the data region to the storage, ourself do not
 * interpret it.
 */
#define HVFS_X_INFO_LEN         (256)
union hvfs_x_info
{
    u8 array[HVFS_X_INFO_LEN];
    struct hvfs_mds_info hmi;
    struct hvfs_mdsl_info hmli;
};

/* please refer to r2/mgr.h struct root, this is a mirror of that structure */
struct root_tx
{
    u64 fsid;
    u64 gdt_uuid;
    u64 gdt_salt;
    u64 root_uuid;
    u64 root_salt;
};

#endif
