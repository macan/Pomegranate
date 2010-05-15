/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-15 19:09:46 macan>
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

#ifndef __ROOT_MGR_H__
#define __ROOT_MGR_H__

#include "hvfs.h"
#include "ring.h"
#include "lib.h"
#include "hvfs_addr.h"

/* site manager to manage the registered site group, on chring changing mgr
 * should notify the registered sites. 
 *
 * site manager indexed by site id. constructed by Hash Table.
 */
struct site_mgr
{
#define HVFS_ROOT_SITE_MGR_SALT         (0xfeadf98424af)
#define HVFS_ROOT_SITE_MGR_HTSIZE       1024
    struct regular_hash *sht;
};

struct site_entry
{
    struct hlist_node hlist;
    u64 site_id;
    
#define SE_STATE_INIT           0x00
#define SE_STATE_NORMAL         0x10
#define SE_STATE_SHUTDOWN       0x11
#define SE_STATE_TRANSIENT      0x20
#define SE_STATE_ERROR          0x30 /* innormal, need recover */
    u32 state;
    u32 hb_lost;                /* # of lost heart beat messages */
    union hvfs_x_info hxi;
    xlock_t lock;
    u32 gid;                    /* group of the ring */
};

/* ring manager to manage the consistent hash ring, we can support dynamic
 * ring point add and delete. Notifications should be sent to the subscribed
 * sites. indexed by ring group id? */
struct ring_mgr
{
#define HVFS_ROOT_RING_MGR_SALT         (0xeadf90878afe)
#define HVFS_ROOT_RING_MGR_HTSIZE       64
    struct regular_hash *rht;
    xrwlock_t rwlock;
    u32 active_ring;
};

struct ring_entry
{
    struct hlist_node hlist;
    struct chring ring;
    atomic_t ref;
};

/* root manager to manage the HVFS root info, indexed by hvfs fsid */
struct root_mgr
{
#define HVFS_ROOT_ROOT_MGR_SALT         (0xfedaafe8970087f)
#define HVFS_ROOT_ROOT_MGR_HTSIZE       64
    struct regular_hash *rht;
    xrwlock_t rwlock;
    u32 active_root;
};

struct root_entry
{
    struct hlist_node hlist;
    u64 fsid;
    u64 gdt_uuid;
    u64 gdt_salt;

    u64 root_uuid;
    u64 root_salt;              /* root salt can be discovered from GDT
                                 * lookup either. */
};

/* address mgr to manage the global site address table, we do support dynamic
 * changes on this table */
struct addr_mgr
{
    struct hvfs_site *xs[HVFS_SITE_MAX];
    xrwlock_t rwlock;
    u32 used_addr;              /* # of used addr */
    u32 active_site;            /* # of active site */
};

/* APIs */
int root_read_hxi(u64 site_id, u64 fsid, union hvfs_x_info *hxi);
int root_write_hxi(struct site_entry *se);

#endif
