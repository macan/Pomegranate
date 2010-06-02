/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-31 14:24:44 macan>
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
    u64 fsid;

#define SE_STATE_INIT           0x00
#define SE_STATE_NORMAL         0x10
#define SE_STATE_SHUTDOWN       0x11
#define SE_STATE_TRANSIENT      0x20
#define SE_STATE_ERROR          0x30 /* innormal, need recover */
    u32 state;
#define TRANSIENT_HB_LOST       0x01
#define MAX_HB_LOST             0x02
    u32 hb_lost;                /* # of lost heart beat messages */
    union hvfs_x_info hxi;
    xlock_t lock;
    u32 gid;                    /* group of the ring */
};

struct site_disk
{
#define SITE_DISK_INVALID       0x00
#define SITE_DISK_VALID         0x01
    u8 state;
    u8 pad0;
    u16 pad1;
    u32 gid;
    u64 fsid;
    u64 site_id;
    union hvfs_x_info hxi;
};

#define SITE_DISK_WHOLE_FS      (sizeof(struct site_disk) * HVFS_SITE_MAX)

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
    /* the following region is the gdt bitmap */
    /* Note that the bitmap region is just a memory region backstored by a
     * file, the size is the file size, we only do simple mmap/munmap on
     * it. */
    u64 gdt_flen;
    u8 *gdt_bitmap;
};

struct root_disk
{
#define ROOT_DISK_INVALID       0x00
#define ROOT_DISK_VALID         0x01
    u8 state;
    u8 pad0;
    u16 pad1;
    u32 reserved;
    u64 fsid;
    u64 gdt_uuid;
    u64 gdt_salt;
    u64 root_uuid;
    u64 root_salt;
    u64 gdt_flen;
    u64 gdt_foffset;
};

/* address mgr to manage the global site address table, we do support dynamic
 * changes on this table */
struct addr_mgr
{
#define HVFS_ROOT_ADDR_MGR_SALT         (0xdfea965786afde)
#define HVFS_ROOT_ADDR_MGR_HTSIZE       16
    struct regular_hash *rht;
    xrwlock_t rwlock;
};

struct addr_entry
{
    struct hlist_node hlist;
    
    struct hvfs_site *xs[HVFS_SITE_MAX];
    xrwlock_t rwlock;
    u32 used_addr;              /* # of used addr */
    u32 active_site;            /* # of active site */
    u64 fsid;
};

/* APIs */
int root_read_hxi(u64 site_id, u64 fsid, union hvfs_x_info *hxi);
int root_write_hxi(struct site_entry *se);
int root_create_hxi(struct site_entry *se);
int root_clean_hxi(struct site_entry *);
int root_read_re(struct root_entry *re);
int root_write_re(struct root_entry *re);
int site_mgr_lookup_create(struct site_mgr *, u64, struct site_entry **);
int root_mgr_lookup_create(struct root_mgr *, u64, struct root_entry **);
int root_mgr_lookup_create2(struct root_mgr *, u64, struct root_entry **);
int root_compact_hxi(u64 site_id, u64 fsid, u32 gid, union hvfs_x_info *);
int ring_mgr_compact_one(struct ring_mgr *, u32, void **, int *);
struct ring_entry *ring_mgr_lookup(struct ring_mgr *, u32);
void ring_mgr_put(struct ring_entry *);
struct root_entry *root_mgr_lookup(struct root_mgr *, u64);
int addr_mgr_compact(struct addr_entry *, void **, int *);
int addr_mgr_update_one(struct addr_entry *, u32, u64, void *);
struct addr_entry *addr_mgr_lookup(struct addr_mgr *, u64);
int addr_mgr_lookup_create(struct addr_mgr *, u64, struct addr_entry **);
struct site_entry *site_mgr_lookup(struct site_mgr *, u64);
struct ring_entry *ring_mgr_alloc_re();
void ring_mgr_put(struct ring_entry *);
struct ring_entry *ring_mgr_insert(struct ring_mgr *, struct ring_entry *);
struct root_entry *root_mgr_insert(struct root_mgr *, struct root_entry *);
struct root_entry *root_mgr_alloc_re();

int site_mgr_init(struct site_mgr *);
int ring_mgr_init(struct ring_mgr *);
int root_mgr_init(struct root_mgr *);
int addr_mgr_init(struct addr_mgr *);
void site_mgr_destroy(struct site_mgr *);
void ring_mgr_destroy(struct ring_mgr *);
void root_mgr_destroy(struct root_mgr *);
void addr_mgr_destroy(struct addr_mgr *);

int root_read_bitmap(u64, u64, void *);
int root_write_bitmap(void *, u64, u64 *);
void *root_bitmap_enlarge(void *, u64);
int root_bitmap_default(struct root_entry *re);

void site_mgr_check(time_t);

#endif
