/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-24 04:34:23 macan>
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

#ifndef __MDS_DH_H__
#define __MDS_DH_H__

#define MDS_DH_DEFAULT_SIZE     (1024)
struct dh
{
    struct regular_hash *ht;
    int hsize;                  /* hash table size */
    atomic_t asize;
};

struct dhe
{
    struct hlist_node hlist;    /* list in DH hash table */
    struct list_head bitmap;    /* list head of bitmap */
    xlock_t lock;               /* protect the bitmap list */
    u64 uuid;                   /* UUID of this directory */
    u64 puuid;                  /* UUID of the parent directory */
    u64 salt;                   /* salt of this directory */
    u64 life;                   /* when this dhe is loaded */
    time_t update;              /* reload update time */
    void *data;                 /* pointer to Trigger data (DTM) */
    u32 mdu_flags;              /* shadow copy of MDU flags */
    atomic_t ref;               /* the reference count */
};

#endif
