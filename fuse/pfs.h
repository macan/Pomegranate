/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-08 15:17:03 macan>
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

#ifndef __PFUSE_H__
#define __PFUSE_H__

#include "hvfs.h"
#include "xnet.h"
#include "mds.h"
#include "ring.h"
#include "lib.h"
#include "root.h"
#include "amc_api.h"
/* which fuse version should we use? */
#warning "We use FUSE version 2.6"
#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <fuse/fuse_lowlevel.h>

extern struct fuse_operations pfs_ops;
extern size_t g_pagesize;

struct __pfs_fuse_mgr
{
    u32 inited:1;               /* indicated whether myself is inited */
    u32 sync_write:1;
    u32 use_config:1;
    u32 noatime:1;
    u32 nodiratime:1;
    u32 use_dstore:1;
    u32 ttl:8;                  /* lru translate cache ttl */
};

extern struct __pfs_fuse_mgr pfs_fuse_mgr;
#endif
