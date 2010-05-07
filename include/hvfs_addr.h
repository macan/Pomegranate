/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-07 17:23:27 macan>
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
 * Note: we just saving the data region to the storage, ourself do not
 * interpret it.
 */
#define HVFS_X_INFO_LEN         (256)
union hvfs_x_info
{
    u8 array[HVFS_X_INFO_LEN];
};
#endif
