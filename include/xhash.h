/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-22 11:08:48 macan>
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

#ifndef __XHASH_H__
#define __XHASH_H__

#ifndef __KERNEL__
#include "xlist.h"
#endif
#include "xlock.h"

struct regular_hash 
{
    struct hlist_head h;        /* use hlist */
    xlock_t lock;
};

struct regular_hash_rw
{
    struct hlist_head h;        /* use hlist */
    xrwlock_t lock;
};

struct regular_hash2
{
    struct list_head h;         /* use list */
    xlock_t lock;
};

#endif
