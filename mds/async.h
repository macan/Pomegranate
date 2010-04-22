/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-22 20:10:21 macan>
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

#ifndef __MDS_ASYNC_H__
#define __MDS_ASYNC_H__

#include "hvfs.h"

struct async_thread_arg
{
    int tid;                    /* thread id */
};

struct async_update_request
{
#define AU_ITB_SPLIT            0x01    /* w/ itb pointer in arg */
#define AU_ITB_BITMAP           0x02    /* w/ bit operations in arg */
#define AU_TXG_WB               0x03    /* w/ txg pointer in arg */
#define AU_DIR_DELTA            0x04    /* w/ hvfs_dir_delta pointer in arg */
#define AU_DIR_DELTA_REPLY      0x05    /* w/ rddb list pointer in arg */
    u64 op;
    u64 arg;
    struct list_head list;
};

struct async_update_mlist
{
    struct list_head aurlist;
    xlock_t lock;
};

/* APIs */
int au_submit(struct async_update_request *);

#endif
