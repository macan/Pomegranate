/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 21:27:48 macan>
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

#ifndef __TX_H__
#define __TX_H__

struct hvfs_tx 
{
    /* FIXME: what types */
#define HVFS_TX_NORMAL          0x00
#define HVFS_TX_NOCOMMIT        0x01
#define HVFS_TX_FORGET          0x02
    u16 op;
#define HVFS_TX_PROCESSING      0x01
#define HVFS_TX_ACKED           0x02
#define HVFS_TX_COMMITED        0x03
    u16 state;                  /* PROCESSING, ACKED, COMMITED */
    u64 tx;                     /* this transaction id */
    u64 reqno;                  /* the reqno in the client side */
    u64 reqno_site;
    struct xnet_msg *req, *rpy;
    struct hvfs_txg *txg;
    struct list_head tx_list;   /* tx list for current session */
    struct list_head lru;       /* linked in the LRU list */
    struct list_head hlist;     /* linked in the txc */
};

struct hvfs_txc 
{
    struct regular_hash *txht;
    struct list_head lru;       /* only for commited TX */
    int size;
};

#endif
