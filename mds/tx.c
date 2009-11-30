/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 21:36:18 macan>
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

#include "hvfs.h"
#include "xtable.h"
#include "tx.h"
#include "xnet.h"

static inline u64 mds_rdtx()
{
    return atomic64_inc_return(&hmi.mi_tx);
}

struct hvfs_tx *mds_alloc_tx(u16 op, struct xnet_msg *req)
{
    struct hvfs_tx *tx;
    
    /* Step 1: try the fast allocation path */
    /* FIXME */
    /* fall back to slow path */
    tx = zalloc(*tx);
    if (!tx) {
        hvfs_debug(mds, "zalloc() hvfs_tx failed\n");
        return NULL;
    }
    
    tx->op = op;
    tx->state = HVFS_TX_PROCESSING;
    tx->tx = mds_rdtx();
    tx->reqno = req->tx.reqno;
    tx->reqno_site = req->tx.ssite_id;
    tx->req = req;
    tx->txg = mds_get_open_txg();   /* get the current opened TXG */
    /* FIXME: insert in the TXC */
    /* FIXME: tx_list? */
}

