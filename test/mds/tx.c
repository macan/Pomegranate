/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-17 13:16:47 macan>
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
#include "mds.h"

#ifdef UNIT_TEST
void tx_in(u16 op, struct xnet_msg *req)
{
    struct hvfs_tx *tx;

    tx = mds_alloc_tx(op, req);
    if (!tx) {
        hvfs_err(mds, "mds_alloc_tx() failed\n");
    }
}

int main(int argc, char *argv[])
{
    struct xnet_msg m;
    struct hvfs_tx *t;
    int err, i, seqno;

    hvfs_info(mds, "TX UNIT TESTing ...\n");
    
    /* init mds unit test */
    lib_init();
    mds_init(10);
    
    err = mds_init_txc(&hmo.txc, 1024, 10); /* default free TXs */
    if (err) {
        hvfs_err(mds, "mds_init_txc() failed %d\n", err);
        goto out;
    }

    for (i = 0, seqno = 0; i < 20; i++) {
        m.tx.reqno = seqno++;
        m.tx.ssite_id = i;
        tx_in(HVFS_TX_NORMAL, &m);
    }

    for (i = 0, seqno = 0; i < 20; i++) {
        t = mds_txc_search(&hmo.txc, i, seqno++);
        if (!t) {
            hvfs_err(mds, "Internal error.\n");
        } else {
            /* ok, delete the TX from the cache */
            mds_tx_done(t);
            mds_tx_reply(t);
            mds_tx_commit(t);
            mds_put_tx(t);
        }
    }

    for (i = 0, seqno = 0; i < 10; i++) {
        m.tx.reqno = seqno++;
        m.tx.ssite_id = i;
        tx_in(HVFS_TX_NORMAL, &m);
    }

    hvfs_info(mds, "FTX in TXC is %d.\n", hmo.txc.ftx);
    
    mds_destroy_txc(&hmo.txc);
    mds_destroy();
out:
    return err;
}

#endif
