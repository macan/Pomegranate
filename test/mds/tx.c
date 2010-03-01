/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-01 15:12:07 macan>
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
    struct xnet_msg *m;
    struct hvfs_tx *t;
    int hsize, ftx, tc;
    int err, i, seqno;

    if (argc == 4) {
        hsize = atoi(argv[1]);
        ftx = atoi(argv[2]);
        tc = atoi(argv[3]);
    } else {
        hsize = 1024;
        ftx = 10;
        tc = 20;
    }

/*     SET_TRACING_FLAG(mds, HVFS_DEBUG); */
    
    hvfs_info(mds, "TX UNIT TESTing (%d,%d,%d)...\n", hsize, ftx, tc);

    /* init mds unit test */
    lib_init();
    err = mds_init(10);
    if (err) {
        hvfs_err(mds, "mds_init() failed %d\n", err);
        goto out;
    }
    
    err = mds_init_txc(&hmo.txc, hsize, ftx); /* default free TXs */
    if (err) {
        hvfs_err(mds, "mds_init_txc() failed %d\n", err);
        goto out;
    }

    for (i = 0, seqno = 0; i < tc; i++) {
        m = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!m) {
            hvfs_err(mds, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto out;
        }
        m->tx.reqno = seqno++;
        m->tx.ssite_id = i;
        tx_in(HVFS_TX_NORMAL, m);
    }

    hvfs_info(mds, "[TX IN ][%10d] done.\n", atomic_read(&hmo.txc.ftx));

    for (i = 0, seqno = 0; i < tc; i++) {
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

    hvfs_info(mds, "[TX DEL][%10d] done.\n", atomic_read(&hmo.txc.ftx));

    for (i = 0, seqno = 0; i < tc; i++) {
        m = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!m) {
            hvfs_err(mds, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto out;
        }
        m->tx.reqno = seqno++;
        m->tx.ssite_id = i;
        tx_in(HVFS_TX_NORMAL, m);
    }

    hvfs_info(mds, "[TX INr][%10d] done.\n", atomic_read(&hmo.txc.ftx));
    
    mds_destroy();
out:
    return err;
}

#endif
