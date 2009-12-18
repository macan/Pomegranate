/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-18 14:30:03 macan>
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
#include "xnet.h"
#include "tx.h"
#include "mds.h"

/* __txg_busy_loop_detector()
 *
 * NOTE: I observe the busy loop situation in the test cast this day, but it
 * is very hard to reproduce it, so I put this loop detector() here in the
 * following test cases to catch it.
 */
#define BLD_COUNT       0
#define BLD_RESET       1
static inline void __txg_busy_loop_detector(struct hvfs_txg *t, int bld)
{
    static int i = 0;
    if (bld == BLD_COUNT) {
        i++;
    } else if (bld == BLD_RESET) {
        i = 0;
    }
    if (i == 100000000) {
        hvfs_err(mds, "TXG %p %ld state %x\n", t, t->txg, t->state);
        exit(0);
    }
}


struct hvfs_txg *txg_alloc(void)
{
    struct hvfs_txg *t;
    
    t = xzalloc(sizeof(struct hvfs_txg));
    if (!t)
        return NULL;
    /* init the lock region */
    t->state = TXG_STATE_OPEN;
    xcond_init(&t->cond);
    xlock_init(&t->ckpt_lock);
    xlock_init(&t->delta_lock);
    xlock_init(&t->itb_lock);
    INIT_LIST_HEAD(&t->dirty_list);

    return t;
}

#define TXG_SET_TIME(txg) ((txg)->open_time = time(NULL))

int txg_init(u64 txg)
{
    struct hvfs_txg *t;
    t = txg_alloc();
    if (!t) {
        hvfs_err(mds, "txg_alloc() failed\n");
        return -ENOMEM;
    }
    TXG_SET_TIME(t);
    t->txg = txg;

    /* init the global txg array */
    hmo.txg[TXG_OPEN] = t;
    hmo.txg[TXG_WB] = NULL;

    return 0;
}

struct hvfs_txg *mds_get_open_txg(struct hvfs_mds_object *hmo)
{
    struct hvfs_txg *t;

retry:
    /* get the txg first */
    t = hmo->txg[TXG_OPEN];     /* atomic read */
    txg_get(t);
    /* checking the txg state */
    if (t->state != TXG_STATE_OPEN) {
        /* oh, txg switched, for correctness, retry myself */
        txg_put(t);
        __txg_busy_loop_detector(t, BLD_COUNT);
        goto retry;
    }

    __txg_busy_loop_detector(t, BLD_RESET);
    return t;
}

/* txg_switch()
 *
 * NOTE: only one thread can call this function, and the WB txg should be
 * commited BEFORE calling this function!
 */
int txg_switch(struct hvfs_mds_info *hmi, struct hvfs_mds_object *hmo)
{
    struct hvfs_txg *nt;
    int err = 0;
    
    /* alloc a txg */
    nt = txg_alloc();
    if (!nt) {
        hvfs_err(mds, "xzalloc() struct hvfs_txg failed.\n");
        err = -ENOMEM;
        goto out;
    }
    TXG_SET_TIME(nt);

    /* make sure the WB txg is commited */
    ASSERT(hmo->txg[TXG_WB] == NULL, mds);

    /* atomic inc the txg # */
    atomic64_inc(&hmi->mi_txg);
    nt->txg = atomic64_read(&hmi->mi_txg);
    
    /* the current opened txg is going into WB state */
    txg_get(hmo->txg[TXG_OPEN]);
    hmo->txg[TXG_WB] = hmo->txg[TXG_OPEN];
    hmo->txg[TXG_WB]->state = TXG_STATE_WB;
    txg_put(hmo->txg[TXG_OPEN]);
    
    /* atomic swith to the current opened txg */
    hmo->txg[TXG_OPEN] = nt;
    
out:
    return err;
}

/* txg_add_itb()
 *
 * NOTE: adding the itb to the txg's dirty list.
 */
void txg_add_itb(struct hvfs_txg *txg, struct itb *i)
{
    xlock_lock(&txg->itb_lock);
    list_add_tail(&i->h.list, &txg->dirty_list);
    xlock_unlock(&txg->itb_lock);
    TXG_SET_DIRTY(txg);
}

/* txg_changer()
 */
void txg_changer(time_t t)
{
    int err;

    /* pre-check */
    if (!TXG_IS_DIRTY(hmo.txg[TXG_OPEN])) {
        /* the txg is clean, just return */
        return;
    }
    /* first, check the open time */
    if (t < hmo.txg[TXG_OPEN]->open_time + hmo.conf.txg_interval) {
        return;
    }
    /* then, check if the writeback slot is free */
    if (hmo.txg[TXG_WB] != NULL) {
        return;
    }
    /* ok, we can switch the txg */
    err = txg_switch(&hmi, &hmo);
    if (err) {
        hvfs_err(mds, "txg_switch() failed w/ low memory.\n");
    } else
        hvfs_info(mds, "Entering new txg %ld\n", hmo.txg[TXG_OPEN]->txg);
}
