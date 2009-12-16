/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-16 20:30:55 macan>
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
#include "mds.h"
#include "lib.h"

#ifdef HVFS_TRACING
//u32 hvfs_mds_tracing_flags = HVFS_DEFAULT_LEVEL | HVFS_DEBUG_ALL;
u32 hvfs_mds_tracing_flags = HVFS_DEFAULT_LEVEL;
#endif

/* Global variable */
struct hvfs_mds_info hmi;
struct hvfs_mds_object hmo = {.conf.option = HVFS_MDS_ITB_MUTEX,};

void mds_sigaction_default(int signo, siginfo_t *info, void *arg)
{
#ifdef HVFS_DEBUG_LOCK
    if (signo == SIGINT) {
        lock_table_print();
    }
#endif
    return;
}

/* mds_init_signal()
 */
static int mds_init_signal()
{
    struct sigaction ac;
    int err;
    
    ac.sa_sigaction = mds_sigaction_default;
    err = sigemptyset(&ac.sa_mask);
    if (err) {
        err = errno;
        goto out;
    }

    err = sigaction(SIGTERM, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = sigaction(SIGHUP, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = sigaction(SIGINT, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = sigaction(SIGQUIT, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }

out:
    return err;
}

/* mds_init()
 *
 * init the MDS threads' pool
 */
#ifndef UNIT_TEST
int mds_init()
{
    int err;
    
    /* FIXME: decode the cmdline */

    /* FIXME: configations */

    /* Init the signal handlers */
    err = mds_init_signal();
    if (err)
        goto out_signal;

    /* FIXME: setup the timers */

    /* FIXME: init the xnet subsystem */

    /* FIXME: init the profiling subsystem */

    /* FIXME: init the fault tolerant subsystem */

    /* FIXME: register with the Ring server */

    /* FIXME: init the TX subsystem, init the commit threads' pool */
    err = mds_init_tx();
    if (err)
        goto out_tx;

    /* FIXME: init hte CBHT subsystem */
    err = mds_cbht_init();
    if (err)
        goto out_cbht;

    /* FIXME: init the async threads' pool */

    /* FIXME: waiting for the notification from R2 */

    /* FIXME: waiting for the requests from client/mds/mdsl/r2 */

out_tx:
out_cbht:
out_signal:
    return err;
}
#else  /* UNIT_TEST */
int mds_init()
{
    struct hvfs_txg *t;
    int err = 0;

    /* init hmi */
    memset(&hmi, 0, sizeof(hmi));
    
    /* init hmo */
    memset(&hmo, 0, sizeof(hmo));
    t = xzalloc(sizeof(*t));
    if (!t) {
        return -ENOMEM;
    }
    hmo.txg[0] = t;
    t = xzalloc(sizeof(*t));
    if (!t) {
        return -ENOMEM;
    }
    hmo.txg[1] = t;
    
    return err;
}
#endif
