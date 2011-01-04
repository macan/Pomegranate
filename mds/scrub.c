/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-04 20:06:54 macan>
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
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "ring.h"
#include "lib.h"

struct scrub_mgr
{
    sem_t sem;
};

static struct scrub_mgr scrub_mgr;

static
void *scrub_main(void *arg)
{
    sigset_t set;
    int err = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    while (!hmo.scrub_thread_stop) {
        err = sem_wait(&scrub_mgr.sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Scrub thread wakeup to evict the ITBs.\n");
        /* trying to evict the itbs */
        if (unlikely(hmo.scrub_thread_stop))
            break;
        mds_cbht_scan(&hmo.cbht, hmo.scrub_op);
        hmo.scrub_running = 0;
    }

    pthread_exit(0);
}

int mds_scrub_create(void)
{
    pthread_attr_t attr;
    int err = 0, stacksize;
    
    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(mds, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hmo.conf.stacksize > (1 << 20) ? 
                 hmo.conf.stacksize : (2 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(mds, "set thread stack size to %d failed w/ %d\n", 
                 stacksize, err);
        goto out;
    }

    /* init the mgr struct */
    sem_init(&scrub_mgr.sem, 0, 0);
    hmo.scrub_running = 0;
    hmo.scrub_thread_stop = 0;
    hmo.scrub_op = HVFS_MDS_OP_EVICT;

    /* init the service thread */
    err = pthread_create(&hmo.scrub_thread, &attr, &scrub_main, NULL);
    if (err) {
        hvfs_err(mds, "create scrub thread failed w/ '%s'\n", 
                 strerror(errno));
        err = -errno;
        goto out;
    }

out:
    return err;
}

void mds_scrub_destroy(void)
{
    hmo.scrub_thread_stop = 1;
    sem_post(&scrub_mgr.sem);
    pthread_join(hmo.scrub_thread, NULL);
    sem_destroy(&scrub_mgr.sem);
}

void mds_scrub_trigger(void)
{
    if (hmo.scrub_running)
        return;
    hmo.scrub_running = 1;
    sem_post(&scrub_mgr.sem);
}
