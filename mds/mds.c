/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-18 14:11:21 macan>
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
//u32 hvfs_mds_tracing_flags = HVFS_DEFAULT_LEVEL | HVFS_DEBUG;
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
static int mds_init_signal(void)
{
    struct sigaction ac;
    int err;
    
    ac.sa_sigaction = mds_sigaction_default;
    err = sigemptyset(&ac.sa_mask);
    if (err) {
        err = errno;
        goto out;
    }

#ifndef UNIT_TEST
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
#endif

out:
    return err;
}

void mds_itimer_default(int signo, siginfo_t *info, void *arg)
{
    sem_post(&hmo.timer_sem);
    hvfs_debug(mds, "Did this signal handler called?\n");

    return;
}

static int __gcd(int m, int n)
{
    int r, temp;
    if (!m && !n)
        return 0;
    else if (!m)
        return n;
    else if (!n)
        return m;

    if (m < n) {
        temp = m;
        m = n;
        n = temp;
    }
    r = m;
    while (r) {
        r = m % n;
        m = n;
        n = r;
    }

    return m;
}

static void *mds_timer_thread_main(void *arg)
{
    sigset_t set;
    int v;

    hvfs_debug(mds, "I am running...\n");

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    /* then, we loop for the timer events */
    while (!hmo.timer_thread_stop) {
        sem_wait(&hmo.timer_sem);
        sem_getvalue(&hmo.timer_sem, &v);
        hvfs_debug(mds, "OK, we receive a SIGALRM event(remain %d).\n", v);
        /* should we work now */
        if (hmo.state > HMO_STATE_LAUNCH) {
            /* ok, checking txg */
            txg_changer(time(NULL));
        }
        /* then, checking profiling */
        /* FIXME: */
    }

    hvfs_debug(mds, "Hooo, I am exiting...\n");
    pthread_exit(0);
}

int mds_setup_timers(void)
{
    struct sigaction ac;
    struct itimerval value, ovalue, pvalue;
    int which = ITIMER_REAL, interval;
    int err;

    /* ok, we create the timer thread now */
    err = pthread_create(&hmo.timer_thread, NULL, &mds_timer_thread_main,
                         NULL);
    if (err)
        goto out;
    /* init the timer semaphore */
    sem_init(&hmo.timer_sem, 0, 0);
    /* then, we setup the itimers */
    memset(&ac, 0, sizeof(ac));
    sigemptyset(&ac.sa_mask);
    ac.sa_flags = 0;
    ac.sa_sigaction = mds_itimer_default;
    err = sigaction(SIGALRM, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = getitimer(which, &pvalue);
    if (err) {
        err = errno;
        goto out;
    }
    interval = __gcd(hmo.conf.profiling_thread_interval,
                     hmo.conf.txg_interval);
    if (interval) {
        value.it_interval.tv_sec = interval;
        value.it_interval.tv_usec = 1;
        value.it_value.tv_sec = interval;
        value.it_value.tv_usec = 1;
        err = setitimer(which, &value, &ovalue);
        if (err) {
            err = errno;
            goto out;
        }
        hvfs_debug(mds, "OK, we have created a timer thread to handle txg change"
                   " and profiling events every %d second(s).\n", interval);
    } else {
        hvfs_debug(mds, "Hoo, there is no need to setup itimers based on the"
                   " configration.\n");
        hmo.timer_thread_stop = 1;
    }
    
out:
    return err;
}

/* mds_init()
 *
 *@bdepth: bucket depth
 *
 * init the MDS threads' pool
 */
int mds_init(int bdepth)
{
    int err;
    
    /* prepare the hmi & hmo */
    memset(&hmi, 0, sizeof(hmi));
    memset(&hmo, 0, sizeof(hmo));
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    
    /* FIXME: decode the cmdline */

    /* FIXME: configations */
    hmo.conf.profiling_thread_interval = 4;
    hmo.conf.txg_interval = 3;
    hmo.conf.option = HVFS_MDS_ITB_RWLOCK;

    /* Init the signal handlers */
    err = mds_init_signal();
    if (err)
        goto out_signal;

    /* FIXME: setup the timers */
    err = mds_setup_timers();
    if (err)
        goto out_timers;

    /* FIXME: init the xnet subsystem */

    /* FIXME: init the profiling subsystem */

    /* FIXME: init the fault tolerant subsystem */

    /* FIXME: register with the Ring server */

    /* FIXME: init the TX subsystem, init the commit threads' pool */
    err = mds_init_tx(0);
    if (err)
        goto out_tx;

    /* FIXME: init hte CBHT subsystem */
    err = mds_cbht_init(&hmo.cbht, bdepth);
    if (err)
        goto out_cbht;

    /* FIXME: init the async threads' pool */

    /* FIXME: waiting for the notification from R2 */

    /* FIXME: waiting for the requests from client/mds/mdsl/r2 */

    /* ok to run */
    hmo.state = HMO_STATE_RUNNING;

out_tx:
out_cbht:
out_timers:
out_signal:
    return err;
}

void mds_destroy(void)
{
    hvfs_err(mds, "OK, stop it now...\n");
    hmo.timer_thread_stop = 1;
    if (hmo.timer_thread)
        pthread_join(hmo.timer_thread, NULL);
    sem_destroy(&hmo.timer_sem);
}

