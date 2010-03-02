/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-02 15:57:25 macan>
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
#include "mdsl.h"
#include "lib.h"

#ifdef HVFS_TRACING
u32 hvfs_mdsl_tracing_flags = HVFS_DEFAULT_LEVEL;
#endif

/* Global variable */
struct hvfs_mdsl_info hmi;
struct hvfs_mdsl_object hmo;

void mdsl_sigaction_default(int signo, siginfo_t *info, void *arg)
{
    if (signo == SIGSEGV) {
        hvfs_info(lib, "Recv %sSIGSEGV%s %s\n",
                  HVFS_COLOR_RED,
                  HVFS_COLOR_END,
                  SIGCODES(info->si_code));
        lib_segv(signo, info, arg);
    }
    return;
}

/* mdsl_init_signal()
 */
static int mdsl_init_signal(void)
{
    struct sigaction ac;
    int err;

    ac.sa_sigaction = mdsl_sigaction_default;
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
    /* FIXME: mask the SIGINT for testing */
#if 0
    err = sigaction(SIGINT, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
#endif
    err = sigaction(SIGSEGV, &ac, NULL);
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

void mdsl_itimer_default(int signo, siginfo_t *info, void *arg)
{
    sem_post(&hmo.timer_sem);
    hvfs_verbose(mdsl, "Did this signal handler called?\n");

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

static void *mdsl_timer_thread_main(void *arg)
{
    sigset_t set;
    int v, err;

    hvfs_debug(mdsl, "I am running...\n");

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    /* then, we loop for the timer events */
    while (!hmo.timer_thread_stop) {
        err = sem_wait(&hmo.timer_sem);
        if (err == EINTR)
            continue;
        sem_getvalue(&hmo.timer_sem, &v);
        hvfs_debug(mdsl, "OK, we receive a SIGALRM event(remain %d).\n", v);
        /* should we work now */
    }

    hvfs_debug(mdsl, "Hooo, I am exiting...\n");
    pthread_exit(0);
}

int mdsl_setup_timers(void)
{
    struct sigaction ac;
    struct itimerval value, ovalue, pvalue;
    int which = ITIMER_REAL, interval;
    int err;

    /* init the timer semaphore */
    sem_init(&hmo.timer_sem, 0, 0);

    /* ok, we create the timer thread now */
    err = pthread_create(&hmo.timer_thread, NULL, &mdsl_timer_thread_main,
                         NULL);
    if (err)
        goto out;
    /* then, we setup the itimers */
    memset(&ac, 0, sizeof(ac));
    sigemptyset(&ac.sa_mask);
    ac.sa_flags = 0;
    ac.sa_sigaction = mdsl_itimer_default;
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
                     hmo.conf.gc_interval);
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
        hvfs_debug(mdsl, "OK, we have created a timer thread to handle txg change"
                   " and profiling events every %d second(s).\n", interval);
    } else {
        hvfs_debug(mdsl, "Hoo, there is no need to setup itimers based on the"
                   " configration.\n");
        hmo.timer_thread_stop = 1;
    }
    
out:
    return err;
}

void mdsl_reset_itimer(void)
{
    struct itimerval value, ovalue, pvalue;
    int err, interval;

    err = getitimer(ITIMER_REAL, &pvalue);
    if (err) {
        goto out;
    }
    interval = __gcd(hmo.conf.profiling_thread_interval,
                     hmo.conf.gc_interval);
    if (interval) {
        value.it_interval.tv_sec = interval;
        value.it_interval.tv_usec = 0;
        value.it_value.tv_sec = interval;
        value.it_value.tv_usec = 0;
        err = setitimer(ITIMER_REAL, &value, &ovalue);
        if (err) {
            goto out;
        }
        hvfs_info(mdsl, "OK, we reset the itimer to %d second(s).\n",
                  interval);
    }
out:
    return;
}

/* mdsl_init()
 */
int mdsl_init(void)
{
    int err;

    /* lib init */
    lib_init();

    /* prepare the hmi & hmo */
    memset(&hmi, 0, sizeof(hmi));
    memset(&hmo, 0, sizeof(hmo));
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif

    /* FIXME: decode the cmdline */

    /* FIXME: configurations */
    hmo.conf.profiling_thread_interval = 5;
    hmo.conf.gc_interval = 5;
    hmo.conf.spool_threads = 8;

    /* init the txg_compact_cache */
    err = mdsl_tcc_init();
    if (err)
        goto out_tcc;

    /* Init the signal handlers */
    err = mdsl_init_signal();
    if (err)
        goto out_signal;

    /* FIXME: setup the timers */
    err = mdsl_setup_timers();
    if (err)
        goto out_timers;
    
    /* FIXME: init the service threads' pool */
    err = mdsl_spool_create();
    if (err)
        goto out_spool;

    /* ok to run */
    hmo.state = HMO_STATE_RUNNING;

out_spool:
out_timers:
out_signal:
out_tcc:
    return err;
}

void mdsl_destroy(void)
{
    hvfs_verbose(mdsl, "OK, stop it now...\n");

    /* stop the timer thread */
    hmo.timer_thread_stop = 1;
    if (hmo.timer_thread)
        pthread_join(hmo.timer_thread, NULL);

    sem_destroy(&hmo.timer_sem);

    /* destroy the service threads' pool */
    mdsl_spool_destroy();

    /* destroy the tcc */
    mdsl_tcc_destroy();
}
