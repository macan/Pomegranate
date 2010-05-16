/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-16 21:39:26 macan>
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

#include "root.h"
#include "root_config.h"

#ifdef HVFS_TRACING
u32 hvfs_root_tracing_flags = HVFS_DEFAULT_LEVEL;
#endif

struct hvfs_root_object hro;

/* root_pre_init()
 * 
 * setting up the internal configs.
 */
void root_pre_init()
{
    /* prepare the hro */
    memset(&hro, 0, sizeof(hro));
    /* setup the state */
    hro.state = HRO_STATE_LAUNCH;
}

/* root_verify()
 */
int root_verify(void)
{
    /* check sth */
    return 0;
}

/* root_config()
 *
 * Get configs from the env
 */
int root_config(void)
{
    char *value;

    if (hro.state != HRO_STATE_LAUNCH) {
        hvfs_err(root, "ROOT state is not in launching, please call "
                 "root_pre_init() firstly!\n");
        return -EINVAL;
    }

    HVFS_ROOT_GET_ENV_atoi(site_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(ring_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(root_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(service_threads, value);
    HVFS_ROOT_GET_ENV_atoi(ring_push_interval, value);
    HVFS_ROOT_GET_ENV_atoi(hb_interval, value);
    HVFS_ROOT_GET_ENV_atoi(sync_interval, value);
    HVFS_ROOT_GET_ENV_atoi(prof_plot, value);

    HVFS_ROOT_GET_ENV_option(opt_memonly, MEMONLY, value);

    /* default configs */
    if (!hro.conf.ring_push_interval) {
        hro.conf.ring_push_interval = 600;
    }
    if (!hro.conf.hb_interval) {
        hro.conf.hb_interval = 60;
    }
    if (!hro.conf.sync_interval) {
        hro.conf.sync_interval = 0; /* do not do sync actually */
    }

    return 0;
}

void root_itimer_default(int signo, siginfo_t *info, void *arg)
{
    sem_post(&hro.timer_sem);
    hvfs_verbose(root, "Did this signal handler called?\n");

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

static void *root_timer_thread_main(void *arg)
{
    sigset_t set;
    time_t cur;
    int v, err;

    hvfs_debug(root, "I am running...\n");

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    /* then, we loop for the timer events */
    while (!hro.timer_thread_stop) {
        err = sem_wait(&hro.timer_sem);
        if (err == EINTR)
            continue;
        sem_getvalue(&hro.timer_sem, &v);
        hvfs_debug(root, "OK, we receive a SIGALRM event(remain %d).\n", v);
        /* should we work now */
        cur = time(NULL);
        if (hro.state > HRO_STATE_LAUNCH) {
            /* ok, check the site entry state now */
        }
    }

    hvfs_debug(root, "Hooo, I am exiting...\n");
    pthread_exit(0);
}

int root_setup_timers(void)
{
    struct sigaction ac;
    struct itimerval value, ovalue, pvalue;
    int which = ITIMER_REAL, interval;
    int err;

    /* init the timer semaphore */
    sem_init(&hro.timer_sem, 0, 0);

    /* ok, we create the timer thread now */
    err = pthread_create(&hro.timer_thread, NULL, &root_timer_thread_main,
                         NULL);
    if (err)
        goto out;
    /* then, we setup the itimers */
    memset(&ac, 0, sizeof(ac));
    sigemptyset(&ac.sa_mask);
    ac.sa_flags = 0;
    ac.sa_sigaction = root_itimer_default;
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
    interval = __gcd(hro.conf.hb_interval, hro.conf.sync_interval);
    interval = __gcd(interval, hro.conf.ring_push_interval);
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
        hvfs_debug(root, "OK, we have created a timer thread to "
                   "handle heartbeat and sync events every %d seconds(s).\n",
                   interval);
    } else {
        hvfs_debug(root, "Hoo, there is no need to setup itimers basedon the"
                   " configuration.\n");
        hro.timer_thread_stop = 1;
    }

out:
    return err;
}

int root_init(void)
{
    int err = 0;

    /* lib init */
    lib_init();

    /* FIXME: decode the cmdline */

    /* FIXME: configrations */
    /* default configurations */
    hro.conf.ring_push_interval = 600; /* 600 seconds */

    /* get configs from env */
    root_config();

    /* FIXME: in the service threads' pool */
    err = root_spool_create();
    if (err)
        goto out_spool;

    /* FIXME: setup the timers */
    err = root_setup_timers();
    if (err)
        goto out_timers;

    /* ok to run */
    hro.state = HRO_STATE_RUNNING;

out_timers:
out_spool:
    return err;
}

void root_destroy(void)
{
    hvfs_verbose(root, "OK, stop it now ...\n");

    /* free something */

    /* destroy the service thread pool */
    root_spool_destroy();

    /* stop the timer thread */
    hro.timer_thread_stop = 1;
    if (hro.timer_thread)
        pthread_join(hro.timer_thread, NULL);
}
