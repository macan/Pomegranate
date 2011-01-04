/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-04 20:09:54 macan>
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
    } else if (signo == SIGBUS) {
        hvfs_info(lib, "Recv %sSIGBUS%s %s\n",
                  HVFS_COLOR_RED,
                  HVFS_COLOR_END,
                  SIGCODES(info->si_code));
        lib_segv(signo, info, arg);
    } else if (signo == SIGHUP) {
        hvfs_info(lib, "Exit MDSL Server ...\n");
        mdsl_destroy();
        exit(0);
    } else if (signo == SIGUSR1) {
        hvfs_info(lib, "Exit some threads ...\n");
        pthread_exit(0);
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
    ac.sa_flags = SA_SIGINFO;

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
    err = sigaction(SIGBUS, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = sigaction(SIGQUIT, &ac, NULL);
    if (err) {
        err = errno;
        goto out;
    }
    err = sigaction(SIGUSR1, &ac, NULL);
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
    time_t cur;
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
        cur = time(NULL);
        /* should we work now */
        mdsl_dump_profiling(cur);
        /* check the pending IOs */
        mdsl_storage_pending_io();
        /* check the fd hash table */
        mdsl_storage_fd_limit_check(cur);
        /* keep page cache clean if there are a lot of page cache entries */
        mdsl_storage_fd_pagecache_cleanup();
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

/* mdsl_pre_init()
 */
void mdsl_pre_init(void)
{
    /* prepare the hmi & hmo */
    memset(&hmi, 0, sizeof(hmi));
    memset(&hmo, 0, sizeof(hmo));
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    /* setup the state */
    hmo.state = HMO_STATE_LAUNCH;
}

/* mdsl_verify()
 */
int mdsl_verify(void)
{
    char path[128] = {0, };
    int err = 0;

    /* check the MDSL_HOME */
    err = mdsl_storage_dir_make_exist(hmo.conf.mdsl_home);
    if (err) {
        hvfs_err(mdsl, "dir %s do not exist.\n", hmo.conf.mdsl_home);
        goto out;
    }

    /* check the MDSL site directory */
    sprintf(path, "%s/%lx", hmo.conf.mdsl_home, hmo.site_id);
    err = mdsl_storage_dir_make_exist(path);
    if (err) {
        hvfs_err(mdsl, "dir %s do not exist.\n", path);
    }

out:
    return err;
}

/* mdsl_config()
 *
 * Get configuration from the execution environment
 */
int mdsl_config(void)
{
    char *value;

    if (hmo.state != HMO_STATE_LAUNCH) {
        hvfs_err(mdsl, "MDSL state is no in launching, please call "
                 "mdsl_pre_init() firstly\n");
        return -EINVAL;
    }

    HVFS_MDSL_GET_ENV_strncpy(dcaddr, value, MDSL_DCONF_MAX_NAME_LEN);
    HVFS_MDSL_GET_ENV_cpy(mdsl_home, value);
    HVFS_MDSL_GET_ENV_cpy(profiling_file, value);
    HVFS_MDSL_GET_ENV_cpy(conf_file, value);
    HVFS_MDSL_GET_ENV_cpy(log_file, value);

    HVFS_MDSL_GET_ENV_atoi(spool_threads, value);
    HVFS_MDSL_GET_ENV_atoi(ring_vid_max, value);
    HVFS_MDSL_GET_ENV_atoi(tcc_size, value);
    HVFS_MDSL_GET_ENV_atoi(prof_plot, value);
    HVFS_MDSL_GET_ENV_atoi(profiling_thread_interval, value);
    HVFS_MDSL_GET_ENV_atoi(gc_interval, value);
    HVFS_MDSL_GET_ENV_atoi(itb_file_chunk, value);
    HVFS_MDSL_GET_ENV_atoi(data_file_chunk, value);
    HVFS_MDSL_GET_ENV_atoi(itb_falloc, value);
    HVFS_MDSL_GET_ENV_atoi(aio_sync_len, value);
    HVFS_MDSL_GET_ENV_atoi(fd_cleanup_N, value);
    HVFS_MDSL_GET_ENV_atoi(stacksize, value);

    HVFS_MDSL_GET_ENV_atol(memlimit, value);
    HVFS_MDSL_GET_ENV_atol(fdlimit, value);
    HVFS_MDSL_GET_ENV_atol(mclimit, value);
    HVFS_MDSL_GET_ENV_atol(pcct, value);

    HVFS_MDSL_GET_ENV_option(write_drop, WDROP, value);
    HVFS_MDSL_GET_ENV_option(memlimit, MEMLIMIT, value);

    /* set default mdsl home */
    if (!hmo.conf.mdsl_home) {
        hmo.conf.mdsl_home = HVFS_MDSL_HOME;
    }

    /* set default chunk if not setted. */
    hmo.conf.itb_file_chunk &= ~(getpagesize() - 1);
    hmo.conf.data_file_chunk &= ~(getpagesize() - 1);    
    if (!hmo.conf.itb_file_chunk ||
        hmo.conf.itb_file_chunk < getpagesize())
        hmo.conf.itb_file_chunk = MDSL_STORAGE_ITB_DEFAULT_CHUNK;
    if (!hmo.conf.data_file_chunk ||
        hmo.conf.data_file_chunk < getpagesize())
        hmo.conf.data_file_chunk = MDSL_STORAGE_DATA_DEFAULT_CHUNK;
    /* round up the the page size */

    /* set default fd limit here, total 2 GB memory for itb/data */
    if (!hmo.conf.mclimit) {
        hmo.conf.mclimit = (1024UL * 1024 * 1024 * 2);
    }

    if (!hmo.conf.fdlimit) {
        hmo.conf.fdlimit = 1024;
    }

    /* set fd cleanup N, default to 32 */
    if (!hmo.conf.fd_cleanup_N)
        hmo.conf.fd_cleanup_N = 32;

    /* set default pcct value to 1GB memory */
    if (!hmo.conf.pcct)
        hmo.conf.pcct = (1024 * 1024 * 1024);

    /* FIXME: hmi should not be set at here actually */
    hmi.itb_depth = 3;
    
    return 0;
}

/* mdsl_help()
 */
void mdsl_help(void)
{
    hvfs_plain(mdsl, "MDSL build @ %s on %s\n", CDATE, CHOST);
    hvfs_plain(mdsl, "Usage: [EV list] mdsl\n\n");
    hvfs_plain(mdsl, "General Environment Variables:\n"
               " hvfs_mdsl_dcaddr               dynamic config addr for "
               "UNIX sockets.\n"
               " hvfs_mdsl_profiling_file       profiling file name.\n"
               " hvfs_mdsl_conf_file            config file name.\n"
               " hvfs_mdsl_log_file             log file name.\n"
               " hvfs_mdsl_spool_threads        spool threads nr.\n"
               " hvfs_mdsl_ring_vid_max         max virtual id for each site.\n"
               " hvfs_mdsl_tcc_size             TCC cache size.\n"
               " hvfs_mdsl_prof_plot            output for gnuplot.\n"
               " hvfs_mdsl_profiling_thread_interval\n"
               "                                wakeup interval for prof thread.\n"
               " hvfs_mdsl_gc_interval          wakeup interval for gc thread.\n"
               " hvfs_mdsl_opt_write_drop       drop the writes to this MDSL.\n"
        );
    hvfs_plain(mdsl, "Any questions please contacts Ma Can <macan@ncic.ac.cn>\n");
}

/* mdsl_init()
 */
int mdsl_init(void)
{
    int err;

    /* lib init */
    lib_init();

    mdsl_pre_init();
    /* FIXME: decode the cmdline */

    /* FIXME: configurations */
    mdsl_config();
    hmo.conf.profiling_thread_interval = 5;
    hmo.conf.gc_interval = 5;
    hmo.conf.spool_threads = 8; /* double # of CPUs */

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
    
    /* init storage */
    err = mdsl_storage_init();
    if (err)
        goto out_storage;

    /* FIXME: init the service threads' pool */
    err = mdsl_spool_create();
    if (err)
        goto out_spool;

    /* init the aio threads */
    err = mdsl_aio_create();
    if (err)
        goto out_aio;
    
    /* mask the SIGUSR1 signal for main thread */
    {
        sigset_t set;

        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
    }

    /* ok to run */
    hmo.state = HMO_STATE_RUNNING;

out_aio:
out_spool:
out_storage:
out_timers:
out_signal:
out_tcc:
    return err;
}

void mdsl_destroy(void)
{
    hvfs_verbose(mdsl, "OK, stop it now...\n");

    /* unreg w/ the r2 server */
    if (hmo.cb_exit) {
        hmo.cb_exit(&hmo);
    }

    /* stop the timer thread */
    hmo.timer_thread_stop = 1;
    if (hmo.timer_thread)
        pthread_join(hmo.timer_thread, NULL);

    sem_destroy(&hmo.timer_sem);

    /* destroy the service threads' pool */
    mdsl_spool_destroy();

    /* destroy the tcc */
    mdsl_tcc_destroy();

    /* destroy the storage */
    mdsl_storage_destroy();

    /* you should wait for the storage destroied and exit the AIO threads */
    mdsl_aio_destroy();
    
}
