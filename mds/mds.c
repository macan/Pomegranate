/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-07 20:18:00 macan>
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
        return;
    }
#endif
    if (signo == SIGSEGV || signo == SIGBUS) {
        hvfs_info(lib, "Recv %sSIGSEGV%s %s\n",
                  HVFS_COLOR_RED,
                  HVFS_COLOR_END,
                  SIGCODES(info->si_code));
        lib_segv(signo, info, arg);
    }
    if (signo == SIGHUP) {
        hvfs_info(lib, "Exit MDS Server ...\n");
        mds_destroy();
        exit(0);
    }
    
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
#endif

out:
    return err;
}

void mds_itimer_default(int signo, siginfo_t *info, void *arg)
{
    sem_post(&hmo.timer_sem);
    hvfs_verbose(mds, "Did this signal handler called?\n");

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
    time_t cur;
    int v, err;

    hvfs_debug(mds, "I am running...\n");

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
        hvfs_debug(mds, "OK, we receive a SIGALRM event(remain %d).\n", v);
        /* should we work now */
        cur = time(NULL);
        if (hmo.state > HMO_STATE_LAUNCH) {
            /* ok, checking txg */
            txg_changer(cur);
        }
        /* then, checking profiling */
        dump_profiling(cur);
        /* next, itb checking */
        mds_spool_mp_check(cur);
        /* next, checking async unlink */
        async_unlink(cur);
        /* next, checking the CBHT slow down */
        async_update_checking(cur);
        /* next, checking the bitmap cache. */
        mds_bc_checking(cur);
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

    /* init the timer semaphore */
    sem_init(&hmo.timer_sem, 0, 0);

    /* ok, we create the timer thread now */
    err = pthread_create(&hmo.timer_thread, NULL, &mds_timer_thread_main,
                         NULL);
    if (err)
        goto out;
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
    interval = __gcd(hmo.conf.unlink_interval, interval);
    interval = __gcd(hmo.conf.bitmap_cache_interval, interval);
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
        hvfs_debug(mds, "OK, we have created a timer thread to handle txg "
                   "change and profiling events every %d second(s).\n", 
                   interval);
    } else {
        hvfs_debug(mds, "Hoo, there is no need to setup itimers based on the"
                   " configration.\n");
        hmo.timer_thread_stop = 1;
    }
    
out:
    return err;
}

void mds_reset_itimer(void)
{
    struct itimerval value, ovalue, pvalue;
    int err, interval;

    err = getitimer(ITIMER_REAL, &pvalue);
    if (err) {
        goto out;
    }
    interval = __gcd(hmo.conf.profiling_thread_interval,
                     hmo.conf.txg_interval);
    interval = __gcd(hmo.conf.unlink_interval, interval);
    if (interval) {
        value.it_interval.tv_sec = interval;
        value.it_interval.tv_usec = 0;
        value.it_value.tv_sec = interval;
        value.it_value.tv_usec = 0;
        err = setitimer(ITIMER_REAL, &value, &ovalue);
        if (err) {
            goto out;
        }
        hvfs_info(mds, "OK, we reset the itimer to %d second(s).\n", 
                   interval);
    }
out:
    return;
}


/* mds_pre_init()
 *
 * setting up the internal configs.
 */
void mds_pre_init()
{
    /* prepare the hmi & hmo */
    memset(&hmi, 0, sizeof(hmi));
    memset(&hmo, 0, sizeof(hmo));
    INIT_LIST_HEAD(&hmo.async_unlink);
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    /* setup the state */
    hmo.state = HMO_STATE_LAUNCH;
}

/* mds_verify()
 */
int mds_verify(void)
{
    /* check modify pause and spool usage */
    if (hmo.conf.option & HVFS_MDS_MEMLIMIT) {
        if (!hmo.xc || (hmo.xc->ops.recv_handler != mds_spool_dispatch)) {
            return -1;
        }
        if (hmo.conf.memlimit == 0)
            return -1;
    }

    return 0;
}

/* mds_config()
 *
 * Get configuration from the execution environment.
 */
int mds_config(void)
{
    char *value;

    if (hmo.state != HMO_STATE_LAUNCH) {
        hvfs_err(mds, "MDS state is not in launching, please call "
                 "mds_pre_init() firstly!\n");
        return -EINVAL;
    }

    HVFS_MDS_GET_ENV_strncpy(dcaddr, value, MDS_DCONF_MAX_NAME_LEN);

    HVFS_MDS_GET_ENV_cpy(profiling_file, value);
    HVFS_MDS_GET_ENV_cpy(conf_file, value);
    HVFS_MDS_GET_ENV_cpy(log_file, value);

    HVFS_MDS_GET_ENV_atoi(commit_threads, value);
    HVFS_MDS_GET_ENV_atoi(service_threads, value);
    HVFS_MDS_GET_ENV_atoi(async_threads, value);
    HVFS_MDS_GET_ENV_atoi(spool_threads, value);
    HVFS_MDS_GET_ENV_atoi(max_async_unlink, value);
    HVFS_MDS_GET_ENV_atoi(txc_hash_size, value);
    HVFS_MDS_GET_ENV_atoi(bc_hash_size, value);
    HVFS_MDS_GET_ENV_atoi(txc_ftx, value);
    HVFS_MDS_GET_ENV_atoi(cbht_bucket_depth, value);
    HVFS_MDS_GET_ENV_atoi(itb_cache, value);
    HVFS_MDS_GET_ENV_atoi(async_unlink, value);
    HVFS_MDS_GET_ENV_atoi(ring_vid_max, value);
    HVFS_MDS_GET_ENV_atoi(itb_depth_default, value);
    HVFS_MDS_GET_ENV_atoi(async_update_N, value);
    HVFS_MDS_GET_ENV_atoi(mp_to, value);
    HVFS_MDS_GET_ENV_atoi(itbid_check, value);
    HVFS_MDS_GET_ENV_atoi(cbht_slow_down, value);
    HVFS_MDS_GET_ENV_atoi(prof_plot, value);
    HVFS_MDS_GET_ENV_atoi(profiling_thread_interval, value);
    HVFS_MDS_GET_ENV_atoi(txg_interval, value);
    HVFS_MDS_GET_ENV_atoi(unlink_interval, value);
    HVFS_MDS_GET_ENV_atoi(bitmap_cache_interval, value);
    HVFS_MDS_GET_ENV_atoi(txg_buf_len, value);
    HVFS_MDS_GET_ENV_atoi(bc_roof, value);
    HVFS_MDS_GET_ENV_atoi(txg_ddht_size, value);
    HVFS_MDS_GET_ENV_atoi(xnet_resend_to, value);

    HVFS_MDS_GET_ENV_atol(memlimit, value);

    HVFS_MDS_GET_ENV_option(opt_chrechk, CHRECHK, value);
    HVFS_MDS_GET_ENV_option(opt_itb_rwlock, ITB_RWLOCK, value);
    HVFS_MDS_GET_ENV_option(opt_itb_mutex, ITB_MUTEX, value);
    HVFS_MDS_GET_ENV_option(opt_memonly, MEMONLY, value);
    HVFS_MDS_GET_ENV_option(opt_memlimit, MEMLIMIT, value);
    HVFS_MDS_GET_ENV_option(opt_limited, LIMITED, value);

    /* default configurations */
    if (!hmo.conf.txg_buf_len) {
        hmo.conf.txg_buf_len = HVFS_MDSL_TXG_BUF_LEN;
    }

    if (!hmo.conf.profiling_thread_interval)
        hmo.conf.profiling_thread_interval = 5;
    if (!hmo.conf.txg_interval) 
        hmo.conf.txg_interval = 30;
    if (!hmo.conf.bitmap_cache_interval)
        hmo.conf.bitmap_cache_interval = 5;

    return 0;
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
    
    /* lib init */
    lib_init();
    
    /* FIXME: decode the cmdline */

    /* FIXME: configations */
    dconf_init();
    /* default configurations */
    hmo.conf.option |= HVFS_MDS_ITB_RWLOCK | HVFS_MDS_CHRECHK;
    hmo.conf.max_async_unlink = 1024;
    hmo.conf.async_unlink = 0;  /* disable async unlink */
    hmo.conf.unlink_interval = 2;
    hmo.conf.txc_hash_size = 1024;
    hmo.conf.txc_ftx = 1;
    hmo.conf.cbht_bucket_depth = bdepth;
    hmo.conf.itb_depth_default = 3;
    hmo.conf.async_update_N = 4;
    hmo.conf.spool_threads = 8;
    hmo.conf.mp_to = 60;

    /* get configs from env */
    mds_config();

    /* Init the signal handlers */
    err = mds_init_signal();
    if (err)
        goto out_signal;

    /* FIXME: init the TXC subsystem */
    err = mds_init_txc(&hmo.txc, hmo.conf.txc_hash_size, 
                       hmo.conf.txc_ftx);
    if (err)
        goto out_txc;

    /* FIXME: init the BC subsystem */
    err = mds_bitmap_cache_init();
    if (err)
        goto out_bc;

    /* FIXME: setup the timers */
    err = mds_setup_timers();
    if (err)
        goto out_timers;

    /* FIXME: init the xnet subsystem */

    /* FIXME: init the profiling subsystem */

    /* FIXME: init the fault tolerant subsystem */

    /* FIXME: register with the Ring server */

    /* FIXME: init the dh subsystem */
    err = mds_dh_init(&hmo.dh, MDS_DH_DEFAULT_SIZE);
    if (err)
        goto out_dh;
    
    /* FIXME: init the TX subsystem, init the commit threads' pool */
    err = mds_init_tx(0);
    if (err)
        goto out_tx;

    /* FIXME: init the async update subsystem */
    err = async_tp_init();
    if (err)
        goto out_async;

    /* FIXME: init hte CBHT subsystem */
    err = mds_cbht_init(&hmo.cbht, hmo.conf.cbht_bucket_depth);
    if (err)
        goto out_cbht;

    /* FIXME: init the ITB cache */
    err = itb_cache_init(&hmo.ic, hmo.conf.itb_cache);
    if (err)
        goto out_itb;
    
    /* FIXME: init the local async unlink thead */
    err = unlink_thread_init();
    if (err)
        goto out_unlink;
    
    /* FIXME: init the service threads' pool */
    err = mds_spool_create();
    if (err)
        goto out_spool;

    /* FIXME: waiting for the notification from R2 */

    /* FIXME: waiting for the requests from client/mds/mdsl/r2 */

    /* ok to run */
    hmo.state = HMO_STATE_RUNNING;

out_spool:
out_unlink:
out_itb:
out_cbht:
out_async:
out_tx:
out_dh:
out_txc:
out_bc:
out_timers:
out_signal:
    return err;
}

void mds_destroy(void)
{
    hvfs_verbose(mds, "OK, stop it now...\n");

    /* unreg w/ the r2 server */
    if (hmo.cb_exit) {
        hmo.cb_exit(&hmo);
    }

    /* stop the timer thread */
    hmo.timer_thread_stop = 1;
    if (hmo.timer_thread)
        pthread_join(hmo.timer_thread, NULL);

    sem_destroy(&hmo.timer_sem);

    /* stop the unlink thread */
    unlink_thread_destroy();

    /* itb */
    itb_cache_destroy(&hmo.ic);
    
    /* cbht */
    mds_cbht_destroy(&hmo.cbht);

    /* stop the async threads */
    async_tp_destroy();

    /* stop the commit threads */
    mds_destroy_tx();

    /* destroy the dh */
    mds_dh_destroy(&hmo.dh);

    /* destroy the BC */
    mds_bitmap_cache_destroy();

    /* destroy the txc */
    mds_destroy_txc(&hmo.txc);

    /* destroy the dconf */
    dconf_destroy();

    /* destroy the service thread pool */
    mds_spool_destroy();

    /* close the files */
    if (hmo.conf.pf_file)
        fclose(hmo.conf.pf_file);
}

u64 mds_select_ring(struct hvfs_mds_object *hmo)
{
    if (hmo->ring_site)
        return hmo->ring_site;
    else
        return HVFS_RING(0);
}

void mds_set_ring(u64 site_id)
{
    hmo.ring_site = site_id;
}

