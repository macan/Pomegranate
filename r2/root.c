/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-06 12:48:14 macan>
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

void root_sigaction_default(int signo, siginfo_t *info, void *arg)
{
    if (signo == SIGSEGV || signo == SIGBUS) {
        hvfs_info(lib, "Recv %sSIGSEGV%s %s\n",
                  HVFS_COLOR_RED,
                  HVFS_COLOR_END,
                  SIGCODES(info->si_code));
        lib_segv(signo, info, arg);
    }
    if (signo == SIGHUP) {
        hvfs_info(lib, "Exit ROOT Server ...\n");
        root_destroy();
        exit(0);
    }
    if (signo == SIGUSR1) {
        hvfs_info(lib, "Exit some thread ...\n");
        pthread_exit(0);
    }

    return;
}

/* root_init_signal()
 */
static int root_init_signal(void)
{
    struct sigaction ac;
    int err;

    ac.sa_sigaction = root_sigaction_default;
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

int root_dir_make_exist(char *path)
{
    int err;

    err = mkdir(path, 0755);
    if (err) {
        err = -errno;
        if (errno == EEXIST) {
            err = 0;
        } else if (errno == EACCES) {
            hvfs_err(root, "Failed to create the dir %s, no permission.\n",
                     path);
        } else {
            hvfs_err(root, "mkdir %s failed w/ %d\n", path, errno);
        }
    }

    return err;
}

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
    int err = 0;
    
    /* check the HVFS_HOME */
    err = root_dir_make_exist(hro.conf.root_home);
    if (err) {
        hvfs_err(root, "dir %s do not exist.\n", hro.conf.root_home);
        goto out;
    }

out:
    return err;
}

/* root_config()
 *
 * Get configs from the env
 */
int root_config(void)
{
    char *value, *__path;
    int err = 0;
    
    if (hro.state != HRO_STATE_LAUNCH) {
        hvfs_err(root, "ROOT state is not in launching, please call "
                 "root_pre_init() firstly!\n");
        return -EINVAL;
    }

    HVFS_ROOT_GET_ENV_cpy(root_home, value);
    HVFS_ROOT_GET_ENV_cpy(root_store, value);
    HVFS_ROOT_GET_ENV_cpy(bitmap_store, value);
    HVFS_ROOT_GET_ENV_cpy(site_store, value);
    HVFS_ROOT_GET_ENV_cpy(addr_store, value);

    HVFS_ROOT_GET_ENV_atoi(site_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(ring_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(root_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(addr_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(service_threads, value);
    HVFS_ROOT_GET_ENV_atoi(ring_push_interval, value);
    HVFS_ROOT_GET_ENV_atoi(profile_interval, value);
    HVFS_ROOT_GET_ENV_atoi(hb_interval, value);
    HVFS_ROOT_GET_ENV_atoi(log_print_interval, value);
    HVFS_ROOT_GET_ENV_atoi(sync_interval, value);
    HVFS_ROOT_GET_ENV_atoi(ring_vid_max, value);
    HVFS_ROOT_GET_ENV_atoi(prof_plot, value);

    HVFS_ROOT_GET_ENV_option(opt_memonly, MEMONLY, value);

    /* default configs */
    if (!hro.conf.ring_vid_max) {
        hro.conf.ring_vid_max = HVFS_RING_VID_MAX;
    }
    
    if (!hro.conf.root_home) {
        hro.conf.root_home = HVFS_ROOT_HOME;
    }

    if (!hro.conf.root_store) {
        hro.conf.root_store = HVFS_ROOT_STORE;
    }

    if (!hro.conf.profile_interval) {
        hro.conf.profile_interval = 5;
    }
    
    {
        __path = xzalloc(256);

        if (!__path) {
            hvfs_err(root, "get path storage failed.\n");
            err = -ENOMEM;
            goto out;
        }
        
        snprintf(__path, 255, "%s/%s", hro.conf.root_home,
                 hro.conf.root_store);
        hro.conf.root_store = __path;
    }

    if (!hro.conf.bitmap_store) {
        hro.conf.bitmap_store = HVFS_BITMAP_STORE;
    }
    {
        __path = xzalloc(256);

        if (!__path) {
            hvfs_err(root, "get path storage failed.\n");
            err = -ENOMEM;
            goto out;
        }
        
        snprintf(__path, 255, "%s/%s", hro.conf.root_home,
                 hro.conf.bitmap_store);
        hro.conf.bitmap_store = __path;
    }

    if (!hro.conf.site_store) {
        hro.conf.site_store = HVFS_SITE_STORE;
    }
    {
        __path = xzalloc(256);

        if (!__path) {
            hvfs_err(root, "get path storage failed.\n");
            err = -ENOMEM;
            goto out;
        }
        
        snprintf(__path, 255, "%s/%s", hro.conf.root_home,
                 hro.conf.site_store);
        hro.conf.site_store = __path;
    }

    if (!hro.conf.addr_store) {
        hro.conf.addr_store = HVFS_ADDR_STORE;
    }
    {
        __path = xzalloc(256);

        if (!__path) {
            hvfs_err(root, "get path storage failed.\n");
            err = -ENOMEM;
            goto out;
        }

        snprintf(__path, 255, "%s/%s", hro.conf.root_home,
                 hro.conf.addr_store);
        hro.conf.addr_store = __path;
    }

    if (!hro.conf.ring_push_interval) {
        hro.conf.ring_push_interval = 600;
    }
    if (!hro.conf.hb_interval) {
        hro.conf.hb_interval = 60;
    }
    if (!hro.conf.log_print_interval) {
        hro.conf.log_print_interval = 15;
    }
    if (!hro.conf.sync_interval) {
        hro.conf.sync_interval = 0; /* do not do sync actually */
    }

out:
    return err;
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
            site_mgr_check(cur);
            site_mgr_check2(cur);
            {
                struct objid id = {.uuid = 100, .bid = 10,};
                struct osd_list *list = om_query_obj(id);
                int i;
                
                if (!IS_ERR(list)) {
                    hvfs_info(root, "OK, query return osd list => \n");
                    for (i = 0; i < list->size; i++) {
                        hvfs_info(root, "osd[%d] = %lx\n", i, list->site[i]);
                    }
                    xfree(list);
                } else {
                    hvfs_err(root, "Bad, query return %ld\n", PTR_ERR(list));
                }
            }
            /* write profile? */
            if (hro.conf.prof_plot == ROOT_PROF_PLOT) {
                root_profile_flush(cur);
            }
        }
    }

    hvfs_debug(root, "Hooo, I am exiting...\n");
    pthread_exit(0);
}

static int root_setup_timers(void)
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
    interval = __gcd(interval, hro.conf.profile_interval);
    if (interval) {
        value.it_interval.tv_sec = interval;
        value.it_interval.tv_usec = 1;
        value.it_value.tv_sec = interval;
        value.it_value.tv_usec = 1;
        err = setitimer(which, &value, &ovalue);
        if (err) {
            hvfs_err(root, "setitimer failed w/ %s\n", strerror(errno));
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
    err = root_config();
    if (err)
        goto out_config;

    /* verify the configs */
    err = root_verify();
    if (err)
        goto out_verify;

    err = root_init_signal();
    if (err)
        goto out_signal;
    
    /* init hro */
    err = site_mgr_init(&hro.site);
    if (err)
        goto out_site_mgr;

    err = ring_mgr_init(&hro.ring);
    if (err)
        goto out_ring_mgr;

    err = root_mgr_init(&hro.root);
    if (err)
        goto out_root_mgr;

    err = addr_mgr_init(&hro.addr);
    if (err)
        goto out_addr_mgr;
    
    /* FIXME: in the service threads' pool */
    err = root_spool_create();
    if (err)
        goto out_spool;

    /* FIXME: setup the timers */
    err = root_setup_timers();
    if (err)
        goto out_timers;

    /* FIXME: setup the profile unit */
    err = root_setup_profile();
    if (err)
        goto out_profile;

    /* setup the object manager */
    err = om_init(HVFS_OM_TYPE_MASTER);
    if (err)
        goto out_om;

    /* maks the SIGUSR1 signal for main thread */
    {
        sigset_t set;

        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
    }

    /* ok to run */
    hro.state = HRO_STATE_RUNNING;
    hro.uptime = time(NULL);

out_om:
out_profile:
out_timers:
out_spool:
out_addr_mgr:
out_root_mgr:
out_ring_mgr:
out_site_mgr:
out_signal:
out_verify:
out_config:
    
    return err;
}

void root_destroy(void)
{
    hvfs_verbose(root, "OK, stop it now ...\n");

    /* free something */
    om_destroy();

    /* destroy the service thread pool */
    root_spool_destroy();

    /* stop the timer thread */
    hro.timer_thread_stop = 1;
    if (hro.timer_thread) {
        sem_post(&hro.timer_sem);
        pthread_join(hro.timer_thread, NULL);
    }

    /* destroy hro */
    site_mgr_destroy(&hro.site);
    ring_mgr_destroy(&hro.ring);
    root_mgr_destroy(&hro.root);
    addr_mgr_destroy(&hro.addr);
}
