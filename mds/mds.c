/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-09-04 15:52:21 macan>
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

void mds_reset_tracing_flags(u64 flag)
{
    hvfs_mds_tracing_flags = flag;
}
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
    if (signo == SIGSEGV || signo == SIGBUS || signo == SIGABRT) {
        hvfs_info(lib, "Recv %sSIGSEGV/SIGBUS/SIGABRT%s %s @ addr %p\n",
                  HVFS_COLOR_RED,
                  HVFS_COLOR_END,
                  SIGCODES(info->si_code),
                  info->si_addr);
        lib_segv(signo, info, arg);
    }
    if (signo == SIGHUP) {
        hvfs_info(lib, "Exit MDS Server ...\n");
        mds_destroy();
        exit(0);
    }
    if (signo == SIGUSR1) {
        hvfs_info(lib, "Exit some threads ...\n");
        pthread_exit(0);
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

static inline
int network_congestion(time_t cur)
{
    static time_t last_ts = 0;
    static u64 last_obytes = 0;
    u64 cur_obytes;
    int ret = 0;

    if (cur > last_ts) {
        if (unlikely(!hmo.prof.xnet)) {
            /* xnet in/out bytes info is not avaliable, we randomly congested */
            ret = lib_random(1);
        } else {
            if (!last_ts) {
                last_ts = cur;
                last_obytes = atomic64_read(&hmo.prof.xnet->outbytes);
            }
            if (cur > last_ts) {
                cur_obytes = atomic64_read(&hmo.prof.xnet->outbytes);
                /* bigger than 5MB/s means network congested */
                if ((cur_obytes - last_obytes) / (cur - last_ts) > 
                    (5 << 20)) {
                    ret = 1;
                }
                last_ts = cur;
                last_obytes = cur_obytes;
            }
        }
    }

    return ret;
}

static inline
void dynamic_adjust_txg_interval(time_t cur)
{
    static u64 last_modify = 0;
    static time_t last_ts = 0;
    static int nr = 0;

    if (!hmo.conf.dati)
        return;
    
    if (hmo.conf.txg_interval && cur > last_ts) {
        if ((atomic64_read(&hmo.prof.cbht.modify) - last_modify) / 
            (cur - last_ts) > 500) {
            nr = 0;
            hmo.conf.txg_interval = min(hmo.conf.txg_interval << 2, 15 * 60);
        } else {
            nr++;
            if (nr > 60)
                hmo.conf.txg_interval = max(hmo.conf.txg_interval >> 1, 30);
            /* is it slow? boost up */
            if (network_congestion(cur))
                hmo.conf.txg_interval = min(hmo.conf.txg_interval << 2, 15 * 60);
        }
        last_ts = cur;
        last_modify = atomic64_read(&hmo.prof.cbht.modify);
    }
}

void mds_itimer_default(int signo, siginfo_t *info, void *arg)
{
    u64 cur = time(NULL);
    
    sem_post(&hmo.timer_sem);
    /* Note that, we must check the profiling interval at here, otherwise
     * checking the profiling interval at timer_thread will lost some
     * statistics */
    if (!hmo.timer_thread_stop)
        dump_profiling(cur, &hmo.hp);
    hmo.tick = cur;
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

void mds_hb_wrapper(time_t t)
{
    static time_t prev = 0;

    if (!hmo.cb_hb)
        return;
    
    if (hmo.state >= HMO_STATE_RUNNING) {
        if (t < prev + hmo.conf.hb_interval) {
            return;
        }
        prev = t;
        hmo.cb_hb(&hmo);
    }
}

/* scrub the CBHT
 */
void mds_scrub(time_t t)
{
    if (hmo.conf.option & HVFS_MDS_NOSCRUB)
        return;
    
    if (hmo.scrub_running)
        return;
    if (t < hmo.scrub_ts + hmo.conf.scrub_interval)
        return;

    hmo.scrub_ts = t;
    mds_scrub_trigger();
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
        hmo.tick = cur;
        if (hmo.state > HMO_STATE_LAUNCH) {
            /* ok, checking txg */
            dynamic_adjust_txg_interval(cur);
            txg_changer(cur);
        }
        /* then, checking profiling */
        dump_profiling(cur, &hmo.hp);
        /* next, itb checking */
        mds_spool_mp_check(cur);
        /* next, checking async unlink */
        async_unlink(cur);
        /* next, checking the CBHT slow down */
        async_update_checking(cur);
        /* next, checking the bitmap cache. */
        mds_bc_notify_check();
        /* next, checking the heart beat beep */
        mds_hb_wrapper(cur);
        /* next, checking the scrub progress */
        mds_scrub(cur);
        /* next, check the dh hash table */
        mds_dh_check(cur);
        /* next, reap redo logs */
        redo_log_reap(cur);
        /* FIXME: */
    }

    hvfs_debug(mds, "Hooo, I am exiting...\n");
    pthread_exit(0);
}

int mds_setup_timers(void)
{
    pthread_attr_t attr;
    struct sigaction ac;
    struct itimerval value, ovalue, pvalue;
    int which = ITIMER_REAL, interval;
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

    /* init the timer semaphore */
    sem_init(&hmo.timer_sem, 0, 0);

    /* ok, we create the timer thread now */
    err = pthread_create(&hmo.timer_thread, &attr, &mds_timer_thread_main,
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
    interval = __gcd(hmo.conf.hb_interval, interval);
    interval = __gcd(hmo.conf.scrub_interval, interval);
    if (interval) {
        value.it_interval.tv_sec = interval;
        value.it_interval.tv_usec = 0;
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

/* we support sub-second timers to promote the triggers
 */
void mds_reset_itimer_us(u64 us)
{
    struct itimerval value, ovalue;
    int err;

    if (us) {
        value.it_interval.tv_sec = 0;
        value.it_interval.tv_usec = us;
        value.it_value.tv_sec = 0;
        value.it_value.tv_usec = us;
        err = setitimer(ITIMER_REAL, &value, &ovalue);
        if (err) {
            goto out;
        }
        hvfs_info(mds, "OK, we reset the itimer to %ld us.\n",
                  us);
    } else {
        hvfs_err(mds, "Invalid sub-second timer value.\n");
    }
out:
    return;
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
    interval = __gcd(hmo.conf.bitmap_cache_interval, interval);
    interval = __gcd(hmo.conf.hb_interval, interval);
    interval = __gcd(hmo.conf.scrub_interval, interval);
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

/* mds_cbht_evict_default()
 *
 * Hold the bucket.rlock and be.rlock
 *
 * we should update to the be.wlock and check if we can free the ITB
 */

int mds_cbht_evict_default(struct bucket *b, void *arg0, void *arg1)
{
    struct bucket_entry *be = (struct bucket_entry *)arg0;
    struct bucket_entry *obe;
    struct itbh *ih = (struct itbh *)arg1;
    struct hvfs_txg *t;
    int err = 0;

    xrwlock_wlock(&ih->lock);
    if (ih->state == ITB_STATE_CLEAN) {
        /* ok, this is the target to operate on */
        obe = ih->be;
        t = mds_get_open_txg(&hmo);
        if (be == obe) {
            if (ih->be != be ||
                ih->twin != 0 || 
                atomic_read(&ih->ref) > 1 ||
                !list_empty(&ih->list) ||
                !TXG_IS_COMMITED(ih->txg)) {
                if (ih->txg == t->txg && !TXG_IS_DIRTY(t))
                    goto ok;
                /* we just failed to update the wlock, exit... */
                txg_put(t);
                goto out_unlock;
            }
        ok:
            /* try to release the ITB now */
            if (ih->be == obe && atomic_read(&ih->ref) == 1) {
                /* not moved, unhash it */
                hlist_del_init(&ih->cbht);
                ih->be = NULL;
                atomic_dec(&b->active);
                atomic64_sub(atomic_read(&ih->entries), 
                             &hmo.prof.cbht.aentry);
            } else {
                /* moved, not unhash */
                txg_put(t);
                goto out_unlock;
            }

            hvfs_warning(mds, "DO evict on clean ITB %ld txg %ld ref %d\n", 
                         ih->itbid, ih->txg, atomic_read(&ih->ref));
            /* free it finally */
            itb_put((struct itb *)ih);
        }
        txg_put(t);
        goto out;
    } else if (ih->state == ITB_STATE_DIRTY) {
        hvfs_debug(mds, "DO not evict dirty ITB %ld\n", ih->itbid);
    } else {
        hvfs_debug(mds, "DO not evict ITB %ld state %d\n", ih->itbid, ih->state);
    }

out_unlock:
    xrwlock_wunlock(&ih->lock);
out:
    return err;
}

/* mds_cbht_evice_all_default()
 *
 * Hold the bucket.rlock and be.rlock
 *
 * We should update to the be.wlock and check if we can free the ITB. This
 * function is NOT the same as evict_default(). It will evict the clean ITBs
 * in current txg if and only if current is not dirty.
 */
int mds_cbht_evict_all_default(struct bucket *b, void *arg0, void *arg1)
{
    struct bucket_entry *be = (struct bucket_entry *)arg0;
    struct bucket_entry *obe;
    struct itbh *ih = (struct itbh *)arg1;
    struct hvfs_txg *t;
    int err = 0;

    xrwlock_wlock(&ih->lock);
    hvfs_warning(mds, "Try to evict ITB (%lx,%ld) txg %ld state %x "
                 "be %p obe %p twin %ld ref %d list_empty %d\n", 
                 ih->puuid, ih->itbid, ih->txg, ih->state, be, ih->be, 
                 ih->twin, atomic_read(&ih->ref), list_empty(&ih->list));
    if (ih->state == ITB_STATE_CLEAN) {
        /* ok, this is the target to operate on */
        obe = ih->be;
        t = mds_get_open_txg(&hmo);
        if (be == obe) {
            if (ih->be != be ||
                ih->twin != 0 || 
                atomic_read(&ih->ref) > 1 ||
                !list_empty(&ih->list)) {
                /* we just failed to update the wlock, exit... */
                txg_put(t);
                goto out_unlock;
            }

            /* try to release the ITB now */
            if (ih->be == obe) {
                /* not moved, unhash it */
                hlist_del_init(&ih->cbht);
                ih->be = NULL;
                atomic_dec(&b->active);
                atomic64_sub(atomic_read(&ih->entries), 
                             &hmo.prof.cbht.aentry);
            } else {
                /* moved, not unhash */
                txg_put(t);
                goto out_unlock;
            }

            hvfs_warning(mds, "DO evict on clean ITB %ld txg %ld success\n", 
                         ih->itbid, ih->txg);
            itb_put((struct itb *)ih);
        }
        txg_put(t);
        goto out;
    } else if (ih->state == ITB_STATE_DIRTY) {
        hvfs_warning(mds, "DO not evict dirty ITB %ld\n", ih->itbid);
    }

out_unlock:
    xrwlock_wunlock(&ih->lock);
out:
    return err;
}

int rdir_init(void)
{
    int i;
    
    if (!hmo.conf.rdir_hsize)
        hmo.conf.rdir_hsize = RDIR_HTSIZE;

    hmo.rm.hsize = hmo.conf.rdir_hsize;
    hmo.rm.ht = xzalloc(hmo.rm.hsize * sizeof(struct regular_hash));
    if (!hmo.rm.ht) {
        hvfs_err(mds, "xzalloc() rdir hash table failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < hmo.rm.hsize; i++) {
        INIT_HLIST_HEAD(&(hmo.rm.ht + i)->h);
        xlock_init(&(hmo.rm.ht + i)->lock);
    }
    atomic_set(&hmo.rm.active, 0);

    return 0;
}

void rdir_destroy(void)
{
    xfree(hmo.rm.ht);
}

static inline
int rdir_hash(u64 key)
{
    u64 val1;

    val1 = hash_64(key, 64);
    val1 = val1 ^ GOLDEN_RATIO_PRIME;

    return val1 % hmo.rm.hsize; /* FIXME: need more faster! */
}

int rdir_lookup(struct rdir_mgr *rm, u64 uuid)
{
    struct regular_hash *rh;
    struct rdir_entry *re;
    struct hlist_node *n;
    int idx, found = 0;

    idx = rdir_hash(uuid);
    rh = hmo.rm.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(re, n, &rh->h, hlist) {
        if (likely(re->uuid == uuid)) {
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    return found;
}

int rdir_insert(struct rdir_mgr *rm, u64 uuid)
{
    struct regular_hash *rh;
    struct rdir_entry *re, *new;
    struct hlist_node *n;
    int idx, found = 0;

    new = xmalloc(sizeof(*new));
    if (!new) {
        hvfs_err(mds, "alloc rdir entry failed\n");
        return -ENOMEM;
    }
    INIT_HLIST_NODE(&new->hlist);
    new->uuid = uuid;
    
    idx = rdir_hash(uuid);
    rh = hmo.rm.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(re, n, &rh->h, hlist) {
        if (likely(re->uuid == new->uuid)) {
            found = 1;
            break;
        }
    }
    if (!found) {
        hlist_add_head(&new->hlist, &rh->h);
        atomic_inc(&hmo.rm.active);
    }
    xlock_unlock(&rh->lock);
    if (found) {
        xfree(new);
    }

    return !found;
}

int rdir_remove(struct rdir_mgr *rm, u64 uuid)
{
    struct regular_hash *rh;
    struct rdir_entry *re;
    struct hlist_node *pos, *n;
    int idx;

    idx = rdir_hash(uuid);
    rh = hmo.rm.ht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(re, pos, n, &rh->h, hlist) {
        if (unlikely(re->uuid == uuid)) {
            hlist_del(&re->hlist);
            xfree(re);
            atomic_dec(&hmo.rm.active);
        }
    }
    xlock_unlock(&rh->lock);

    return 0;
}

int rdir_remove_all(struct rdir_mgr *rm)
{
    struct regular_hash *rh;
    struct rdir_entry *re;
    struct hlist_node *pos, *n;
    int idx;

    for (idx = 0; idx < hmo.rm.hsize; idx++) {
        rh = hmo.rm.ht + idx;
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(re, pos, n, &rh->h, hlist) {
            hlist_del(&re->hlist);
            xfree(re);
            atomic_dec(&hmo.rm.active);
        }
        xlock_unlock(&rh->lock);
    }
    
    return 0;
}

void mds_rdir_get_all(struct rdir_mgr *rm, u64 **out, size_t *size)
{
    struct regular_hash *rh;
    struct rdir_entry *re;
    struct hlist_node *n;
    u64 *p = NULL;
    size_t s = 0;
    int idx;

    *out = NULL;
    
    for (idx = 0; idx < hmo.rm.hsize; idx++) {
        rh = hmo.rm.ht + idx;
        xlock_lock(&rh->lock);
        hlist_for_each_entry(re, n, &rh->h, hlist) {
            s++;
            p = xrealloc(*out, s * sizeof(u64));
            if (!p) {
                hvfs_err(mds, "realloc() rdir entry failed\n");
                xlock_unlock(&rh->lock);
                *size = s - 1;
                return;
            }
            *out = p;
            p[s - 1] = re->uuid;
        }
        xlock_unlock(&rh->lock);
    }

    *size = s;
}

void mds_rdir_check(time_t cur)
{
    if (atomic_read(&hmo.rm.active) > 0) {
        /* we should clean the itbs */
        mds_cbht_scan(&hmo.cbht, HVFS_MDS_OP_CLEAN);
        /* it is ok to remove some MORE entries :) */
        rdir_remove_all(&hmo.rm);
        atomic_set(&hmo.rm.active, 0);
    }
}

/* mdsl_cbht_clean_default()
 *
 * This function check if the directory is removed. If it is, then commit and
 * remove the current ITB.
 */
int mds_cbht_clean_default(struct bucket *b, void *arg0, void *arg1)
{
    struct bucket_entry *be = (struct bucket_entry *)arg0;
    struct bucket_entry *obe;
    struct itbh *ih = (struct itbh *)arg1;
    struct hvfs_txg *t;
    int err = 0;

    xrwlock_wlock(&ih->lock);
    hvfs_debug(mds, "Try to clean ITB %ld txg %ld state %x "
               "be %p obe %p twin %ld ref %d list_empty %d\n", 
               ih->itbid, ih->txg, ih->state, be, ih->be, 
               ih->twin, atomic_read(&ih->ref), list_empty(&ih->list));
    if (rdir_lookup(&hmo.rm, ih->puuid)) {
        /* ok, we should clean this itb NOW. Actually, we do not care about
         * the itb->h.state, but we check it either */

        if (ih->state == ITB_STATE_CLEAN) {
            /* ok, this is the target to operate on */
            obe = ih->be;
            t = mds_get_open_txg(&hmo);
            if (be == obe) {
                if (ih->be != be ||
                    ih->twin != 0 || 
                    atomic_read(&ih->ref) > 1 ||
                    !list_empty(&ih->list)) {
                    /* we just failed to update the wlock, exit... */
                    txg_put(t);
                    goto out_unlock;
                }
                
                /* try to release the ITB now */
                if (ih->be == obe) {
                    /* not moved, unhash it */
                    hlist_del_init(&ih->cbht);
                    ih->be = NULL;
                    atomic_dec(&b->active);
                    atomic64_sub(atomic_read(&ih->entries), 
                                 &hmo.prof.cbht.aentry);
                } else {
                    /* moved, not unhash */
                    txg_put(t);
                    goto out_unlock;
                }
                
                hvfs_warning(mds, "DO evict on clean ITB %ld txg %ld success\n", 
                             ih->itbid, ih->txg);
                itb_put((struct itb *)ih);
            }
            txg_put(t);
            goto out;
        } else if (ih->state == ITB_STATE_DIRTY) {
            hvfs_warning(mds, "DO not evict dirty ITB %ld\n", ih->itbid);
        }
    }
        
out_unlock:
    xrwlock_wunlock(&ih->lock);
out:
    return err;
}

int rpc_realloc(struct mds_rpc_table **omrt)
{
    struct mds_rpc_table *mrt = NULL;
    int size = 0;

    if (*omrt) {
        size = (*omrt)->psize;
    }
    size += 64;

    mrt = xrealloc(*omrt, sizeof(struct mds_rpc_table) + 
                   size * sizeof(struct mds_rpc_entry));
    if (!mrt) {
        hvfs_err(mds, "realloc MRT failed w/ ENOMEM\n");
        return -ENOMEM;
    }

    *omrt = mrt;

    return 0;
}

int rpc_init(void)
{
    int err = 0;

    /* init the rpc table to 64 entries */
    err = rpc_realloc(&hmo.mrt);
    if (err) {
        hvfs_err(mds, "RPC realloc failed w/ %d\n", err);
        goto out;
    }
    
out:    
    return err;
}

/* rpc_reg() return the index of the RPC entry
 */
int rpc_reg(char *name, rpc_callback_t cb)
{
    int err = 0, i;
    
    if (hmo.mrt->asize == hmo.mrt->psize) {
        /* realloc the rpc table */
        err = rpc_realloc(&hmo.mrt);
        if (err) {
            hvfs_err(mds, "RPC realloc failed w/ %d\n", err);
            return err;
        }
    }
    /* check for name conflict */
    for (i = 0; i < hmo.mrt->asize; i++) {
        if (strcmp(hmo.mrt->mre[i].name, name) == 0) {
            hvfs_err(mds, "Conflict RPC function name on '%s'\n", name);
            return -EINVAL;
        }
    }
    
    /* ok to install the rpc entry */
    hmo.mrt->mre[hmo.mrt->asize].name = strdup(name);
    hmo.mrt->mre[hmo.mrt->asize].cb = cb;
    hmo.mrt->asize++;

    return hmo.mrt->asize - 1;
}

void *__rpc_default(void *arg)
{
    hvfs_err(mds, "This RPC has been reset to default function call\n");
    return NULL;
}

/* Return value: 1: error; 0: found and deleted
 */
int rpc_unreg(char *name)
{
    int i;

    for (i = 0; i < hmo.mrt->asize; i++) {
        if (strcmp(hmo.mrt->mre[i].name, name) == 0) {
            hmo.mrt->mre[i].name = "";
            hmo.mrt->mre[i].cb = __rpc_default;
            return 0;
        }
    }

    return 1;
}

struct eh_operations ehops_default = {
    .evict = mds_cbht_evict_default,
    .evict_all = mds_cbht_evict_all_default,
    .clean = mds_cbht_clean_default,
};

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
    hmo.state = HMO_STATE_INIT;
}

/* make sure the dir exist
 */
int mds_dir_make_exist(char *path)
{
    int err;
    
    err = mkdir(path, 0755);
    if (err) {
        err = -errno;
        if (errno == EEXIST) {
            err = 0;
        } else if (errno == EACCES) {
            hvfs_err(mds, "Failed to create the dir %s, no permission.\n",
                     path);
        } else {
            hvfs_err(mds, "mkdir %s failed w/ %d\n", path, errno);
        }
    }
    
    return err;
}

/* mds_verify()
 */
int mds_verify(void)
{
    char path[256];
    int err = 0;
    
    if (!HVFS_IS_MDS(hmo.site_id))
        goto set_state;
    
    /* check the MDS_HOME */
    err = mds_dir_make_exist(hmo.conf.mds_home);
    if (err) {
        hvfs_err(mds, "dir %s does not exist %d.\n", 
                 hmo.conf.mds_home, err);
        return -EINVAL;
    }
    /* check the MDS site home directory */
    sprintf(path, "%s/%lx", hmo.conf.mds_home, hmo.site_id);
    err = mds_dir_make_exist(path);
    if (err) {
        hvfs_err(mds, "dir %s does not exist %d.\n", path, err);
        return -EINVAL;
    }
    
    /* check modify pause and spool usage */
    if (hmo.conf.option & HVFS_MDS_MEMLIMIT) {
        if (!hmo.xc || (hmo.xc->ops.recv_handler != mds_spool_dispatch)) {
            return -1;
        }
        if (hmo.conf.memlimit == 0 || hmo.conf.memlimit <
            (sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE))
            return -1;
    }
    /* reset the open txg */
    {
        struct hvfs_txg *t = mds_get_open_txg(&hmo);

        /* this two lines is SO importent! */
        atomic64_set(&hmo.ctxg, atomic64_read(&hmi.mi_txg) - 1);
        t->txg = atomic64_read(&hmi.mi_txg);
        txg_put(t);
    }

    /* init redo log, this must be done AFTER reg with R2 */
    err = redo_log_init(hmo.chring[CH_RING_MDS], hmo.conf.redo_replicas);
    if (err)
        return err;

    /* we are almost done, but we have to check if we need a recovery */
    if (hmo.aux_state & HMO_AUX_STATE_RECOVER) {
        u64 redo_txg, saved_txg, r2_txg = atomic64_read(&hmi.mi_txg);
        
        /* Step 1: check the latest committed txg in mdsl's txg log */
        err = mds_analyse_storage(hmo.site_id, HVFS_ANA_MAX_TXG, &saved_txg, 
                                  NULL);
        if (err) {
            hvfs_err(mds, "Analyse storage failed w/ %d\n", err);
            saved_txg = 0;
        }

        /* Step 2: compare mi_txg with max/min txg in redo log */
        if (saved_txg > r2_txg)
            hvfs_info(mds, "MDSL saves txg %ld > R2 %ld, use MDSL!.\n",
                      saved_txg, r2_txg);
        else if (saved_txg < r2_txg) {
            if (saved_txg)
                hvfs_info(mds, "MDSL saves txg %ld < R2 %ld, use MDSL!.\n",
                          saved_txg, r2_txg);
            else {
                /* this means MDSL has NO info of commited entries, maybe
                 * txg_log is missing or it is too longer to remember which
                 * txg this mds had been committed. In this situation we try
                 * our best to REDO sth (this may corrupt current state:( ) */
                saved_txg = ((s64)(r2_txg - 2) < 0) ? 0 : r2_txg - 2;
                hvfs_info(mds, "MDSL info missing, R2 txg is %ld, "
                          "we use txg %ld!\n",
                          r2_txg, saved_txg);
            }
        }
        err = redo_log_recovery(saved_txg, &redo_txg);
        switch (err) {
        case 0:
            hvfs_info(mds, "No redo info, it is ok to continue!\n");
            break;
        case 1:
            /* we have trouble, need recover */
            hvfs_info(mds, "There are pending TX, we have to do recovery!\n");
            redo_log_apply(saved_txg, 0);
            break;
        default:
            hvfs_err(mds, "Query recovery info failed w/ %d, "
                     "kill myself!\n", err);
            exit(-err);
        }
        /* reset mi_txg if needed */
        if (saved_txg > r2_txg) {
            atomic64_set(&hmi.mi_txg, saved_txg);
            hvfs_info(mds, "After recovery, update HMI txg to %ld\n",
                      saved_txg);
        }
    }

set_state:
    /* enter into running mode */
    hmo.state = HMO_STATE_RUNNING;

    return 0;
}

/* mds_config()
 *
 * Get configuration from the execution environment.
 */
int mds_config(void)
{
    char *value;

    if (hmo.state != HMO_STATE_INIT) {
        hvfs_err(mds, "MDS state is not in launching, please call "
                 "mds_pre_init() firstly!\n");
        return -EINVAL;
    }

    /* default to enable DATI */
    if (!hmo.conf.dati)
        hmo.conf.dati = 1;

    HVFS_MDS_GET_ENV_strncpy(dcaddr, value, MDS_DCONF_MAX_NAME_LEN);

    HVFS_MDS_GET_ENV_cpy(mds_home, value);
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
    HVFS_MDS_GET_ENV_atoi(mpcheck_sensitive, value);
    HVFS_MDS_GET_ENV_atoi(itbid_check, value);
    HVFS_MDS_GET_ENV_atoi(cbht_slow_down, value);
    HVFS_MDS_GET_ENV_atoi(prof_plot, value);
    HVFS_MDS_GET_ENV_atoi(profiling_thread_interval, value);
    HVFS_MDS_GET_ENV_atoi(txg_interval, value);
    HVFS_MDS_GET_ENV_atoi(unlink_interval, value);
    HVFS_MDS_GET_ENV_atoi(bitmap_cache_interval, value);
    HVFS_MDS_GET_ENV_atoi(dh_hsize, value);
    HVFS_MDS_GET_ENV_atoi(dh_ii, value);
    HVFS_MDS_GET_ENV_atoi(dhupdatei, value);
    HVFS_MDS_GET_ENV_atoi(txg_buf_len, value);
    HVFS_MDS_GET_ENV_atoi(bc_roof, value);
    HVFS_MDS_GET_ENV_atoi(txg_ddht_size, value);
    HVFS_MDS_GET_ENV_atoi(xnet_resend_to, value);
    HVFS_MDS_GET_ENV_atoi(hb_interval, value);
    HVFS_MDS_GET_ENV_atoi(scrub_interval, value);
    HVFS_MDS_GET_ENV_atoi(gto, value);
    HVFS_MDS_GET_ENV_atoi(loadin_pressure, value);
    HVFS_MDS_GET_ENV_atoi(dati, value);
    HVFS_MDS_GET_ENV_atoi(active_ft, value);
    HVFS_MDS_GET_ENV_atoi(rdir_hsize, value);
    HVFS_MDS_GET_ENV_atoi(stacksize, value);
    HVFS_MDS_GET_ENV_atoi(redo_replicas, value);

    HVFS_MDS_GET_kmg(memlimit, value);

    HVFS_MDS_GET_ENV_option(opt_chrechk, CHRECHK, value);
    HVFS_MDS_GET_ENV_option(opt_itb_rwlock, ITB_RWLOCK, value);
    HVFS_MDS_GET_ENV_option(opt_itb_mutex, ITB_MUTEX, value);
    HVFS_MDS_GET_ENV_option(opt_memonly, MEMONLY, value);
    HVFS_MDS_GET_ENV_option(opt_memlimit, MEMLIMIT, value);
    HVFS_MDS_GET_ENV_option(opt_limited, LIMITED, value);
    HVFS_MDS_GET_ENV_option(opt_mdzip, MDZIP, value);

    /* default configurations */
    if (!hmo.conf.mds_home) {
        hmo.conf.mds_home = HVFS_MDS_HOME;
    }
    
    if (!hmo.conf.txg_buf_len) {
        hmo.conf.txg_buf_len = HVFS_MDSL_TXG_BUF_LEN;
    }

    if (!hmo.conf.profiling_thread_interval)
        hmo.conf.profiling_thread_interval = 5;
    if (!hmo.conf.txg_interval) 
        hmo.conf.txg_interval = 30;
    if (!hmo.conf.bitmap_cache_interval)
        hmo.conf.bitmap_cache_interval = 5;
    /* set default dh invalidate interval to ONE hour */
    if (!hmo.conf.dh_ii)
        hmo.conf.dh_ii = 3600;
    if (!hmo.conf.dhupdatei)
        hmo.conf.dhupdatei = 60;
    if (!hmo.conf.gto)
        hmo.conf.gto = 1;
    if (!hmo.conf.loadin_pressure)
        hmo.conf.loadin_pressure = 30;
    if (!hmo.conf.redo_replicas)
        hmo.conf.redo_replicas = 1;

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

    /* lzo lib init */
    err = lzo_init();
    if (err != LZO_E_OK) {
        hvfs_err(mds, "init lzo library failed w/ %d\n", err);
        goto out_lzo;
    }
    
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
    /* unset the default spool theads number */
    /* hmo.conf.spool_threads = 8; */
    hmo.conf.mp_to = 60;
    hmo.conf.hb_interval = 60;
    hmo.conf.scrub_interval = 3600;

    /* get configs from env */
    err = mds_config();
    if (err)
        goto out_config;

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
    err = mds_dh_init(&hmo.dh, hmo.conf.dh_hsize);
    if (err)
        goto out_dh;
    
    /* FIXME: init the TX subsystem, init the commit threads' pool */
    err = mds_init_tx(atomic64_read(&hmi.mi_txg));
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
    hmo.cbht.ops = &ehops_default;

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

    /* FIXME: init the scrub thread */
    err = mds_scrub_create();
    if (err)
        goto out_scrub;

    /* FIXME: init the ft gossip module */
    err = ft_init(1);
    if (err)
        goto out_ft;
    
    /* FIXME: init the gossip thread */
    err = gossip_init();
    if (err)
        goto out_gossip;

    /* FIXME: init the rdir mgr */
    err = rdir_init();
    if (err)
        goto out_rdir;

    /* FIXME: init the rpc subsystem */
    err = rpc_init();
    if (err)
        goto out_rpc;

    /* FIXME: waiting for the notification from R2 */

    /* FIXME: waiting for the requests from client/mds/mdsl/r2 */

    /* mask the SIGUSR1 signal for main thread */
    {
        sigset_t set;

        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
    }

    /* FIXME: init the branch subsystem */
    if (hmo.cb_branch_init) {
        hmo.cb_branch_init(NULL);
    }

    /* ok to run */
    hmo.state = HMO_STATE_LAUNCH;
    hmo.uptime = time(NULL);

out_rpc:
out_rdir:
out_gossip:
out_ft:
out_scrub:
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
out_config:
out_lzo:
    return err;
}

void mds_destroy(void)
{
    hvfs_verbose(mds, "OK, stop it now...\n");

    /* try to change to a new txg immediately */
    txg_change_immediately();

    /* destroy branch subsystem */
    if (hmo.cb_branch_destroy) {
        hmo.cb_branch_destroy(NULL);
    }
    
    /* unreg w/ the r2 server */
    if (hmo.state >= HMO_STATE_RUNNING && hmo.cb_exit) {
        hmo.cb_exit(&hmo);
    }

    /* destroy the BC before timer thread */
    mds_bitmap_cache_destroy();

    /* stop the timer thread */
    hmo.timer_thread_stop = 1;
    /* Bug fix: hmo.timer_thread is type pthread_t, this value is a ID which
     * can be zero. Thus, we can not rely on ZERO detection for invalid
     * values. */
    pthread_join(hmo.timer_thread, NULL);

    sem_destroy(&hmo.timer_sem);

    /* stop the gossip thread */
    gossip_destroy();
    
    ft_destroy();

    /* stop the scrub thread */
    mds_scrub_destroy();

    /* stop the unlink thread */
    unlink_thread_destroy();

    /* stop the async threads */
    async_tp_destroy();

    /* stop the commit threads */
    mds_destroy_tx();

    /* destroy the dh */
    mds_dh_destroy(&hmo.dh);

    /* destroy the txc */
    mds_destroy_txc(&hmo.txc);

    /* destroy the dconf */
    dconf_destroy();

    /* destroy the service thread pool */
    mds_spool_destroy();

    /* cbht */
    mds_cbht_destroy(&hmo.cbht);

    /* itb */
    itb_cache_destroy(&hmo.ic);
    
    /* rdir */
    rdir_destroy();
    
    /* it is ok to free redo resources */
    redo_log_destroy();

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
