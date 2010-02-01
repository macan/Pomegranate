/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-01 16:15:47 macan>
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

#include "lib.h"

#ifdef HVFS_DEBUG_LOCK
#define BT_SIZE 100
struct __tid
{
    struct list_head list;
    pthread_t tid;
    void *bt[BT_SIZE];          /* backtrace */
    int size;
};

struct lock_entry
{
    struct list_head list;
    void *p;                    /* lock address */
    atomic64_t trl;             /* # of try rlock */
    atomic64_t twl;             /* # of try wlock */
    atomic64_t rl;              /* # of rlocked */
    atomic64_t wl;              /* # of wlocked */
    xlock_t lock;               /* protect tid list */
    struct list_head tid;       /* list of thread id */
};

/* fixed hash table size */
#define LOCK_TABLE_SIZE 4096
struct lock_table
{
    struct regular_hash2 ht[LOCK_TABLE_SIZE];
};

struct lock_table lt;

void lock_debug(int signr)
{
    static int ent = 0;

    if (ent < 5) {
        hvfs_debug(lib, "RECEIVE LOCK DEBUG SIGNAL, print the LOCK TABLE.\n");
        lock_table_print();
    } else {
        /* reset sighandler */
        signal(SIGINT, SIG_DFL);
    }
    ent++;
}

void lock_table_init(void)
{
    int i;
    
    hvfs_debug(lib, "LOCK TABLE INIT ...\n");
    memset(&lt, 0, sizeof(lt));
    for (i = 0; i < LOCK_TABLE_SIZE; i++) {
        INIT_LIST_HEAD(&lt.ht[i].h);
        xlock_init(&lt.ht[i].lock);
    }
    /* setup sighandler */
    if (signal(SIGINT, lock_debug) == SIG_ERR) {
        hvfs_err(lib, "signal() failed\n");
    }
}

u32 __lock_hash(void *p)
{
    return hash_64((u64)p, 32);
}

void __add_tid(struct lock_entry *le)
{
    struct __tid *t;

    t = xzalloc(sizeof(struct __tid));
    if (!t) {
        hvfs_err(lib, "xzalloc() struct __tid failed\n");
        return;
    }
    t->tid = pthread_self();
    INIT_LIST_HEAD(&t->list);
    t->size = backtrace(t->bt, BT_SIZE);

    xlock_lock(&le->lock);
    list_add_tail(&t->list, &le->tid);
    hvfs_debug(lib, "add %lx le %p to list\n", t->tid, le->p);
    xlock_unlock(&le->lock);
}

void __del_tid(struct lock_entry *le)
{
    pthread_t tid = pthread_self();
    struct __tid *pos, *n;

    if (!le)
        return;
    
    xlock_lock(&le->lock);
    list_for_each_entry_safe_reverse(pos, n, &le->tid, list) {
        if (pos->tid == tid) {
            list_del(&pos->list);
            xfree(pos);
            hvfs_debug(lib, "del %lx le %p from list\n", tid, le->p);
            xlock_unlock(&le->lock);
            return;
        }
    }
    xlock_unlock(&le->lock);
    hvfs_err(lib, "Internal error on deleting TID %lx on le %p.\n", 
             tid, le->p);
    lock_table_print();
    *((int *)0) = 1;
}

struct lock_entry *__add_lock_entry(struct lock_entry *le)
{
    u32 hash = __lock_hash(le->p);
    u32 index = hash % LOCK_TABLE_SIZE;
    struct lock_entry *pos;
    int found = 0;

    xlock_lock(&lt.ht[index].lock);
    list_for_each_entry(pos, &lt.ht[index].h, list) {
        if (pos->p == le->p) {
            found = 1;
            xfree(le);
            le = pos;
            break;
        }
    }
    if (!found)
        list_add(&le->list, &lt.ht[index].h);
    xlock_unlock(&lt.ht[index].lock);

    return le;
}

void __del_lock_entry(struct lock_entry *le)
{
    u32 hash = __lock_hash(le->p);
    u32 index = hash % LOCK_TABLE_SIZE;

    xlock_lock(&lt.ht[index].lock);
    list_del(&le->list);
    xlock_unlock(&lt.ht[index].lock);
}

struct lock_entry *__find_lock_entry(void *p)
{
    u32 hash = __lock_hash(p);
    u32 index = hash % LOCK_TABLE_SIZE;
    struct lock_entry *pos;

    xlock_lock(&lt.ht[index].lock);
    list_for_each_entry(pos, &lt.ht[index].h, list) {
        if (pos->p == p) {
            xlock_unlock(&lt.ht[index].lock);
            return pos;
        }
    }
    xlock_unlock(&lt.ht[index].lock);

    return NULL;
}

struct lock_entry *__find_create_lock_entry(void *p)
{
    struct lock_entry *le;

    le = __find_lock_entry(p);
    if (!le) {
        le = xzalloc(sizeof(struct lock_entry));
        if (!le) {
            hvfs_err(lib, "xzalloc() lock_entry failed.\n");
            return NULL;
        }
        /* init the lock_entry */
        INIT_LIST_HEAD(&le->list);
        INIT_LIST_HEAD(&le->tid);
        xlock_init(&le->lock);
        le->p = p;
        /* add to the list */
        le = __add_lock_entry(le);
    }

    return le;
}

void lock_table_print(void)
{
    struct lock_entry *pos;
    struct __tid *t;
    char line[520], *p;
    int i, len, n;

    for (i = 0; i < LOCK_TABLE_SIZE; i++) {
        xlock_lock(&lt.ht[i].lock);
        list_for_each_entry(pos, &lt.ht[i].h, list) {
            p = line;
            n = 520;
            if (atomic64_read(&pos->trl) || atomic64_read(&pos->twl) ||
                atomic64_read(&pos->rl) || atomic64_read(&pos->wl)) {
                len = snprintf(p, n, 
                               "[%6d] [%16p] trl %ld, twl %ld, rl %ld, "
                               "wl %ld: [", i, pos->p, 
                               atomic64_read(&pos->trl), 
                               atomic64_read(&pos->twl), 
                               atomic64_read(&pos->rl), 
                               atomic64_read(&pos->wl));
                p += len;
                n -= len;
                if (atomic64_read(&pos->rl)) {
                    len = snprintf(p, n, "rl <");
                    p += len;
                    n -= len;
                    xlock_lock(&pos->lock);
                    list_for_each_entry(t, &pos->tid, list) {
                        len = snprintf(p, n, "%lx, ", t->tid);
                        p += len;
                        n -= len;
                    }
                    xlock_unlock(&pos->lock);
                    len = snprintf(p, n, ">");
                    p += len;
                    n -= len;
                }
                if (atomic64_read(&pos->wl)) {
                    len = snprintf(p, n, "wl <");
                    p += len;
                    n -= len;
                    xlock_lock(&pos->lock);
                    list_for_each_entry(t, &pos->tid, list) {
                        len = snprintf(p, n, "%lx, ", t->tid);
                        p += len;
                        n -= len;
                    }
                    xlock_unlock(&pos->lock);
                    len = snprintf(p, n, ">");
                    p += len;
                    n -= len;
                }
                snprintf(p, n, "]\n");
                hvfs_info(lib, "%s", line);
                /* ok, print the locking backtrace */
                if (atomic64_read(&pos->rl)) {
                    xlock_lock(&pos->lock);
                    list_for_each_entry(t, &pos->tid, list) {
                        char **bts = backtrace_symbols(t->bt, t->size);
                        int i;
                        if (bts){
                            for (i = 0; i < t->size; i++) {
                                hvfs_info(lib, "[%lx] -> %s\n", t->tid, bts[i]);
                            }
                            free(bts);
                        } else {
                            hvfs_info(lib, "[%lx] -> BACKTRACE SYMBOLS ERROR.\n",
                                t->tid);
                        }
                    }
                    xlock_unlock(&pos->lock);
                }
                if (atomic64_read(&pos->wl)) {
                    xlock_lock(&pos->lock);
                    list_for_each_entry(t, &pos->tid, list) {
                        char **bts = backtrace_symbols(t->bt, t->size);
                        int i;
                        if (bts) {
                            for (i = 0; i < t->size; i++) {
                                hvfs_info(lib, "[%lx] -> %s\n", t->tid, bts[i]);
                            }
                            free(bts);
                        } else {
                            hvfs_info(lib, "[%lx] -> BACKTRACE SYMBOLS ERROR.\n",
                                t->tid);
                        }
                    }
                    xlock_unlock(&pos->lock);
                }
            }
        }
        xlock_unlock(&lt.ht[i].lock);
    }
    return;
}

void __deadlock_detect(void)
{
}

int xrwlock_rlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    atomic64_inc(&le->trl);
    
    err = pthread_rwlock_tryrdlock(lock);
    ASSERT(err != EDEADLOCK, lib);
    if (err == EBUSY)
        err = pthread_rwlock_rdlock(lock);

    atomic64_inc(&le->rl);
    atomic64_dec(&le->trl);
    __add_tid(le);
    return err;
}

int xrwlock_tryrlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    atomic64_inc(&le->trl);

    err = pthread_rwlock_tryrdlock(lock);
    ASSERT(err != EDEADLOCK, lib);
    if (!err) {
        atomic64_inc(&le->rl);
        __add_tid(le);
    }
    atomic64_dec(&le->trl);

    return err;
}

int xrwlock_runlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    err = pthread_rwlock_unlock(lock);
    if (!err) {
        atomic64_dec(&le->rl);
        __del_tid(le);
    }

    return err;
}

int xrwlock_wlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    atomic64_inc(&le->twl);

    err = pthread_rwlock_trywrlock(lock);
    ASSERT(err != EDEADLOCK, lib);
    if (err == EBUSY)
        err = pthread_rwlock_wrlock(lock);

    atomic64_inc(&le->wl);
    atomic64_dec(&le->twl);
    __add_tid(le);
    
    return err;
}

int xrwlock_trywlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    atomic64_inc(&le->twl);

    err = pthread_rwlock_trywrlock(lock);
    ASSERT(err != EDEADLOCK, lib);
    if (!err) {
        atomic64_inc(&le->wl);
        __add_tid(le);
    }
    atomic64_dec(&le->twl);
    
    return err;
}

int xrwlock_wunlock(xrwlock_t *lock)
{
    struct lock_entry *le;
    int err;

    le = __find_create_lock_entry(lock);
    if (!le) {
        return ENOMEM;
    }
    err = pthread_rwlock_unlock(lock);
    if (!err) {
        atomic64_dec(&le->wl);
        __del_tid(le);
    }

    return err;
}

int xrwlock_init(xrwlock_t *lock)
{
    return pthread_rwlock_init(lock, NULL);
}

int xrwlock_destroy(xrwlock_t *lock)
{
    return pthread_rwlock_destroy(lock);
}

int xlock_lock(xlock_t *lock)
{
    return pthread_mutex_lock(lock);
}

int xlock_unlock(xlock_t *lock)
{
    return pthread_mutex_unlock(lock);
}

int xlock_init(xlock_t *lock)
{
    return pthread_mutex_init(lock, NULL);
}

int xlock_destroy(xlock_t *lock)
{
    return pthread_mutex_destroy(lock);
}

#endif
