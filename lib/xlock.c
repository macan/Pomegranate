/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-09 16:49:28 macan>
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
struct lock_entry
{
    struct list_head list;
    void *p;                    /* lock address */
    atomic64_t rl;
    atomic64_t wl;
};

int xrwlock_rlock(xrwlock_t *lock)
{
    return pthread_rwlock_rdlock(lock);
}

int xrwlock_tryrlock(xrwlock_t *lock)
{
    return pthread_rwlock_tryrdlock(lock);
}

int xrwlock_runlock(xrwlock_t *lock)
{
    return pthread_rwlock_unlock(lock);
}

int xrwlock_wlock(xrwlock_t *lock)
{
    return pthread_rwlock_wrlock(lock);
}

int xrwlock_trywlock(xrwlock_t *lock)
{
    return pthread_rwlock_trywrlock(lock);
}

int xrwlock_wunlock(xrwlock_t *lock)
{
    return pthread_rwlock_unlock(lock);
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
