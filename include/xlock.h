/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-17 15:41:53 macan>
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

#ifndef __XLOCK_H__
#define __XLOCK_H__

#ifdef __KERNEL__

/* section for rwlock */
typedef struct rw_semaphore xrwlock_t;
#define xrwlock_rlock down_read
#define xrwlock_runlock up_read
#define xrwlock_wlock down_write
#define xrwlock_wunlock up_write
#define xrwlock_init init_rwsem
#define xrwlock_destroy(l)

#else  /* !__KERNEL__ */

#ifdef HVFS_DEBUG_LOCK
/* section for rwlock */
typedef pthread_rwlock_t xrwlock_t;
int xrwlock_rlock(xrwlock_t *);
int xrwlock_tryrlock(xrwlock_t *);
int xrwlock_runlock(xrwlock_t *);
int xrwlock_wlock(xrwlock_t *);
int xrwlock_trywlock(xrwlock_t *);
int xrwlock_wunlock(xrwlock_t *);
int xrwlock_init(xrwlock_t *);
int xrwlock_destroy(xrwlock_t *);

/* section for lock */
typedef pthread_mutex_t xlock_t;
int xlock_lock(xlock_t *);
int xlock_unlock(xlock_t *);
int xlock_init(xlock_t *);
int xlock_destroy(xlock_t *);

#else  /* !HVFS_LOCK_DEBUG */
/* section for rwlock */
typedef pthread_rwlock_t xrwlock_t;
#define xrwlock_rlock pthread_rwlock_rdlock
#define xrwlock_tryrlock pthread_rwlock_tryrdlock
#define xrwlock_runlock pthread_rwlock_unlock
#define xrwlock_wlock pthread_rwlock_wrlock
#define xrwlock_trywlock pthread_rwlock_trywrlock
#define xrwlock_wunlock pthread_rwlock_unlock
#define xrwlock_init(l) pthread_rwlock_init(l, NULL)
#define xrwlock_destroy pthread_rwlock_destroy

/* section for lock */
typedef pthread_mutex_t xlock_t;
#define xlock_lock pthread_mutex_lock
#define xlock_unlock pthread_mutex_unlock
#define xlock_init(l) pthread_mutex_init(l, NULL)
#define xlock_destroy pthread_mutex_destroy

#endif

/* section for cond */
struct __cond
{
    xlock_t l;                  /* pthread mutex */
    pthread_cond_t c;           /* pthread cond */
};
typedef struct __cond xcond_t;

#define xcond_lock(cond) xlock_lock(&(cond)->l)
#define xcond_unlock(cond) xlock_unlock(&(cond)->l)
#define xcond_wait(cond) pthread_cond_wait(&(cond)->c, &(cond)->l)
#define xcond_timedwait(cond, time) pthread_cond_timedwait(&(cond)->c,  \
                                                           &(cond)->l, time)
#define xcond_signal(cond) pthread_cond_signal(&(cond)->c)
#define xcond_broadcast(cond) pthread_cond_broadcast(&(cond)->c)

#define xcond_init(cond) do {                   \
        pthread_cond_init(&(cond)->c, NULL);    \
        xlock_init(&(cond)->l);                 \
    } while (0)
#define xcond_destroy(cond) do {                \
        pthread_cond_destroy(&(cond)->c);       \
        xlock_destroy(&(cond)->l);              \
    } while (0)

#endif

#endif
