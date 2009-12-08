/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-08 10:40:27 macan>
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

#ifndef __ATOMIC_H__
#define __ATOMIC_H__

#ifndef __KERNEL__
typedef struct { volatile int counter; } atomic_t;
typedef struct { volatile long counter; } atomic64_t;

#define ATOMIC_INIT(i)		( (atomic_t) { (i) } )
#define ATOMIC64_INIT(i)	( (atomic64_t) { (i) } )

#define atomic_read(v)		((v)->counter + 0)
#define atomic64_read(v)	((v)->counter + 0)

#define atomic_set(v,i)		((v)->counter = (i))
#define atomic64_set(v,i)	((v)->counter = (i))

#define LOCK_PREFIX "lock;"

/**
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic_add(int i, atomic_t *v)
{
    asm volatile(LOCK_PREFIX "addl %1,%0"
                 : "=m" (v->counter)
                 : "ir" (i), "m" (v->counter));
}

/**
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic_sub(int i, atomic_t *v)
{
    asm volatile(LOCK_PREFIX "subl %1,%0"
                 : "=m" (v->counter)
                 : "ir" (i), "m" (v->counter));
}

/**
 * atomic64_add - add integer to atomic64 variable
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v.
 */
static inline void atomic64_add(long i, atomic64_t *v)
{
    asm volatile(LOCK_PREFIX "addq %1,%0"
                 : "=m" (v->counter)
                 : "er" (i), "m" (v->counter));
}

/**
 * atomic_add_return - add and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return(int i, atomic_t *v)
{
    int __i = i;
    asm volatile(LOCK_PREFIX "xaddl %0, %1"
                 : "+r" (i), "+m" (v->counter)
                 : : "memory");
    return i + __i;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
    return atomic_add_return(-i, v);
}

#define atomic_inc_return(v)  (atomic_add_return(1, v))
#define atomic_dec_return(v)  (atomic_sub_return(1, v))

/**
 * atomic64_sub - subtract the atomic64 variable
 * @i: integer value to subtract
 * @v: pointer to type atomic64_t
 *
 * Atomically subtracts @i from @v.
 */
static inline void atomic64_sub(long i, atomic64_t *v)
{
    asm volatile(LOCK_PREFIX "subq %1,%0"
                 : "=m" (v->counter)
                 : "er" (i), "m" (v->counter));
}

/**
 * atomic64_add_return - add and return
 * @i: integer value to add
 * @v: pointer to type atomic64_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline long atomic64_add_return(long i, atomic64_t *v)
{
    long __i = i;
    asm volatile(LOCK_PREFIX "xaddq %0, %1;"
                 : "+r" (i), "+m" (v->counter)
                 : : "memory");
    return i + __i;
}

static inline long atomic64_sub_return(long i, atomic64_t *v)
{
    return atomic64_add_return(-i, v);
}

#define atomic_inc(v) atomic_add(1,(v))
#define atomic64_inc(v) atomic64_add(1,(v))

#define atomic_dec(v) atomic_sub(1,(v))
#define atomic64_dec(v) atomic64_sub(1,(v))

#define atomic64_inc_return(v)  (atomic64_add_return(1, (v)))
#define atomic64_dec_return(v)  (atomic64_sub_return(1, (v)))

#define __xg(x) ((volatile long *)(x))

static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
                                      unsigned long new, int size)
{
    unsigned long prev;
    switch (size) {
    case 1:
        asm volatile(LOCK_PREFIX "cmpxchgb %b1,%2"
                     : "=a"(prev)
                     : "q"(new), "m"(*__xg(ptr)), "0"(old)
                     : "memory");
        return prev;
    case 2:
        asm volatile(LOCK_PREFIX "cmpxchgw %w1,%2"
                     : "=a"(prev)
                     : "r"(new), "m"(*__xg(ptr)), "0"(old)
                     : "memory");
        return prev;
    case 4:
        asm volatile(LOCK_PREFIX "cmpxchgl %k1,%2"
                     : "=a"(prev)
                     : "r"(new), "m"(*__xg(ptr)), "0"(old)
                     : "memory");
        return prev;
    case 8:
        asm volatile(LOCK_PREFIX "cmpxchgq %1,%2"
                     : "=a"(prev)
                     : "r"(new), "m"(*__xg(ptr)), "0"(old)
                     : "memory");
        return prev;
    }
    return old;
}

#define cmpxchg(ptr, o, n)                                              \
	((__typeof__(*(ptr)))__cmpxchg((ptr), (unsigned long)(o),           \
                                   (unsigned long)(n), sizeof(*(ptr))))
#endif  /* for user space only */

#endif
