/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-16 19:20:52 macan>
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

#ifndef __LIB_H__
#define __LIB_H__

#include "hvfs.h"

#ifdef HVFS_TRACING
extern u32 hvfs_lib_tracing_flags;
#endif

#ifdef HVFS_DEBUG_LOCK
extern struct list_head glt;           /* global lock table */
#endif

/* defines */
#define EXTRACT_HI      0x10
#define EXTRACT_MDU     0x20
#define EXTRACT_LS      0x40
#define EXTRACT_BITMAP  0x80
#define EXTRACT_DC      0x1000

/* APIs */
void lib_timer_start(struct timeval *begin);
void lib_timer_stop(struct timeval *end);
void lib_timer_echo(struct timeval *begin, struct timeval *end, int loop);
void lib_timer_acc(struct timeval *, struct timeval *, double *);
void lib_timer_echo_plus(struct timeval *, struct timeval *, int, char *);

#define lib_timer_def() struct timeval begin, end
#define lib_timer_B() lib_timer_start(&begin)
#define lib_timer_E() lib_timer_stop(&end)
#define lib_timer_O(loop, str) lib_timer_echo_plus(&begin, &end, loop, str)
#define lib_timer_A(ACC) lib_timer_acc(&begin, &end, (ACC))

void lib_backtrace(void);

long find_first_zero_bit(const unsigned long *, unsigned long);
long find_next_zero_bit(const unsigned long *, long, long);
long find_first_bit(const unsigned long *, unsigned long);
long find_next_bit(const unsigned long *, long, long);

void lib_segv(int, siginfo_t *, void *);

void lib_init(void);
static inline
u64 lib_random(int hint)
{
    return random() % hint;
}

void *hmr_extract(void *, int, int *);
void *hmr_extract_local(void *, int, int *);

/* Region for fast bit operations */
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
/* Technically wrong, but this avoids compilation errors on some gcc
   versions. */
#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define ADDR				BITOP_ADDR(addr)

/**
 * lib_bitmap_tas - Set a bit and return its old value
 * @offset: Bit to set
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline
int lib_bitmap_tas(volatile void *addr, u32 offset)
{
    int oldbit;

    asm volatile("lock; bts %2,%1\n\t"
                 "sbb %0,%0" 
                 : "=r" (oldbit), ADDR : "Ir" (offset) : "memory");

    return oldbit;
}

/**
 * lib_bitmap_tac - Clear a bit and return its old value
 * @offset: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline
int lib_bitmap_tac(volatile void *addr, u32 offset)
{
    int oldbit;

    asm volatile("lock; btr %2,%1\n\t"
                 "sbb %0,%0"
                 : "=r" (oldbit), ADDR : "Ir" (offset) : "memory");

    return oldbit;
}


/**
 * lib_bitmap_tach - Change a bit and return its old value
 * @offset: Bit to change
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline
int lib_bitmap_tach(volatile void *addr, u32 offset)
{
    int oldbit;

    asm volatile("lock; btc %2,%1\n\t"
                 "sbb %0,%0"
                 : "=r" (oldbit), ADDR : "Ir" (offset) : "memory");

    return oldbit;
}

/**
 * __set_bit - Set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * Unlike set_bit(), this function is non-atomic and may be reordered.
 * If it's called on the same region of memory simultaneously, the effect
 * may be that only one operation succeeds.
 */
static inline
void __set_bit(int nr, volatile unsigned long *addr)
{
    asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}

/*
 * __clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 */
static inline
void __clear_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

/**
 * fls - find last set bit in word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffs, but returns the position of the most significant set bit.
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static inline 
int fls(int x)
{
    int r;
#ifdef CONFIG_X86_CMOV
    asm("bsrl %1,%0\n\t"
        "cmovzl %2,%0"
        : "=&r" (r) : "rm" (x), "rm" (-1));
#else
    asm("bsrl %1,%0\n\t"
        "jnz 1f\n\t"
        "movl $-1,%0\n"
        "1:" : "=r" (r) : "rm" (x));
#endif
    return r + 1;
}

/*
 * __fls64: find last set bit in word
 * @word: The word to search
 *
 * Undefined if no set bit exists, so code should check against 0 first.
 */
static inline 
unsigned long __fls64(unsigned long word)
{
    asm("bsr %1,%0"
        : "=r" (word)
        : "rm" (word));
    return word;
}

/*
 * fls64: wapper for __fls64(), and return -1 if the word is zero.
 */
static inline
int fls64(unsigned long word)
{
    if (!word)
        return -1;
    
    return __fls64(word);
}

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static __inline__ unsigned long __ffs(unsigned long word)
{
	__asm__("bsfq %1,%0"
		:"=r" (word)
		:"rm" (word));
	return word;
}

/* ffs64: wapper for __ffs(), and return -1 if the word is zero.
 */
static inline
unsigned long ffs64(unsigned long word)
{
    if (!word)
        return -1;

    return __ffs(word);
}

static char *si_code[] 
__attribute__((unused)) = {"",
                           "address not mapped to object",
                           "invalid permissions for mapped object",
};
#define SIGCODES(i) ({                                      \
        char *res = NULL;                                   \
        if (likely(i == SEGV_MAPERR || i == SEGV_ACCERR)) { \
            res = si_code[i];                               \
        }                                                   \
        res;                                                \
    })

#ifdef HVFS_DEBUG_LOCK
void lock_table_init(void);
void lock_table_print(void);
#endif

/* conf.c to provide config file parsing */
typedef enum {
    PARSER_INIT,
    PARSER_EXPECT_SITE,
    PARSER_EXPECT_FS
} parser_state_t;

enum {
    PARSER_OK = 0,
    PARSER_NEED_RETRY,
    PARSER_CONTINUE,
    PARSER_FAILED = 1000
};

int conf_parse(char *, struct conf_site *, int *);
u64 conf_site_id(char *, int);

void lib_md5_print(void *addr, int len, char *str);

static inline
u64 lib_rdtsc(void)
{
    u32 hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)lo) | (((u64)hi) << 32);
}

extern u64 cpu_frequency;

/* embedpy.c */
int ebpy(u16 where, void *itb, void *ite, void *hi, int status,
         void *dt);

/* brtree.c: binary range tree */
struct brtnode
{
    u64 low, high;
};

int brt_add(struct brtnode *n, void **rootp);
int brt_del(u64 low, u64 high, void **rootp);
void brt_destroy(void *root, void (*free_node)(void *p));
int brt_loop_on_holes(void **rootp, void *arg, 
                      void (*cb)(u64 low, u64 high, void *arg));
int brt_loop_on_ranges(void **rootp, void *arg, 
                       void (*cb)(u64 low, u64 high, void *arg));

#endif
