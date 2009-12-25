/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-25 22:43:52 macan>
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
int lib_bitmap_tas(volatile void *addr, u32 offset)
{
    int oldbit;

    asm volatile("lock ; btsl %2,%1\n\t"
                 "sbbl %0,%0" 
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
int lib_bitmap_tach(volatile void *addr, u32 offset)
{
    int oldbit;

    asm volatile("lock; btc %2,%1\n\t"
                 "sbb %0,%0"
                 : "=r" (oldbit), ADDR : "Ir" (offset) : "memory");

    return oldbit;
}


static inline long
__find_first_zero_bit(const unsigned long * addr, unsigned long size)
{
    long d0, d1, d2;
    long res;

    /*
     * We must test the size in words, not in bits, because
     * otherwise incoming sizes in the range -63..-1 will not run
     * any scasq instructions, and then the flags used by the je
     * instruction will have whatever random value was in place
     * before.  Nobody should call us like that, but
     * find_next_zero_bit() does when offset and size are at the
     * same word and it fails to find a zero itself.
     */
    size += 63;
    size >>= 6;
    if (!size)
        return 0;
    asm volatile(
        "  repe; scasq\n"
        "  je 1f\n"
        "  xorq -8(%%rdi),%%rax\n"
        "  subq $8,%%rdi\n"
        "  bsfq %%rax,%%rdx\n"
        "1:  subq %[addr],%%rdi\n"
        "  shlq $3,%%rdi\n"
        "  addq %%rdi,%%rdx"
        :"=d" (res), "=&c" (d0), "=&D" (d1), "=&a" (d2)
        :"0" (0ULL), "1" (size), "2" (addr), "3" (-1ULL),
         [addr] "S" (addr) : "memory");
    /*
     * Any register would do for [addr] above, but GCC tends to
     * prefer rbx over rsi, even though rsi is readily available
     * and doesn't have to be saved.
     */
    return res;
}

/**
 * find_first_zero_bit - find the first zero bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first zero bit, not the number of the byte
 * containing a bit.
 */
long find_first_zero_bit(const unsigned long * addr, unsigned long size)
{
    return __find_first_zero_bit (addr, size);
}

/**
 * find_next_zero_bit - find the next zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
long find_next_zero_bit (const unsigned long * addr, long size, long offset)
{
    const unsigned long * p = addr + (offset >> 6);
    unsigned long set = 0;
    unsigned long res, bit = offset&63;
    
    if (bit) {
        /*
         * Look for zero in first word
         */
        asm("bsfq %1,%0\n\t"
            "cmoveq %2,%0"
            : "=r" (set)
            : "r" (~(*p >> bit)), "r"(64L));
        if (set < (64 - bit))
            return set + offset;
        set = 64 - bit;
        p++;
    }
    /*
     * No zero yet, search remaining full words for a zero
     */
    
    res = __find_first_zero_bit (p, size - 64 * (p - addr));
    return (offset + set + res);
}

static inline long
__find_first_bit(const unsigned long * addr, unsigned long size)
{
    long d0, d1;
    long res;

    /*
     * We must test the size in words, not in bits, because
     * otherwise incoming sizes in the range -63..-1 will not run
     * any scasq instructions, and then the flags used by the jz
     * instruction will have whatever random value was in place
     * before.  Nobody should call us like that, but
     * find_next_bit() does when offset and size are at the same
     * word and it fails to find a one itself.
     */
    size += 63;
    size >>= 6;
    if (!size)
        return 0;
    asm volatile(
        "   repe; scasq\n"
        "   jz 1f\n"
        "   subq $8,%%rdi\n"
        "   bsfq (%%rdi),%%rax\n"
        "1: subq %[addr],%%rdi\n"
        "   shlq $3,%%rdi\n"
        "   addq %%rdi,%%rax"
        :"=a" (res), "=&c" (d0), "=&D" (d1)
        :"0" (0ULL), "1" (size), "2" (addr),
         [addr] "r" (addr) : "memory");
    return res;
}

/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first set bit, not the number of the byte
 * containing a bit.
 */
long find_first_bit(const unsigned long * addr, unsigned long size)
{
    return __find_first_bit(addr,size);
}

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
long find_next_bit(const unsigned long * addr, long size, long offset)
{
    const unsigned long * p = addr + (offset >> 6);
    unsigned long set = 0, bit = offset & 63, res;
    
    if (bit) {
        /*
         * Look for nonzero in the first 64 bits:
         */
        asm("bsfq %1,%0\n\t"
            "cmoveq %2,%0\n\t"
            : "=r" (set)
            : "r" (*p >> bit), "r" (64L));
        if (set < (64 - bit))
            return set + offset;
        set = 64 - bit;
        p++;
    }
    /*
     * No set bit yet, search remaining full words for a bit
     */
    res = __find_first_bit (p, size - 64 * (p - addr));
    return (offset + set + res);
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
void __set_bit(int nr, volatile unsigned long *addr)
{
    asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}

/*
 * __clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 */
void __clear_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

#define CONFIG_X86_CMOV
/**
 * ffs - find first set bit in word
 * @x: the word to search
 *
 * This is defined the same way as the libc and compiler builtin ffs
 * routines, therefore differs in spirit from the other bitops.
 *
 * ffs(value) returns 0 if value is 0 or the position of the first
 * set bit if value is nonzero. The first (least significant) bit
 * is at position 1.
 */
int ffs(int x)
{
    int r;
#ifdef CONFIG_X86_CMOV
    asm("bsfl %1,%0\n\t"
        "cmovzl %2,%0"
        : "=r" (r) : "rm" (x), "r" (-1));
#else
    asm("bsfl %1,%0\n\t"
        "jnz 1f\n\t"
        "movl $-1,%0\n"
        "1:" : "=r" (r) : "rm" (x));
#endif
    return r + 1;
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
