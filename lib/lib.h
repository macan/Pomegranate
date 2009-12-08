/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-08 15:45:12 macan>
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

/* APIs */
void lib_timer_start(struct timeval *begin);
void lib_timer_stop(struct timeval *end);
void lib_timer_echo(struct timeval *begin, struct timeval *end, int loop);

int lib_bitmap_tas(volatile void *, u32);
int lib_bitmap_tac(volatile void *, u32);
int lib_bitmap_tach(volatile void *, u32);
long find_first_zero_bit(const unsigned long *, unsigned long);
long find_next_zero_bit(const unsigned long *, long, long);
long find_first_bit(const unsigned long *, unsigned long);
long find_next_bit(const unsigned long *, long, long);

#endif
