/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-14 14:36:18 macan>
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

#ifdef HVFS_TRACING
u32 hvfs_lib_tracing_flags = HVFS_DEFAULT_LEVEL | HVFS_DEBUG_ALL;
#endif

#ifdef HVFS_DEBUG_LOCK
struct list_head glt;           /* global lock table */
#endif

void lib_init(void)
{
    srandom(time(NULL));
}

u64 lib_random(int hint)
{
    return random() % hint;
}
