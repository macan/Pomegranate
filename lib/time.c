/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-07 16:41:11 macan>
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

void lib_timer_start(struct timeval *begin)
{
    if (gettimeofday(begin, NULL)) {
        hvfs_err(lib, "gettimeofday() failed.\n");
    }
}

void lib_timer_stop(struct timeval *end)
{
    if (gettimeofday(end, NULL)) {
        hvfs_err(lib, "gettimeofday() failed.\n");
    }
}

void lib_timer_echo(struct timeval *begin, struct timeval *end)
{
    hvfs_info(lib, "ECHO\t %ld us\n", (end->tv_sec - begin->tv_sec) * 1000000 +
              end->tv_usec - begin->tv_usec);
}
