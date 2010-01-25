/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 14:14:42 macan>
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
#include "mds.h"
#include "prof.h"

void dump_profiling(time_t t)
{
    if (!hmo.conf.profiling_thread_interval)
        return;
    if (t < hmo.prof.ts + hmo.conf.profiling_thread_interval) {
        return;
    }
    hmo.prof.ts = t;
    hvfs_info(mds, "-- ITB Cache Size %d\n", 
              atomic_read(&hmo.ic.csize));
    hvfs_info(mds, "|  CBHT Prof: lookup %s%ld%s, modify %s%ld%s, "
              "split %s%ld%s, "
              "buckets %s%ld%s, depth %ld\n",
              HVFS_COLOR_RED,
              atomic64_read(&hmo.prof.cbht.lookup),
              HVFS_COLOR_END, HVFS_COLOR_GREEN,
              atomic64_read(&hmo.prof.cbht.modify),
              HVFS_COLOR_END, HVFS_COLOR_YELLOW,
              atomic64_read(&hmo.prof.cbht.split),
              HVFS_COLOR_END, HVFS_COLOR_PINK,
              atomic64_read(&hmo.prof.cbht.buckets),
              HVFS_COLOR_END, 
              atomic64_read(&hmo.prof.cbht.depth));
    hvfs_info(mds, "|  ITB Prof: active %ld, cowed %ld, async_unlink %ld\n",
              atomic64_read(&hmo.prof.cbht.aitb),
              atomic64_read(&hmo.prof.itb.cowed),
              atomic64_read(&hmo.prof.itb.async_unlink));
    if (hmo.prof.xnet) {
        hvfs_info(mds, "|  XNET Prof: alloc %ld, free %ld, inb %ld, outb %ld\n",
                  atomic64_read(&hmo.prof.xnet->msg_alloc),
                  atomic64_read(&hmo.prof.xnet->msg_free),
                  atomic64_read(&hmo.prof.xnet->inbytes),
                  atomic64_read(&hmo.prof.xnet->outbytes));
    }
    hvfs_info(mds, "-- ITC Prof: ftx %d, total %d\n", 
              atomic_read(&hmo.txc.ftx),
              atomic_read(&hmo.txc.total));
}
