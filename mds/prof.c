/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-22 17:20:55 macan>
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
    if (t < hmo.prof.ts + hmo.conf.profiling_thread_interval) {
        return;
    }
    hmo.prof.ts = t;
    hvfs_info(mds, "ITB Cache Size %d\n", atomic_read(&hmo.ic.csize));
    hvfs_info(mds, "CBHT Prof: lookup %ld, modify %ld, split %ld, "
              "buckets %ld, depth %ld\n",
              atomic64_read(&hmo.prof.cbht.lookup),
              atomic64_read(&hmo.prof.cbht.modify),
              atomic64_read(&hmo.prof.cbht.split),
              atomic64_read(&hmo.prof.cbht.buckets),
              atomic64_read(&hmo.prof.cbht.depth));
    hvfs_info(mds, "ITB Prof: cowed %ld\n",
              atomic64_read(&hmo.prof.itb.cowed));
}
