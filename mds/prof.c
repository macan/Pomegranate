/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-18 22:18:10 macan>
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

static inline
void dump_profiling_plot(time_t t)
{
    if (!hmo.conf.profiling_thread_interval)
        return;
    if (t < hmo.prof.ts + hmo.conf.profiling_thread_interval) {
        return;
    }
    hmo.prof.ts = t;
    /* the output format is :
     *
     * "timestamp ic.csize cbht.lookup cbht.modify cbht.split cbht.buckets
     *  cbht.depth cbht.aitb itb.cowed itb.async_unlink itb.split_submit
     *  itb.split_local mds.split mds.forward mds.ausplit txc.ftx txc.total
     *  xnet.msg_alloc xnet.msg_free xnet.inbytes xnet.outbytes
     *  xnet.active_links mds.loop_fwd mds.paused_mreq cbht.aentry"
     */
    hvfs_pf("PLOT %ld %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %d %d %ld %ld %ld %ld %ld %ld %ld %ld\n",
            t, 
            atomic_read(&hmo.ic.csize),
            atomic64_read(&hmo.prof.cbht.lookup),
            atomic64_read(&hmo.prof.cbht.modify),
            atomic64_read(&hmo.prof.cbht.split),
            atomic64_read(&hmo.prof.cbht.buckets),
            atomic64_read(&hmo.prof.cbht.depth),
            atomic64_read(&hmo.prof.cbht.aitb),
            atomic64_read(&hmo.prof.itb.cowed),
            atomic64_read(&hmo.prof.itb.async_unlink),
            atomic64_read(&hmo.prof.itb.split_submit),
            atomic64_read(&hmo.prof.itb.split_local),
            atomic64_read(&hmo.prof.mds.split),
            atomic64_read(&hmo.prof.mds.forward),
            atomic64_read(&hmo.prof.mds.ausplit),
            atomic64_read(&hmo.txc.ftx),
            atomic64_read(&hmo.txc.total),
            (hmo.prof.xnet ?
             atomic64_read(&hmo.prof.xnet->msg_alloc) : 0),
            (hmo.prof.xnet ?
             atomic64_read(&hmo.prof.xnet->msg_free) : 0),
            (hmo.prof.xnet ?
             atomic64_read(&hmo.prof.xnet->inbytes) : 0),
            (hmo.prof.xnet ?
             atomic64_read(&hmo.prof.xnet->outbytes) : 0),
            (hmo.prof.xnet ?
             atomic64_read(&hmo.prof.xnet->active_links) : 0),
            atomic64_read(&hmo.prof.mds.loop_fwd),
            atomic64_read(&hmo.prof.mds.paused_mreq),
            atomic64_read(&hmo.prof.cbht.aentry)
        );
}

static inline
void dump_profiling_human(time_t t)
{
    if (!hmo.conf.profiling_thread_interval)
        return;
    if (t < hmo.prof.ts + hmo.conf.profiling_thread_interval) {
        return;
    }
    hmo.prof.ts = t;
    hvfs_info(mds, "%16ld -- ITB Cache Size %d\n",
              t, 
              atomic_read(&hmo.ic.csize));
    hvfs_info(mds, "%16ld |  CBHT Prof: lookup %s%ld%s, modify %s%ld%s, "
              "split %s%ld%s, "
              "buckets %s%ld%s, depth %ld\n",
              t, 
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
    hvfs_info(mds, "%16ld |  ITB Prof: active %ld, cowed %ld, "
              "async_unlink %ld, "
              "split_submit %ld, split_local %ld\n",
              t, 
              atomic64_read(&hmo.prof.cbht.aitb),
              atomic64_read(&hmo.prof.itb.cowed),
              atomic64_read(&hmo.prof.itb.async_unlink),
              atomic64_read(&hmo.prof.itb.split_submit),
              atomic64_read(&hmo.prof.itb.split_local));
    hvfs_info(mds, "%16ld |  MDS Prof: Rsplit %ld, forward %ld, ausplit %ld\n",
              t,
              atomic64_read(&hmo.prof.mds.split),
              atomic64_read(&hmo.prof.mds.forward),
              atomic64_read(&hmo.prof.mds.ausplit));
    if (hmo.prof.xnet) {
        hvfs_info(mds, "%16ld |  XNET Prof: alloc %ld, free %ld, inb %ld, "
                  "outb %ld, links %ld\n", t,
                  atomic64_read(&hmo.prof.xnet->msg_alloc),
                  atomic64_read(&hmo.prof.xnet->msg_free),
                  atomic64_read(&hmo.prof.xnet->inbytes),
                  atomic64_read(&hmo.prof.xnet->outbytes),
                  atomic64_read(&hmo.prof.xnet->active_links));
    }
    hvfs_info(mds, "%16ld -- ITC Prof: ftx %d, total %d\n",
              t,
              atomic_read(&hmo.txc.ftx),
              atomic_read(&hmo.txc.total));
}

void dump_profiling(time_t t)
{
    if (likely(hmo.conf.prof_plot)) {
        dump_profiling_plot(t);
    } else {
        dump_profiling_human(t);
    }
}
