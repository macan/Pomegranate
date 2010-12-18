/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-18 22:25:38 macan>
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
#include "xnet.h"
#include "mdsl.h"
#include "lprof.h"

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
     * "timestamp ring.reqout, ring.update, ring.size, mds.itb, mds.bitmap,
     * mds.txg, mdsl.range_in, mdsl.range_out, mdsl.range_copy,
     * misc.reqin_total, misc.reqin_handle, xnet.msg_alloc, xnet.msg_free,
     * xnet.inbytes, xnet.outbytes, xnet.active_links, storage.wbytes,
     * storage.rbytes, storage.wreq, storage.rreq, storage.cpbytes,
     * storage.aio_submitted, storage.aio_handled misc.tcc_size misc.tcc_used
     * storage.active stroage.memcache"
     */
    hvfs_pf("PLOT %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %d %d %d %ld\n", 
            t, 
            atomic64_read(&hmo.prof.ring.reqout),
            atomic64_read(&hmo.prof.ring.update),
            atomic64_read(&hmo.prof.ring.size),
            atomic64_read(&hmo.prof.mds.itb),
            atomic64_read(&hmo.prof.mds.bitmap),
            atomic64_read(&hmo.prof.mds.txg),
            atomic64_read(&hmo.prof.mdsl.range_in),
            atomic64_read(&hmo.prof.mdsl.range_out),
            atomic64_read(&hmo.prof.mdsl.range_copy),
            atomic64_read(&hmo.prof.misc.reqin_total),
            atomic64_read(&hmo.prof.misc.reqin_handle),
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
            atomic64_read(&hmo.prof.storage.wbytes),
            atomic64_read(&hmo.prof.storage.rbytes),
            atomic64_read(&hmo.prof.storage.wreq),
            atomic64_read(&hmo.prof.storage.rreq),
            atomic64_read(&hmo.prof.storage.cpbytes),
            atomic64_read(&hmo.prof.storage.aio_submitted),
            atomic64_read(&hmo.prof.storage.aio_handled),
            atomic_read(&hmo.prof.misc.tcc_size),
            atomic_read(&hmo.prof.misc.tcc_used),
            atomic_read(&hmo.storage.active),
            atomic64_read(&hmo.storage.memcache)
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
    hvfs_info(mdsl, "%16ld -- MDS Prof: itb %s%ld%s, bitmap %s%ld%s, "
              "txg %s%ld%s\n", 
              t, 
              HVFS_COLOR_RED,
              atomic64_read(&hmo.prof.mds.itb),
              HVFS_COLOR_END, HVFS_COLOR_GREEN,
              atomic64_read(&hmo.prof.mds.bitmap),
              HVFS_COLOR_END, HVFS_COLOR_YELLOW,
              atomic64_read(&hmo.prof.mds.txg),
              HVFS_COLOR_END);
    
    if (hmo.prof.xnet) {
        hvfs_info(mdsl, "%16ld |  XNET Prof: alloc %ld, free %ld, inb %ld, "
                  "outb %ld, links %ld\n", t,
                  atomic64_read(&hmo.prof.xnet->msg_alloc),
                  atomic64_read(&hmo.prof.xnet->msg_free),
                  atomic64_read(&hmo.prof.xnet->inbytes),
                  atomic64_read(&hmo.prof.xnet->outbytes),
                  atomic64_read(&hmo.prof.xnet->active_links));
    }
    hvfs_info(mdsl, "%16ld -- MISC Prof: reqin_total %ld, reqin_handle %ld\n",
              t,
              atomic64_read(&hmo.prof.misc.reqin_total),
              atomic64_read(&hmo.prof.misc.reqin_handle));
}

void mdsl_dump_profiling(time_t t)
{
    if (likely(hmo.conf.prof_plot)) {
        dump_profiling_plot(t);
    } else {
        dump_profiling_human(t);
    }
}
