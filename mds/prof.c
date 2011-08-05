/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-07-27 00:00:08 macan>
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
#include "profile.h"
#include "async.h"

static inline
void dump_profiling_r2(time_t t, struct hvfs_profile *hp)
{
    int i = 0;
    
    if (!hmo.conf.profiling_thread_interval)
        return;
    if (t < hmo.prof.ts + hmo.conf.profiling_thread_interval) {
        return;
    }
    hmo.prof.ts = t;
    hp->flag |= HP_UP2DATE;

    HVFS_PROFILE_VALUE_ADDIN(hp, i, t);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic_read(&hmo.ic.csize));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.lookup));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.modify));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.split));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.buckets));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.depth));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.aitb));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.cowed));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.async_unlink));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.split_submit));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.split_local));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.split));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.forward));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.ausplit));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.txc.ftx));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.txc.total));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, 
                             (hmo.prof.xnet ?
                              atomic64_read(&hmo.prof.xnet->msg_alloc) : 0));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, 
                             (hmo.prof.xnet ? 
                              atomic64_read(&hmo.prof.xnet->msg_free) : 0));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, 
                             (hmo.prof.xnet ?
                              atomic64_read(&hmo.prof.xnet->inbytes) : 0));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, 
                             (hmo.prof.xnet ? 
                              atomic64_read(&hmo.prof.xnet->outbytes) : 0));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, 
                             (hmo.prof.xnet ?
                              atomic64_read(&hmo.prof.xnet->active_links) : 
                              0));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.loop_fwd));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.paused_mreq));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.cbht.aentry));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.au_submit));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.au_handle));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.au_bitmap));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.au_dd));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.au_ddr));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.bitmap_in));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.bitmap_out));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.itb_load));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.itb_wb));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.bitmap));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.gossip_bitmap));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_total));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_handle));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_drop));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.gossip_ft));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.rsearch_depth));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.itb.wsearch_depth));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_qd));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, get_redo_prof(REDO_PROF_CLIENT));
    hp->nr = i;

    /* submit a async send request */
    {
        struct async_update_request *aur =
            xzalloc(sizeof(struct async_update_request));
        int err = 0;

        if (unlikely(!aur)) {
            hvfs_err(mds, "xzalloc() AU request faield, ignore this update.\n");
        } else {
            aur->op = AU_PROFILE;
            aur->arg = (u64)(&hmo.hp);
            INIT_LIST_HEAD(&aur->list);
            err = au_submit(aur);
            if (err) {
                hvfs_err(mds, "submit AU request failed, ignore this update.\n");
            }
        }
    }
}

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
     *  xnet.active_links mds.loop_fwd mds.paused_mreq cbht.aentry
     *  misc.au_submit misc.au_handle misc.au_bitmap misc.au_dd misc.au_ddr
     *  mds.bitmap_in mds.bitmap_out mdsl.itb_load, mdsl.itb_wb, mdsl.bitmap
     *  mds.gossip_bitmap misc.reqin_total misc.reqin_handle misc.reqin_drop
     *  mds.gossip_ft itb.rsearch_depth itb.wsearch_depth misc.reqin_qd
     *  redo.client_redo_nr"
     *
     * Note that, we send the header to R2 server for aggregation. If you
     * change the header, make sure change the header define in
     * dump_profiling_r2() and r2/x2r.c -> hvfs_mds_profile_setup()!
     */
    hvfs_pf("PLOT %ld %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %d %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %ld %ld\n",
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
            atomic64_read(&hmo.prof.cbht.aentry),
            atomic64_read(&hmo.prof.misc.au_submit),
            atomic64_read(&hmo.prof.misc.au_handle),
            atomic64_read(&hmo.prof.misc.au_bitmap),
            atomic64_read(&hmo.prof.misc.au_dd),
            atomic64_read(&hmo.prof.misc.au_ddr),
            atomic64_read(&hmo.prof.mds.bitmap_in),
            atomic64_read(&hmo.prof.mds.bitmap_out),
            atomic64_read(&hmo.prof.mdsl.itb_load),
            atomic64_read(&hmo.prof.mdsl.itb_wb),
            atomic64_read(&hmo.prof.mdsl.bitmap),
            atomic64_read(&hmo.prof.mds.gossip_bitmap),
            atomic64_read(&hmo.prof.misc.reqin_total),
            atomic64_read(&hmo.prof.misc.reqin_handle),
            atomic64_read(&hmo.prof.misc.reqin_drop),
            atomic64_read(&hmo.prof.mds.gossip_ft),
            atomic64_read(&hmo.prof.itb.rsearch_depth),
            atomic64_read(&hmo.prof.itb.wsearch_depth),
            atomic64_read(&hmo.prof.misc.reqin_qd),
            get_redo_prof(REDO_PROF_CLIENT)
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

void dump_profiling(time_t t, struct hvfs_profile *hp)
{
    if (hmo.state < HMO_STATE_LAUNCH)
        return;
    
    switch (hmo.conf.prof_plot) {
    case MDS_PROF_PLOT:
        dump_profiling_plot(t);
        break;
    case MDS_PROF_HUMAN:
        dump_profiling_human(t);
        break;
    case MDS_PROF_R2:
        /* always send the current profiling copy to HVFS_RING(0)? */
        dump_profiling_r2(t, hp);
        break;
    case MDS_PROF_NONE:
    default:
        ;
    }
}
