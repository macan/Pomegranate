/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-28 15:31:55 macan>
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
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.ring.reqout));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.ring.update));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.ring.size));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.itb));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.bitmap));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mds.txg));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.range_in));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.range_out));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.mdsl.range_copy));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_total));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.misc.reqin_handle));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hmo.prof.xnet ?
                             atomic64_read(&hmo.prof.xnet->msg_alloc) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hmo.prof.xnet ?
                             atomic64_read(&hmo.prof.xnet->msg_free) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hmo.prof.xnet ?
                             atomic64_read(&hmo.prof.xnet->inbytes) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hmo.prof.xnet ?
                             atomic64_read(&hmo.prof.xnet->outbytes) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hmo.prof.xnet ?
                             atomic64_read(&hmo.prof.xnet->active_links) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.wbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.rbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.wreq));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.rreq));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.cpbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.aio_submitted));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.prof.storage.aio_handled));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic_read(&hmo.prof.misc.tcc_size));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic_read(&hmo.prof.misc.tcc_used));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic_read(&hmo.storage.active));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.storage.memcache));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmo.pending_ios));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmi.mi_bused));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmi.mi_bfree));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmi.mi_bwrite));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hmi.mi_bread));
    hp->nr = i;

    /* send the request to R2 server now */
    {
        static struct hvfs_profile ghp = {.nr = 0,};
        struct hvfs_profile diff;
        struct xnet_msg *msg;
        u64 dsite;
        int err = 0, i;

        if (!ghp.nr) {
            diff = ghp = *hp;
            /* reset time stamp to ZERO */
            diff.hpv[0].value = 0;
        } else {
            diff = *hp;
            for (i = 0; i < hp->nr; i++) {
                diff.hpv[i].value -= ghp.hpv[i].value;
            }
            ghp = *hp;
        }

        /* reset the flag now */
        hp->flag &= (~HP_UP2DATE);

        /* prepare the xnet_msg */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(mdsl, "xnet_alloc_msg() failed.\n");
            err = -ENOMEM;
            goto out;
        }

        /* send this profile to r2 server */
        dsite = mdsl_select_ring(&hmo);
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0, hmo.site_id, dsite);
        xnet_msg_fill_cmd(msg, HVFS_R2_PROFILE, 0, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_add_sdata(msg, &diff, sizeof(diff));

        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mdsl, "Profile request to R2(%lx) failed w/ %d\n",
                     dsite, err);
            goto out_free_msg;
        }
    out_free_msg:
        xnet_free_msg(msg);
    }

out:
    return;
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
     * "timestamp ring.reqout, ring.update, ring.size, mds.itb, mds.bitmap,
     * mds.txg, mdsl.range_in, mdsl.range_out, mdsl.range_copy,
     * misc.reqin_total, misc.reqin_handle, xnet.msg_alloc, xnet.msg_free,
     * xnet.inbytes, xnet.outbytes, xnet.active_links, storage.wbytes,
     * storage.rbytes, storage.wreq, storage.rreq, storage.cpbytes,
     * storage.aio_submitted, storage.aio_handled misc.tcc_size misc.tcc_used
     * storage.active stroage.memcache hmo.pending_ios hmi.mi_bused
     * hmi.mi_bfree hmi.mi_bwrite hmi.mi_bread"
     *
     * Note that, we send this profile header to r2 server. If you are
     * modifying this header, please make sure modify the defination in
     * root/profile.c -> hvfs_mdsl_profile_setup()!
     */
    hvfs_pf("PLOT %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %d %d %d %ld "
            "%ld %ld %ld %ld %ld\n", 
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
            atomic64_read(&hmo.storage.memcache),
            atomic64_read(&hmo.pending_ios),
            atomic64_read(&hmi.mi_bused),
            atomic64_read(&hmi.mi_bfree),
            atomic64_read(&hmi.mi_bwrite),
            atomic64_read(&hmi.mi_bread)
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

void mdsl_dump_profiling(time_t t, struct hvfs_profile *hp)
{
    switch (hmo.conf.prof_plot) {
    case MDSL_PROF_PLOT:
        dump_profiling_plot(t);
        break;
    case MDSL_PROF_HUMAN:
        dump_profiling_human(t);
        break;
    case MDSL_PROF_R2:
        /* always send the current profiling copy to HVFS_RING(0)? */
        dump_profiling_r2(t, hp);
        break;
    case MDSL_PROF_NONE:
    default:;
    }
}
