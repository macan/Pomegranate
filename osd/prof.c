/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@iie.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-08 11:04:27 macan>
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
#include "osd.h"
#include "lprof.h"

static inline
void dump_profiling_r2(time_t t, struct hvfs_profile *hp)
{
    int i = 0;

    if (!hoo.conf.profiling_thread_interval)
        return;
    if (t < hoo.prof.ts + hoo.conf.profiling_thread_interval) {
        return;
    }
    hoo.prof.ts = t;
    hp->flag |= HP_UP2DATE;

    HVFS_PROFILE_VALUE_ADDIN(hp, i, t);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.client.objrnr));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.client.objwnr));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.client.objrbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.client.objwbytes));

    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.ring.update));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.ring.size));

    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.mdsl.objrnr));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.mdsl.objwnr));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.mdsl.objrbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.mdsl.objwbytes));

    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.misc.reqin_total));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.misc.reqin_handle));

    HVFS_PROFILE_VALUE_ADDIN(hp, i, hoo.prof.xnet ?
                             atomic64_read(&hoo.prof.xnet->msg_alloc) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hoo.prof.xnet ?
                             atomic64_read(&hoo.prof.xnet->msg_free) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hoo.prof.xnet ?
                             atomic64_read(&hoo.prof.xnet->inbytes) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hoo.prof.xnet ?
                             atomic64_read(&hoo.prof.xnet->outbytes) : 0);
    HVFS_PROFILE_VALUE_ADDIN(hp, i, hoo.prof.xnet ?
                             atomic64_read(&hoo.prof.xnet->active_links) : 0);

    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.storage.wbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.storage.rbytes));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.storage.wreq));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.storage.rreq));
    HVFS_PROFILE_VALUE_ADDIN(hp, i, atomic64_read(&hoo.prof.storage.cpbytes));

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
            hvfs_err(osd, "xnet_alloc_msg() failed.\n");
            err = -ENOMEM;
            goto out;
        }

        /* send this profile to r2 server */
        dsite = osd_select_ring(&hoo);
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0, hoo.site_id, dsite);
        xnet_msg_fill_cmd(msg, HVFS_R2_PROFILE, 0, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_add_sdata(msg, &diff, sizeof(diff));

        err = xnet_send(hoo.xc, msg);
        if (err) {
            hvfs_err(osd, "Profile request to R2(%lx) failed w/ %d\n",
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
    if (!hoo.conf.profiling_thread_interval)
        return;
    if (t < hoo.prof.ts + hoo.conf.profiling_thread_interval) {
        return;
    }
    hoo.prof.ts = t;
    /* the output format is :
     *
     * "timestamp client.objrnr, client.objwnr, client.objrbytes,
     * client.objwbytes, ring.update, ring.size, mdsl.objrnr, mdsl.objwnr,
     * mdsl.objrbytes, mdsl.objwbytes, misc.reqin_total, misc.reqin_handle,
     * xnet.msg_alloc, xnet.msg_free, xnet.inbytes, xnet.outbytes,
     * xnet.active_links, storage.wbytes, storage.rbytes, storage.wreq,
     * storage.rreq, storage.cpbytes
     *
     * Note that, we send this profile header to r2 server. If you are
     * modifying this header, please make sure modify the defination in
     * root/profile.c -> hvfs_osd_profile_setup()!
     */
    hvfs_pf("PLOT %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld "
            "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld\n", 
            t, 
            atomic64_read(&hoo.prof.client.objrnr),
            atomic64_read(&hoo.prof.client.objwnr),
            atomic64_read(&hoo.prof.client.objrbytes),
            atomic64_read(&hoo.prof.client.objwbytes),
            atomic64_read(&hoo.prof.ring.update),
            atomic64_read(&hoo.prof.ring.size),
            atomic64_read(&hoo.prof.mdsl.objrnr),
            atomic64_read(&hoo.prof.mdsl.objwnr),
            atomic64_read(&hoo.prof.mdsl.objrbytes),
            atomic64_read(&hoo.prof.mdsl.objwbytes),
            atomic64_read(&hoo.prof.misc.reqin_total),
            atomic64_read(&hoo.prof.misc.reqin_handle),
            (hoo.prof.xnet ?
             atomic64_read(&hoo.prof.xnet->msg_alloc) : 0),
            (hoo.prof.xnet ?
             atomic64_read(&hoo.prof.xnet->msg_free) : 0),
            (hoo.prof.xnet ?
             atomic64_read(&hoo.prof.xnet->inbytes) : 0),
            (hoo.prof.xnet ?
             atomic64_read(&hoo.prof.xnet->outbytes) : 0),
            (hoo.prof.xnet ?
             atomic64_read(&hoo.prof.xnet->active_links) : 0),
            atomic64_read(&hoo.prof.storage.wbytes),
            atomic64_read(&hoo.prof.storage.rbytes),
            atomic64_read(&hoo.prof.storage.wreq),
            atomic64_read(&hoo.prof.storage.rreq),
            atomic64_read(&hoo.prof.storage.cpbytes)
        );
}

static inline
void dump_profiling_human(time_t t)
{
    if (!hoo.conf.profiling_thread_interval)
        return;
    if (t < hoo.prof.ts + hoo.conf.profiling_thread_interval) {
        return;
    }
    hoo.prof.ts = t;
    if (hoo.prof.xnet) {
        hvfs_info(osd, "%16ld |  XNET Prof: alloc %ld, free %ld, inb %ld, "
                  "outb %ld, links %ld\n", t,
                  atomic64_read(&hoo.prof.xnet->msg_alloc),
                  atomic64_read(&hoo.prof.xnet->msg_free),
                  atomic64_read(&hoo.prof.xnet->inbytes),
                  atomic64_read(&hoo.prof.xnet->outbytes),
                  atomic64_read(&hoo.prof.xnet->active_links));
    }
    hvfs_info(osd, "%16ld -- MISC Prof: reqin_total %ld, reqin_handle %ld\n",
              t,
              atomic64_read(&hoo.prof.misc.reqin_total),
              atomic64_read(&hoo.prof.misc.reqin_handle));
}

void osd_dump_profiling(time_t t, struct hvfs_profile *hp)
{
    switch (hoo.conf.prof_plot) {
    case OSD_PROF_PLOT:
        dump_profiling_plot(t);
        break;
    case OSD_PROF_HUMAN:
        dump_profiling_human(t);
        break;
    case OSD_PROF_R2:
        /* always send the current profiling copy to HVFS_RING(0)? */
        dump_profiling_r2(t, hp);
        break;
    case OSD_PROF_NONE:
    default:;
    }
}
