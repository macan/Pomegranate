/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-29 03:04:55 macan>
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
#include "mds.h"

/* In this file we implement a gossip like protocol to transfer memory state
 * from one machine to another machine. For example, we can use this function
 * to transfer local bitmap to the remote site.
 */

struct gossip_mgr
{
    /* this manager trigger the gossip sending on random timeouts */
    int gto;                    /* gossip timeout */
};

struct gossip_mgr gm = {
    .gto = 5,
};

/* select a random site and send the rdir entries */
void mds_rdir_gossip(struct rdir_mgr *rm)
{
    u64 *buf = NULL;
    size_t size = 0;
    struct xnet_msg *msg;
    struct chp *p;
    u64 point;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(mds, "xnet_alloc_msg() in low memory.\n");
            return;
        }
    }

    /* select a random site from the mds ring */
    point = hvfs_hash(lib_random(0xfffffff),
                      lib_random(0xfffffff), 0, HASH_SEL_GDT);
    p = ring_get_point2(point, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point2() failed w/ %ld\n",
                 PTR_ERR(p));
        goto out_free;
    }

    if (p->site_id == hmo.xc->site_id) {
        /* self gossip? do not do it */
        goto out_free;
    }

    /* send the request to the selected site */
    mds_rdir_get_all(rm, &buf, &size);
    if (!size) {
        /* zero length, do not send */
        goto out_free;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE, 
                     hmo.xc->site_id, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_GR, size, 0);
    xnet_msg_add_sdata(msg, buf, size * sizeof(u64));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
    }

    xnet_free_msg(msg);
    return;
out_free:
    xnet_raw_free_msg(msg);
}

void *gossip_thread_main(void *arg)
{
    sigset_t set;
    time_t last_ts = time(NULL), cur_ts;
    u64 last_fwd = atomic64_read(&hmo.prof.mds.forward);
    int nr;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errors */

    while (!hmo.gossip_thread_stop) {
        nr = gm.gto;
        while (nr) {
            nr = sleep(nr);
            if (hmo.gossip_thread_stop)
                goto out;
        }
        /* sanity check */
        if (hmo.state < HMO_STATE_RUNNING)
            continue;
        /* send the gossip message now */
        mds_rdir_gossip(&hmo.rm);
        mds_dh_gossip(&hmo.dh);
        /* ft gossip */
        if (hmo.conf.active_ft)
            ft_gossip_send();

        cur_ts = time(NULL);
        if (cur_ts > last_ts) {
            if ((atomic64_read(&hmo.prof.mds.forward) - last_fwd) /
                (cur_ts - last_ts) > 1000) {
                /* faster gossip */
                mds_gossip_faster();
            } else {
                /* slower gossip */
                mds_gossip_slower();
            }
        }
        last_fwd = atomic64_read(&hmo.prof.mds.forward);
        last_ts = cur_ts;
        gm.gto = lib_random(hmo.conf.gto);
    }
out:
    pthread_exit(0);
}

int gossip_init(void)
{
    pthread_attr_t attr;
    int err = 0, stacksize;

    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(mds, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hmo.conf.stacksize > (1 << 20) ? 
                 hmo.conf.stacksize : (2 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(mds, "set thread stack size to %d failed w/ %d\n", 
                 stacksize, err);
        goto out;
    }

    err = pthread_create(&hmo.gossip_thread, &attr, &gossip_thread_main,
                         NULL);
    if (err)
        hvfs_err(mds, "pthread_create gossip thread failed: %s\n",
                 strerror(err));

out:
    return err;
}

void gossip_destroy(void)
{
    if (hmo.gossip_thread_stop)
        return;
    hmo.gossip_thread_stop = 1;
    pthread_kill(hmo.gossip_thread, SIGUSR1);
    pthread_join(hmo.gossip_thread, NULL);
}

