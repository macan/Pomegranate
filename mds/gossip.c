/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-07-17 16:02:49 macan>
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

void *gossip_thread_main(void *arg)
{
    sigset_t set;
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
        /* send the gossip message now */
        mds_dh_gossip(&hmo.dh);
        
        gm.gto = lib_random(15);
    }
out:
    pthread_exit(0);
}

int gossip_init(void)
{
    int err = 0;

    err = pthread_create(&hmo.gossip_thread, NULL, &gossip_thread_main,
                         NULL);
    if (err)
        hvfs_err(mds, "pthread_create gossip thread failed: %s\n",
                 strerror(err));

    return err;
}

void gossip_destroy(void)
{
    hmo.gossip_thread_stop = 1;
    pthread_kill(hmo.gossip_thread, SIGINT);
    pthread_join(hmo.gossip_thread, NULL);
}

