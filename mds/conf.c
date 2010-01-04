/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-04 11:27:43 macan>
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

/* This file is intent to support dynamic configuration */

/* 
 * NOTE: we use unix domain socket to receive the request from
 * user/kernel-level tools, and we also support reading the conf/profiling
 * info by this approach
 */

static void __dconf_cmd_action(struct dconf_req *dcr, int fd)
{
    hvfs_verbose(mds, "ACTION on CMD %ld %ld...\n", dcr->cmd, dcr->arg0);
    switch (dcr->cmd) {
    case DCONF_ECHO_CONF:
        /* reply the configuration */
        break;
    case DCONF_SET_TXG_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing TXG  Interval to %ld\n", dcr->arg0);
            hmo.conf.txg_interval = dcr->arg0;
        }
        mds_reset_itimer();
        break;
    case DCONF_SET_PROF_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing Prof Interval to %ld\n", dcr->arg0);
            hmo.conf.profiling_thread_interval = dcr->arg0;
        }
        mds_reset_itimer();
        break;
    case DCONF_SET_UNLINK_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing UNLK Interval to %ld\n", dcr->arg0);
            hmo.conf.unlink_interval = dcr->arg0;
        }
        mds_reset_itimer();
        break;
    default:
        ;
    }
}


static void __dconf_read_and_reply(int fd)
{
    int bi, bl = 0;
    char data[256] = {0,};
    struct dconf_req *dcr = (struct dconf_req *)data;
    
    do {
        bi = recv(fd, data + bl, 256 - bl, 0);
        if (bi == -1 && errno != EAGAIN) {
            hvfs_err(mds, "cmd channel recv failed %d\n", errno);
            return;
        }
        bl += bi;
    } while (bl < 256);
    
    /* ok, we get the request now */
    __dconf_cmd_action(dcr, fd);
}

static void *mds_dconf_thread_main(void *arg)
{
    sigset_t set;
    struct epoll_event ev;      /* only check one entry */
    int err;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    /* next, we wait for the requests */
    while (!hmo.dconf_thread_stop) {
        err = epoll_wait(hmo.conf.dcepfd, &ev, 1, 50);
        if (err == -1 && errno == EINTR) {
            continue;
        } else if (err == -1) {
            hvfs_err(mds, "epoll wait failed %d\n", errno);
            continue;
        }
        if (err) {
            __dconf_read_and_reply(ev.data.fd);
        }
    }
    pthread_exit(0);
}

int dconf_init(void)
{
    int err = 0;
    struct sockaddr_un addr = {.sun_family = AF_UNIX,};
    struct epoll_event ev;

    snprintf(hmo.conf.dcaddr, MDS_DCONF_MAX_NAME_LEN, "/tmp/.MDS.DCONF");
    unlink(hmo.conf.dcaddr);

    hmo.conf.dcfd = socket(AF_UNIX, SOCK_DGRAM, AF_UNIX);
    if (hmo.conf.dcfd == -1) {
        hvfs_err(mds, "create unix socket failed %d\n", errno);
        err = errno;
        goto out;
    }
    sprintf(addr.sun_path, "%s", hmo.conf.dcaddr);
    if (bind(hmo.conf.dcfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        hvfs_err(mds, "bind unix socket failed %d\n", errno);
        err = errno;
        goto out;
    }
    /* then, create the epoll fd */
    hmo.conf.dcepfd = epoll_create(10);
    if (hmo.conf.dcepfd == -1) {
        hvfs_err(mds, "epoll create failed %d\n", errno);
        err = errno;
        goto out;
    }
    err = fcntl(hmo.conf.dcfd, F_GETFL);
    if (err == -1) {
        hvfs_err(mds, "fcntl F_GETFL failed %d\n", errno);
        err = errno;
        goto out;
    }
    err = fcntl(hmo.conf.dcfd, F_SETFL, err | O_NONBLOCK);
    if (err == -1) {
        hvfs_err(mds, "fcntl F_SETFL failed %d\n", errno);
        err = errno;
        goto out;
    }
    ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET;
    ev.data.fd = hmo.conf.dcfd;

    err = epoll_ctl(hmo.conf.dcepfd, EPOLL_CTL_ADD, hmo.conf.dcfd, &ev);
    if (err == -1) {
        hvfs_err(mds, "epoll add fd %d failed %d\n", hmo.conf.dcfd, errno);
        err = errno;
        goto out;
    }

    /* ok, let us create a dconf thread to poll the request and do the
     * reply */
    err = pthread_create(&hmo.conf.dcpt, NULL, &mds_dconf_thread_main,
                         NULL);
    if (err)
        goto out;
    
    hvfs_info(mds, "DCONF cmd channel: %s\n", hmo.conf.dcaddr);
out:
    return err;
}

void dconf_destroy(void)
{
    if (hmo.conf.dcfd) {
        close(hmo.conf.dcfd);
        unlink(hmo.conf.dcaddr);
    }
}
