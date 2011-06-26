/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-24 02:41:53 macan>
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
#include "xnet.h"

/* This file is intent to support dynamic configuration */

/* 
 * NOTE: we use unix domain socket to receive the request from
 * user/kernel-level tools, and we also support reading the conf/profiling
 * info by this approach
 */

static int __dconf_write(char *str, int fd)
{
    int len = strlen(str);
    int bl = 0, bw, err = 0;

    /* write the data length */
    do {
        bw = send(fd, (void *)&len + bl, sizeof(len) - bl, 0);
        if (bw == -1) {
            hvfs_err(mds, "send to fd %d failed w/ %s(%d)\n",
                     fd, strerror(errno), errno);
            err = -errno;
            goto out;
        }
        bl += bw;
    } while (bl < sizeof(len));

    /* write the string now */
    bl = 0;
    do {
        bw = send(fd, str + bl, len - bl, 0);
        if (bw == -1) {
            hvfs_err(mds, "send to fd %d failed w/ %s(%d)\n",
                     fd, strerror(errno), errno);
            err = -errno;
            goto out;
        }
        bl += bw;
    } while (bl < sizeof(len));

out:
    return err;
}

static void __dconf_cmd_action(struct dconf_req *dcr, int fd)
{
    char str[1024];

    hvfs_verbose(mds, "ACTION on CMD %ld %ld...\n", dcr->cmd, dcr->arg0);
    switch (dcr->cmd) {
    case DCONF_ECHO_CONF:
    {
        struct rusage ru;

        if (getrusage(RUSAGE_SELF, &ru) < 0) {
            hvfs_err(mds, "getrusage() failed w/ %s(%d)\n",
                     strerror(errno), errno);
        }
        
        /* reply the configuration */
        snprintf(str, 1023, "%s %lx Uptime %lds State %s, "
                 "register w/ R2 server %lx fsid %ld.\n"
                 "Total OP [lookup %ld, modify %ld]\n"
                 "Resource Usage: \n"
                 "\tutime %fs stime %fs \n"
                 "\tRSS %ldK Shared Text %ldK Unshared Data %ldK Unshared Stack %ldK\n"
                 "\tPage Reclaims %ld Page Faults %ld\n"
                 "\tSwaps %ld InBlock %ld OutBlock %ld\n"
                 "\tMsgSnd %ld MsgRcv %ld\n"
                 "\tSignals %ld Voluntary CS %ld Involuntary CS %ld\n",
                 (HVFS_IS_MDS(hmo.site_id) ? "MDS Server" : 
                  (HVFS_IS_CLIENT(hmo.site_id) ? "Client" : "BP")),
                 hmo.site_id,
                 (u64)(time(NULL) - hmo.uptime),
                 (hmo.state == HMO_STATE_INIT ? "INIT" :
                  (hmo.state == HMO_STATE_LAUNCH ? "LAUNCH" :
                   (hmo.state == HMO_STATE_RUNNING ? "RUNNING" :
                    (hmo.state == HMO_STATE_PAUSE ? "PAUSE" :
                     (hmo.state == HMO_STATE_RDONLY ? "RDONLY" :
                      (hmo.state == HMO_STATE_OFFLINE ? "OFFLINE" :
                       "Unknown")))))),
                 (hmo.ring_site == 0 ? HVFS_ROOT(0) : hmo.ring_site), 
                 hmo.fsid,
                 atomic64_read(&hmo.prof.cbht.lookup), 
                 atomic64_read(&hmo.prof.cbht.modify),
                 /* rusage */
                 ru.ru_utime.tv_sec + (float)ru.ru_utime.tv_usec / 1000000,
                 ru.ru_stime.tv_sec + (float)ru.ru_stime.tv_usec / 1000000,
                 ru.ru_maxrss, ru.ru_ixrss, ru.ru_idrss, ru.ru_isrss,
                 ru.ru_minflt, ru.ru_majflt,
                 ru.ru_nswap, ru.ru_inblock, ru.ru_oublock,
                 ru.ru_msgsnd, ru.ru_msgrcv,
                 ru.ru_nsignals, ru.ru_nvcsw, ru.ru_nivcsw);
        __dconf_write(str, fd);
        break;
    }
    case DCONF_SET_TXG_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing TXG  Interval to %ld\n", dcr->arg0);
            hmo.conf.txg_interval = dcr->arg0;
        }
        mds_reset_itimer();
        snprintf(str, 1023, "Changing TXG  Interval to %ld\n", dcr->arg0);
        __dconf_write(str, fd);
        break;
    case DCONF_SET_PROF_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing Prof Interval to %ld\n", dcr->arg0);
            hmo.conf.profiling_thread_interval = dcr->arg0;
        }
        mds_reset_itimer();
        snprintf(str, 1023, "Changing Prof Interval to %ld\n", dcr->arg0);
        __dconf_write(str, fd);
        break;
    case DCONF_SET_UNLINK_INTV:
        if (dcr->arg0 >= 0) {
            hvfs_info(mds, "Changing UNLK Interval to %ld\n", dcr->arg0);
            hmo.conf.unlink_interval = dcr->arg0;
        }
        snprintf(str, 1023, "Changing UNLK Interval to %ld\n", dcr->arg0);
        __dconf_write(str, fd);
        mds_reset_itimer();
        break;
    case DCONF_SET_MDS_FLAG:
    {
        u32 sflag = hvfs_mds_tracing_flags;
        
        mds_reset_tracing_flags(dcr->arg0);
        snprintf(str, 1023, "Change MDS tracing flag from %08x to %08x\n",
                 sflag, hvfs_mds_tracing_flags);
        __dconf_write(str, fd);
        break;
    }
    case DCONF_SET_XNET_FLAG:
    {
        u32 sflag = hvfs_xnet_tracing_flags;
        
        xnet_reset_tracing_flags(dcr->arg0);
        snprintf(str, 1023, "Change XNET tracing flag from %08x to %08x\n",
                 sflag, hvfs_xnet_tracing_flags);
        __dconf_write(str, fd);
        break;
    }
    case DCONF_GET_LATENCY:
    {
        if (hmo.cb_latency) {
            char *p = NULL;
            
            hmo.cb_latency(&p);
            if (p)
                __dconf_write(p, fd);
            else {
                sprintf(str, "Has latency callback, but failed execution!\n");
                __dconf_write(str, fd);
            }
            xfree(p);
        } else {
            sprintf(str, "No latency callback registered!\n");
            __dconf_write(str, fd);
        }
        break;
    }
    default:
        snprintf(str, 1023, "Unknown commands %ld\n", dcr->cmd);
        __dconf_write(str, fd);
    }
}


static void __dconf_read_and_reply(int fd)
{
    int bi, bl = 0;
    char data[256] = {0,};
    struct dconf_req *dcr = (struct dconf_req *)data;
    struct timespec ts, ts2;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    do {
        clock_gettime(CLOCK_REALTIME, &ts2);
        if (ts2.tv_sec - ts.tv_sec >= 5) {
            /* close this connection please */
            close(fd);
            return;
        }
        bi = recv(fd, data + bl, 256 - bl, 0);
        if (bi == -1 && errno != EAGAIN) {
            hvfs_err(mds, "cmd channel recv failed %d\n", errno);
            return;
        }
        if (bi > 0)
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

        if (ev.data.fd == hmo.conf.dcfd) {
            int nfd;
            
            /* accept the new connection and add to the epoll pool */
            nfd = accept(hmo.conf.dcfd, NULL, NULL);
            if (nfd < 0) {
                hvfs_err(mds, "accept() failed %s\n", strerror(errno));
                continue;
            }
            ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET;
            ev.data.fd = nfd;
            err = epoll_ctl(hmo.conf.dcepfd, EPOLL_CTL_ADD, nfd, &ev);
            if (err < 0) {
                hvfs_err(mds, "epoll_ctl() add fd %d failed %d\n",
                         nfd, errno);
                continue;
            }
            hvfs_warning(mds, "Accept dconf connection %d\n", nfd);
        } else if (err) {
            if (ev.events & EPOLLERR || ev.events & EPOLLHUP) {
                hvfs_err(mds, "Hoo, the connection %d is broken\n",
                         ev.data.fd);
                epoll_ctl(hmo.conf.dcepfd, EPOLL_CTL_DEL, ev.data.fd, &ev);
                close(ev.data.fd);
                continue;
            }
            if (ev.events & EPOLLIN) {
                __dconf_read_and_reply(ev.data.fd);
            }
        }
    }
    pthread_exit(0);
}

int dconf_init(void)
{
    pthread_attr_t attr;
    struct sockaddr_un addr = {.sun_family = AF_UNIX,};
    struct epoll_event ev;
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

    snprintf(hmo.conf.dcaddr, MDS_DCONF_MAX_NAME_LEN, "/tmp/.MDS.DCONF.%d", getpid());
    unlink(hmo.conf.dcaddr);

    hmo.conf.dcfd = socket(AF_UNIX, SOCK_STREAM, AF_UNIX);
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
    if (listen(hmo.conf.dcfd, 10) == -1) {
        hvfs_err(mds, "listen on unix socked failed %d\n", errno);
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
    err = pthread_create(&hmo.conf.dcpt, &attr, &mds_dconf_thread_main,
                         NULL);
    if (err)
        goto out;
    
    hvfs_info(mds, "create DCONF cmd channel: %s w/ %d\n", 
              hmo.conf.dcaddr, err);
out:
    return err;
}

void dconf_destroy(void)
{
    int err;
    
    if (hmo.conf.dcfd) {
        close(hmo.conf.dcfd);
        err = unlink(hmo.conf.dcaddr);
        if (err < 0) {
            hvfs_err(mds, "unlink %s failed %s\n", hmo.conf.dcaddr,
                     strerror(errno));
        }
    }
}
