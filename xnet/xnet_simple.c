/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-24 09:01:39 macan>
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
#include "lib.h"

/*
 * NOTE: this file is a simple single-host implementation of XNET. We use TCP
 * sockets, so we can easily extend the framework to multi-host systems.
 */

#ifdef USE_XNET_SIMPLE

void *mds_gwg;
struct xnet_prof g_xnet_prof;

#define RESEND_TIMEOUT          (0x10)
#define SEND_TIMEOUT            (60)
#define SIOV_NR                 (50)
struct xnet_conf g_xnet_conf = {
    .resend_timeout = RESEND_TIMEOUT,
    .send_timeout = SEND_TIMEOUT,
    .siov_nr = SIOV_NR,
};

/* First, how do we handle the site_id to ip address translation?
 */
#ifndef XNET_CONNS
#define XNET_CONNS      8
#define XNET_CONNS_DEF  4       /* default to setup 4 connections */
#endif
struct xnet_addr
{
    struct list_head list;
    struct sockaddr sa;
    int index;                  /* used index */
    int sockfd[XNET_CONNS];
    xlock_t socklock[XNET_CONNS];
    xlock_t lock;
    xlock_t clock;
};
struct xnet_site
{
#define XNET_SITE_LOCAL         0x01
    u32 flag;
    struct list_head addr;
};

struct site_table
{
    struct xnet_site *site[1 << 20]; /* we only have 2^20 site_id space */
};

struct accept_conn
{
    struct list_head list;
    int sockfd;
#define AC_INIT         0
#define AC_CONFIRM      1
    int state;
};

struct active_conn
{
    struct list_head list;
    int sockfd;
};

struct site_table gst;
pthread_t pollin_thread;        /* poll-in any requests */
pthread_t resend_thread;        /* resend the pending requests */
LIST_HEAD(accept_list);         /* recored the accepted sockets */
LIST_HEAD(active_list);         /* recored the actived sockets */
xlock_t active_list_lock;
int lsock = 0;                  /* local listening socket */
int epfd = 0;
int pollin_thread_stop = 0;
int resend_thread_stop = 0;
atomic_t global_reqno;
LIST_HEAD(global_xc_list);

static inline
int accept_lookup(int fd)
{
    struct accept_conn *pos, *n;
    int ret = 0;

    list_for_each_entry_safe(pos, n, &accept_list, list) {
        if (pos->sockfd == fd) {
            ret = 1;
            list_del(&pos->list);
            xfree(pos);
            break;
        }
    }

    return ret;
}

void setnodelay(int fd)
{
    int err = 0, val = 1;

    err = setsockopt(fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
    if (err < 0) {
        hvfs_err(xnet, "setsockopt() failed %d, the short messages may be "
                 "very slow now\n", errno);
    }
}

#ifdef XNET_BLOCKING
#define setnonblocking(fd)
#else
/* NOTE that: we found that the NONBLOCK Interface is not very good for
 * our test case */
void setnonblocking(int fd)
{
    int err;

    err = fcntl(fd, F_GETFL);
    if (err < 0) {
        hvfs_err(xnet, "fcntl() GET failed %d\n", errno);
        goto out;
    }
    err = fcntl(fd, F_SETFL, err | O_NONBLOCK);
    if (err < 0) {
        hvfs_err(xnet, "fcntl() SET failed %d\n", errno);
        goto out;
    }
out:
    return;
}
#endif

#ifdef XNET_BLOCKING
#define unsetnonblocking(fd)
#else
void unsetnonblocking(int fd)
{
    int err;

    err = fcntl(fd, F_GETFL);
    if (err < 0) {
        hvfs_err(xnet, "fcntl() GET failed %d\n", errno);
        goto out;
    }
    err = fcntl(fd, F_SETFL, (err & (~O_NONBLOCK)));
    if (err < 0) {
        hvfs_err(xnet, "fcntl() SET failed %d\n", errno);
        goto out;
    }
out:
    return;
}
#endif

static inline
struct xnet_context *__find_xc(u64 site_id)
{
    struct xnet_context *xc;
    int found = 0;

    list_for_each_entry(xc, &global_xc_list, list) {
        if (xc->site_id == site_id) {
            found = 1;
            break;
        }
    }
    if (!found)
        return NULL;
    else
        return xc;
}


int st_update_sockfd(struct site_table *st, int fd, u64 dsid);
int st_clean_sockfd(struct site_table *st, int fd);

/*
 * Return value: 0 => 
 */
int xnet_resend_remove(struct xnet_msg *msg)
{
    struct xnet_msg *pos, *n;
    struct xnet_context *xc = msg->xc;
    int found = 0;

    ASSERT(xc, xnet);
    xlock_lock(&xc->resend_lock);
    list_for_each_entry_safe(pos, n, &xc->resend_q, list) {
        if (pos == msg) {
            list_del_init(&pos->list);
            atomic_dec(&pos->ref);
            found = 1;
            break;
        }
    }
    xlock_unlock(&xc->resend_lock);

    return found;
}

/* __xnet_handle_tx()
 *
 * NOTE: this function should try to read from this socket hardly, until the
 * whole message is returned. At this point, we should try to read from the
 * socket either. Until EAGAIN returned, we must try to read deeply.
 */
int __xnet_handle_tx(int fd)
{
    struct xnet_msg *msg, *req;
    struct xnet_context *xc;
    int br, bt;
    int next = 1;               /* this means we should retry the read */
    int flag = MSG_DONTWAIT;

#ifdef HVFS_DEBUG_LATENCY
    lib_timer_def();
    lib_timer_B();
#endif
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* FIXME: we should put this fd in the retry queue, we can retry the
         * receiving */
        return next;
    }

    msg->state = XNET_MSG_RX;
    /* receive the tx */
    br = 0;
    do {
        bt = recv(fd, ((void *)&msg->tx) + br, 
                  sizeof(struct xnet_msg_tx) - br, flag);
        if (bt < 0) {
            if (errno == EAGAIN && !br) {
                /* pseudo calling, just return */
                next = 0;
                goto out_raw_free;
            }
            hvfs_verbose(xnet, "read() err %d w/ br %d(%ld)\n", 
                         errno, br, sizeof(struct xnet_msg_tx));
            if (errno == EAGAIN || errno == EINTR)
                continue;
            /* FIXME: how to handle this err? */
            next = -1;
            goto out_raw_free;
        } else if (bt == 0) {
            /* hoo, we got the EOF of the socket stream */
            next = -1;
            goto out_raw_free;
        }
        br += bt;
        flag = 0;
    } while (br < sizeof(struct xnet_msg_tx));
    atomic64_add(br, &g_xnet_prof.inbytes);

    hvfs_debug(xnet, "We have recieved the MSG_TX, dpayload %d\n",
               msg->tx.len);

    {
        int err;

        if (unlikely(msg->tx.type == XNET_MSG_HELLO)) {

            err = accept_lookup(fd);
            
            if (unlikely(err == 1)) {
                struct xnet_msg_tx htx = {
                    .version = 0,
                    .len = sizeof(htx),
                    .type = XNET_MSG_HELLO_ACK,
                    .ssite_id = msg->tx.dsite_id,
                    .dsite_id = msg->tx.ssite_id,
                };
                struct iovec __iov = {
                    .iov_base = &htx,
                    .iov_len = sizeof(htx),
                };
                struct msghdr __msg = {
                    .msg_iov = &__iov,
                    .msg_iovlen = 1,
                };
                int bt;
                
                bt = sendmsg(fd, &__msg, MSG_NOSIGNAL);
                if (bt < 0 || bt < sizeof(htx)) {
                    hvfs_err(xnet, "sendmsg do not support redo now(%s) :(\n",
                             strerror(errno));
                    next = -1;
                    goto out_raw_free;
                }

                err = st_update_sockfd(&gst, fd, msg->tx.ssite_id);
                if (err) {
#if 0
                    struct accept_conn *ac;
                    
                    ac = xzalloc(sizeof(struct accept_conn));
                    if (!ac) {
                        hvfs_err(xnet, "xzalloc() struct accept_conn "
                                 "failed\n");
                    } else {
                        /* FIXME: a lock is needed here! */
                        INIT_LIST_HEAD(&ac->list);
                        ac->sockfd = fd;
                        list_add_tail(&ac->list, &accept_list);
                    }
#else
                    /* shutdown the connection now */
                    struct epoll_event ev;
                    
                    err = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
                    if (err) {
                        hvfs_err(xnet, "epoll_ctl del fd %d failed w/ %s\n",
                                 fd, strerror(errno));
                    }
                    next = -1;
                    goto out_free;
#endif
                }
            } else {
                hvfs_err(xnet, "hello msg w/o accept entry %d\n", fd);
            }
            goto out_free;
        }
    }

    /* lookup the target xnet_context */
    xc = __find_xc(msg->tx.dsite_id);
    if (!xc) {
        /* just return, nobody cares this msg */
        hvfs_err(xnet, "find xc %lx failed in fd %d\n", msg->tx.dsite_id, fd);
        /* note that we should tear down the connection! */
        next = -1;
        goto out_free;
    }

    /* receive the data if exists */
#ifdef XNET_EAGER_WRITEV
    msg->tx.len -= sizeof(struct xnet_msg_tx);
#endif
    if (msg->tx.len > 0) {
        /* we should pre-alloc the buffer */
        void *buf;

        if (xc->ops.buf_alloc)
            buf = xc->ops.buf_alloc(msg->tx.len, msg->tx.cmd);
        else {
            buf = xzalloc(msg->tx.len);
            /* we should default to free all the resource from xnet. */
            xnet_set_auto_free(msg);
        }
        if (!buf) {
            hvfs_err(xnet, "xmalloc() buffer failed\n");
            ASSERT(0, xnet);
            goto out_free;
        }
        br = 0;
        do {
            bt = recv(fd, buf + br, msg->tx.len - br, MSG_WAITALL);
            if (bt < 0) {
                hvfs_verbose(xnet, "read() err %d w/ br %d(%d)\n", 
                             errno, br, msg->tx.len);
                if (errno == EAGAIN || errno == EINTR) {
                    sleep(0);
                    continue;
                }
                /* this means the connection is broken, let us failed */
                next = -1;
                goto out_free;
            } else if (bt == 0) {
                next = -1;
                goto out_free;
            }
            br += bt;
        } while (br < msg->tx.len);

        /* add the data to the riov */
        xnet_msg_add_rdata(msg, buf, br);
        atomic64_add(br, &g_xnet_prof.inbytes);
    } else if (msg->tx.len < 0) {
        hvfs_err(xnet, "Recv invalid xnet_msg len %d from %lx\n",
                 msg->tx.len, msg->tx.ssite_id);
        next = -1;
        goto out_free;
    }
    
    /* find the related msg */
    if (msg->tx.type == XNET_MSG_REQ) {
        /* this is a fresh requst msg, just receive the data */
        hvfs_debug(xnet, "We got a REQ message (%lx to %lx)\n",
                   msg->tx.ssite_id, msg->tx.dsite_id);
        sem_post(&xc->wait);
        msg->xc = xc;
        if (xc->ops.recv_handler)
            xc->ops.recv_handler(msg);
    } else if (msg->tx.type == XNET_MSG_RPY) {
        /* we should find the original request by handle */
        hvfs_debug(xnet, "We got a RPY(%lx) message, handle to msg %p\n", 
                   msg->tx.cmd, (void *)msg->tx.handle);
        req = (struct xnet_msg *)msg->tx.handle;
        if (req == NULL) {
            hvfs_err(xnet, "Invalid reply msg from %lx to %lx reqno %d\n",
                     msg->tx.ssite_id, msg->tx.dsite_id, msg->tx.reqno);
        }
        ASSERT(req, xnet);

        /* check if this reply is the correct reply */
        if (req->tx.reqno != msg->tx.reqno) {
            /* hoo, we just ignore this reply message */
            hvfs_err(xnet, "ignore the reply message, mismatch %u vs %u\n",
                     req->tx.reqno, msg->tx.reqno);
            goto out_free;
        }
        
        /* remove from the resend_list */
        if (!req->xc) {
            req->xc = xc;
        }
        {
            int err;
            
            err = xnet_resend_remove(req);
            if (!err) {
                /* FIXME: we should release the reference here, however,
                 * release it will lead to SIGSEGV, ugly:( */
                hvfs_err(xnet, "try to remove req %p %u from resend Q, "
                         "not found\n", req, req->tx.reqno);
            }
        }
        msg->state = XNET_MSG_PAIRED;

        /* fallback to normal cmd */
        xnet_rpy_cmd_fallback(msg);

        /* switch for REPLY/ACK/COMMIT */
        if (msg->tx.cmd == XNET_RPY_DATA) {
            req->state = XNET_MSG_ACKED;
            req->pair = msg;
        } else if (msg->tx.cmd == XNET_RPY_COMMIT) {
            req->state = XNET_MSG_COMMITED;
            /* auto free the commit msg */
        } else if (msg->tx.cmd == XNET_RPY_ACK) {
            req->state = XNET_MSG_ACKED;
            /* auto free the ack msg */
            req->pair = msg;
        } else {
            ASSERT(0, xnet);
        }
        sem_post(&req->event);
    } else if (msg->tx.type == XNET_MSG_CMD) {
        /* just receive the data */
    } else if (msg->tx.type == XNET_MSG_NOP) {
        hvfs_debug(xnet, "recv NOP message, just receive the next msg.\n");
    }
#ifdef HVFS_DEBUG_LATENCY
    lib_timer_E();
    lib_timer_O(1, "Total Handle Time");
#endif

    if (next < 0) {
        xnet_free_msg(msg);
    }
    return next;
out_free:
    xnet_free_msg(msg);
    return next;
out_raw_free:
    xnet_raw_free_msg(msg);
    return next;
}

void *resend_thread_main(void *arg)
{
    struct xnet_context *xc = (struct xnet_context *)arg;
    struct xnet_msg *pos, *msg, *n;
    sigset_t set;
    int err = 0, nr;
    
    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    for (; !resend_thread_stop;) {
        nr = g_xnet_conf.resend_timeout;
        while (nr) {
            nr = sleep(nr);
            if (resend_thread_stop) {
                goto out;
            }
        }

    retry:
        msg = NULL;
        xlock_lock(&xc->resend_lock);
        list_for_each_entry_safe(pos, n, &xc->resend_q, list) {
            if (time(NULL) - pos->ts >= g_xnet_conf.resend_timeout) {
                msg = pos;
                break;
            }
        }
        xlock_unlock(&xc->resend_lock);

        if (msg) {
            hvfs_info(xnet, "Resend msg %p from %lx to %lx reqno %d\n",
                      msg, msg->tx.ssite_id, msg->tx.dsite_id, msg->tx.reqno);
            ASSERT(xc == msg->xc, xnet);
            err = xnet_resend(xc, msg);
            if (err) {
                hvfs_err(xnet, "resend msg %p failed w/ %d\n", msg, err);
            }
            goto retry;
        }
    }

out:
    pthread_exit(NULL);
}

void *pollin_thread_main(void *arg)
{
    struct epoll_event ev, events[10];
    struct sockaddr_in addr = {0,};
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct accept_conn *ac;
    sigset_t set;
    int asock, i;
    int err, nfds;
    
    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = lsock;
    err = epoll_ctl(epfd, EPOLL_CTL_ADD, lsock, &ev);
    if (err < 0) {
        hvfs_err(xnet, "epoll_ctl() add fd %d failed %d\n", lsock, errno);
        err = -errno;
        goto out;
    }
    
    hvfs_debug(xnet, "POLL-IN thread running, waiting for any request in...\n");
    for (; !pollin_thread_stop;) {
        nfds = epoll_wait(epfd, events, 10, 50);
        if (nfds == -1) {
            hvfs_debug(xnet, "epoll_wait() failed %d\n", errno);
            continue;
        }
        for (i = 0; i < nfds; i++) {
            if (events[i].data.fd == lsock) {
                asock = accept(lsock, (struct sockaddr *)(&addr), &addrlen);
                if (asock < 0) {
                    hvfs_err(xnet, "accept() failed %d\n", errno);
                    continue;
                }
                ac = xzalloc(sizeof(struct accept_conn));
                if (!ac) {
                    hvfs_err(xnet, "xzalloc() struct accept_conn failed\n");
                    close(asock);
                    continue;
                }
                INIT_LIST_HEAD(&ac->list);
                ac->sockfd = asock;
                list_add_tail(&ac->list, &accept_list);
                
                setnonblocking(asock);
                setnodelay(asock);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = asock;
                err = epoll_ctl(epfd, EPOLL_CTL_ADD, asock, &ev);
                if (err < 0) {
                    hvfs_err(xnet, "epoll_ctl() add fd %d failed %d\n",
                             asock, errno);
                    continue;
                }

                hvfs_info(xnet, "Accept connection from %s %d fd %d.\n",
                          inet_ntoa(addr.sin_addr),
                          ntohs(addr.sin_port),
                          asock);
            } else {
                /* handle input requests */
                int next;

                hvfs_debug(xnet, "RECV from fd %d.......\n", 
                           events[i].data.fd);
                if (events[i].events & EPOLLERR) {
                    hvfs_err(xnet, "Hoo, the connection %d is broken.\n",
                             events[i].data.fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                    st_clean_sockfd(&gst, events[i].data.fd);
                    continue;
                }
                do {
                    next = __xnet_handle_tx(events[i].data.fd);
                    if (next < 0) {
                        /* this means the connection is shutdown */
                        hvfs_err(xnet, "connection %d is shutdown.\n",
                                 events[i].data.fd);
                        epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                        st_clean_sockfd(&gst, events[i].data.fd);
                        break;
                    }
                } while (next); /* if we have successfully handle one TX, then
                                 * we out. This note is out-of-date! */
            }
        }
    }

out:
    return ERR_PTR(err);
}

int st_init(void)
{
    memset(&gst, 0, sizeof(gst));
    atomic64_set(&g_xnet_prof.msg_alloc, 0);
    atomic64_set(&g_xnet_prof.msg_free, 0);
    atomic64_set(&g_xnet_prof.inbytes, 0);
    atomic64_set(&g_xnet_prof.outbytes, 0);
    xlock_init(&active_list_lock);

    return 0;
}

void st_destroy(void)
{
    return;
}

/* st_add() add xnet_site to the table
 */
int st_add(struct site_table *st, struct xnet_site *xs, u64 site_id)
{
    if (st->site[site_id]) {
        hvfs_err(xnet, "This site_id(%ld) is already mapped, please use "
                 "st_update() update it.\n", site_id);
        return -EEXIST;
    } else {
        st->site[site_id] = xs;
    }
    return 0;
}

/* st_del() del the xnet_site site_id relationship from the site table
 */
int st_del(struct site_table *st, u64 site_id)
{
    if (st->site[site_id]) {
        xfree(st->site[site_id]);
        st->site[site_id] = NULL;
    } else {
        hvfs_err(xnet, "Trying to del a non-exist site_id(%ld).\n", site_id);
        return -ENOTEXIST;
    }
    return 0;
}

/* st_lookup() return the struct xnet_site pointer
 */
int st_lookup(struct site_table *st, struct xnet_site **xs, u64 site_id)
{
    ASSERT(st, xnet);
    *xs = st->site[site_id];
    if (!(*xs)) {
        hvfs_debug(xnet, "The site_id(%lx) is not mapped.\n", site_id);
        return -1;
    }
    return 0;
}

/* st_update() update the relationship
 */
int st_update(struct site_table *st, struct xnet_site *xs, u64 site_id)
{
    struct xnet_site *t;

    t = st->site[site_id];
    st->site[site_id] = xs;
    if (t) {
        /* close the active connections? */
        xfree(t);
    }
    return 0;
}

void st_dump(struct site_table *st)
{
    struct xnet_addr *xa;
    int i, j;

    for (i = 0; i < (1 << 20); i++) {
        if (st->site[i]) {
            if (st->site[i]->flag & XNET_SITE_LOCAL) {
                continue;
            }
            list_for_each_entry(xa, &st->site[i]->addr, list) {
                xlock_lock(&xa->lock);
                for (j = 0; j < xa->index; j++) {
                    hvfs_info(xnet, "Site %x @ %d => %d.\n", i, j, xa->sockfd[j]);
                }
                xlock_unlock(&xa->lock);
            }
        }
    }
}

/* st_update_sockfd() update the related addr with the new connection fd
 */
int st_update_sockfd(struct site_table *st, int fd, u64 dsid)
{
    struct xnet_addr *xa;

    if (st->site[dsid]) {
        if (st->site[dsid]->flag & XNET_SITE_LOCAL)
            return 0;
        list_for_each_entry(xa, &st->site[dsid]->addr, list) {
            xlock_lock(&xa->lock);
            /* ok, find it */
            hvfs_debug(xnet, "Hoo, find it @ %lx{%d} <- %d.\n", 
                       dsid, xa->index, fd);
            if (xa->index == XNET_CONNS) {
                xlock_unlock(&xa->lock);
                return -1;
            }
            xa->sockfd[xa->index++] = fd;
            xlock_unlock(&xa->lock);
            atomic64_inc(&g_xnet_prof.active_links);
        }
    }

    return 0;
}

/* st_clean_sockfd() clean the related addr with the same fd
 */
int st_clean_sockfd(struct site_table *st, int fd)
{
    struct xnet_addr *xa;
    int i, j, k, m;

    for (i = 0; i < (1 << 20); i++) {
        if (st->site[i]) {
            if (st->site[i]->flag & XNET_SITE_LOCAL)
                continue;
            list_for_each_entry(xa, &st->site[i]->addr, list) {
                xlock_lock(&xa->lock);
                for (j = 0; j < xa->index; j++) {
                    m = j;
                    if (xa->sockfd[j] == fd) {
                        hvfs_debug(xnet, "Hoo, clean it @ %d[%d] <- %d.\n", 
                                   i, j, fd);
                        /* move the following entries */
                        for (k = j + 1; k < xa->index; k++, j++) {
                            xlock_lock(&xa->socklock[k]);
                            xa->sockfd[j] = xa->sockfd[k];
                            xlock_unlock(&xa->socklock[k]);
                        }
                        xa->sockfd[--xa->index] = 0;
                        atomic64_dec(&g_xnet_prof.active_links);
                    }
                    j = m;
                }
                xlock_unlock(&xa->lock);
            }
        }
    }

    /* FIXME: should we dump the site table? */
    /* st_dump(st); */
    accept_lookup(fd);
    close(fd);
    return 0;
}

int xnet_update_ipaddr(u64 site_id, int argc, char **ipaddr, short *port)
{
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int i;

    if (!argc)
        return 0;
    
    xa = xzalloc(argc * sizeof(struct xnet_addr));
    if (!xa) {
        hvfs_err(xnet, "xzalloc() xnet_addr failed\n");
        return -ENOMEM;
    }

    xs = xzalloc(sizeof(*xs));
    if (!xs) {
        hvfs_err(xnet, "xzalloc() xnet_site failed\n");
        xfree(xa);
        return -ENOMEM;
    }
    
    for (i = 0; i < argc; i++) {
        inet_aton(*(ipaddr + i), &((struct sockaddr_in *)&
                               ((xa + i)->sa))->sin_addr);
        ((struct sockaddr_in *)&((xa + i)->sa))->sin_family = AF_INET;
        ((struct sockaddr_in *)&((xa + i)->sa))->sin_port = htons(*(port + i));
    }

    /* set the local flag now */
    if (__find_xc(site_id)) {
        xs->flag |= XNET_SITE_LOCAL;
    }
    INIT_LIST_HEAD(&xs->addr);
    INIT_LIST_HEAD(&xa->list);
    for (i = 0; i < XNET_CONNS; i++) {
        xlock_init(&xa->socklock[i]);
    }
    xlock_init(&xa->lock);
    xlock_init(&xa->clock);
    list_add_tail(&xa->list, &xs->addr);
    st_update(&gst, xs, site_id);

    i = st_lookup(&gst, &xs, site_id);
    hvfs_debug(xnet, "Update Site %lx port %d %d\n", site_id, *port, i);
    
    return 0;
}

struct xnet_context *xnet_register_lw(u8 type, u16 port, u64 site_id,
                                      struct xnet_type_ops *ops)
{
    struct xnet_context *xc;
    struct sockaddr addr;
    struct sockaddr_in *ia = (struct sockaddr_in *)&addr;
    struct epoll_event ev;
    int val = 1;
    int lsock;
    int err = 0;

    xc = __find_xc(site_id);
    if (xc) {
        return xc;
    }

    /* we need to alloc one new XC */
    xc = xzalloc(sizeof(*xc));
    if (!xc) {
        hvfs_err(xnet, "xzalloc() xnet_context failed\n");
        return ERR_PTR(-ENOMEM);
    }

    xc->type = type;
    if (ops)
        xc->ops = *ops;
    xc->site_id = site_id;
    xc->service_port = port;
    sem_init(&xc->wait, 0, 0);
    INIT_LIST_HEAD(&xc->list);
    INIT_LIST_HEAD(&xc->resend_q);
    xlock_init(&xc->resend_lock);
    list_add_tail(&xc->list, &global_xc_list);

    /* ok, let us create the listening socket now */
    err = socket(AF_INET, SOCK_STREAM, 0);
    if (err < 0) {
        hvfs_err(xnet, "socket() failed %d\n", errno);
        err = -errno;
        goto out_free;
    }
    lsock = err;

    /* next, we should set the REUSE sockopt */
    err = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if (err < 0) {
        hvfs_err(xnet, "setsockopt() failed %d\n", errno);
        err = -errno;
        goto out_free;
    }

    /* it is ok to bind and listen now */
    ia->sin_family = AF_INET;
    ia->sin_addr.s_addr = htonl(INADDR_ANY);
    ia->sin_port = htons(port);
    err = bind(lsock, &addr, sizeof(addr));
    if (err < 0) {
        hvfs_err(xnet, "bind() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }

    err = listen(lsock, SOMAXCONN);
    if (err < 0) {
        hvfs_err(xnet, "listen() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }
    
    hvfs_debug(xnet, "Listener start @ %s %d\n", inet_ntoa(ia->sin_addr),
               port);

    /* do not need to create epfd here */
    ASSERT(epfd != 0, xnet);
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = lsock;
    err = epoll_ctl(epfd, EPOLL_CTL_ADD, lsock, &ev);
    if (err < 0) {
        hvfs_err(xnet, "epoll_ctl() add fd %d failed %d\n",
                 lsock, errno);
        err = -errno;
        goto out_close;
    }
    
    return xc;
out_close:
    close(lsock);
out_free:
    xfree(xc);
    return ERR_PTR(err);
}

struct xnet_context *xnet_register_type(u8 type, u16 port, u64 site_id,
                                        struct xnet_type_ops *ops)
{
    struct xnet_context *xc;
    struct sockaddr addr;
    struct sockaddr_in *ia = (struct sockaddr_in *)&addr;
    int val = 1;
    int err;

    /* init the global_reqno */
    atomic_set(&global_reqno, -1);

    /* set the fd limit firstly */
    struct rlimit rli = {
        .rlim_cur = 65536,
        .rlim_max = 70000,
    };
    err = setrlimit(RLIMIT_NOFILE, &rli);
    if (err) {
        hvfs_err(xnet, "setrlimit failed w/ %s\n", strerror(errno));
        return ERR_PTR(-errno);
    }
    
    xc = xzalloc(sizeof(*xc));
    if (!xc) {
        hvfs_err(xnet, "xzalloc() xnet_context failed\n");
        return ERR_PTR(-ENOMEM);
    }

    xc->type = type;
    if (ops)
        xc->ops = *ops;
    xc->site_id = site_id;
    xc->service_port = port;
    sem_init(&xc->wait, 0, 0);
    INIT_LIST_HEAD(&xc->list);
    INIT_LIST_HEAD(&xc->resend_q);
    xlock_init(&xc->resend_lock);
    list_add_tail(&xc->list, &global_xc_list);

    /* ok, let us create the listening socket now */
    err = socket(AF_INET, SOCK_STREAM, 0);
    if (err < 0) {
        hvfs_err(xnet, "socket() failed %d\n", errno);
        err = -errno;
        goto out_free;
    }
    lsock = err;

    /* next, we should set the REUSE sockopt */
    err = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if (err < 0) {
        hvfs_err(xnet, "setsockopt() failed %d\n", errno);
        err = -errno;
        goto out_free;
    }

    /* it is ok to bind and listen now */
    ia->sin_family = AF_INET;
    ia->sin_addr.s_addr = htonl(INADDR_ANY);
    ia->sin_port = htons(port);
    err = bind(lsock, &addr, sizeof(addr));
    if (err < 0) {
        hvfs_err(xnet, "bind() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }

    err = listen(lsock, SOMAXCONN);
    if (err < 0) {
        hvfs_err(xnet, "listen() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }
    
    hvfs_debug(xnet, "Listener start @ %s %d\n", inet_ntoa(ia->sin_addr),
               port);
    
    /* create the epfd */
    err = epoll_create(100);
    if (err < 0) {
        hvfs_err(xnet, "epoll_create1() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }
    epfd = err;

    /* we should create one thread to accept connections */
    err = pthread_create(&pollin_thread, NULL, pollin_thread_main, NULL);
    if (err) {
        hvfs_err(xnet, "pthread_create() failed %d\n", err);
        goto out_close;
    }

    /* we should create one thread to resend the requests */
    err = pthread_create(&resend_thread, NULL, resend_thread_main, xc);
    if (err) {
        hvfs_err(xnet, "pthread_create() failed %d\n", err);
        goto out_close;
    }
    
    hvfs_debug(xnet, "Poll-in thread created.\n");

    return xc;
out_close:
    close(lsock);
out_free:
    xfree(xc);
    return ERR_PTR(err);
}

int xnet_unregister_type(struct xnet_context *xc)
{
    /* waiting for the disconnections */
    pollin_thread_stop = 1;
    pthread_kill(pollin_thread, SIGINT);
    pthread_join(pollin_thread, NULL);
    resend_thread_stop = 1;
    pthread_kill(resend_thread, SIGINT);
    pthread_join(resend_thread, NULL);
    
    sem_destroy(&xc->wait);

    if (xc)
        xfree(xc);
    if (lsock)
        close(lsock);
    if (epfd)
        close(epfd);
    return 0;
}

static inline
int IS_CONNECTED(struct xnet_addr *xa, struct xnet_context *xc)
{
    int i, ret = 0;

    xlock_lock(&xa->lock);
    for (i = 0; i < xa->index; i++) {
        if (xa->sockfd[i])
            ret++;
    }
    xlock_unlock(&xa->lock);

    /* FIXME: do not doing active connect */
    if (!HVFS_IS_CLIENT(xc->site_id)) {
        return ret;
    } else {
        if (ret >= XNET_CONNS_DEF)
            return 1;
        else
            return 0;
    }
}

static inline
int SELECT_CONNECTION(struct xnet_addr *xa, int *idx)
{
    int ssock = -1;

    /* we do not need any lock here actually */
    xlock_lock(&xa->lock);
    if (!xa->index) {
        xlock_unlock(&xa->lock);
        return ssock;
    }

    ssock = lib_random(xa->index);
    *idx = ssock;
    xlock_lock(&xa->socklock[ssock]);
    ssock = xa->sockfd[ssock];
    xlock_unlock(&xa->lock);
    
    return ssock;
}

static inline
void __iov_recal(struct iovec *in, struct iovec **out, int inlen, size_t *outlen,
                 int offset)
{
    struct iovec *__out;
    int i, j;

    __out = xmalloc(sizeof(struct iovec) * inlen);
    if (!__out) {
        hvfs_err(xnet, "xmalloc iovec failed.\n");
        ASSERT(0, xnet);
    }

    for (i = 0, j = 0; i < inlen; i++) {
        if (offset < (in + i)->iov_len) {
            (__out + j)->iov_base = (in + i)->iov_base + offset;
            (__out + j)->iov_len = (in + i)->iov_len - offset;
            j++;
            offset = 0;
        } else {
            /* skip this iov entry */
            offset -= (in + i)->iov_len;
        }
    }
    *out = __out;
    *outlen = j;
}

/* xnet_resend()
 *
 * This is a shadow function of xnet_send() which do not wait for any replies
 */
int xnet_resend(struct xnet_context *xc, struct xnet_msg *msg)
{
    struct epoll_event ev;
    struct xnet_msg *pos, *n;
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int err = 0, csock = 0, found = 0, reconn = 0;
    int ssock = 0;              /* selected socket */
    int nr_conn = 0;
    int lock_idx = 0;
    int __attribute__((unused))bw, bt, msg_found = 0;

    xlock_lock(&xc->resend_lock);
    list_for_each_entry_safe(pos, n, &xc->resend_q, list) {
        if (msg == pos) {
            list_del_init(&pos->list);
            msg_found = 1;
        }
        break;
    }
    if (msg_found) {
        /* add to the resend queue */
        msg->ts = time(NULL);
        list_add_tail(&pos->list, &xc->resend_q);
    }
    xlock_unlock(&xc->resend_lock);
    if (!msg_found)
        return 0;

    if (msg->tx.ssite_id == msg->tx.dsite_id) {
        hvfs_err(xnet, "Warning: target site is the original site, BYPASS?\n");
    }

    if (msg->state == XNET_MSG_ACKED || 
        msg->state == XNET_MSG_COMMITED ||
        atomic_read(&msg->ref) == 1) {
        /* remove from the resend Q */
        xlock_lock(&xc->resend_lock);
        list_del_init(&msg->list);
        xlock_unlock(&xc->resend_lock);
        if (atomic_dec_return(&msg->ref) == 0) {
            xnet_free_msg(msg);
        }
        return 0;
    }

    err = st_lookup(&gst, &xs, msg->tx.dsite_id);
    if (err) {
        hvfs_err(xnet, "Dest Site(%lx) unreachable.\n", msg->tx.dsite_id);
        return -EINVAL;
    }
retry:
    err = 0;
    list_for_each_entry(xa, &xs->addr, list) {
        if (!IS_CONNECTED(xa, xc)) {
            /* not connected, dynamic connect */
            /* Note that: we should serialize the connecting threads here! */
            xlock_lock(&xa->clock);
            if (!csock) {
                csock = socket(AF_INET, SOCK_STREAM, 0);
                if (csock < 0) {
                    hvfs_err(xnet, "socket() failed %d\n", errno);
                    err = -errno;
                    goto out;
                }
            }
            err = connect(csock, &xa->sa, sizeof(xa->sa));
            if (err < 0) {
                xlock_unlock(&xa->clock);
                hvfs_err(xnet, "connect() %s %d failed '%s' %d times\n",
                         inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                         ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                         strerror(errno), reconn);
                err = -errno;
                if (reconn < 10) {
                    reconn++;
                    sleep(1);
                    goto retry;
                }
                close(csock);
                goto out;
            } else {
                struct active_conn *ac;

            realloc:                
                ac = xzalloc(sizeof(struct active_conn));
                if (!ac) {
                    hvfs_err(xnet, "xzalloc() struct active_conn failed\n");
                    sleep(1);
                    goto realloc;
                }
                INIT_LIST_HEAD(&ac->list);
                ac->sockfd = csock;
                xlock_lock(&active_list_lock);
                list_add_tail(&ac->list, &active_list);
                xlock_unlock(&active_list_lock);

                /* yap, we have connected, following the current protocol, we
                 * should send a hello msg and recv a hello ack msg */
                {
                    struct xnet_msg_tx htx = {
                        .version = 0,
                        .len = sizeof(htx),
                        .type = XNET_MSG_HELLO,
                        .ssite_id = xc->site_id,
                        .dsite_id = msg->tx.dsite_id,
                    };
                    struct iovec __iov = {
                        .iov_base = &htx,
                        .iov_len = sizeof(htx),
                    };
                    struct msghdr __msg = {
                        .msg_iov = &__iov,
                        .msg_iovlen = 1,
                    };
                    int bt, br;

                    bt = sendmsg(csock, &__msg, MSG_NOSIGNAL);
                    if (bt < 0 || bt < sizeof(htx)) {
                        xlock_unlock(&xa->clock);
                        hvfs_err(xnet, "sendmsg do not support redo now(%s) "
                                 ":(\n", strerror(errno));
                        err = -errno;
                        close(csock);
                        csock = 0;
                        goto retry;
                    }
                    /* recv the hello ack in handle_tx thread */
                    br = 0;
                    do {
                        bt = recv(csock, (void *)&htx + br, sizeof(htx) - br,
                                  MSG_WAITALL);
                        if (bt < 0) {
                            if (errno == EAGAIN || errno == EINTR) {
                                sched_yield();
                                continue;
                            }
                            xlock_unlock(&xa->clock);
                            hvfs_err(xnet, "recv error: %s\n", strerror(errno));
                            close(csock);
                            csock = 0;
                            goto retry;
                        }
                        br += bt;
                    } while (br < sizeof(htx));
                }

                /* now, it is ok to push this socket to the epoll thread */
                setnonblocking(csock);
                setnodelay(csock);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = csock;
                err = epoll_ctl(epfd, EPOLL_CTL_ADD, csock, &ev);
                if (err < 0) {
                    xlock_unlock(&xa->clock);
                    hvfs_err(xnet, "epoll_ctl() add fd %d to SET(%d) "
                             "failed %d\n", 
                             csock, epfd, errno);
                    close(csock);
                    csock = 0;
                    sleep(1);
                    goto retry;
                }
                
                /* ok, it is ok to update this socket to the site table */
                err = st_update_sockfd(&gst, csock, msg->tx.dsite_id);
                if (err) {
                    xlock_unlock(&xa->clock);
                    /* do NOT remove from the epoll set, for pollin thread to
                     * tear down the connection */
                    st_clean_sockfd(&gst, csock);
                    csock = 0;
                    sleep(1);
                    goto retry;
                }

                hvfs_debug(xnet, "We just create connection %s %d -> fd %d\n",
                           inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                           ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                           csock);

                nr_conn++;
#if 0
                if (nr_conn < XNET_CONNS_DEF) {
                    csock = 0;
                    xlock_unlock(&xa->clock);
                    goto retry;
                }
#endif
            }
            found = 1;
            xlock_unlock(&xa->clock);
            break;
        } else {
            found = 1;
            if (csock)
                close(csock);
            break;
        }
    }

    if (!found) {
        hvfs_err(xnet, "Sorry, we can not find the target site %ld\n",
                 msg->tx.dsite_id);
        err = -EINVAL;
        goto out;
    }
    
    msg->tx.ssite_id = xc->site_id;
    if (msg->tx.type != XNET_MSG_RPY)
        msg->tx.handle = (u64)msg;
    ASSERT((u64)msg == msg->tx.handle, xnet);

reselect_conn:
    ssock = SELECT_CONNECTION(xa, &lock_idx);
    /* already connected, just send the message */
    hvfs_debug(xnet, "OK, select connection %d, we will send the msg "
               "site %lx -> %lx ...\n", ssock, 
               msg->tx.ssite_id, msg->tx.dsite_id);
    if (ssock < 0) {
        err = -EINVAL;
        goto out;
    }
    
#ifndef XNET_EAGER_WRITEV
    /* send the msg tx by the selected connection */
    bw = 0;
    do {
        bt = send(ssock, ((void *)&msg->tx) + bw, 
                  sizeof(struct xnet_msg_tx) - bw, MSG_MORE);
        if (bt < 0) {
            hvfs_err(xnet, "write() err %d\n", errno);
            if (errno == EINTR || errno == EAGAIN)
                continue;
            err = -errno;
            goto out_unlock;
        }
        bw += bt;
    } while (bw < sizeof(struct xnet_msg_tx));
    atomic64_add(bw, &g_xnet_prof.outbytes);
#endif

    /* then, send the data region */
    if (msg->siov_ulen) {
        hvfs_debug(xnet, "There is some data to send (iov_len %d) len %d.\n",
                   msg->siov_ulen, msg->tx.len);
#ifdef XNET_BLOCKING
        {
            struct msghdr __msg = {
                .msg_iov = msg->siov,
                .msg_iovlen = msg->siov_ulen,
            };

            bw = 0;
            do {
                bt = sendmsg(ssock, &__msg, MSG_NOSIGNAL);
                if (bt < 0 || msg->tx.len > bt) {
                    if (bt >= 0) {
                        /* ok, we should adjust the iov */
                        __iov_recal(msg->siov, &__msg.msg_iov, msg->siov_ulen,
                                    &__msg.msg_iovlen, bt + bw);
                        bw += bt;
                        continue;
                    } else if (errno == EINTR || errno == EAGAIN) {
                        continue;
                    }
                    hvfs_err(xnet, "sendmsg(%d[%lx],%d,%d) err %d, "
                             "for now we do support redo:)\n", 
                             ssock, msg->tx.dsite_id, bt,
                             msg->tx.len, 
                             errno);
                    if (errno == ECONNRESET || errno == EBADF || 
                        errno == EPIPE) {
                        /* select another link and resend the whole msg */
                        xlock_unlock(&xa->socklock[lock_idx]);
                        st_clean_sockfd(&gst, ssock);
                        hvfs_err(xnet, "Reselect Conn [%d] --> ?\n", ssock);
                        goto reselect_conn;
                    }
                    err = -errno;
                    goto out_unlock;
                }
                bw += bt;
            } while (bw < msg->tx.len);
            atomic64_add(bt, &g_xnet_prof.outbytes);
        }
#elif 1
        bt = writev(ssock, msg->siov, msg->siov_ulen);
        if (bt < 0 || msg->tx.len > bt) {
            hvfs_err(xnet, "writev(%d[%lx]) err %d, for now we do not "
                     "support redo:(\n", ssock, msg->tx.dsite_id,
                     errno);
            err = -errno;
            goto out_unlock;
        }
        atomic64_add(bt, &g_xnet_prof.outbytes);
#else
        int i;

        for (i = 0; i < msg->siov_ulen; i++) {
            bw = 0;
            do {
                bt = write(ssock, msg->siov[i].iov_base + bw, 
                           msg->siov[i].iov_len - bw);
                if (bt < 0) {
                    hvfs_err(xnet, "write() err %d\n", errno);
                    if (errno == EINTR || errno == EAGAIN)
                        continue;
                    err = -errno;
                    goto out_unlock;
                }
                bw += bt;
            } while (bw < msg->siov[i].iov_len);
            atomic64_add(bw, &g_xnet_prof.outbytes);
        }
#endif
    }

    xlock_unlock(&xa->socklock[lock_idx]);

    hvfs_debug(xnet, "We have sent the msg %p throuth link %d\n", msg, ssock);

out:
    return err;
out_unlock:
    xlock_unlock(&xa->socklock[lock_idx]);
    return err;
}

/* xnet_send()
 */
int xnet_send(struct xnet_context *xc, struct xnet_msg *msg)
{
    struct epoll_event ev;
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int err = 0, csock = 0, found = 0, reconn = 0;
    int ssock = 0;              /* selected socket */
    int nr_conn = 0;
    int lock_idx = 0;
    int __attribute__((unused))bw, bt;

    if (msg->tx.ssite_id == msg->tx.dsite_id) {
        hvfs_err(xnet, "Warning: target site is the original site, BYPASS?\n");
    }

    if (msg->tx.flag & XNET_NEED_RESEND ||
        msg->tx.flag & XNET_NEED_REPLY) {
        /* add to the resend queue */
        msg->ts = time(NULL);
        msg->xc = xc;
        xlock_lock(&xc->resend_lock);
        list_add_tail(&msg->list, &xc->resend_q);
        atomic_inc(&msg->ref);
        xlock_unlock(&xc->resend_lock);
    }

    err = st_lookup(&gst, &xs, msg->tx.dsite_id);
    if (err) {
        hvfs_err(xnet, "Dest Site(%lx) unreachable.\n", msg->tx.dsite_id);
        return -EINVAL;
    }
retry:
    err = 0;
    list_for_each_entry(xa, &xs->addr, list) {
        if (!IS_CONNECTED(xa, xc)) {
            /* not connected, dynamic connect */
            if (!csock) {
                csock = socket(AF_INET, SOCK_STREAM, 0);
                if (csock < 0) {
                    hvfs_err(xnet, "socket() failed %d\n", errno);
                    err = -errno;
                    goto out;
                }
            }
            err = connect(csock, &xa->sa, sizeof(xa->sa));
            if (err < 0) {
                hvfs_err(xnet, "connect() %s %d failed '%s' %d times\n",
                         inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                         ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                         strerror(errno), reconn);
                err = -errno;
                if (reconn < 10) {
                    reconn++;
                    sleep(1);
                    goto retry;
                }
                close(csock);
                goto out;
            } else {
                struct active_conn *ac;

            realloc:                
                ac = xzalloc(sizeof(struct active_conn));
                if (!ac) {
                    hvfs_err(xnet, "xzalloc() struct active_conn failed\n");
                    sleep(1);
                    goto realloc;
                }
                INIT_LIST_HEAD(&ac->list);
                ac->sockfd = csock;
                xlock_lock(&active_list_lock);
                list_add_tail(&ac->list, &active_list);
                xlock_unlock(&active_list_lock);

                /* yap, we have connected, following the current protocol, we
                 * should send a hello msg and recv a hello ack msg */
                {
                    struct xnet_msg_tx htx = {
                        .version = 0,
                        .len = sizeof(htx),
                        .type = XNET_MSG_HELLO,
                        .ssite_id = xc->site_id,
                        .dsite_id = msg->tx.dsite_id,
                    };
                    struct iovec __iov = {
                        .iov_base = &htx,
                        .iov_len = sizeof(htx),
                    };
                    struct msghdr __msg = {
                        .msg_iov = &__iov,
                        .msg_iovlen = 1,
                    };
                    int bt, br;

                    bt = sendmsg(csock, &__msg, MSG_NOSIGNAL);
                    if (bt < 0 || bt < sizeof(htx)) {
                        hvfs_err(xnet, "sendmsg do not support redo now(%s) "
                                 ":(\n", strerror(errno));
                        err = -errno;
                        close(csock);
                        csock = 0;
                        goto retry;
                    }
                    /* recv the hello ack in handle_tx thread */
                    br = 0;
                    do {
                        bt = recv(csock, (void *)&htx + br, sizeof(htx) - br,
                                  MSG_WAITALL);
                        if (bt < 0) {
                            if (errno == EAGAIN || errno == EINTR) {
                                sched_yield();
                                continue;
                            }
                            hvfs_err(xnet, "recv error: %s\n", strerror(errno));
                            close(csock);
                            csock = 0;
                            goto retry;
                        }
                        br += bt;
                    } while (br < sizeof(htx));
                }

                /* now, it is ok to push this socket to the epoll thread */
                setnonblocking(csock);
                setnodelay(csock);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = csock;
                err = epoll_ctl(epfd, EPOLL_CTL_ADD, csock, &ev);
                if (err < 0) {
                    hvfs_err(xnet, "epoll_ctl() add fd %d to SET(%d) "
                             "failed %d\n", 
                             csock, epfd, errno);
                    close(csock);
                    csock = 0;
                    sleep(1);
                    goto retry;
                }
                
                /* ok, it is ok to update this socket to the site table */
                err = st_update_sockfd(&gst, csock, msg->tx.dsite_id);
                if (err) {
                    /* do NOT remove from the epoll set, for pollin thread to
                     * tear down the connection */
                    st_clean_sockfd(&gst, csock);
                    csock = 0;
                    sleep(1);
                    goto retry;
                }

                hvfs_debug(xnet, "We just create connection %s %d -> fd %d\n",
                           inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                           ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                           csock);

                nr_conn++;
#if 0                           /* Note that: the following section is used to
                                 * generate heavy connect load */
                if (nr_conn < XNET_CONNS_DEF) {
                    csock = 0;
                    goto retry;
                }
#endif
            }
            found = 1;
            break;
        } else {
            found = 1;
            if (csock)
                close(csock);
            break;
        }
    }

    if (!found) {
        hvfs_err(xnet, "Sorry, we can not find the target site %ld\n",
                 msg->tx.dsite_id);
        err = -EINVAL;
        goto out;
    }
    
    msg->tx.ssite_id = xc->site_id;
    if (msg->tx.type == XNET_MSG_REQ)
        msg->tx.reqno = atomic_inc_return(&global_reqno);
    if (msg->tx.type != XNET_MSG_RPY)
        msg->tx.handle = (u64)msg;

reselect_conn:
    ssock = SELECT_CONNECTION(xa, &lock_idx);
    /* already connected, just send the message */
    hvfs_debug(xnet, "OK, select connection %d, we will send the msg "
               "site %lx -> %lx ...\n", ssock, 
               msg->tx.ssite_id, msg->tx.dsite_id);
    if (ssock < 0) {
        err = -EINVAL;
        goto out;
    }
    
#ifndef XNET_EAGER_WRITEV
    /* send the msg tx by the selected connection */
    bw = 0;
    do {
        bt = send(ssock, ((void *)&msg->tx) + bw, 
                  sizeof(struct xnet_msg_tx) - bw, MSG_MORE);
        if (bt < 0) {
            hvfs_err(xnet, "write() err %d\n", errno);
            if (errno == EINTR || errno == EAGAIN)
                continue;
            err = -errno;
            goto out_unlock;
        }
        bw += bt;
    } while (bw < sizeof(struct xnet_msg_tx));
    atomic64_add(bw, &g_xnet_prof.outbytes);
#endif

    /* then, send the data region */
    if (msg->siov_ulen) {
        hvfs_debug(xnet, "There is some data to send (iov_len %d) len %d.\n",
                   msg->siov_ulen, msg->tx.len);
#ifdef XNET_BLOCKING
        {
            struct msghdr __msg = {
                .msg_iov = msg->siov,
                .msg_iovlen = msg->siov_ulen,
            };

            bw = 0;
            do {
                bt = sendmsg(ssock, &__msg, MSG_NOSIGNAL);
                if (bt < 0 || msg->tx.len > bt) {
                    if (bt >= 0) {
                        /* ok, we should adjust the iov */
                        __iov_recal(msg->siov, &__msg.msg_iov, msg->siov_ulen,
                                    &__msg.msg_iovlen, bt + bw);
                        bw += bt;
                        continue;
                    } else if (errno == EINTR || errno == EAGAIN) {
                        continue;
                    }
                    hvfs_err(xnet, "sendmsg(%d[%lx],%d,%d) err %d, "
                             "for now we do support redo:)\n", 
                             ssock, msg->tx.dsite_id, bt,
                             msg->tx.len, 
                             errno);
                    if (errno == ECONNRESET || errno == EBADF || 
                        errno == EPIPE) {
                        /* select another link and resend the whole msg */
                        xlock_unlock(&xa->socklock[lock_idx]);
                        st_clean_sockfd(&gst, ssock);
                        hvfs_err(xnet, "Reselect Conn [%d] --> ?\n", ssock);
                        goto reselect_conn;
                    }
                    err = -errno;
                    goto out_unlock;
                }
                bw += bt;
            } while (bw < msg->tx.len);
            atomic64_add(bt, &g_xnet_prof.outbytes);
        }
#elif 1
        bt = writev(ssock, msg->siov, msg->siov_ulen);
        if (bt < 0 || msg->tx.len > bt) {
            hvfs_err(xnet, "writev(%d[%lx]) err %d, for now we do not "
                     "support redo:(\n", ssock, msg->tx.dsite_id,
                     errno);
            err = -errno;
            goto out_unlock;
        }
        atomic64_add(bt, &g_xnet_prof.outbytes);
#else
        int i;

        for (i = 0; i < msg->siov_ulen; i++) {
            bw = 0;
            do {
                bt = write(ssock, msg->siov[i].iov_base + bw, 
                           msg->siov[i].iov_len - bw);
                if (bt < 0) {
                    hvfs_err(xnet, "write() err %d\n", errno);
                    if (errno == EINTR || errno == EAGAIN)
                        continue;
                    err = -errno;
                    goto out_unlock;
                }
                bw += bt;
            } while (bw < msg->siov[i].iov_len);
            atomic64_add(bw, &g_xnet_prof.outbytes);
        }
#endif
    }

    xlock_unlock(&xa->socklock[lock_idx]);

    hvfs_debug(xnet, "We have sent the msg %p throuth link %d\n", msg, ssock);

    /* finally, we wait for the reply msg */
    if (msg->tx.flag & XNET_NEED_REPLY) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += g_xnet_conf.send_timeout;
    rewait:
        err = sem_timedwait(&msg->event, &ts);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else if (errno == ETIMEDOUT) {
                err = -ETIMEDOUT;
            } else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }

        /* Haaaaa, we got the reply now */
        hvfs_debug(xnet, "We(%p) got the reply msg %p.\n", msg, msg->pair);
    }
    
out:
    return err;
out_unlock:
    xlock_unlock(&xa->socklock[lock_idx]);
    return err;
}

void xnet_wait_any(struct xnet_context *xc)
{
    int err;
retry:
    err = sem_wait(&xc->wait);
    if (err < 0) {
        if (errno == EINTR)
            goto retry;
    }
}

int xnet_msg_add_sdata(struct xnet_msg *msg, void *buf, int len)
{
    int err = 0;
    
    if (!msg->siov_alen) {
        /* first access, alloc some entries */
        msg->siov = xzalloc(sizeof(struct iovec) * g_xnet_conf.siov_nr);
        if (!msg->siov) {
            err = -ENOMEM;
            goto out;
        }
        msg->siov_alen = g_xnet_conf.siov_nr;
    }
    if (unlikely(msg->siov_alen == msg->siov_ulen)) {
        hvfs_err(xnet, "For now, we do not support iovec expanding!\n");
        ASSERT(0, xnet);
    }
    msg->siov[msg->siov_ulen].iov_base = buf;
    msg->siov[msg->siov_ulen].iov_len = len;
    msg->siov_ulen++;
    msg->tx.len += len;

out:
    return err;
}

void xnet_msg_free_sdata(struct xnet_msg *msg)
{
    int i;
    
    if (!msg->siov_alen || !msg->siov_ulen)
        return;
    if (!msg->siov) {
        hvfs_warning(xnet, "XNET IOV operation internal error.\n");
        return;
    }
    for (i = 0; i < msg->siov_ulen; i++) {
#ifdef XNET_EAGER_WRITEV
        if (!i)
            continue;
#endif
        ASSERT(msg->siov[i].iov_base, xnet);
        xfree(msg->siov[i].iov_base);
    }
    xfree(msg->siov);
}

int xnet_msg_add_rdata(struct xnet_msg *msg, void *buf, int len)
{
    int err = 0;
    
    if (!msg->riov_alen) {
        /* first access, alloc some entries */
        msg->riov = xzalloc(sizeof(struct iovec) * 10);
        if (!msg->riov) {
            err = -ENOMEM;
            goto out;
        }
        msg->riov_alen = 10;
    }
    if (unlikely(msg->riov_alen == msg->riov_ulen)) {
        hvfs_err(xnet, "For now, we do not support iovec expanding!\n");
        ASSERT(0, xnet);
    }
    msg->riov[msg->riov_ulen].iov_base = buf;
    msg->riov[msg->riov_ulen].iov_len = len;
    msg->riov_ulen++;

out:
    return err;
}

void xnet_msg_free_rdata(struct xnet_msg *msg)
{
    int i;
    
    if (!msg->riov_alen || !msg->riov_ulen)
        return;
    if (!msg->riov) {
        hvfs_warning(xnet, "XNET IOV operation internal error.\n");
        return;
    }
    for (i = 0; i < msg->riov_ulen; i++) {
        ASSERT(msg->riov[i].iov_base, xnet);
        xfree(msg->riov[i].iov_base);
    }
    xfree(msg->riov);
}

int xnet_isend(struct xnet_context *xc, struct xnet_msg *msg)
{
    return xnet_send(xc, msg);
}

int xnet_wait_group_add(void *gwg, struct xnet_msg *msg)
{
    return -ENOSYS;
}

int xnet_wait_group_del(void *gwg, struct xnet_msg *msg)
{
    return -ENOSYS;
}

/* Note that the following region is used to convert the standard R2 site
 * table to the st_table used in xnet, it is a little urgly :( */
int xnet_add_ipaddr(u64 site_id, int argc, struct hvfs_addr_tx *hat)
{
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int err = 0;
    int i;

    if (!argc)
        return 0;

    xa = xzalloc(argc * sizeof(struct xnet_addr));
    if (!xa) {
        hvfs_err(xnet, "xzalloc() xnet_addr failed\n");
        return -ENOMEM;
    }

    /* lookup it or create it */
    err = st_lookup(&gst, &xs, site_id);
    if (err) {
        hvfs_err(xnet, "lookup site %lx failed w/ %d\n", site_id, err);
        xs = xzalloc(sizeof(*xs));
        if (!xs) {
            hvfs_err(xnet, "xzalloc() xnet_site failed\n");
            xfree(xa);
            return -ENOMEM;
        }
    }

    for (i = 0; i < argc; i++) {
        (xa + i)->sa = (hat + i)->sock.sa;
    }

    /* set the local flag now */
    if (__find_xc(site_id)) {
        xs->flag |= XNET_SITE_LOCAL;
    }
    INIT_LIST_HEAD(&xs->addr);
    INIT_LIST_HEAD(&xa->list);
    for (i = 0; i < XNET_CONNS; i++) {
        xlock_init(&xa->socklock[i]);
    }
    xlock_init(&xa->lock);
    list_add_tail(&xa->list, &xs->addr);
    st_update(&gst, xs, site_id);

    i = st_lookup(&gst, &xs, site_id);
    hvfs_debug(xnet, "Update site %lx w/ %d\n", site_id, i);

    return 0;
}

int xnet_del_ipaddr(u64 site_id, int argc, struct hvfs_addr_tx *hat)
{
    struct xnet_site *xs;
    struct xnet_addr *xa, *n;
    int err = 0, i, should_free;

    if (!argc)
        return 0;

    err = st_lookup(&gst, &xs, site_id);
    if (err) {
        hvfs_err(xnet, "lookup site %lx failed w/ %d\n", site_id, err);
        goto out;
    }
    list_for_each_entry_safe(xa, n, &xs->addr, list) {
        struct sockaddr_in *sin0 = (struct sockaddr_in *)&xa->sa;

        should_free = 0;
        xlock_lock(&xa->lock);
        for (i = 0; i < argc; i++) {
            struct sockaddr_in *sin1 = (struct sockaddr_in *)
                &(hat + i)->sock.sa;
            if (sin0->sin_addr.s_addr == sin1->sin_addr.s_addr &&
                sin0->sin_port == sin1->sin_port) {
                /* ok, find it */
                list_del(&xa->list);
                should_free = 1;
                break;
            }
        }
        xlock_unlock(&xa->lock);
        if (should_free)
            xfree(xa);
    }
    
out:
    return err;
}

int xnet_replace_ipaddr(u64 site_id, int argc, struct hvfs_addr_tx *hat)
{
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int i;

    if (!argc)
        return 0;

    xa = xzalloc(argc * sizeof(struct xnet_addr));
    if (!xa) {
        hvfs_err(xnet, "xzalloc() xnet_addr failed\n");
        return -ENOMEM;
    }

    xs = xzalloc(sizeof(*xs));
    if (!xs) {
        hvfs_err(xnet, "xzalloc() xnet_site failed\n");
        xfree(xa);
        return -ENOMEM;
    }

    for (i = 0; i < argc; i++) {
        (xa + i)->sa = (hat + i)->sock.sa;
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)
                &(xa + i)->sa;
            
            hvfs_err(xnet, "site %lx addr %s %d\n", site_id, 
                     inet_ntoa(sin->sin_addr),
                     ntohs(sin->sin_port));
        }
    }

    /* set the local flag now */
    if (__find_xc(site_id)) {
        xs->flag |= XNET_SITE_LOCAL;
    }
    INIT_LIST_HEAD(&xs->addr);
    INIT_LIST_HEAD(&xa->list);
    for (i = 0; i < XNET_CONNS; i++) {
        xlock_init(&xa->socklock[i]);
    }
    xlock_init(&xa->lock);
    list_add_tail(&xa->list, &xs->addr);
    st_update(&gst, xs, site_id);

    i = st_lookup(&gst, &xs, site_id);
    hvfs_debug(xnet, "Update site %lx w/ %d\n", site_id, i);

    return 0;
}

int hst_to_xsst(void *data, int len)
{
    struct hvfs_site_tx *hst = (struct hvfs_site_tx *)data;
    void *end = data + len;
    int err = 0;
    
    while ((void *)hst < end) {
        switch (hst->flag) {
        case HVFS_SITE_REPLACE:
            err = xnet_replace_ipaddr(hst->site_id, hst->nr, hst->addr);
            if (err) {
                hvfs_err(xnet, "replace ipaddr2 failed w/ %d\n", err);
                continue;
            }
            break;
        case HVFS_SITE_ADD:
            err = xnet_add_ipaddr(hst->site_id, hst->nr, hst->addr);
            if (err) {
                hvfs_err(xnet, "add ipaddr2 failed w/ %d\n", err);
                continue;
            }
            break;
        case HVFS_SITE_DEL:
            err = xnet_del_ipaddr(hst->site_id, hst->nr, hst->addr);
            if (err) {
                hvfs_err(xnet, "del ipaddr2 failed w. %d\n", err);
                continue;
            }
            break;
        default:
            hvfs_err(xnet, "Invalid op flag %x\n", hst->flag);
        }
        hst = (void *)hst + sizeof(*hst) + 
            hst->nr * sizeof(struct hvfs_addr_tx);
        
    }

    return err;
}

#endif
