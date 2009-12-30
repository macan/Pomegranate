/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-30 21:45:24 macan>
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

/*
 * NOTE: this file is a simple single-host implementation of XNET. We use TCP
 * sockets, so we can easily extend the framework to multi-host systems.
 */

#ifdef USE_XNET_SIMPLE
/* First, how do we handle the site_id to ip address translation?
 */
struct xnet_addr
{
    struct list_head list;
    struct sockaddr sa;
    int sockfd;
};
struct xnet_site
{
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
};

struct site_table gst;
pthread_t pollin_thread;        /* poll-in any requests */
struct list_head accept_list;   /* recored the accepted sockets */
int lsock = 0;                  /* local listening socket */
int epfd = 0;
int pollin_thread_stop = 0;
int global_reqno = 0;
LIST_HEAD(global_xc_list);

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


int st_update_sockfd(struct site_table *st, struct sockaddr_in *sin, int fd);

/* __xnet_handle_tx()
 *
 * NOTE: this function should try to read from this socket hardly, until the
 * whole message is returned. At this point, we should try to read from the
 * socket either. Until EAGAIN returned, we must try to read deeply.
 */
int __xnet_handle_tx(int fd)
{
    struct xnet_msg *msg, *req;
    int br, bt;
    int next = 1;               /* this means we should retry the read */

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* FIXME: we should put this fd in the retry queue */
        return next;
    }

    /* receive the tx */
    br = 0;
    do {
        bt = read(fd, ((void *)&msg->tx) + br, 
                  sizeof(struct xnet_msg_tx) - br);
        if (bt < 0) {
            if (errno == EAGAIN && !br) {
                /* pseudo calling, just return */
                next = 0;
                goto out_free;
            }
            hvfs_err(xnet, "read() err %d\n", errno);
            if (errno == EAGAIN || errno == EINTR)
                continue;
            /* FIXME: how to handle this err? */
            ASSERT(0, xnet);
        } else if (bt == 0) {
            /* hoo, we got the EOF of the socket stream */
            next = -1;
            goto out_free;
        }
        br += bt;
    } while (br < sizeof(struct xnet_msg_tx));

    hvfs_info(xnet, "We have recieved the TX\n");

    /* receive the data if exists */
    if (msg->tx.len) {
        /* we should pre-alloc the buffer */
        void *buf = xmalloc(msg->tx.len);
        if (!buf) {
            hvfs_err(xnet, "xmalloc() buffer failed\n");
            goto out_free;
        }
        br = 0;
        do {
            bt = read(fd, buf + br, msg->tx.len - br);
            if (bt < 0) {
                hvfs_err(xnet, "read() err %d\n", errno);
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                ASSERT(0, xnet);
            } else if (bt == 0) {
                next = -1;
                goto out_free;
            }
            br += bt;
        } while (br < msg->tx.len);

        /* add the data to the riov */
        xnet_msg_add_rdata(msg, buf, br);
    }
    
    /* find the related msg */
    if (msg->tx.type == XNET_MSG_REQ) {
        /* this is a fresh requst msg, just receive the data */
        struct xnet_context *xc;

        xc = __find_xc(msg->tx.dsite_id);
        if (!xc) {
            /* just return, nobody cares this msg */
            goto out_free;
        } else {
            sem_post(&xc->wait);
        }
        hvfs_info(xnet, "We got a REQ message\n");
        if (xc->ops.recv_handler)
            xc->ops.recv_handler(msg);
    } else if (msg->tx.type == XNET_MSG_RPY) {
        /* we should find the original request by handle */
        hvfs_info(xnet, "We got a RPY message, handle to msg %p\n", 
                  (void *)msg->tx.handle);
        req = (struct xnet_msg *)msg->tx.handle;
        req->pair = msg;

        sem_post(&req->event);
    } else if (msg->tx.type == XNET_MSG_CMD) {
        /* just receive the data */
    } else if (msg->tx.type == XNET_MSG_NOP) {
        hvfs_info(xnet, "recv NOP message, just receive the next msg.\n");
    }

    return next;
out_free:
    xfree(msg);
    return next;
}

void *pollin_thread_main(void *arg)
{
    struct epoll_event ev, events[10];
    struct sockaddr_in addr = {0,};
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct accept_conn *ac;
    int asock, i;
    int err, nfds;
    
    INIT_LIST_HEAD(&accept_list);
    err = epoll_create(100);
    if (err < 0) {
        hvfs_err(xnet, "epoll_create1() failed %d\n", errno);
        err = -errno;
        goto out;
    }
    epfd = err;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = lsock;
    err = epoll_ctl(epfd, EPOLL_CTL_ADD, lsock, &ev);
    if (err < 0) {
        hvfs_err(xnet, "epoll_ctl() add fd %d failed %d\n", lsock, errno);
        err = -errno;
        goto out;
    }
    
    hvfs_info(xnet, "POLL-IN thread running, waiting for any request in...\n");
    for (; !pollin_thread_stop;) {
        nfds = epoll_wait(epfd, events, 10, 50);
        if (nfds == -1) {
            hvfs_err(xnet, "epoll_wait() failed %d\n", errno);
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
                st_update_sockfd(&gst, &addr, asock);
                
                setnonblocking(asock);
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
                hvfs_info(xnet, "RECV from fd %d.......\n", events[i].data.fd);
                if (events[i].events & EPOLLERR) {
                    hvfs_err(xnet, "Hoo, the connection %d is broken.\n",
                             events[i].data.fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                    continue;
                }
                do {
                    next = __xnet_handle_tx(events[i].data.fd);
                    if (next < 0) {
                        /* this means the connection is shutdown */
                        hvfs_debug(xnet, "connection %d is shutdown.\n",
                                   events[i].data.fd);
                        epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
                        break;
                    }
                } while (next);
            }
        }
    }

out:
    return ERR_PTR(err);
}

int st_init(void)
{
    memset(&gst, 0, sizeof(gst));
    
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
    *xs = st->site[site_id];
    if (!(*xs)) {
        hvfs_debug(xnet, "The site_id(%ld) is not mapped.\n", site_id);
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
    if (t)
        xfree(t);
    return 0;
}

int st_update_sockfd(struct site_table *st, struct sockaddr_in *sin, int fd)
{
    struct xnet_addr *xa;
    int i;

    for (i = 0; i < (1 << 20); i++) {
        if (st->site[i]) {
            list_for_each_entry(xa, &st->site[i]->addr, list) {
                if ((((struct sockaddr_in *)&xa->sa)->sin_addr.s_addr == 
                     sin->sin_addr.s_addr)) {
                    /* ok, find it */
                    hvfs_info(xnet, "Hoo, find it @ %d <- %d.\n", i, fd);
                    xa->sockfd = fd;
                    ((struct sockaddr_in *)&xa->sa)->sin_port = sin->sin_port;
                }
            }
        }
    }

    return 0;
}

int xnet_update_ipaddr(u64 site_id, int argc, char *ipaddr[], short port[])
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
        inet_aton(ipaddr[i], &((struct sockaddr_in *)&(xa->sa))->sin_addr);
        ((struct sockaddr_in *)&(xa->sa))->sin_family = AF_INET;
        ((struct sockaddr_in *)&(xa->sa))->sin_port = htons(port[i]);
    }

    INIT_LIST_HEAD(&xs->addr);
    INIT_LIST_HEAD(&xa->list);
    list_add_tail(&xa->list, &xs->addr);
    st_update(&gst, xs, site_id);
    
    return 0;
}

struct xnet_context *xnet_register_type(u8 type, u16 port, u64 site_id,
                                        struct xnet_type_ops *ops)
{
    struct xnet_context *xc;
    struct sockaddr addr;
    struct sockaddr_in *ia = (struct sockaddr_in *)&addr;
    int val = 1;
    int err;

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

    err = listen(lsock, 10);
    if (err < 0) {
        hvfs_err(xnet, "listen() failed %d\n", errno);
        err = -errno;
        goto out_close;
    }
    
    hvfs_info(xnet, "Listener start @ %s %d\n", inet_ntoa(ia->sin_addr),
              port);
    
    /* we should create one thread to accept connections */
    err = pthread_create(&pollin_thread, NULL, pollin_thread_main, NULL);
    if (err) {
        hvfs_err(xnet, "pthread_create() failed %d\n", err);
        goto out_close;
    }
    
    hvfs_info(xnet, "Poll-in thread created.\n");

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
    pthread_join(pollin_thread, NULL);
    
    sem_destroy(&xc->wait);

    if (xc)
        xfree(xc);
    if (lsock)
        close(lsock);
    return 0;
}

/* xnet_send()
 */
int xnet_send(struct xnet_context *xc, struct xnet_msg *msg)
{
    struct epoll_event ev;
    struct xnet_site *xs;
    struct xnet_addr *xa;
    int err = 0, csock = 0, found = 0, reconn = 0;
    int bw, bt;
    
    st_lookup(&gst, &xs, msg->tx.dsite_id);
retry:
    list_for_each_entry(xa, &xs->addr, list) {
        if (!xa->sockfd) {
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
                hvfs_err(xnet, "connect() %s %d failed %d\n",
                         inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                         ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                         errno);
                err = -errno;
                if (reconn < 10) {
                    reconn++;
                    sleep(1);
                    goto retry;
                }
                close(csock);
                goto out;
            } else {
                struct accept_conn *ac;

            realloc:                
                ac = xzalloc(sizeof(struct accept_conn));
                if (!ac) {
                    hvfs_err(xnet, "xzalloc() struct accept_conn failed\n");
                    sleep(1);
                    goto realloc;
                }
                INIT_LIST_HEAD(&ac->list);
                ac->sockfd = csock;
                list_add_tail(&ac->list, &accept_list);
                st_update_sockfd(&gst, (struct sockaddr_in *)&xa->sa, csock);
                
                setnonblocking(csock);
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = csock;
                err = epoll_ctl(epfd, EPOLL_CTL_ADD, csock, &ev);
                if (err < 0) {
                    hvfs_err(xnet, "epoll_ctl() add fd %d failed %d\n",
                             csock, errno);
                    err = -errno;
                    goto out;
                }
                
                hvfs_debug(xnet, "We just create connection %s %d -> fd %d\n",
                           inet_ntoa(((struct sockaddr_in *)&xa->sa)->sin_addr),
                           ntohs(((struct sockaddr_in *)&xa->sa)->sin_port), 
                           csock);
            }
            xa->sockfd = csock;
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
    msg->tx.reqno = global_reqno++;
    if (msg->tx.type != XNET_MSG_RPY)
        msg->tx.handle = (u64)msg;

    /* already connected, just send the message */
    hvfs_info(xnet, "OK, select connection %d, we will send the msg "
              "site %ld -> %ld ...\n", xa->sockfd, 
              msg->tx.ssite_id, msg->tx.dsite_id);
    
    /* send the msg tx by the selected connection */
    bw = 0;
    do {
        bt = write(xa->sockfd, ((void *)&msg->tx) + bw, 
                   sizeof(struct xnet_msg_tx) - bw);
        if (bt < 0) {
            hvfs_err(xnet, "write() err %d\n", errno);
            if (errno == EINTR || errno == EAGAIN)
                continue;
            err = -errno;
            goto out;
        }
        bw += bt;
    } while (bw < sizeof(struct xnet_msg_tx));

    /* then, send the data region */
    if (msg->siov_ulen) {
        hvfs_info(xnet, "There is some data to send ...\n");
        int i;
        for (i = 0; i < msg->siov_ulen; i++) {
            do {
                bw = 0;
                bt = write(xa->sockfd, msg->siov[i].iov_base + bw, 
                           msg->siov[i].iov_len - bw);
                if (bt < 0) {
                    hvfs_err(xnet, "write() err %d\n", errno);
                    if (errno == EINTR || errno == EAGAIN)
                        continue;
                    err = -errno;
                    goto out;
                }
                bw += bt;
            } while (bt < msg->siov[i].iov_len);
        }
    }

    hvfs_info(xnet, "We have sent the msg %p\n", msg);

    /* finally, we wait for the reply msg */
    if (msg->tx.flag & XNET_NEED_REPLY) {
        sem_init(&msg->event, 0, 0);
    rewait:
        err = sem_wait(&msg->event);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }

        /* Haaaaa, we got the reply now */
        hvfs_info(xnet, "We(%p) got the reply msg %p.\n", msg, msg->pair);
    }
    
out:
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
        msg->siov = xzalloc(sizeof(struct iovec) * 10);
        if (!msg->siov) {
            err = -ENOMEM;
            goto out;
        }
        msg->siov_alen = 10;
    }
    if (msg->siov_alen == msg->siov_ulen) {
        hvfs_err(xnet, "For now, we do not support iovec expanding!\n");
        ASSERT(0, xnet);
    }
    msg->siov[msg->siov_ulen].iov_base = buf;
    msg->siov[msg->siov_ulen].iov_len = len;
    msg->siov_ulen++;

out:
    return err;
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
    if (msg->riov_alen == msg->riov_ulen) {
        hvfs_err(xnet, "For now, we do not support iovec expanding!\n");
        ASSERT(0, xnet);
    }
    msg->riov[msg->riov_ulen].iov_base = buf;
    msg->riov[msg->riov_ulen].iov_len = len;
    msg->riov_ulen++;

out:
    return err;
}
#endif
