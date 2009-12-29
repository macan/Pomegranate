/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-29 17:03:33 macan>
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

struct site_table gst;
int lsock;                      /* local listening socket */

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

int xnet_update_ipaddr(u64 site_id, int argc, char *ipaddr[], short port[])
{
    struct xnet_addr *xa;
    int i;

    if (!argc)
        return 0;
    
    xa = xzalloc(argc * sizeof(struct xnet_addr));
    if (!xa) {
        hvfs_err(xnet, "xzalloc() xnet_addr failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < argc; i++) {
        inet_aton(ipaddr[i], &((struct sockaddr_in *)&(xa->sa))->sin_addr);
        ((struct sockaddr_in *)&(xa->sa))->sin_family = AF_INET;
        ((struct sockaddr_in *)&(xa->sa))->sin_port = htons(port[i]);
    }

    return 0;
}

struct xnet_context *xnet_register_type(u8 type, u16 port, 
                                        struct xnet_type_ops *ops)
{
    struct xnet_context *xc;
    int err;

    xc = xzalloc(sizeof(*xc));
    if (!xc) {
        hvfs_err(xnet, "xzalloc() xnet_context failed\n");
        return ERR_PTR(-ENOMEM);
    }

    xc->type = type;
    xc->ops = ops;
    xc->service_port = port;

    /* ok, let us create the listening socket now */
    err = socket(AF_INET, SOCK_STREAM, 0);
    if (err < 0) {
        hvfs_err(xnet, "socket() failed %d\n", errno);
        err = -errno;
        goto out_free;
    }
    lsock = err;

    /* FIXME: it is ok to bind and listen now */

    return xc;
out_free:
    xfree(xc);
    return ERR_PTR(err);
}

int xnet_unregister_type(struct xnet_context *xc)
{
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
    return -ENOSYS;
}
#endif
