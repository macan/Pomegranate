/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-30 21:36:20 macan>
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

#ifdef UNIT_TEST
char *ipaddr1[] = {
    "10.10.111.117",
};

char *ipaddr2[] = {
    "10.10.111.9",
};

short port1[] = {
    8412,
};

short port2[] = {
    8210,
};

struct xnet_context *xc = NULL;

/* This function just return one reply message
 */
int xnet_test_handler(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        return -ENOMEM;
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, 
                     msg->tx.dsite_id, msg->tx.ssite_id);
    rpy->tx.handle = msg->tx.handle;

    xnet_send(xc, rpy);
    
    return 0;
}

int main(int argc, char *argv[])
{
    struct xnet_msg *msg;
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = xnet_test_handler,
    };
    int err = 0;
    int dsite;
    short port;

    hvfs_info(xnet, "XNET Simple UNIT TESTing ...\n");

    if (argc == 2) {
        port = 8210;
        dsite = 0;
    } else {
        port = 8412;
        dsite = 1;
    }

    mds_init(10);

    st_init();
    xc = xnet_register_type(0, port, !dsite, &ops);
    if (IS_ERR(xc)) {
        err = PTR_ERR(xc);
        goto out;
    }

    xnet_update_ipaddr(0, 1, ipaddr1, port1);
    xnet_update_ipaddr(1, 1, ipaddr2, port2);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_unreg;
    }

    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE | 
                     XNET_NEED_REPLY, !dsite, dsite);

    if (dsite)
        xnet_send(xc, msg);
    else
        xnet_wait_any(xc);
    
out_unreg:
    xnet_unregister_type(xc);
    st_destroy();

    mds_destroy();
out:
    return err;
}
#endif
