/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-29 10:37:53 macan>
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
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

char *ipaddr[] = {
    "10.10.111.9",              /* server */
    "10.10.111.90",

    "10.10.111.9",              /* client */
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.9",
    "10.10.111.91",             /* 8 */
    "10.10.111.92",
    "10.10.111.93",
    "10.10.111.94",
};

short port[] = {
    8210,                       /* server */
    5410,

    8412,                       /* client */
    8413,
    8414,
    8415,
    8416,
    8417,
    8418,
    8419,
    5411,
    5411,
    5411,
    5411,
};

#define HVFS_TYPE(type, idx) ({                 \
            u64 __sid = -1UL;                   \
            switch (type){                      \
            case TYPE_MDS:                      \
                __sid = HVFS_MDS(idx);          \
                break;                          \
            case TYPE_CLIENT:                   \
                __sid = HVFS_CLIENT(idx);       \
                break;                          \
            case TYPE_MDSL:                     \
                __sid = HVFS_MDSL(idx);         \
                break;                          \
            case TYPE_RING:                     \
                __sid = HVFS_RING(idx);         \
                break;                          \
            default:;                           \
            }                                   \
            __sid;                              \
        })

static inline
u64 HVFS_TYPE_SEL(int type, int id)
{
    u64 site_id = -1UL;

    switch (type) {
    case TYPE_MDS:
        site_id = HVFS_MDS(id);
        break;
    case TYPE_CLIENT:
        site_id = HVFS_CLIENT(id);
        break;
    case TYPE_MDSL:
        site_id = HVFS_MDSL(id);
    case TYPE_RING:
        site_id = HVFS_RING(id);
    default:;
    }

    return site_id;
}

struct xnet_context *xc = NULL;

/* This function just return one reply message
 */
int xnet_test_handler(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    char data[100];

    if (msg->tx.flag & XNET_NEED_REPLY) {
        rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!rpy) {
            hvfs_err(xnet, "xnet_alloc_msg() failed\n");
            return -ENOMEM;
        }
        xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, 
                         msg->tx.dsite_id, msg->tx.ssite_id);
        xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
        xnet_msg_add_sdata(rpy, data, sizeof(data));
        rpy->tx.handle = msg->tx.handle;
        
        xnet_send(xc, rpy);
    
        xnet_free_msg(rpy);
    }
    xnet_set_auto_free(msg);
    xnet_free_msg(msg);

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
    int err = 0, i;
    short sport;
    char *value;
    u64 site;
    int type;
    int loop;
    int mode = 0;               /* default to client mode */
    int target = 0;             /* default to server 0 */

    hvfs_info(xnet, "XNET Simple UNIT TESTing ...\n");
    hvfs_info(xnet, "type 0/1/2/3 => MDS/CLIENT/MDSL/RING\n");

    value = getenv("type");
    if (value) {
        type = atoi(value);
    } else {
        hvfs_err(xnet, "Please set the type=?\n");
        return EINVAL;
    }

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        return EINVAL;
    } else {
        site = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is %s:%ld.\n",
                  (type == TYPE_MDS ? "mds" : 
                   (type == TYPE_CLIENT ? "client" : 
                    (type == TYPE_MDSL ? "mdsl" : "ring"))),
                  site);
    }

    switch (type) {
    case TYPE_MDS:
        sport = port[site];
        site = HVFS_MDS(site);
        mode = 1;               /* change to server mode */
        break;
    case TYPE_CLIENT:
        sport = port[2 + site];
        site = HVFS_CLIENT(site);
        break;
    case TYPE_MDSL:
        sport = port[site];
        site = HVFS_MDSL(site);
        break;
    case TYPE_RING:
        sport = port[site];
        site = HVFS_RING(site);
        break;
    default:
        sport = port[site];
    }
    
    value = getenv("loop");
    if (value) {
        loop = atoi(value);
    } else {
        loop = 10000;
    }

    value = getenv("target");
    if (value) {
        target = atoi(value);
    } else {
        target = 0;
    }

    mds_pre_init();
    mds_init(10);
    hmo.prof.xnet = &g_xnet_prof;

    st_init();
    xc = xnet_register_type(0, sport, site, &ops);
    if (IS_ERR(xc)) {
        err = PTR_ERR(xc);
        goto out;
    }

    for (i = 0; i < 14; i++) {
        if (i < 2) {
            xnet_update_ipaddr(HVFS_TYPE(TYPE_MDS, i), 1, 
                               &ipaddr[i], (short *)(&port[i]));
        } else {
            xnet_update_ipaddr(HVFS_TYPE(TYPE_CLIENT, (i - 2)), 1, 
                               &ipaddr[i], (short *)(&port[i]));
        }
    }

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_unreg;
    }

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, site, HVFS_TYPE_SEL(TYPE_MDS, target));
/*     xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE,  */
/*                      site, HVFS_TYPE_SEL(TYPE_MDS, target)); */

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    if (!mode) {
        int i;

        lib_timer_def();
        lib_timer_B();
        for (i = 0; i < loop; i++) {
            err = xnet_send(xc, msg);
            if (err) {
                hvfs_err(mds, "xnet_send() error %d\n", err);
            }
            if (msg->pair) {
                xnet_set_auto_free(msg->pair);
                xnet_free_msg(msg->pair);
            }
        }
        lib_timer_E();
        lib_timer_O(loop, "Ping-Pong Latency\t");
    } else {
        int i;
        lib_timer_def();
        lib_timer_B();
        for (i = 0; i < loop; i++) {
            xnet_wait_any(xc);
        }
        lib_timer_E();
        lib_timer_O(loop, "Handle    Latency\t");
    }
    
out_unreg:
    xnet_unregister_type(xc);
out:
    st_destroy();
    mds_destroy();
    return err;
}
#endif
