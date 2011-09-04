/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-08-25 11:42:16 macan>
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

#define TEST_LEN        (100)

char *ipaddr[2] = {
    "127.0.0.1",
    "127.0.0.1",
};

short port[2] = {
    8210,
    5410,
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
        break;
    case TYPE_RING:
        site_id = HVFS_RING(id);
        break;
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
    char data[TEST_LEN << 1];

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
        rpy->tx.reqno = msg->tx.reqno;
        
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
    char *value;
    int type;
    int loop;
    int mode = 0;               /* default to server mode */
    char data[TEST_LEN];

    hvfs_info(xnet, "XNET Simple UNIT TESTing ...\n");
    hvfs_info(xnet, "type 0/1 => Server/Client\n");
    hvfs_info(xnet, "Args: IP PORT RIP RPORT\n");

    value = getenv("type");
    if (value) {
        type = atoi(value);
    } else {
        hvfs_err(xnet, "Please set the type=?\n");
        return EINVAL;
    }

    if (argc >= 5) {
        if (type == 0) {
            ipaddr[0] = strdup(argv[1]);
            ipaddr[1] = strdup(argv[3]);
            port[0] = atoi(argv[2]);
            port[1] = atoi(argv[4]);
        } else {
            ipaddr[0] = strdup(argv[3]);
            ipaddr[1] = strdup(argv[1]);
            port[0] = atoi(argv[4]);
            port[1] = atoi(argv[2]);
        }
    }
    hvfs_info(xnet, "Use Args: IP=%s, PORT=%d, RIP=%s, RPORT=%d\n",
              ipaddr[0], port[0], ipaddr[1], port[1]);
    
    switch (type) {
    case 0:                     /* server */
        mode = 0;
        break;
    case 1:                     /* client */
        mode = 1;
        break;
    default:
        hvfs_err(xnet, "Invalid TYPE: please use 0/1!\n");
        return EINVAL;
    }

    value = getenv("loop");
    if (value) {
        loop = atoi(value);
    } else {
        loop = 10000;
    }

    mds_pre_init();
    mds_init(10);
    hmo.gossip_thread_stop = 1;
    hmo.prof.xnet = &g_xnet_prof;

    st_init();
    xc = xnet_register_type(0, port[mode], mode, &ops);
    if (IS_ERR(xc)) {
        err = PTR_ERR(xc);
        goto out;
    }

    for (i = 0; i < 2; i++) {
        xnet_update_ipaddr(i, 1, &ipaddr[i], (short *)(&port[i]));
    }

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_unreg;
    }

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 
                     XNET_NEED_REPLY, mode, !mode);
/*     xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE,  */
/*                      site, HVFS_TYPE_SEL(TYPE_MDS, target)); */

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, data, sizeof(data));

    if (mode) {
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
