/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-23 21:03:10 macan>
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
#include "ring.h"
#include "lib.h"

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

#define NR_THREAD       4

char *ipaddr[] = {
    "10.10.111.9",              /* mds */
    "10.10.111.9",              /* client */
    "10.10.111.9",              /* mdsl */
    "10.10.111.9",              /* ring */
};

#if 1
short port[4][4] = {
    {8210, 8210, 8210, 8210,},  /* mds */
    {8412, 8412, 8412, 8412,},  /* client */
    {8810, 8810, 8810, 8810,},  /* mdsl */
    {8710, 8710, 8710, 8710,},  /* ring */
};
#else
short port[4][4] = {
    {8210, 8211, 8212, 8213,},  /* mds */
    {8412, 8413, 8414, 8415,},  /* client */
    {8810, 8811, 8812, 8813,},  /* mdsl */
    {8710, 8711, 8712, 8713,},  /* ring */
};
#endif

struct thread_args
{
    struct xnet_context *xc;
    u64 site_id;
    int tid;
    int type;
    short port;
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


/* This function just return one reply message
 */
int xnet_test_handler(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    int *di, i;
    int data[4096];

    ASSERT(msg->xc->site_id == msg->tx.dsite_id, xnet);
    /* checking the data region */
    di = (int *)msg->xm_data;
    for (i = 0; i < 4096; i++) {
        ASSERT(*(di + i) == msg->tx.ssite_id + i, xnet);
    }
    
    for (i = 0; i < 4096; i++) {
        data[i] = msg->tx.ssite_id + i;
    }

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        return -ENOMEM;
    }
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, 
                     msg->tx.dsite_id, msg->tx.ssite_id);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_add_sdata(rpy, data, sizeof(data));
    rpy->tx.handle = msg->tx.handle;

    xnet_send(msg->xc, rpy);
    xnet_free_msg(rpy);
    xnet_free_msg(msg);
    
    return 0;
}

int msg_send(struct xnet_context *xc, u64 dsid_base, 
             u64 ssid, int nr)
{
    struct xnet_msg *msg;
    int err = 0, i, j, *di;
    int data[4096];

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_msg_alloc failed\n");
        err = -ENOMEM;
        goto out;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    for (i = 0; i < 4096; i++) {
        data[i] = xc->site_id + i;
    }
    xnet_msg_add_sdata(msg, data, sizeof(data));
    /* all-to-all mode */
    for (i = 0; i < nr; i++) {
        xnet_msg_fill_tx(msg, XNET_MSG_REQ,
                         XNET_NEED_REPLY, ssid, dsid_base + i);
        xnet_send(xc, msg);
        /* check the data */
        di = (int *)msg->pair->xm_data;
        for (j = 0; j < 4096; j++) {
            ASSERT(*(di + i) == xc->site_id + i, xnet);
        }
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
    }

    hvfs_info(xnet, "All-to-All(block) test done.\n");

out:
    xnet_free_msg(msg);
    return err;
}

int msg_wait()
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

void *test_thread(void *arg)
{
    struct thread_args *ta = (struct thread_args *)arg;

    switch (ta->type) {
    case TYPE_MDS:
        msg_wait();
        break;
    case TYPE_CLIENT:
        msg_send(ta->xc, HVFS_MDS(0), ta->site_id, 4);
        break;
    default:;
    }

    pthread_exit(0);
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = xnet_test_handler,
    };
    struct thread_args ta[NR_THREAD];
    pthread_t pt[NR_THREAD];
    int err = 0;
    int type = 0;
    int self, sport, i, j;
    char *value;

    hvfs_info(xnet, "%sNOTICE: this test case is conflict w/ XNET-simple "
              "New Version!\n work <= %s%s\n",
              HVFS_COLOR_RED, 
              "commit 520319349415c6160dab5328ad132bbe6b1585f1", 
              HVFS_COLOR_END);
    hvfs_info(xnet, "type: 0/1/2/3 => mds/client/mdsl/ring\n");
    value = getenv("type");
    if (value) {
        type = atoi(value);
    }

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is %s:[%d-%d].\n",
                  (type == TYPE_MDS ? "mds" : 
                   (type == TYPE_CLIENT ? "client" : 
                    (type == TYPE_MDSL ? "mdsl" : "ring"))),
                  self, self + NR_THREAD - 1);
    }

    st_init();
    lib_init();
    mds_pre_init();
    mds_init(10);
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.itbid_check = 1;

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);

    for (i = 0; i < 2; i++) {
        for (j = 0; j < 4; j++) {
            xnet_update_ipaddr(HVFS_TYPE(i, j), 1, &ipaddr[i], 
                               (short *)(&port[i][j]));
        }
    }

    sport = port[type][self];

    switch (type) {
    case TYPE_MDS:
        self = HVFS_MDS(self);
        break;
    case TYPE_CLIENT:
        self = HVFS_CLIENT(self);
        break;
    case TYPE_MDSL:
        self = HVFS_MDSL(self);
        break;
    case TYPE_RING:
        self = HVFS_RING(self);
        break;
    default:;
    }

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    for (i = 0; i < 4; i++) {
        ta[i].xc = xnet_register_lw(type, port[type][i] + i, 
                                    HVFS_TYPE_SEL(type, i), &ops);
        ta[i].tid = i;
        ta[i].site_id = self + i;
        ta[i].port = sport;
        ta[i].type = type;
    }

    for (i = 0; i < 4; i++) {
        err = pthread_create(&pt[i], NULL, test_thread, &ta[i]);
        if (err) {
            hvfs_err(xnet, "pthread_create failed %d\n", err);
            goto out_unreg;
        }
    }

    for (i = 0; i < 4; i++) {
        pthread_join(pt[i], NULL);
    }

out_unreg:
    xnet_unregister_type(hmo.xc);
out:
    return err;
}

#endif
