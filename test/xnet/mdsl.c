/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-20 09:50:38 macan>
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
#include "mdsl.h"
#include "lib.h"
#include "ring.h"
#include "root.h"

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

u64 fsid = 0;

char *ipaddr[] = {
    "127.0.0.1",              /* mds */
    "127.0.0.1",              /* client */
    "127.0.0.1",              /* mdsl */
    "127.0.0.1",              /* ring */
    "10.10.111.96",             /* test client */
};

short port[5][5] = {
    {8210, 8211, 8212, 8213, 8214,},  /* mds */
    {8412, 8413, 8414, 8415,},        /* client */
    {8810, 8811, 8812, 8813,},        /* mdsl */
    {8710, 8711, 8712, 8713,},        /* ring */
    {9000, 8214},                     /* test client */
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

int msg_wait()
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

/* ring_add() add one site to the CH ring
 */
int ring_add(struct chring **r, u64 site)
{
    struct chp *p;
    char buf[256];
    int vid_max, i, err;

    vid_max = hmo.conf.ring_vid_max ? hmo.conf.ring_vid_max : HVFS_RING_VID_MAX;

    if (!*r) {
        *r = ring_alloc(vid_max << 1, 0);
        if (!*r) {
            hvfs_err(xnet, "ring_alloc() failed.\n");
            return -ENOMEM;
        }
    }

    p = (struct chp *)xzalloc(vid_max * sizeof(struct chp));
    if (!p) {
        hvfs_err(xnet, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < vid_max; i++) {
        snprintf(buf, 256, "%ld.%d", site, i);
        (p + i)->point = hvfs_hash(site, (u64)buf, strlen(buf), HASH_SEL_VSITE);
        (p + i)->vid = i;
        (p + i)->type = CHP_AUTO;
        (p + i)->site_id = site;
        err = ring_add_point_nosort(p + i, *r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
}

struct chring *chring_tx_to_chring(struct chring_tx *ct)
{
    struct chring *ring;
    int err = 0, i;

    ring = ring_alloc(ct->nr, ct->group);
    if (IS_ERR(ring)) {
        hvfs_err(xnet, "ring_alloc failed w/ %ld\n",
                 PTR_ERR(ring));
        return ring;
    }

    /* ok, let's copy the array to chring */
    for (i = 0; i < ct->nr; i++) {
        err = ring_add_point_nosort(&ct->array[i], ring);
        if (err) {
            hvfs_err(xnet, "ring add point failed w/ %d\n", err);
            goto out;
        }
    }
    /* sort it */
    ring_resort_nolock(ring);

    /* calculate the checksum of the CH ring */
    lib_md5_print(ring->array, ring->alloc * sizeof(struct chp), "CHRING");

    return ring;
out:
    ring_free(ring);
    return ERR_PTR(err);
}

/* r2cli_do_reg()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_reg(u64 request_site, u64 root_site, u64 fsid, u32 gid)
{
    struct xnet_msg *msg;
    int err = 0;

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_REG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* send the reg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ERECOVER) {
        hvfs_err(xnet, "R2 notify a client recover process on site "
                 "%lx, do it.\n", request_site);
    } else if (msg->pair->tx.err == -EHWAIT) {
        hvfs_err(xnet, "R2 reply that another instance is still alive, "
                 "wait a moment and retry.\n");
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "Reg site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

    /* parse the register reply message */
    hvfs_err(xnet, "Begin parse the reg reply message\n");
    if (msg->pair->xm_datacheck) {
        void *data = msg->pair->xm_data;
        void *bitmap;
        union hvfs_x_info *hxi;
        struct chring_tx *ct;
        struct root_tx *rt;
        struct hvfs_site_tx *hst;

        /* parse hxi */
        err = bparse_hxi(data, &hxi);
        if (err < 0) {
            hvfs_err(root, "bparse_hxi failed w/ %d\n", err);
            goto out;
        }
        memcpy(&hmi, hxi, sizeof(hmi));
        data += err;
        /* parse ring */
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        hmo.chring[CH_RING_MDS] = chring_tx_to_chring(ct);
        if (!hmo.chring[CH_RING_MDS]) {
            hvfs_err(root, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        hmo.chring[CH_RING_MDSL] = chring_tx_to_chring(ct);
        if (!hmo.chring[CH_RING_MDS]) {
            hvfs_err(root, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        /* parse root_tx */
        err = bparse_root(data, &rt);
        if (err < 0) {
            hvfs_err(root, "bparse root failed w/ %d\n", err);
            goto out;
        }
        data += err;
        hvfs_info(root, "fsid %ld gdt_uuid %ld gdt_salt %lx "
                  "root_uuid %ld root_salt %lx\n",
                  rt->fsid, rt->gdt_uuid, rt->gdt_salt, 
                  rt->root_uuid, rt->root_salt);
        /* FIXME: we do not need to insert the dh entry */
        /* dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt); */

        /* parse bitmap */
        err = bparse_bitmap(data, &bitmap);
        if (err < 0) {
            hvfs_err(root, "bparse bitmap failed w/ %d\n", err);
            goto out;
        }
        data += err;
        /* FIXME: we do not need to insert the bitmap! */
        /* bitmap_insert2(hmi.gdt_uuid, 0, bitmap, err - sizeof(u32)); */
        
        /* parse addr */
        err = bparse_addr(data, &hst);
        if (err < 0) {
            hvfs_err(root, "bparse addr failed w/ %d\n", err);
            goto out;
        }
        /* add the site table to the xnet */
        err = hst_to_xsst(hst, err - sizeof(u32));
        if (err) {
            hvfs_err(root, "hst to xsst failed w/ %d\n", err);
        }
    }
    
out:
    xnet_free_msg(msg);
out_nofree:

    return err;
}

/* r2cli_do_unreg()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_unreg(u64 request_site, u64 root_site, u64 fsid, u32 gid)
{
    struct xnet_msg *msg;
    union hvfs_x_info *hxi;
    int err = 0;

    hxi = (union hvfs_x_info *)&hmi;

    /* alloc one msg and send it to the perr site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_UNREG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hxi, sizeof(*hxi));

    /* send te unreeg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err) {
        hvfs_err(xnet, "Unreg site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

out:
    xnet_free_msg(msg);
out_nofree:
    return err;
}

void mdsl_cb_exit(void *arg)
{
    int err = 0;

    err = r2cli_do_unreg(hmo.xc->site_id, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "unreg self %lx w/ r2 %x failed w/ %d\n",
                 hmo.xc->site_id, HVFS_RING(0), err);
        return;
    }
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = mdsl_spool_dispatch,
        .dispatcher = mdsl_dispatch,
    };
    int err = 0;
    int self, sport = -1, i, j, mode;
    char *value;
    char *ring_ip = NULL;
    char profiling_fname[256];

    hvfs_info(xnet, "MDSL Unit Testing...\n");
    hvfs_info(xnet, "Usage %s id ring_ip self_port\n", argv[0]);
    hvfs_info(xnet, "Mode is 0/1 (no ring/with ring)\n");

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is mdsl:%d.\n", self);
        if (argc == 4) {
            ring_ip = argv[2];
            sport = atoi(argv[3]);
        } else if (argc == 3)
            ring_ip = argv[2];
    }

    value = getenv("mode");
    if (value) {
        mode = atoi(value);
    } else 
        mode = 0;

    value = getenv("fsid");
    if (value) {
        fsid = atoi(value);
    } else
        fsid = 0;

    st_init();
    mdsl_pre_init();
    mdsl_config();
    err = mdsl_init();
    if (err) {
        hvfs_err(xnet, "mdsl_init() failed %d\n", err);
        goto out;
    }

    /* init misc configrations */
    hmo.prof.xnet = &g_xnet_prof;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            xnet_update_ipaddr(HVFS_TYPE(i, j), 1, &ipaddr[i],
                               (short *)(&port[i][j]));
        }
    }
    xnet_update_ipaddr(HVFS_MDS(4), 1, &ipaddr[0], (short *)(&port[0][4]));
    xnet_update_ipaddr(HVFS_CLIENT(12), 1, &ipaddr[4], (short *)(&port[4][0]));
    
    /* prepare the ring address */
    if (!ring_ip) {
        xnet_update_ipaddr(HVFS_RING(0), 1, &ipaddr[3],
                           (short *)(&port[3][0]));
        if (sport == -1)
            sport = port[TYPE_MDSL][self];
    } else {
        xnet_update_ipaddr(HVFS_RING(0), 1, &ring_ip,
                           (short *)(&port[3][0]));
        if (sport == -1)
            sport = port[TYPE_MDSL][0];
    }

    /* setup the profiling file */
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "./CP-BACK-mdsl.%d", self);
    hmo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hmo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s faield %d\n",
                 profiling_fname, errno);
        return EINVAL;
    }

    self = HVFS_MDSL(self);

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;
    mdsl_verify();

    if (mode == 0) {
        hmi.gdt_salt = 0;
        hvfs_info(xnet, "Select GDT salt to  %lx\n", hmi.gdt_salt);
        hmi.root_uuid = 1;
        hmi.root_salt = 0xdfeadb0;
        hvfs_info(xnet, "Select root salt to %lx\n", hmi.root_salt);
        
#if 0
        ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
        ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(1));
        ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(2));
        ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(3));
#else
        ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(4));
#endif
        ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(0));
        ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(1));
        
        ring_resort_nolock(hmo.chring[CH_RING_MDS]);
        ring_resort_nolock(hmo.chring[CH_RING_MDSL]);

        ring_dump(hmo.chring[CH_RING_MDS]);
        ring_dump(hmo.chring[CH_RING_MDSL]);
    } else {
        hmo.cb_exit = mdsl_cb_exit;
        /* use ring info to init the mdsl */
        err = r2cli_do_reg(self, HVFS_RING(0), fsid, 0);
        if (err) {
            hvfs_err(xnet, "reg self %x w/ r2 %x failed w/ %d\n",
                     self, HVFS_RING(0), err);
            goto out;
        }
    }

    hvfs_info(xnet, "MDSL is UP for serving requests now.\n");

    //SET_TRACING_FLAG(mdsl, HVFS_DEBUG);
    msg_wait();

    mdsl_destroy();
    xnet_unregister_type(hmo.xc);
out:
    return err;
}
#endif
