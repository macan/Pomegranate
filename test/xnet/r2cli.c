/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-29 11:47:20 macan>
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
#include "root.h"
#include "lib.h"
#include "ring.h"

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

union hvfs_x_info g_hxi;

char *ipaddr[] = {
    "10.10.111.9",              /* mds */
    "10.10.111.9",              /* client */
    "10.10.111.9",              /* mdsl */
    "10.10.111.9",              /* ring */
};

short port[5][5] = {
    {8210, 8211, 8212, 8213, 8214,},  /* mds */
    {8412, 8413, 8414, 8415,},  /* client */
    {8810, 8811, 8812, 8813,},  /* mdsl */
    {8710, 8711, 8712, 8713,},  /* ring */
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

void __dump_hxi(u64 site_id)
{
    if (HVFS_IS_CLIENT(site_id)) {
        struct hvfs_client_info *hci = (struct hvfs_client_info *)&g_hxi;
        hvfs_info(xnet, "HCI: gdt_uuid %ld gdt_salt %lx root_uuid %ld"
                  " root_salt %lx group %ld\n",
                  hci->gdt_uuid, hci->gdt_salt, hci->root_uuid,
                  hci->root_salt, hci->group);
    } else if (HVFS_IS_MDS(site_id)) {
        struct hvfs_mds_info *hmi = (struct hvfs_mds_info *)&g_hxi;

        hvfs_info(xnet, "HMI: gdt_uuid %ld gdt_salt %lx root_uuid %ld"
                  " root_salt %lx group %ld\n",
                  hmi->gdt_uuid, hmi->gdt_salt, hmi->root_uuid,
                  hmi->root_salt, hmi->group);
    } else if (HVFS_IS_MDSL(site_id)) {
        struct hvfs_mdsl_info *hmi = (struct hvfs_mdsl_info *)&g_hxi;

        hvfs_info(xnet, "HMI: gdt_uuid %ld gdt_salt %lx root_uuid %ld"
                  " root_salt %lx group %ld\n",
                  hmi->gdt_uuid, hmi->gdt_salt, hmi->root_uuid,
                  hmi->root_salt, hmi->group);
    } else if (HVFS_IS_AMC(site_id)) {
        struct hvfs_amc_info *ami = (struct hvfs_amc_info *)&g_hxi;

        hvfs_info(xnet, "AMI: gdt_uuid %ld gdt_salt %lx root_uuid %ld"
                  " root_salt %lx group %ld\n",
                  ami->gdt_uuid, ami->gdt_salt, ami->root_uuid,
                  ami->root_salt, ami->group);
    }
}

void __update_hxi(u64 site_id, struct root_tx *rt)
{
    if (HVFS_IS_CLIENT(site_id)) {
        struct hvfs_client_info *hci = (struct hvfs_client_info *)&g_hxi;
        hci->gdt_uuid = rt->gdt_uuid;
        hci->gdt_salt = rt->gdt_salt;
        hci->root_uuid = rt->root_uuid;
        hci->root_salt = rt->root_salt;
    } else if (HVFS_IS_MDS(site_id)) {
        struct hvfs_mds_info *hmi = (struct hvfs_mds_info *)&g_hxi;

        hmi->gdt_uuid = rt->gdt_uuid;
        hmi->gdt_salt = rt->gdt_salt;
        hmi->root_uuid = rt->root_uuid;
        hmi->root_salt = rt->root_salt;
    } else if (HVFS_IS_MDSL(site_id)) {
        struct hvfs_mdsl_info *hmi = (struct hvfs_mdsl_info *)&g_hxi;

        hmi->gdt_uuid = rt->gdt_uuid;
        hmi->gdt_salt = rt->gdt_salt;
        hmi->root_uuid = rt->root_uuid;
        hmi->root_salt = rt->root_salt;
    } else if (HVFS_IS_AMC(site_id)) {
        struct hvfs_amc_info *ami = (struct hvfs_amc_info *)&g_hxi;

        ami->gdt_uuid = rt->gdt_uuid;
        ami->gdt_salt = rt->gdt_salt;
        ami->root_uuid = rt->root_uuid;
        ami->root_salt = rt->root_salt;
    }
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
                     hro.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_REG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* send the reg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hro.xc, msg);
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
        memcpy(&g_hxi, hxi, sizeof(*hxi));
        __dump_hxi(request_site);
        data += err;
        /* parse ring */
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
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
        /* parse bitmap */
        err = bparse_bitmap(data, &bitmap);
        if (err < 0) {
            hvfs_err(root, "bparse bitmap failed w/ %d\n", err);
            goto out;
        }
        data += err;
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

    hxi = &g_hxi;
    
    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hro.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_UNREG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hxi, sizeof(*hxi));

    /* send te unreeg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hro.xc, msg);
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

/* r2cli_do_mkfs()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_mkfs(u64 request_site, u64 root_site, u64 fsid, u32 gid)
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
                     hro.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_MKFS, request_site, fsid);
    msg->tx.reserved = gid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* send the mkfs request to root_site w/ requested siteid = request_site */
    err = xnet_send(hro.xc, msg);
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
        hvfs_err(xnet, "mkfs site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

    /* parse the mkfs reply message */
    hvfs_err(xnet, "Begin parse the mkfs reply message\n");
    if (msg->pair->xm_datacheck) {
        void *data = msg->pair->xm_data;
        struct root_tx *rt;

        /* parse root tx */
        err = bparse_root(data, &rt);
        if (err < 0) {
            hvfs_err(root, "bparse root failed w/ %d\n", err);
            goto out;
        }
        hvfs_info(root, "MKFS fsid %ld w/ root_salt %lx\n", 
                  fsid, rt->root_salt);
        /* update to g_hxi */
        __update_hxi(request_site, rt);
        err = 0;
    } else {
        hvfs_err(xnet, "Internal error, data lossing\n");
        err = -EFAULT;
    }

out:
    xnet_free_msg(msg);
out_nofree:

    return err;
}

/* r2cli_do_hb()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_hb(u64 request_site, u64 root_site, u64 fsid, u32 gid)
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

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hro.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_HB, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
out:
    xnet_free_msg(msg);
out_nofree:
    
    return err;
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = NULL,
    };
    char *value;
    int type = 0;
    int err = 0;
    int self, sport, op, fsid;

    hvfs_info(xnet, "R2 Unit Test Client running...\n");
    hvfs_info(xnet, "type 0/1/2/3 => MDS/CLIENT/MDSL/RING\n");
    hvfs_info(xnet, "fsid => 0-$\n");
    hvfs_info(xnet, "op 0/1 => hb/mkfs\n");

    value = getenv("type");
    if (value) {
        type = atoi(value);
    } else {
        hvfs_err(xnet, "Please set the type=?\n");
        return EINVAL;
    }

    value = getenv("op");
    if (value) {
        op = atoi(value);
    } else {
        op = 0;
    }

    value = getenv("fsid");
    if (value) {
        fsid = atoi(value);
    } else {
        fsid = 0;
    }

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is %s:%d.\n",
                  (type == TYPE_MDS ? "mds" :
                   (type == TYPE_CLIENT ? "client" :
                    (type == TYPE_MDSL ? "mdsl" : "ring"))),
                  self);
    }
    
    st_init();
    root_pre_init();
//    SET_TRACING_FLAG(root, HVFS_DEBUG | HVFS_VERBOSE);
    err = root_init();
    if (err) {
        hvfs_err(xnet, "root_init() failed w/ %d\n", err);
        goto out;
    }

    /* init misc configurations */
    hro.prof.xnet = &g_xnet_prof;

    sport = port[type][self];
    self = HVFS_TYPE_SEL(type, self);

    hro.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hro.xc)) {
        err = PTR_ERR(hro.xc);
        goto out;
    }

    hro.site_id = self;
    root_verify();

    /* prepare the init site table now */
    xnet_update_ipaddr(HVFS_TYPE(TYPE_RING, 0), 1, &ipaddr[3],
                       (short *)(&port[3][0]));

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
    /* do sent here */
    err = r2cli_do_reg(self, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "reg self %x w/ r2 %x failed w/ %d\n",
                 self, HVFS_RING(0), err);
        goto out;
    }

    switch (op) {
    case 0:
        err = r2cli_do_hb(self, HVFS_RING(0), fsid, 0);
        if (err) {
            hvfs_err(xnet, "hb %x w/ r2 %x failed w/ %d\n",
                     self, HVFS_RING(0), err);
            goto out_unreg;
        }
        break;
    case 1:
        err = r2cli_do_mkfs(self, HVFS_RING(0), fsid, 0);
        if (err) {
            hvfs_err(xnet, "mkfs self %x w/ r2 %x failed w/ %d\n",
                     self, HVFS_RING(0), err);
            goto out_unreg;
        }
    default:;
    }

out_unreg:
    err = r2cli_do_unreg(self, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "unreg self %x w/ r2 %x failed w/ %d\n",
                 self, HVFS_RING(0), err);
        goto out;
    }

    root_destroy();
    xnet_unregister_type(hro.xc);
    return 0;
out:
    root_destroy();
    return err;
}
#endif
