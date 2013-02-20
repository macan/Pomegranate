/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-21 16:11:13 macan>
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
#include "osd.h"
#include "lib.h"
#include "ring.h"
#include "root.h"

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3
#define TYPE_OSD        4

u64 fsid = 0;

char *ipaddr[] = {
    "127.0.0.1",              /* mds */
    "127.0.0.1",              /* client */
    "127.0.0.1",              /* mdsl */
    "127.0.0.1",              /* ring */
    "127.0.0.1",              /* osd */
};

short port[5][5] = {
    {8210, 8211, 8212, 8213, 8214,},  /* mds */
    {8412, 8413, 8414, 8415,},        /* client */
    {8810, 8811, 8812, 8813,},        /* mdsl */
    {8710, 8711, 8712, 8713,},        /* ring */
    {9200,},                          /* osd */
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
            case TYPE_OSD:                      \
                __sid = HVFS_OSD(idx);          \
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
    case TYPE_OSD:
        site_id = HVFS_OSD(id);
        break;
    default:;
    }

    return site_id;
}

int msg_wait()
{
    while (1) {
        xnet_wait_any(hoo.xc);
    }
    return 0;
}

struct chring *chring_tx_to_chring(struct chring_tx *ct)
{
    return (struct chring *)1;  /* just reutrn a non-NULL value */
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
                     hoo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_REG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* send the reg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

resend:
    err = xnet_send(hoo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* Reply ABI:
     * @tx.arg0: network magic
     */

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ERECOVER) {
        hvfs_err(xnet, "R2 notify a client recover process on site "
                 "%lx, do it.\n", request_site);
    } else if (msg->pair->tx.err == -EHWAIT) {
        hvfs_err(xnet, "R2 reply that another instance is still alive, "
                 "wait a moment and retry.\n");
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        sleep(1);
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "Reg site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

    /* parse the register reply message */
    hvfs_info(xnet, "Begin parse the reg reply message\n");
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
        memcpy(&hoi, hxi, sizeof(hoi));
        data += err;
        /* parse ring */
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        
        if (!chring_tx_to_chring(ct)) {
            hvfs_err(root, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        
        if (!chring_tx_to_chring(ct)) {
            hvfs_err(root, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(root, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        if (!chring_tx_to_chring(ct)) {
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
        /* dh_insert(hoi.gdt_uuid, hoi.gdt_uuid, hoi.gdt_salt); */

        /* parse bitmap */
        err = bparse_bitmap(data, &bitmap);
        if (err < 0) {
            hvfs_err(root, "bparse bitmap failed w/ %d\n", err);
            goto out;
        }
        data += err;
        /* FIXME: we do not need to insert the bitmap! */
        /* bitmap_insert2(hoi.gdt_uuid, 0, bitmap, err - sizeof(u32)); */
        
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

        /* set network magic */
        xnet_set_magic(msg->pair->tx.arg0);
    }
    hvfs_info(xnet, "End parse the reg reply message\n");
    
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

    hxi = (union hvfs_x_info *)&hoi;

    /* alloc one msg and send it to the perr site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hoo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_UNREG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hxi, sizeof(*hxi));

    /* send te unreeg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hoo.xc, msg);
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

/* r2cli_do_hb()
 *
 * @gid: already right shift 2 bits
 */
static
int r2cli_do_hb(u64 request_site, u64 root_site, u64 fsid, u32 gid)
{
    struct xnet_msg *msg;
    union hvfs_x_info *hxi;
    int err = 0;

    hxi = (union hvfs_x_info *)&hoi;
    
    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hoo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_HB, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hxi, sizeof(*hxi));

    msg->tx.reserved = gid;

    err = xnet_send(hoo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
out:
    xnet_free_msg(msg);
out_nofree:
    
    return err;
}

void osd_cb_exit(void *arg)
{
    int err = 0;

    err = r2cli_do_unreg(hoo.xc->site_id, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "unreg self %lx w/ r2 %x failed w/ %d\n",
                 hoo.xc->site_id, HVFS_RING(0), err);
        return;
    }
}

void osd_cb_hb(void *arg)
{
    u64 ring_site;
    int err = 0;

    ring_site = osd_select_ring(&hoo);
    err = r2cli_do_hb(hoo.xc->site_id, ring_site, fsid, 0);
    if (err) {
        hvfs_err(xnet, "hb %lx w/ r2 %x failed w/ %d\n",
                 hoo.xc->site_id, HVFS_RING(0), err);
    }
}

void osd_cb_addr_table_update(void *arg)
{
    struct hvfs_site_tx *hst;
    void *data = arg;
    int err = 0;

    hvfs_info(xnet, "Update address table ...\n");

    err = bparse_addr(data, &hst);
    if (err < 0) {
        hvfs_err(xnet, "bparse_addr failed w/ %d\n", err);
        goto out;
    }
    
    err = hst_to_xsst(hst, err - sizeof(u32));
    if (err) {
        hvfs_err(xnet, "hst to xsst failed w/ %d\n", err);
        goto out;
    }

out:
    return;
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = osd_spool_dispatch,
        .dispatcher = osd_dispatch,
    };
    int err = 0;
    int self, sport = -1, plot_method;
    char *value;
    char *ring_ip = NULL;
    char profiling_fname[256], *log_home;

    hvfs_info(xnet, "OSD Unit Testing...\n");
    hvfs_info(xnet, "Usage %s id ring_ip self_port\n", argv[0]);

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is osd:%d.\n", self);
        if (argc == 4) {
            ring_ip = argv[2];
            sport = atoi(argv[3]);
        } else if (argc == 3)
            ring_ip = argv[2];
    }

    value = getenv("fsid");
    if (value) {
        fsid = atoi(value);
    } else
        fsid = 0;

    value = getenv("plot");
    if (value) {
        plot_method = atoi(value);
    } else
        plot_method = OSD_PROF_PLOT;

    value = getenv("LOG_DIR");
    if (value) {
        log_home = strdup(value);
    } else
        log_home = NULL;

    st_init();
    osd_pre_init();
    hoo.conf.prof_plot = plot_method;
    osd_config();

    /* BUG-XXXX: we have set the site_id BEFORE osd_init() */
    hoo.site_id = HVFS_OSD(self);
    err = osd_init();
    if (err) {
        hvfs_err(xnet, "osd_init() failed %d\n", err);
        goto out;
    }

    /* init misc configrations */
    hoo.prof.xnet = &g_xnet_prof;

    /* prepare the ring address */
    if (!ring_ip) {
        xnet_update_ipaddr(HVFS_RING(0), 1, &ipaddr[3],
                           (short *)(&port[3][0]));
        if (sport == -1)
            sport = port[TYPE_OSD][0];
    } else {
        xnet_update_ipaddr(HVFS_RING(0), 1, &ring_ip,
                           (short *)(&port[3][0]));
        if (sport == -1)
            sport = port[TYPE_OSD][0];
    }

    /* setup the profiling file */
    if (!log_home)
        log_home = ".";
    
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "%s/CP-BACK-osd.%d", log_home, self);
    hoo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hoo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s faield %d\n",
                 profiling_fname, errno);
        return EINVAL;
    }

    self = HVFS_OSD(self);

    hoo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hoo.xc)) {
        err = PTR_ERR(hoo.xc);
        return err;
    }

    hoo.site_id = self;

    hoo.cb_exit = osd_cb_exit;
    hoo.cb_hb = osd_cb_hb;
    hoo.cb_addr_table_update = osd_cb_addr_table_update;
    
    /* use ring info to init the osd */
    err = r2cli_do_reg(self, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "reg self %x w/ r2 %x failed w/ %d\n",
                 self, HVFS_RING(0), err);
        goto out;
    }

    osd_verify();

    hvfs_info(xnet, "OSD is UP for serving requests now.\n");
    {
        char path[100];
        struct objid obj = {.uuid = 100, .bid = 10, .len = 9,};

        osd_get_obj_path(obj, "STORE", path);
        hvfs_info(xnet, "OSD path : %s\n", path);
    }

    //SET_TRACING_FLAG(osd, HVFS_DEBUG);
    msg_wait();

    osd_destroy();
    xnet_unregister_type(hoo.xc);
out:
    return err;
}
#endif
