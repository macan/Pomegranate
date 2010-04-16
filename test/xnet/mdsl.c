/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-16 16:38:29 macan>
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

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

char *ipaddr[] = {
    "10.10.111.9",              /* mds */
    "10.10.111.9",              /* client */
    "10.10.111.9",              /* mdsl */
    "10.10.111.9",              /* ring */
};

short port[4][4] = {
    {8210, 8211, 8212, 8213,},  /* mds */
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
    case TYPE_RING:
        site_id = HVFS_RING(id);
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
        err = ring_add_point(p + i, *r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
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
    int self, sport, i, j;
    char *value;
    char profiling_fname[256];

    hvfs_info(xnet, "MDSL Unit Testing...\n");

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is mdsl:%d.\n", self);
    }

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
    
    /* setup the profiling file */
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "./CP-BACK-mdsl.%d", self);
    hmo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hmo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s faield %d\n",
                 profiling_fname, errno);
        return EINVAL;
    }

    sport = port[TYPE_MDSL][self];
    self = HVFS_MDSL(self);

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;
    mdsl_verify();
    hmi.gdt_salt = 0;
    hvfs_info(xnet, "Select GDT salt to  %lx\n", hmi.gdt_salt);
    hmi.root_uuid = 1;
    hmi.root_salt = 0xdfeadb0;
    hvfs_info(xnet, "Select root salt to %lx\n", hmi.root_salt);

    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(1));
    ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(0));
    ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(1));

    ring_dump(hmo.chring[CH_RING_MDS]);
    ring_dump(hmo.chring[CH_RING_MDSL]);

    msg_wait();

    xnet_unregister_type(hmo.xc);
    mdsl_destroy();
out:
    return err;
}
#endif
