/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-05 20:46:47 macan>
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

char *ipaddr1[] = {
    "10.10.111.9",
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

int msg_send(int dsite, int loop)
{
    lib_timer_def();
    int i, err = 0;

    /* Load DH */
    lib_timer_B();
    for (i = 0; i < loop; i++) {
    }
    lib_timer_E();
    lib_timer_O(loop, "Load DH Latency: ");

    return err;
}

int msg_wait(int dsite)
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

int dh_insert(u64 uuid, u64 puuid, u64 psalt)
{
    struct hvfs_index hi;
    struct dhe *e;
    int err = 0;

    memset(&hi, 0, sizeof(hi));
    hi.uuid = uuid;
    hi.puuid = puuid;
    hi.ssalt = psalt;

    e = mds_dh_insert(&hmo.dh, &hi);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_info(xnet, "Insert dir:%8ld in DH w/  %p\n", uuid, e);
out:
    return err;
}

int dh_search(u64 uuid)
{
    struct dhe *e;
    int err = 0;

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    hvfs_info(xnet, "Search dir:%8ld in DH hit %p\n", uuid, e);
out:
    return err;
}

int dh_remove(u64 uuid)
{
    return mds_dh_remove(&hmo.dh, uuid);
}

int bitmap_insert(u64 uuid, u64 offset)
{
    struct dhe *e;
    struct itbitmap *b;
    int err = 0, i;

    b = xzalloc(sizeof(*b));
    if (!b) {
        hvfs_err(xnet, "xzalloc() struct itbitmap failed\n");
        err = -ENOMEM;
        goto out;
    }
    INIT_LIST_HEAD(&b->list);
    b->offset = (offset / XTABLE_BITMAP_SIZE) * XTABLE_BITMAP_SIZE;
    b->flag = BITMAP_END;
    /* set all bits to 1, within the previous 8 ITBs */
    for (i = 0; i < ((1 << hmo.conf.itb_depth_default) / 8); i++) {
        b->array[i] = 0xff;
    }

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out_free;
    }
    err = __mds_bitmap_insert(e, b);
    if (err) {
        hvfs_err(xnet, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }

out:
    return err;
out_free:
    xfree(b);
    return err;
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
        .recv_handler = mds_fe_dispatch,
    };
    int err = 0;
    int dsite, self, entry = 0;
    short port;
    char *value;

    value = getenv("entry");
    if (value) {
        entry = atoi(value);
    }
    if (!entry)
        entry = 100;

    if (argc == 2) {
        /* Server Mode */
        port = 8210;
        dsite = HVFS_MDS(1);
        self = HVFS_MDS(0);
    } else {
        /* Client Mode */
        port = 8412;
        dsite = HVFS_MDS(0);
        self = HVFS_MDS(1);
    }

    hvfs_info(xnet, "Full Path MDS/MDS w/ XNET Simple UNIT TESTing Mode(%s)"
              "...\n", (HVFS_IS_MDS(self) ? "Server" : "Client"));

    st_init();
    lib_init();
    mds_init(10);
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.itbid_check = 1;

    hmo.xc = xnet_register_type(0, port, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }
    hmo.site_id = self;
    hmi.gdt_salt = lib_random(0xfffffff);
    hvfs_info(xnet, "Select GDT salt to %ld\n", hmi.gdt_salt);

    xnet_update_ipaddr(HVFS_MDS(1), 1, ipaddr1, port1);
    xnet_update_ipaddr(HVFS_MDS(0), 1, ipaddr2, port2);

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
//    SET_TRACING_FLAG(mds, HVFS_DEBUG);
//    SET_TRACING_FLAG(lib, HVFS_DEBUG);

    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_dump(hmo.chring[CH_RING_MDS]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);

    if (self == HVFS_MDS(1)) {
        msg_send(dsite, entry);
    } else {
        msg_wait(dsite);
    }

    xnet_unregister_type(hmo.xc);
out:
    dh_remove(hmi.gdt_uuid);
    st_destroy();
    mds_destroy();
    return 0;
}

#endif
