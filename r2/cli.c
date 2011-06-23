/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-23 09:56:06 macan>
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

/* cli_scan_ring() find the top N large ranges in the consistent hash ring and
 * saved into the range array.
 */
int cli_scan_ring(struct ring_entry *re, int topn, 
                  struct ring_range *rr)
{
    int err = 0;

    err = ring_topn_range(topn, &re->ring, rr);
    if (err) {
        hvfs_err(root, "ring_topn_range() faild /w %d\n", err);
    }
    
    return err;
}

/* cli_add_vsite() add one virtual site to the ring at location point.
 */
int cli_add_vsite(struct ring_entry *re, u64 point, u32 vid, u64 site_id)
{
    struct chp p = {
        .point = point,
        .vid = vid,
        .site_id = site_id,
        .type = CHP_MANUAL,
    };
    int err = 0;

    err = ring_add_point(&p, &re->ring);
    if (err) {
        hvfs_err(root, "ring_add_point() failed.\n");
        return err;
    }

    return 0;
}

/* cli_find_topn_add()
 *
 * Return Value: >=0 (# of changed ranges)? ok!, <0 err
 */
int cli_find_topn_add(struct ring_entry *re, u64 site_id, int vnr, 
                      struct ring_range **orr)
{
    struct ring_range *rr;
    struct chp *p;
    int err = 0, rb = 0, i;

    if (vnr <= 0 || vnr > re->ring.used)
        return -EINVAL;

    rr = xzalloc(vnr * sizeof(struct ring_range));
    if (!rr) {
        hvfs_err(root, "xzalloc() ring_range failed\n");
        return -ENOMEM;
    }

    err = cli_scan_ring(re, vnr, rr);
    if (err) {
        hvfs_err(root, "cli_scan_ring() failed w/ %d\n", err);
        goto out;
    }

    for (i = 0; i < vnr; i++) {
        if (rr[i].dist != 0) {
            err = cli_add_vsite(re, (rr[i].start + rr[i].end) / 2,
                                i, site_id);
            if (err) {
                rb = i;
                hvfs_err(root, "cli_add_vsite() failed w/ %d\n",
                         err);
                goto rollback;
            }
        }
    }
    *orr = rr;
    
out:
    return err;
rollback:
    for (i = 0; i < rb; i++) {
        p = ring_get_point2(rr[i].start + 1, &re->ring);
        if (IS_ERR(p)) {
            hvfs_err(root, "ring_get_point2() failed w/ %ld\n",
                     PTR_ERR(p));
            continue;
        }
        err = ring_del_point(p, &re->ring);
        if (err) {
            hvfs_err(root, "ring_del_point() failed w/ %d\n",
                     err);
        }
    }
    *orr = NULL;
    goto out;
}

/* cli_find_topn() no add
 *
 * Return Value: >=0 ok, <0 err
 */
int cli_find_topn(struct ring_entry *re, int vnr, struct ring_range **orr)
{
    struct ring_range *rr;
    int err = 0;

    if (!re->ring.used)
        return -EISEMPTY;

    if (vnr <= 0 || vnr > re->ring.used)
        return -EINVAL;

    rr = xzalloc(vnr * sizeof(struct ring_range));
    if (!rr) {
        hvfs_err(root, "xzalloc() ring_range failed\n");
        return -ENOMEM;
    }

    err = cli_scan_ring(re, vnr, rr);
    if (err) {
        hvfs_err(root, "cli_scan_ring() failed w/ %d\n", err);
        goto out;
    }

    *orr = rr;

out:
    return err;
}

/* cli_range_add() to split and add a site to the ranges
 */
int cli_range_add(struct ring_entry *re, u64 site_id, int vnr,
                  struct ring_range *rr) 
{
    struct chp *p;
    int err = 0, rb = 0, i;
    
    for (i = 0; i < vnr; i++) {
        if (rr[i].dist != 0) {
            err = cli_add_vsite(re, (rr[i].start + rr[i].end) / 2,
                                i, site_id);
            if (err) {
                rb = i;
                hvfs_err(root, "cli_add_vsite() failed w/ %d\n",
                         err);
                goto rollback;
            }
        }
    }

out:
    return err;
rollback:
    for (i = 0; i < rb; i++) {
        p = ring_get_point2(rr[i].start + 1, &re->ring);
        if (IS_ERR(p)) {
            hvfs_err(root, "ring_get_point2() failed w/ %ld\n",
                     PTR_ERR(p));
            continue;
        }
        err = ring_del_point(p, &re->ring);
        if (err) {
            hvfs_err(root, "ring_del_point() failed w/ %d\n",
                     err);
        }
    }
    goto out;
}

/* cli_find_del()
 *
 * Find and delete the sites in the ring
 */
int cli_find_del_site(struct ring_entry *re, u64 site_id)
{
    void *data;
    struct chp **p;
    int nr, i, err;

rescan:
    data = NULL;
    nr = ring_find_site(&re->ring, site_id, &data);
    if (nr < 0 || !data) {
        hvfs_err(root, "ring_find_site() failed w/ %d\n", nr);
        return nr;
    }

    p = (struct chp **)data;
    for (i = 0; i < nr; i++) {
        err = ring_del_point(*(p + i), &re->ring);
        if (err) {
            hvfs_err(root, "ring_del_point() failed w/ %d\n", err);
        }
        goto rescan;
    }
    xfree(data);

    return 0;
}

/* @site_id: target site
 * @gid_ns: the right shifted group id, need left shift!
 */
struct ring_args
{
    u64 site_id;                /* site id filled by traverse function */
    u32 state;                  /* state filled by traverse function */
    u32 gid_ns;
};

static inline
int __pack_msg(struct xnet_msg *msg, void *data, int len)
{
    u32 *__len = xmalloc(sizeof(u32));

    if (!__len) {
        hvfs_err(root, "pack msg xmalloc failed\n");
        return -ENOMEM;
    }

    *__len = len;
    xnet_msg_add_sdata(msg, __len, sizeof(u32));
    xnet_msg_add_sdata(msg, data, len);

    return 0;
}
void *__cli_send_rings(void *args)
{
    struct xnet_msg *msg;
    struct ring_args *ra = (struct ring_args *)args;
    struct ring_entry *ring;
    void *ring_data = NULL, *ring_data2 = NULL;
    int ring_len, ring_len2;
    u32 gid;
    int err = 0;

    if (ra->state == SE_STATE_INIT ||
        ra->state == SE_STATE_SHUTDOWN) {
        return NULL;
    }

    hvfs_warning(root, "Send rings to %lx gid %u\n", ra->site_id, ra->gid_ns);
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(root, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hro.xc->site_id, ra->site_id);
    xnet_msg_fill_cmd(msg, HVFS_FR2_RU, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* Step 1: pack the MDS ring */
    gid = ra->gid_ns << 2;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup() gid %d failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send;
    }

    err = ring_mgr_compact_one(&hro.ring, gid,
                               &ring_data, &ring_len);
    if (err) {
        hvfs_err(root, "ring_mgr_compact_one() failed w/ %d\n",
                 err);
        ring_mgr_put(ring);
        goto send;
    }
    err = __pack_msg(msg, ring_data, ring_len);
    if (err) {
        hvfs_err(root, "pack ring %d failed w/ %d\n",
                 gid, err);
        goto send;
    }
    ring_mgr_put(ring);
    /* Step 2: pack the MDSL ring */
    gid = ra->gid_ns << 2 | CH_RING_MDSL;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup() gid %d failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send;
    }

    err = ring_mgr_compact_one(&hro.ring, gid,
                               &ring_data2, &ring_len2);
    if (err) {
        hvfs_err(root, "ring_mgr_compact_one() failed w/ %d\n",
                 err);
        ring_mgr_put(ring);
        goto send;
    }
    err = __pack_msg(msg, ring_data2, ring_len2);
    if (err) {
        hvfs_err(root, "pack ring %d failed w/ %d\n",
                 gid, err);
        goto send;
    }
    ring_mgr_put(ring);

    /* Step 3: send the message to receiver */
send:
    if (err) {
        xnet_msg_set_err(msg, err);
    }
    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(root, "xnet_send() to %lx failed\n", ra->site_id);
        goto out_msg;
    }

    /* Step 4: free memory */
out_msg:
    xfree(ring_data);
    xfree(ring_data2);

    xnet_free_msg(msg);
out:
    return ERR_PTR(err);
}

/* snapshot level: (DO NOT CHANGE!)
 *
 * 0: snapstho w/ memory commit;
 * 1: snapshot w/ memory commit and request pause;
 * 2: snapshot w/ memory commit and request drop;
 * 3: snapstho w/ memory commit and reqeust error;
 */
#define SNAP_CACHE              0
#define SNAP_CACHE_PAUSE        1
#define SNAP_CACHE_DROP         2
#define SNAP_CACHE_ERR          3
int __cli_trigger_snapshot(u64 site_id, int level)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(root, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hro.xc->site_id, site_id);
    /* Note that, arg1 == 1 means to pause client/amc requests handling! */
    xnet_msg_fill_cmd(msg, HVFS_R22MDS_COMMIT, site_id, level);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(root, "xnet_send() to %lx failed\n", site_id);
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

/* Resume level:
 *
 * 0: defautl
 * 1: change state to ONLINE(Running)
 */
int __cli_resume(u64 site_id, int level)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hro.xc->site_id, site_id);
    xnet_msg_fill_cmd(msg, HVFS_R22MDS_RESUME, site_id, level);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(root, "xnet_send() to %lx failed\n", site_id);
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

struct addr_args
{
    u64 site_id;                /* site id filled by traverse function */
    u32 state;                  /* site state filled by traverse function */

    int len;
    void *data;
};

void *__cli_send_addr_table(void *args)
{
    struct xnet_msg *msg;
    struct addr_args *aa = (struct addr_args *)args;
    int err = 0;

    if (aa->state == SE_STATE_INIT ||
        aa->state == SE_STATE_SHUTDOWN) {
        return NULL;
    }
    
    hvfs_info(root, "Send addr table to %lx len %d\n", aa->site_id, aa->len);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(root, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hro.xc->site_id, aa->site_id);
    xnet_msg_fill_cmd(msg, HVFS_FR2_AU, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* Step 1: pack the addr table */
    err = __pack_msg(msg, aa->data, aa->len);
    if (err) {
        hvfs_err(root, "pack addr table len %d failed w/ %d\n",
                 aa->len, err);
        goto send;
    }

    /* Step 2: send the message to receiver */
send:
    if (err) {
        xnet_msg_set_err(msg, err);
    }
    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(root, "xnet_send() to %lx failed\n", aa->site_id);
        goto out_msg;
    }
out_msg:
    xnet_free_msg(msg);
out:
    return ERR_PTR(err);
}

/* __add2ring() add one site to the CH ring w/ ring_vid_max entries
 */
int __add2ring(struct chring *r, u64 site)
{
    struct chp *p;
    char buf[256];
    int vid_max, i, err;

    vid_max = hro.conf.ring_vid_max ? hro.conf.ring_vid_max : 
        HVFS_RING_VID_MAX;

    p = (struct chp *)xzalloc(vid_max * sizeof(struct chp));
    if (!p) {
        hvfs_err(root, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < vid_max; i++) {
        snprintf(buf, 256, "%ld.%d", site, i);
        (p + i)->point = hvfs_hash(site, (u64)buf, strlen(buf), 
                                   HASH_SEL_VSITE);
        (p + i)->vid = i;
        (p + i)->type = CHP_AUTO;
        (p + i)->site_id = site;
        err = ring_add_point_nosort(p + i, r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }

    return 0;
}

int cli_dynamic_add_site(struct ring_entry *re, u64 site_id)
{
    struct ring_range *rr = NULL;
    struct chp *p = NULL;
    struct xnet_group *xg = NULL;
    static atomic_t progress = {.counter = 0,};
    struct ring_args ra = {.gid_ns = 0,};
    int err = 0, i;

    if (atomic_inc_return(&progress) > 1) {
        atomic_dec(&progress);
        return -EINVAL;
    }
    
    /* Step 1: change the ring by insert the site to the topn large ranges */
    err = cli_find_topn(re, hro.conf.ring_vid_max, &rr);
    if (err == -EISEMPTY) {
        hvfs_warning(root, "empty CH ring, just do insert.\n");
        /* just add the site to the ring */
        err = __add2ring(&re->ring, site_id);
        if (err) {
            hvfs_err(root, "add site %lx to ring failed\n", site_id);
            goto out;
        }
        goto bcast;
    } else if (err) {
        hvfs_err(root, "cli_find_topn() failed w/ %d\n", err);
        goto out;
    }
        
    /* Step 2: find the previous governer of the new added chp, and notify
     * them to pause modification and flush their dirty content to mdsl */
    for (i = 0; i < hro.conf.ring_vid_max; i++) {
        p = ring_get_point2(rr[i].end, &re->ring);
        if (IS_ERR(p)) {
            hvfs_err(root, "ring_get_point2() failed w/ %ld\n", PTR_ERR(p));
            goto out_free;
        }
        err = xnet_group_add(&xg, p->site_id);
    }
    for (i = 0; i < xg->asize; i++) {
        hvfs_info(root, "Try to send pasue and evict message to %lx\n", 
                   xg->sites[i].site_id);
        err = __cli_trigger_snapshot(xg->sites[i].site_id, SNAP_CACHE_PAUSE);
        if (err) {
            hvfs_err(root, "trigger a snapshot on site %lx failed w/ %d\n",
                     xg->sites[i].site_id, err);
            goto out_free;
        }
    }

    /* Step 3: commit and broadcast the new ring */
    err = cli_range_add(re, site_id, hro.conf.ring_vid_max, rr);
    if (err) {
        hvfs_err(root, "cli_range_add() failed w/ %d\n", err);
        goto out_free;
    }
    /* bcast the ring */
bcast:
    err = site_mgr_traverse(&hro.site, __cli_send_rings, &ra);
    if (err) {
        hvfs_err(root, "bcast the ring failed w/ %d\n", err);
        goto out_free;
    }

    /* add the new site to the group */
    err = xnet_group_add(&xg, site_id);
    
    /* resume request handling */
    for (i = 0; i < xg->asize; i++) {
        err = __cli_resume(xg->sites[i].site_id, 1);
        if (err) {
            hvfs_err(root, "resume the request handling on site %lx "
                     "failed w/ %d\n", xg->sites[i].site_id, err);
            goto out_free;
        }
    }

out_free:
    xfree(rr);
out:
    atomic_dec(&progress);
    
    return err;
}

int cli_dynamic_del_site(struct ring_entry *re, u64 site_id, int force)
{
    static atomic_t progress = {.counter = 0,};
    struct ring_args ra = {.gid_ns = 0,};
    int err = 0;

    if (atomic_inc_return(&progress) > 1) {
        atomic_dec(&progress);
        return -EINVAL;
    }
    
    /* Step 1: snapshot the infected site now */
    err = __cli_trigger_snapshot(site_id, SNAP_CACHE_ERR);
    if (err) {
        hvfs_err(root, "try to snapshot on %lx failed w/ %d\n",
                 site_id, err);
        if (!force)
            goto out;
        else
            hvfs_warning(root, "delete site %lx forcely, maybe data losing\n",
                         site_id);
    }

    /* Step 2: change the ring */
    err = cli_find_del_site(re, site_id);
    if (err) {
        hvfs_err(root, "find and delete %lx from the ring failed w/ %d\n",
                 site_id, err);
        goto out;
    }

    /* Step 3: bcast the ring */
    err = site_mgr_traverse(&hro.site, __cli_send_rings, &ra);
    if (err) {
        hvfs_err(root, "bcast the ring failed w/ %d\n", err);
        goto out;
    }

out:
    atomic_dec(&progress);

    return err;
}

struct xnet_group *cli_get_active_site(struct chring *r)
{
    struct xnet_group *xg = NULL;
    int i, err;

    for (i = 0; i < r->used; i++) {
        err = xnet_group_add(&xg, r->array[i].site_id);
    }

    return xg;
}

/* cli_do_addsite manipulate the address table!
 */
int cli_do_addsite(struct sockaddr_in *sin, u64 fsid, u64 site_id)
{
    struct addr_args aa;
    struct addr_entry *ae;
    int err = 0;

    site_id = hst_find_free(site_id);
    
    err = addr_mgr_lookup_create(&hro.addr, fsid, &ae);
    if (err > 0) {
        hvfs_info(root, "Create addr table for fsid %ld\n", 
                  fsid);
    } else if (err < 0) {
        hvfs_err(root, "addr_mgr_lookup_create() fsid %ld failed w/ %d\n",
                 fsid, err);
        goto out;
    }

    err = addr_mgr_update_one(ae, HVFS_SITE_PROTOCOL_TCP |
                              HVFS_SITE_REPLACE,
                              site_id,
                              sin);
    if (err) {
        hvfs_err(xnet, "addr_mgr_update entry %lx failed w/ %d\n",
                 site_id, err);
        goto out;
    }

    /* export the new addr to st_table */
    {
        void *data;
        int len;

        err = addr_mgr_compact_one(ae, site_id, HVFS_SITE_REPLACE, 
                                   &data, &len);
        if (err) {
            hvfs_err(xnet, "compact addr mgr failed w/ %d\n", err);
            goto out;
        }

        err = hst_to_xsst(data, len);
        if (err) {
            hvfs_err(xnet, "hst to xsst failed w/ %d\n", err);
            xfree(data);
            goto out;
        }

        /* trigger an addr table update now */
        aa.data = data;
        aa.len = len;
        err = site_mgr_traverse(&hro.site, __cli_send_addr_table, &aa);
        if (err) {
            hvfs_err(root, "bcast the address table failed w/ %d\n", err);
            xfree(data);
            goto out;
        }

        xfree(data);
    }
out:
    return err;
}

int cli_do_rmvsite(struct sockaddr_in *sin, u64 fsid, u64 site_id)
{
    struct addr_args aa;
    struct addr_entry *ae;
    int err = 0;

    ae = addr_mgr_lookup(&hro.addr, fsid);
    if (IS_ERR(ae)) {
        hvfs_err(root, "addr_mgr_lookup() fsid %ld failed w/ %ld\n",
                 fsid, PTR_ERR(ae));
        err = PTR_ERR(ae);
        goto out;
    }

    /* export the new addr to st_table */
    {
        void *data;
        int len;

        err = addr_mgr_compact_one(ae, site_id, HVFS_SITE_DEL,
                                   &data, &len);
        if (err) {
            hvfs_err(xnet, "compact addr mgr failed w/ %d\n", err);
            goto out;
        }

        err = hst_to_xsst(data, len);
        if (err) {
            hvfs_err(xnet, "hst to xsst failed w/ %d\n", err);
            xfree(data);
            goto out;
        }

        err = addr_mgr_update_one(ae, HVFS_SITE_PROTOCOL_TCP |
                                  HVFS_SITE_DEL,
                                  site_id, sin);
        if (err) {
            hvfs_err(xnet, "addr_mgr_update entry %lx failed w/ %d\n",
                     site_id, err);
            xfree(data);
            goto out;
        }

        /* trigger an addr table update now */
        aa.data = data;
        aa.len = len;
        err = site_mgr_traverse(&hro.site, __cli_send_addr_table, &aa);
        if (err) {
            hvfs_err(root, "bcast the address table failed w/ %d\n", err);
            xfree(data);
            goto out;
        }

        xfree(data);
    }
    
out:
    return err;
}

struct site_info_args
{
    u64 site_id;
    u32 state;

    u32 flag;
    u32 init, normal, transient, error, shutdown;
};

static inline
void __sia_analyze_state(struct site_info_args *sia)
{
    switch (sia->state) {
    case SE_STATE_INIT:
        sia->init++;
        break;
    case SE_STATE_NORMAL:
        sia->normal++;
        break;
    case SE_STATE_TRANSIENT:
        sia->transient++;
        break;
    case SE_STATE_ERROR:
        sia->error++;
        break;
    case SE_STATE_SHUTDOWN:
        sia->shutdown++;
        break;
    default:;
    }
}

void *__cli_get_site_info(void *args)
{
    struct site_info_args *sia = args;

    switch (sia->flag & HVFS_SYSINFO_SITE_MASK) {
    case HVFS_SYSINFO_SITE_ALL:
        __sia_analyze_state(sia);
        break;
    case HVFS_SYSINFO_SITE_MDS:
        if (HVFS_IS_MDS(sia->site_id))
            __sia_analyze_state(sia);
        break;
    case HVFS_SYSINFO_SITE_MDSL:
        if (HVFS_IS_MDSL(sia->site_id))
            __sia_analyze_state(sia);
        break;
    case HVFS_SYSINFO_SITE_CLIENT:
        if (HVFS_IS_CLIENT(sia->site_id))
            __sia_analyze_state(sia);
        break;
    case HVFS_SYSINFO_SITE_BP:
        if (HVFS_IS_BP(sia->site_id))
            __sia_analyze_state(sia);
        break;
    case HVFS_SYSINFO_SITE_R2:
        if (HVFS_IS_ROOT(sia->site_id))
            __sia_analyze_state(sia);
        break;
    default:;
    }
    
    return NULL;
}

static inline
char *__sysinfo_type(u64 arg)
{
    switch (arg & HVFS_SYSINFO_SITE_MASK) {
    case HVFS_SYSINFO_SITE_ALL:
        return "All sites";
    case HVFS_SYSINFO_SITE_MDS:
        return "MDS sites";
    case HVFS_SYSINFO_SITE_MDSL:
        return "MDSL sites";
    case HVFS_SYSINFO_SITE_CLIENT:
        return "Client sites";
    case HVFS_SYSINFO_SITE_BP:
        return "BP sites";
    case HVFS_SYSINFO_SITE_R2:
        return "R2 sites";
    default:
        return "Unknown sites";
    }
    return "Unkonw sites";
}

int root_info_site(u64 arg, void **buf)
{
    struct site_info_args sia;
    char *p;
    int err = 0;

    memset(&sia, 0, sizeof(sia));
    sia.flag = arg;
    
    err = site_mgr_traverse(&hro.site, __cli_get_site_info, &sia);
    if (err) {
        hvfs_err(root, "Traverse site table failed w/ %d\n", err);
        goto out;
    }

    p = xzalloc(512);
    if (!p) {
        err = -ENOMEM;
        goto out;
    }
    *buf = (void *)p;

    p += sprintf(p, "%s total %d active %d inactive %d indoubt %d\n",
                 __sysinfo_type(arg),
                 sia.init + sia.normal + sia.transient + sia.error + 
                 sia.shutdown,
                 sia.normal,
                 sia.init + sia.shutdown,
                 sia.transient + sia.error);
    p += sprintf(p, " -> [INIT] %d [NORM] %d [TRAN] %d [ERROR] %d "
                 "[SHUTDOWN] %d\n",
                 sia.init, sia.normal, sia.transient,
                 sia.error, sia.shutdown);

out:
    return err;
}
