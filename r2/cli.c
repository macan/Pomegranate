/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-11 14:59:04 macan>
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
    struct chp *p = NULL;
    int nr, i, err;

    nr = ring_find_site(&re->ring, site_id, &p);
    if (nr < 0 || !p) {
        hvfs_err(root, "ring_find_site() failed /w %d\n", nr);
        return nr;
    }

    for (i = 0; i < nr; i++) {
        err = ring_del_point(p + i, &re->ring);
        if (err) {
            hvfs_err(root, "ring_del_point() failed w/ %d\n", err);
        }
    }

    return 0;
}

int __cli_trigger_snapshot(u64 site_id)
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
    /* Note that, arg1 == 1 means to pause client/amc requests handling! */
    xnet_msg_fill_cmd(msg, HVFS_R22MDS_COMMIT, site_id, 1);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() to %lx failed\n", site_id);
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

int __cli_resume(u64 site_id)
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
    xnet_msg_fill_cmd(msg, HVFS_R22MDS_RESUME, site_id, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() to %lx failed\n", site_id);
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

int cli_dynamic_add_site(struct ring_entry *re, u64 site_id)
{
    struct ring_range *rr = NULL;
    struct chp *p = NULL;
    struct xnet_group *xg = NULL;
    static atomic_t progress = {.counter = 0,};
    int err = 0, i;

    if (atomic_inc_return(&progress) > 1) {
        atomic_dec(&progress);
        return -EINVAL;
    }
    
    /* Step 1: change the ring by insert the site to the topn large ranges */
    err = cli_find_topn(re, hro.conf.ring_vid_max, &rr);
    if (err) {
        hvfs_err(root, "cli_find_topn_add() failed w/ %d\n", err);
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
        err = __cli_trigger_snapshot(xg->sites[i].site_id);
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
    err = site_mgr_traverse(&hro.site, NULL);
    if (err) {
        hvfs_err(root, "bcast the ring failed w/ %d\n", err);
        goto out_free;
    }
    
    /* resume request handling */
    for (i = 0; i < xg->asize; i++) {
        err = __cli_resume(xg->sites[i].site_id);
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

int cli_dynamic_del_site(struct ring_entry *re, u64 site_id)
{
    static atomic_t progress = {.counter = 0,};
    int err = 0;

    if (atomic_inc_return(&progress) > 1) {
        atomic_dec(&progress);
        return -EINVAL;
    }
    
    /* Step 1: snapshot the infected site now */
    err = __cli_trigger_snapshot(site_id);
    if (err) {
        hvfs_err(root, "try to snapshot on %lx failed w/ %d\n",
                 site_id, err);
        goto out;
    }

    /* Step 2: change the ring */
    err = cli_find_del_site(re, site_id);
    if (err) {
        hvfs_err(root, "find and delete %lx from the ring failed w/ %d\n",
                 site_id, err);
        goto out;
    }

    /* Step 3: bcast the ring */
    err = site_mgr_traverse(&hro.site, NULL);
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
