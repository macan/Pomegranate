/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-07-12 15:39:41 macan>
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
 * Return Value: >=0 # of changed ranges, <0 err
 */
int cli_find_topn_add(struct ring_entry *re, u64 site_id, int vnr)
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
            err = cli_add_vsite(re, rr[i].start / 2 + rr[i].end / 2,
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

int cli_dynamic_add_site(struct ring_entry *re, u64 site_id)
{
    int err = 0;
    
    /* Step 1: change the ring by insert the site to the topn large ranges */
    err = cli_find_topn_add(re, site_id, hro.conf.ring_vid_max);
    if (err) {
        hvfs_err(root, "cli_find_topn_add() failed w/ %d\n", err);
        goto out;
    }
        
    /* Step 2: find the previous governer of the new added chp, and notify
     * them to pause modification and flush their dirty content to mdsl */
    /* Step 3: broadcast the new ring */
out:
    return err;
}

