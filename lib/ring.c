/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-10 15:13:50 macan>
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

#include "lib.h"
#include "ring.h"

struct chring *ring_alloc(int alloc, u32 gid)
{
    struct chring *r;

    r = xzalloc(sizeof(struct chring));
    if (!r)
        return ERR_PTR(-ENOMEM);
    
    alloc >>= RING_ALLOC_FACTOR_SHIFT;
    alloc += 1;
    alloc <<= RING_ALLOC_FACTOR_SHIFT;
    r->array = xzalloc(alloc * sizeof(struct chp));
    if (r->array)
        r->alloc = alloc;
    r->group = gid;
    xrwlock_init(&r->rwlock);

    return r;
}

void ring_free(struct chring *r)
{
    if (!r)
        return;
    if (r->alloc && r->array)
        xfree(r->array);
    xrwlock_destroy(&r->rwlock);
    xfree(r);
}

static int chp_compare(const void *a, const void *b)
{
    return (((struct chp *)a)->point < ((struct chp *)b)->point) ? -1 : 
        ((((struct chp *)a)->point > ((struct chp *)b)->point) ? 1 : 0);
}

#ifdef __KERNEL__
static inline void ring_resort(struct chring *r)
{
    sort(r->array, r->used, sizeof(struct chp), chp_compare, NULL);
}
#else
static inline void ring_resort(struct chring *r)
{
    qsort(r->array, r->used, sizeof(struct chp), chp_compare);
}
#endif

void ring_resort_nolock(struct chring *r)
{
    ring_resort(r);
}

void ring_resort_locked(struct chring *r)
{
    if (!r || !r->array)
        return;

    xrwlock_wlock(&r->rwlock);
    ring_resort(r);
    xrwlock_wunlock(&r->rwlock);
}

int ring_add_point(struct chp *p, struct chring *r)
{
    if (!p || !r)
        return -EINVAL;

    xrwlock_wlock(&r->rwlock);
    /* realloc the array */
    if (r->alloc <= r->used) {
        r->array = xrealloc(r->array, (r->alloc + RING_ALLOC_FACTOR) * 
                            sizeof(struct chp));
        if (!r->array) {
            xrwlock_wunlock(&r->rwlock);
            hvfs_debug(lib, "xrealloc failed\n");
            return -ENOMEM;
        }
        r->alloc += RING_ALLOC_FACTOR;
    }

    ASSERT(r->alloc > r->used, lib);
    r->array[r->used++] = *p;
    ring_resort(r);

    xrwlock_wunlock(&r->rwlock);
    return 0;
}

int ring_add_point_nosort(struct chp *p, struct chring *r)
{
    if (!p || !r)
        return -EINVAL;

    xrwlock_wlock(&r->rwlock);
    /* realloc the array */
    if (r->alloc <= r->used) {
        r->array = xrealloc(r->array, (r->alloc + RING_ALLOC_FACTOR) * 
                            sizeof(struct chp));
        if (!r->array) {
            xrwlock_wunlock(&r->rwlock);
            hvfs_debug(lib, "xrealloc failed\n");
            return -ENOMEM;
        }
        r->alloc += RING_ALLOC_FACTOR;
    }

    ASSERT(r->alloc > r->used, lib);
    r->array[r->used++] = *p;

    xrwlock_wunlock(&r->rwlock);
    return 0;
}

int ring_del_point(struct chp *p, struct chring *r)
{
    struct chp *q;
    
    if (!p || !r)
        return -EINVAL;

    xrwlock_wlock(&r->rwlock);
    /* FIXME */
    for (q = p + 1; q < r->array + r->used; p++, q++) {
        *p = *q;
    }
    r->used--;
    /* no need to sort */
    xrwlock_wunlock(&r->rwlock);
    return 0;
}

static inline
struct chp *__ring_get_point2(u64 point, struct chring *r)
{
    s64 highp;
    s64 lowp = 0, midp;
    u64 midval, midval1;
    struct chp *p;
    
    if (unlikely(!r || !r->used))
        return ERR_PTR(-EINVAL);

    highp = r->used;
    xrwlock_rlock(&r->rwlock);
    while (1) {
        midp = (lowp + highp) >> 1;
        if (midp == r->used) {
            p = &r->array[0];
            goto out;
        }

        midval = r->array[midp].point;
        midval1 = midp == 0 ? 0 : r->array[midp - 1].point;

        if (point <= midval && point > midval1) {
            p = &r->array[midp];
            goto out;
        }

        if (midval < point)
            lowp = midp + 1;
        else
            highp = midp - 1;

        if (lowp > highp) {
            p = &r->array[0];
            goto out;
        }
    }
out:
    xrwlock_runlock(&r->rwlock);
    
    return p;
}

struct chp *ring_get_point2(u64 point, struct chring *r)
{
    return __ring_get_point2(point, r);
}

struct chp *ring_get_point(u64 key, u64 salt, struct chring *r)
{
    return ring_get_point2(hvfs_hash(key, salt, sizeof(salt), 
                                     HASH_SEL_RING), r);
}

/* ABI: we assume that the rr array has at least topn slots
 */
int ring_topn_range(int topn, struct chring *r, struct ring_range *rr)
{
    u64 cur_start, cur_end, cur_dist;
    struct ring_range tmp;
    int i, j;
    
    memset(rr, 0, topn * sizeof(struct ring_range));
    /* setup the N-1 range */
    rr[0].dist = r->array[0].point + 
        (-1UL - r->array[r->used].point);
    rr[0].start = r->array[r->used].point;
    rr[0].end = r->array[0].point;
    
    for (i = 1; i < r->used; i++) {
        cur_dist = r->array[i].point - r->array[i - 1].point;
        cur_start = r->array[i - 1].point;
        cur_end = r->array[i].point;
        for (j = 0; j < topn; j++) {
            if (cur_dist > rr[j].dist) {
                tmp = rr[j];
                rr[j].dist = cur_dist;
                rr[j].start = cur_start;
                rr[j].end = cur_end;
                cur_dist = tmp.dist;
                cur_start = tmp.start;
                cur_end = tmp.end;
            }
        }
    }

    return 0;
}

/* ABI:
 *
 * Return Value: <0 means err; =0 means not found; >0 means found and return
 * the # of found chps.
 */
int ring_find_site(struct chring *r, u64 site_id, void **data)
{
    struct chp **p;
    int nr = 0, i, j;

    if (!r || !data)
        return -EINVAL;
    
    /* first pass, check the # of the hit points */
    for (i = 0; i < r->used; i++) {
        if (r->array[i].site_id == site_id) {
            nr++;
        }
    }
    if (!nr)
        return 0;
    *data = xzalloc(nr * sizeof(struct chp *));
    if (!*data) {
        hvfs_err(lib, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    p = (struct chp **)(*data);
    for (i = 0, j = 0; i < r->used; i++) {
        if (r->array[i].site_id == site_id) {
            *(p + j) = &r->array[i];
            j++;
        }
    }

    return nr;
}

void ring_dump(struct chring *r)
{
    int i;
    
    if (!r)
        return;

    hvfs_debug(lib, "Ring %d with %d(%d) entries:\n", r->group, 
               r->used, r->alloc);
    for (i = 0; i < r->used; i++) {
        hvfs_debug(lib, "%16d: %20lu %20lx\n", i, r->array[i].point,
                   r->array[i].site_id);
    }
}

/* @nr: # of physical sites
 */
void ring_stat(struct chring *r, int nr)
{
    u64 *rglen, last_point = 0;
    int i;

    if (nr <= 0)
        return;

    rglen = xzalloc(nr * sizeof(u64));
    if (!rglen)
        return;
    
    hvfs_info(lib, "Ring Stat:\n");
    for (i = 0; i < r->used; i++) {
        if (i == 0) {
            rglen[r->array[i].site_id - HVFS_MDS(0)] +=
                r->array[i].point;
            rglen[r->array[i].site_id - HVFS_MDS(0)] += (
                0xffffffffffffffff - r->array[r->used].point);
        } else {
            rglen[r->array[i].site_id - HVFS_MDS(0)] += 
                r->array[i].point - last_point;
        }
        last_point = r->array[i].point;
    }
    for (i = 0; i < nr; i++) {
        hvfs_info(lib, "rglen[%d] = %ld %.2f%%\n", i, rglen[i],
                  (double)rglen[i] / 0xffffffffffffffff * 100);
    }
}

#ifdef UNIT_TEST
TRACING_FLAG(lib, HVFS_DEFAULT_LEVEL | HVFS_DEBUG_ALL);

int main(int argc, char *argv[])
{
    struct chring *r;
    struct chp p, *x;
    int ret, i;
    u64 point;

    hvfs_info(lib, "Begin ring unit test: case 1...\n");
    r = ring_alloc(20, 0);
    if (!r) {
        hvfs_err(lib, "ring_alloc() failed.\n");
        return PTR_ERR(r);
    }
    /* add points now */
    srandom(time(NULL));
    for (i = 0; i < 100; i++) {
        memset(&p, 0, sizeof(p));
        p.point = random();
        ret = ring_add_point(&p, r);
        if (ret) {
            hvfs_err(lib, "ring_add_point() failed.\n");
            return ret;
        }
    }
    /* dump the ring now */
    ring_dump(r);
    /* get the point */
    point = 2134132413;
    x = ring_get_point2(point, r);
    hvfs_info(lib, "%ld in R:  %50ld\n", point, x->point);

    ring_free(r);

    hvfs_info(lib, "Begin ring unit test: case 2...\n");
    r = ring_alloc(0, 0);
    if (!r) {
        hvfs_err(lib, "ring_alloc() failed.\n");
        return PTR_ERR(r);
    }
    srandom(time(NULL));
    ring_mem_prepare(r, 100, ret);
    if (ret) {
        hvfs_err(lib, "ring_mem_prepare failed\n");
        return ret;
    }
    for (i = 0; i < 100; i++) {
        memset(&p, 0, sizeof(p));
        p.point = random();
        ring_add_blob(r, i, &p);
    }
    /* ok, first dump it, then sort it */
    hvfs_info(lib, "pre-sort:\n");
    ring_dump(r);
    ring_resort_nolock(r);
    hvfs_info(lib, "after-sort:\n");
    ring_dump(r);

    /* get the point */
    point = 2134132413;
    x = ring_get_point2(point, r);
    if (!IS_ERR(x))
    hvfs_info(lib, "%ld in R:  %50ld\n", point, x->point);

    {
        struct ring_range rr[100] = {0,};
        struct chp p, *p3;
        void *p2;
        int nr = 10, err = 0;
        
        ring_topn_range(nr, r, rr);
        for (i = 0; i < nr; i++) {
            hvfs_info(lib, "TOP %d: pt %lu dist %lu\n",
                      i, rr[i].start, rr[i].dist);
        }
        /* add a point into the largest range */
        p.point = rr[0].start / 2 + rr[0].end / 2;
        p.vid = 0;
        p.type = CHP_MANUAL;
        p.site_id = 0xffff;
        ring_add_point(&p, r);

        ring_dump(r);
        nr = ring_find_site(r, 0xffff, &p2);
        if (nr < 0) {
            hvfs_err(lib, "ring_find_site() failed w/ %d\n", nr);
        } else {
            xfree(p2);
            hvfs_info(lib, "nr = %d\n", nr);
        }
        nr = ring_find_site(r, 0, &p2);
        if (nr < 0) {
            hvfs_err(lib, "ring_find_site() failed w/ %d\n", nr);
        } else {
            xfree(p2);
            hvfs_info(lib, "nr = %d\n", nr);
        }
        
        hvfs_info(lib, "Del the point now ...\n");
        p3 = ring_get_point2(rr[0].start + 1, r);
        if (IS_ERR(p3)) {
            hvfs_err(lib, "ring_get_point2() failed w/ %ld\n",
                     PTR_ERR(p3));
        } else {
            err = ring_del_point(p3, r);
            if (err) {
                hvfs_err(lib, "ring_del_point() failed w/ %d\n",
                         err);
            }
        }
        point = 2134132413;
        x = ring_get_point2(point, r);
        point = x->point;
        x = ring_get_point2(point, r);
        if (!IS_ERR(x))
            hvfs_info(lib, "%ld in R:  %50ld\n", point, x->point);
    }

    ring_dump(r);
    
    ring_free(r);
    return 0;
}
#endif
