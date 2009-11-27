/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-27 15:24:04 macan>
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

#include "ring.h"

u64 ring_hash(u64 key, u64 salt)
{
    u64 val1, val2;
    
    val1 = hash_64(salt, 64);
    val2 = hash_64(key, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

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

struct chp *ring_get_point(u64 key, u64 salt, struct chring *r)
{
    return ring_get_point2(ring_hash(key, salt), r);
}

struct chp *ring_get_point2(u64 point, struct chring *r)
{
    s64 highp = r->used;
    s64 lowp = 0, midp;
    u64 midval, midval1;
    struct chp *p;
    
    if (!r || !r->used)
        return ERR_PTR(-EINVAL);

    xrwlock_rlock(&r->rwlock);
    while (1) {
        midp = (lowp + highp) / 2;
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

void ring_dump(struct chring *r)
{
    int i;
    if (!r)
        return;

    hvfs_info(lib, "Ring %d with %d(%d) entries:\n", r->group, 
              r->used, r->alloc);
    for (i = 0; i < r->used; i++) {
        hvfs_info(lib, "%16d: %50ld\n", i, r->array[i].point);
    }
}

#ifdef UNIT_TEST
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

    ring_free(r);
    return 0;
}
#endif
