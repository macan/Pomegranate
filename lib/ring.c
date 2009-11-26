/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-26 21:16:30 macan>
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

    return val;
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

    return r;
}

void ring_free(struct chring *r)
{
    if (!r)
        return;
    if (r->alloc && r->array)
        xfree(r->array);
    xfree(r);
}

static int chp_compare(const void *a, const void *b)
{
    return ((struct chp *)a->point < (struct chp *)b->point) ? -1 : 
        (((struct chp *)a->point > (struct chp *)b->point) ? 1 : 0);
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

void ring_resort_locked(struct chring *r)
{
    if (!r || !r->array)
        return -EINVAL;

    xrwlock_wlock(&r->lock);
    ring_resort(r);
    xrwlock_wunlock(&r->lock);
}

int ring_add_point(struct chp *p, struct chring *r)
{
    if (!p || !r)
        return -EINVAL;

    xrwlock_wlock(&r->lock);
    /* realloc the array */
    if (r->alloc <= r->used) {
        r->array = xrealloc(r->array, (r->alloc + RING_ALLOC_FACTOR) * 
                            sizeof(struct chp));
        if (!r->array) {
            xrwlock_wunlock(&r->lock);
            hvfs_debug(lib, "xrealloc failed\n");
            return -ENOMEM;
        }
        r->alloc += RING_ALLOC_FACTOR;
    }

    ASSERT(r->alloc > r->used);
    r->array[r->used++] = *p;
    ring_resort(r);

    xrwlock_wunlock(&r->lock);
    return 0;
}

int ring_del_point(struct chp *p, struct chring *r)
{
    struct chp *q;
    
    if (!p || !r)
        return -EINVAL;

    xrwlock_wlock(&r->lock);
    /* FIXME */
    for (q = p + 1; q < r->array + r->used; p++, q++) {
        *p = *q;
    }
    r->used--;
    /* no need to sort */
    xrwlock_wunlock(&r->lock);
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
    
    if (!r)
        return ERR_PTR(-EINVAL);

    xrwlock_rlock(&r->lock);
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
    xrwlock_runlock(&r->lock);
    return p;
}

void ring_dump(struct chring *r)
{
    if (!r)
        return;

    hvfs_info("Ring %d with %d entries:\n", r->group, r->used);
    for (i = 0; i < r->used; i++) {
        hvfs_info(lib, "%16d: %50d\n", i, r->array[i]);
    }
}
