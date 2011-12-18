/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-17 00:10:48 macan>
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

typedef void (*cb_t)(u64, u64, void *);

static cb_t cb_on_hole = NULL, cb_on_range = NULL;
static void *cb_on_hole_arg = NULL, *cb_on_range_arg = NULL;
static u64 lastv = 0;

static int compare(const void *pa, const void *pb)
{
    const struct brtnode *a = pa;
    const struct brtnode *b = pb;

    if (a->high < b->low)
        return -1;
    if (a->low > b->high)
        return 1;
    return 0;
}

void __do_search(struct brtnode *ptr, struct brtnode *last, void **root)
{
    void *val;
    struct brtnode *cur;

    val = tsearch((void *)ptr, root, compare);
    if (val == NULL) {
        /* release the pointer */
        xfree(ptr);
        return;
    } else if (*((struct brtnode **)val) != ptr) {
        cur = *((struct brtnode **)val);

        if (cur->low >= ptr->low && cur->high <= ptr->high) {
            /* research [ptr.low,cur.low] & [cur.high,ptr.high] C */
            
            /* delete the old node and research it until we are sure there is
             * no scene C */
            val = tdelete(cur, root, compare);
            if (val)
                xfree(cur);
            return __do_search(ptr, cur, root);
        } else if (cur->low <= ptr->low && cur->high >= ptr->high) {
            /* D */
            ;
        } else if (cur->low <= ptr->high && cur->high >= ptr->high) {
            /* research [ptr.low,cur.low] A */
            if (cur != last && ptr->low < cur->low) {
                ptr->high = cur->low;
                return __do_search(ptr, cur, root);
            }
        } else if (cur->high >= ptr->low && cur->high <= ptr->high) {
            /* research [cur.high, ptr.high] B */
            if (cur != last && cur->high < ptr->high) {
                ptr->low = cur->high;
                return __do_search(ptr, cur, root);
            }
        }

        if (ptr->low == cur->high) {
            /* delete the old node and research the large one */
            ptr->low = cur->low;
            val = tdelete(cur, root, compare);
            if (val)
                xfree(cur);
            return __do_search(ptr, NULL, root);
        } else if (ptr->high == cur->low) {
            ptr->high = cur->high;
            val = tdelete(cur, root, compare);
            if (val)
                xfree(cur);
            return __do_search(ptr, NULL, root);
        }
        xfree(ptr);
    }
}

/* brt_add() add a br tree node into the tree. Automatically merging!
 */
int brt_add(struct brtnode *n, void **rootp)
{
    __do_search(n, NULL, rootp);

    return 0;
}

/* brt_del() delete a brt range from the tree.
 */
int brt_del(u64 low, u64 high, void **rootp)
{
    hvfs_err(lib, "BR Tree does NOT support deleting now!\n");
    return -ENOSYS;
}

/* brt_destroy() destroy a brt range tree
 */
void brt_destroy(void *root, void (*free_node)(void *p))
{
    tdestroy(root, free_node);
}

/* action_on_holes() call the cb function when detect a range hole
 */
static void action_on_holes(const void *nodep, const VISIT which, 
                            const int depth)
{
    struct brtnode *p;

    switch (which) {
    case preorder:
        break;
    case postorder:
        p = *(struct brtnode **)nodep;
        if (p->low > lastv)
            cb_on_hole(lastv, p->low, cb_on_hole_arg);
        lastv = p->high;
        break;
    case endorder:
        break;
    case leaf:
        p = *(struct brtnode **)nodep;
        if (p->low > lastv)
            cb_on_hole(lastv, p->low, cb_on_hole_arg);
        lastv = p->high;
        break;
    }
}

/* action_on_ranges() call the cb function when detect a valid range
 */
static void action_on_ranges(const void *nodep, const VISIT which,
                             const int depth)
{
    struct brtnode *p;

    switch (which) {
    case preorder:
        break;
    case postorder:
        p = *(struct brtnode **)nodep;
        cb_on_range(p->low, p->high, cb_on_range_arg);
        break;
    case endorder:
        break;
    case leaf:
        p = *(struct brtnode **)nodep;
        cb_on_range(p->low, p->high, cb_on_range_arg);
        break;
    }
}

/* brt_loop_on_holes() loop on range holes
 *
 * Note: we ONLY support one loop walker for each type on ALL the trees
 */
int brt_loop_on_holes(void **rootp, void *arg, 
                      void (*cb)(u64 low, u64 high, void *arg))
{
    if (!*rootp)
        return 0;
    
    if (cb_on_hole) {
        hvfs_err(lib, "An active loop walker on holes is running, "
                 "please wait!\n");
        return -EBUSY;
    }
    cb_on_hole = cb;
    cb_on_hole_arg = arg;
    lastv = 0;

    twalk(*rootp, action_on_holes);

    cb_on_hole = NULL;

    return 0;
}

/* brt_loop_on_ranges() loop on ranges
 *
 * Note: we ONLY support one loop walker for each type on ALL the trees
 */
int brt_loop_on_ranges(void **rootp, void *arg, 
                       void (*cb)(u64 low, u64 high, void *arg))
{
    if (!*rootp)
        return 0;
    
    if (cb_on_range) {
        hvfs_err(lib, "An active loop walker on holes is running, "
                 "please wait!\n");
        return -EBUSY;
    }
    cb_on_range = cb;
    cb_on_range_arg = arg;

    twalk(*rootp, action_on_ranges);

    cb_on_range = NULL;

    return 0;
}

