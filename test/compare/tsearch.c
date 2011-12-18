/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-15 21:41:11 macan>
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

/* This tsearch.c try to maintain a binary tree for ranges. Each tree node
 * represents a valid file range. On inserting, ranges are merged
 * automatically.
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <search.h>

#define _GNU_SOURCE

struct tnode 
{
    unsigned long low, high;
};

void *root = NULL;
static unsigned long lastv = 0;

int compare(const void *pa, const void *pb)
{
    const struct tnode *a = pa;
    const struct tnode *b = pb;

    if (a->high < b->low)
        return -1;
    if (a->low > b->high)
        return 1;
    return 0;
}

void action(const void *nodep, const VISIT which, const int depth)
{
    struct tnode *p;

    switch (which) {
    case preorder:
        break;
    case postorder:
        p = *(struct tnode **)nodep;
        printf("I[%ld,%ld)\n", p->low, p->high);
        if (p->low > lastv)
            printf("Detect hole [%ld,%ld)\n", lastv, p->low);
        lastv = p->high;
        break;
    case endorder:
        break;
    case leaf:
        p = *(struct tnode **)nodep;
        printf("L[%ld,%ld)\n", p->low, p->high);
        if (p->low > lastv)
            printf("Detect hole [%ld,%ld)\n", lastv, p->low);
        lastv = p->high;
        break;
    }
}

void do_search(struct tnode *ptr, struct tnode *last)
{
    void *val;
    struct tnode *cur;

    printf("Search [%ld, %ld)\n", ptr->low, ptr->high);
    val = tsearch((void *)ptr, &root, compare);
    if (val == NULL)
        exit(EXIT_FAILURE);
    else if (*((struct tnode **)val) != ptr) {
        cur = *((struct tnode **)val);
        printf("Current [%ld, %ld)\n", cur->low, cur->high);
        if (cur->low >= ptr->low && cur->high <= ptr->high) {
            /* research [ptr.low,cur.low] & [cur.high,ptr.high] C */

            /* delete the old node and research it until we are sure there is
             * no scene C */
            val = tdelete(cur, &root, compare);
            if (val)
                free(cur);
            return do_search(ptr, cur);
        } else if (cur->low <= ptr->low && cur->high >= ptr->high) {
            /* D */
            ;
        } else if (cur->low <= ptr->high && cur->high >= ptr->high) {
            /* research [ptr.low,cur.low] A */
            if (cur != last && ptr->low < cur->low) {
                ptr->high = cur->low;
                return do_search(ptr, cur);
            }
        } else if (cur->high >= ptr->low && cur->high <= ptr->high) {
            /* research [cur.high, ptr.high] B */
            if (cur != last && cur->high < ptr->high) {
                ptr->low = cur->high;
                return do_search(ptr, cur);
            }
        }

        if (ptr->low == cur->high) {
            /* delete the old node and research the large one */
            ptr->low = cur->low;
            val = tdelete(cur, &root, compare);
            if (val)
                free(cur);
            return do_search(ptr, NULL);
        } else if (ptr->high == cur->low) {
            ptr->high = cur->high;
            val = tdelete(cur, &root, compare);
            if (val)
                free(cur);
            return do_search(ptr, NULL);
        }
        free(ptr);
    }
}

int main(void)
{
    int i;
    void *p[200];
    struct tnode *ptr;
    
    srand(time(NULL));
    for (i = 0; i < 200; i++) {
        p[i] = malloc(sizeof(struct tnode));
    }
#if 0
    for (i = 0; i < 200; i++) {
        ptr = (struct tnode *)p[i];
        ptr->low = rand() & 0xff;
        ptr->high = ptr->low + 5;
        printf("A[%ld,%ld)\n", ptr->low, ptr->high);
        do_search(ptr, NULL);
    }
#else
    /* Scene X */
    ptr = (struct tnode *)p[0];
    ptr->low = 50;
    ptr->high = 100;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene C */
    ptr = (struct tnode *)p[1];
    ptr->low = 40;
    ptr->high = 120;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene Y */
    ptr = (struct tnode *)p[2];
    ptr->low = 0;
    ptr->high = 20;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene A */
    ptr = (struct tnode *)p[3];
    ptr->low = 10;
    ptr->high = 50;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene B */
    ptr = (struct tnode *)p[4];
    ptr->low = 100;
    ptr->high = 150;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene Z */
    ptr = (struct tnode *)p[5];
    ptr->low = 160;
    ptr->high = 180;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);

    /* Scene Z */
    ptr = (struct tnode *)p[6];
    ptr->low = 151;
    ptr->high = 159;
    printf("A[%ld,%ld)\n", ptr->low, ptr->high);
    do_search(ptr, NULL);
#endif

    printf("\n");
    twalk(root, action);
    tdestroy(root, free);
    exit(EXIT_SUCCESS);
}
