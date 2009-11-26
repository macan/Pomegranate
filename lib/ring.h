/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-26 20:40:30 macan>
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

/* point on the consistent hash ring */
struct chp 
{
    u64 point;                  /* point on the ring */
    u32 vid;                    /* virtual id of the machine */
#define CHP_AUTO        0x00
#define CHP_MANUAL      0x01
    u32 type;                   /* auto or manual */
    u64 site_id;                /* the site id of the server */
};

struct chring 
{
    u32 alloc;                  /* point allocated */
    u32 used;                   /* point used */
    u32 group;
    struct xrwlock rwlock;      /* protect the array */
    struct chp *array;          /* array of struct chp, sorted by `point' */
};

#define RING_ALLOC_FACTOR       32
#define RING_ALLOC_FACTOR_SHIFT 5

/* Allocate a ring */
struct chring *ring_alloc(int alloc, u32 gid);

/* Free a ring */
void ring_free(struct chring *r);

int ring_resort(struct chring *r);
int ring_add_point(struct chp *p, struct chring *r);

/* Get the point in the ring */
struct chp *ring_get_point(u64 key, u64 salt, struct chring *r);

/* Dump the consistent hash ring */
void ring_dump(struct chring *r);

/* Ring Hash function, using what? */
u64 ring_hash(u64 key, u64 salt);

