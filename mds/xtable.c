/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 19:21:36 macan>
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
#include "xtable.h"
#include "ring.h"
#include "lib.h"
#include "mds.h"

/* ITB split
 *
 * NOTE: 
 */
int itb_split(struct itb *oi, struct itb **ni)
{
    int err = 0;

    return err;
}

/* ITB overflow
 *
 * NOTE:
 */
int itb_overflow(struct itb *oi, struct itb **ni)
{
    int err = 0;

    return err;
}

/* mds_bitmap_lookup()
 *
 * Test the offset in this slice, return the bit!
 */
int mds_bitmap_lookup(struct itbitmap *b, u64 offset)
{
    int index = offset - b->offset;

    ASSERT((index >= 0 && index < XTABLE_BITMAP_SIZE), mds);
    return test_bit(index, (u64 *)(b->array));
}

/* mds_bitmap_fallback()
 *
 * Fallback to the next location of ITB
 */
u64 mds_bitmap_fallback(u64 offset)
{
    int nr = fls(offset);       /* NOTE: we just use the low 32 bits */

    if (!nr)
        return 0;
    __clear_bit(nr - 1, &offset);
    return offset;
}

/* mds_bitmap_update()
 *
 * Update the old bitmap with the new bitmap. For now, we just OR the new
 * bitmap to the old bitmap:,(
 */
void mds_bitmap_update(struct itbitmap *o, struct itbitmap *n)
{
    u64 *op = (u64 *)o->array;
    u64 *np = (u64 *)n->array;
    int i;
    
    o->ts = n->ts;
    for (i = 0; i < (XTABLE_BITMAP_SIZE / sizeof(u64)); i++) {
        *(op + i) |= *(np + i);
    }
}

/* mds_bitmap_load()
 *
 * Return Value: -ENOEXIST means the slice is not exist!
 */
int mds_bitmap_load(struct dhe *e, u64 offset)
{
    struct hvfs_md_reply *hmr;
    struct xnet_msg *msg;
    struct chp *p;
    struct itbitmap *bitmap, *b;
    int err, no;
    
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return -ENOMEM;
        }
    }

    /* check if we are loading the GDT bitmap */
    if (unlikely(e->uuid == hmi.gdt_uuid)) {
        /* ok, we should send the request to the ROOT server */
        goto send_msg;
    }
    
    /* find the MDS server */
    p = ring_get_point(e->uuid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        return PTR_ERR(p);
    }
    /* prepare the msg */
    xnet_msg_set_site(msg, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LB, e->uuid, offset);

send_msg:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
        goto out_free;
    }
    /* ok, we get the reply: have the bitmap slice in the reply msg */
    hmr = (struct hvfs_md_reply *)(msg->pair->xm_data);
    if (hmr->err) {
        hvfs_err(mds, "bitmap_load request failed %d\n", hmr->err);
        goto out_free;
    }
    bitmap = hmr_extract(hmr, EXTRACT_BITMAP, &no);
    if (!bitmap) {
        hvfs_err(mds, "hmr_extract BITMAP failed, not found this subregion.\n");
        goto out_free;
    }
    /* hey, we got some bitmap slice, let us insert them to the dhe list */
    xlock_lock(&e->lock);
    if (!list_empty(&e->bitmap)) {
        list_for_each_entry(b, &e->bitmap, list) {
            if (b->offset < offset)
                continue;
            if (b->offset == offset) {
                /* hoo, someone insert the bitmap prior us, we just update our
                 * bitmap to the previous one */
                mds_bitmap_update(b, bitmap);
                break;
            }
            if (b->offset > offset) {
                /* ok, insert ourself prior this slice */
                list_add_tail(&bitmap->list, &b->list);
                /* FIXME: XNET clear the auto free flag */
                xnet_clear_auto_free(msg->pair);
                break;
            }
        }
    } else {
        /* ok, this is an empty list */
        list_add_tail(&bitmap->list, &e->bitmap);
        /* FIXME: XNET clear the auto free flag */
        xnet_clear_auto_free(msg->pair);
    }
    xlock_unlock(&e->lock);

out_free:
    xnet_free_msg(msg);
    return err;
}

/* mds_bitmap_free()
 */
void mds_bitmap_free(struct itbitmap *b)
{
    xfree(b);
}

/* __mds_bitmap_insert()
 *
 * This function is ONLY used by the UNIT TEST program
 */
int __mds_bitmap_insert(struct dhe *e, struct itbitmap *b)
{
    struct itbitmap *pos;
    int err = -EEXIST;

    xlock_lock(&e->lock);
    if (!list_empty(&e->bitmap)) {
        list_for_each_entry(pos, &e->bitmap, list) {
            if (pos->offset < b->offset)
                continue;
            if (pos->offset == b->offset) {
                mds_bitmap_update(pos, b);
                break;
            }
            if (pos->offset > b->offset) {
                list_add_tail(&b->list, &pos->list);
                err = 0;
                break;
            }
        }
    } else {
        /* ok, this is an empty list */
        list_add_tail(&b->list, &e->bitmap);
        err = 0;
    }
    xlock_unlock(&e->lock);

    return err;
}
