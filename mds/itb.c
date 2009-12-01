/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-01 16:23:16 macan>
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

#include "xtable.h"
#include "hvfs.h"

itb_add_ite();
itb_search();
get_free_itb();
free_itb();

struct itb *mds_read_itb(u64 puuid, u64 psalt, u64 itbid)
{
    struct storage_index si;
    struct storage_result *sr;
    struct xnet_msg *msg;
    struct chp *p;
    struct itb *i;
    int ret;

    si.sic.uuid = puuid;
    si.sic.arg0 = itbid;
    si.m.sm.len = 0;            /* no data */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(mds, "xnet_alloc_msg() failed with %d\n", 
                     PTR_ERR(msg));
            return msg;         /* return the err */
        }
    }
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed with %d\n", PTR_ERR(p));
        return p;
    }
    /* prepare the msg */
    xnet_msg_set_site(msg, p->site_id);
    xnet_msg_add_data(msg, &si, sizeof(si));
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_ITB, 0);
    ret = xnet_send(hmo.xc, msg);
    if (ret) {
        hvfs_err(mds, "xnet_send() failed with %d\n", ret);
        return ERR_PTR(ret);
    }
    /* ok, we get the reply: ITB.len is the length */
    sr = (struct storage_result *)(msg->pair->xm_data);
    if (sr->src.err)
        i = NULL;
    else
        i = (struct itb *)(sr->data);
    xnet_free_msg(msg);

    return i;
}

/*
 * Search ITE in the ITB, matched by hvfs_index
 *
 * Err Convention: ERR_PTR, can never be NULL!
 */
struct ite *itb_search(struct hvfs_index *hi, struct itb* itb, void *data)
{
    u64 offset = hi->hash & ((1 << itb->h.adepth) - 1);
    struct itb_index *ii;
    struct itb_lock *l;
    int ret = 0;

    /* get the lock */
    l = &itb->lock[offset / ITB_LOCK_GRANULARITY];
    if (hi->flag & INDEX_LOOKUP)
        itb_index_rlock(&l);
    else
        itb_index_wlock(&l);
    
    while (offset < (1 << (itb->h.adepth + 1))) {
        ii = &itb->index[offset];
        if (ii->flag == ITB_INDEX_FREE)
            break;
        ret = ite_match(&itb->ite[ii->entry], hi);

        if (ii->flag == ITB_INDEX_UNIQUE) {
            if (ret == ITE_MATCH_MISS) {
                ret = -ENOENT;
                goto out;
            }
        } else {
            /* CONFLICT & OVERFLOW */
            if (ret == ITE_MATCH_MISS) {
                offset = ii->conflict;
                continue;
            }
        }
        /* OK, found it, already lock it then do xxx on it */
        if (hi->flag & INDEX_LOOKUP) {
            /* read MDU to buffer */
            memcpy(data, itb->ite[ii->entry].g, HVFS_MDU_SIZE);
        } else if (hi->flag & INDEX_CREATE) {
            /* already exist, so... */
            if (!hi->flag & INDEX_CREATE_FORCE) {
                /* should return -EEXIST */
                ret = -EEXIST;
                goto out;
            }
            /* ok, forcely do it */
            if (hi->flag & INDEX_CREATE_DIR) {
            } else if (hi->flag & INDEX_CREATE_COPY) {
            } else if (hi->flag & INDEX_CREATE_LINK) {
            }
        } else if (hi->flag & INDEX_MDU_UPDATE) {
        } else if (hi->flag & INDEX_UNLINK) {
        } else if (hi->flag & INDEX_LINK_ADD) {
        } else if (hi->flag & INDEX_SYMLINK) {
        }
    }
}
