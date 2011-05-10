/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-10 16:29:43 macan>
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

TRACING_FLAG(xnet, HVFS_DEFAULT_LEVEL);
void xnet_reset_tracing_flags(u64 flag)
{
    hvfs_xnet_tracing_flags = flag;
}

struct xnet_msg *xnet_alloc_msg(u8 alloc_flag)
{
    struct xnet_msg *msg;

#ifndef USE_XNET_SIMPLE
    /* fast method */
    if (alloc_flag == XNET_MSG_CACHE)
        return NULL;
    
    /* slow method */
    if (alloc_flag != XNET_MSG_NORMAL)
        return NULL;
#endif

#ifndef USE_XNET_SIMPLE
    msg = xzalloc(sizeof(struct xnet_msg));
#else
    msg = xzalloc(sizeof(struct xnet_msg) + sizeof(struct iovec) *
                  (g_xnet_conf.siov_nr));
#endif
    if (unlikely(!msg)) {
        hvfs_err(xnet, "xzalloc() struct xnet_msg failed\n");
        return NULL;
    }

    INIT_LIST_HEAD(&msg->list);

#ifdef USE_XNET_SIMPLE
    sem_init(&msg->event, 0, 0);
    atomic64_inc(&g_xnet_prof.msg_alloc);
    atomic_set(&msg->ref, 1);
    msg->siov = (void *)msg + sizeof(struct xnet_msg);
    msg->siov_alen = g_xnet_conf.siov_nr;
#endif

    return msg;
}

void xnet_raw_free_msg(struct xnet_msg *msg)
{
    if (atomic_dec_return(&msg->ref) == 0) {
        /* FIXME: check whether this msg is in the cache */
        xfree(msg);
#ifdef USE_XNET_SIMPLE
        atomic64_inc(&g_xnet_prof.msg_free);
#endif
    }
}

void xnet_free_msg(struct xnet_msg *msg)
{
    if (!msg)
        return;
    
    if (atomic_dec_return(&msg->ref) > 0) {
        return;
    }
    /* Note that, change reqno to zero to prohibit the current access to the
     * xnet_msg by xnet_handle_tx() */
    msg->tx.reqno = 0;

    /* FIXME: we should check the alloc_flag and auto free flag */
    if (msg->pair)
        xnet_free_msg(msg->pair);
    if (unlikely(msg->tx.flag & XNET_PTRESTORE)) {
        msg->xm_data = (void *)msg->tx.reserved;
    }
    if (msg->tx.flag & XNET_NEED_DATA_FREE) {
        if (msg->tx.type == XNET_MSG_REQ) {
            /* check and free the siov */
            xnet_msg_free_sdata(msg);
            xnet_msg_free_rdata(msg);
        } else if (msg->tx.type == XNET_MSG_RPY) {
            /* check and free the riov */
            xnet_msg_free_sdata(msg);
            xnet_msg_free_rdata(msg);
        } else {
            /* FIXME: do we need to free the data region */
        }
    } else {
        if (msg->siov_alen > g_xnet_conf.siov_nr) {
            if (msg->siov)
                xfree(msg->siov);
            if (msg->riov)
                xfree(msg->riov);
        }
    }
    xfree(msg);
#ifdef USE_XNET_SIMPLE
    atomic64_inc(&g_xnet_prof.msg_free);
#endif
}

#ifndef USE_XNET_SIMPLE
int xnet_msg_add_sdata(struct xnet_msg *msg, void *addr, u32 len)
{
    return 0;
}

int xnet_msg_add_rdata(struct xnet_msg *msg, void *addr, u32 len)
{
    return 0;
}

void xnet_msg_free_sdata(struct xnet_msg *msg)
{
}

void xnet_msg_free_rdata(struct xnet_msg *msg)
{
}

int xnet_send(struct xnet_context *xc, struct xnet_msg *msg)
{
    return -ENOSYS;
}

int xnet_isend(struct xnet_context *xc, struct xnet_msg *msg)
{
    return -ENOSYS;
}

void *mds_gwg;
int xnet_wait_group_add(void *gwg, struct xnet_msg *msg)
{
    return -ENOSYS;
}

int xnet_wait_group_del(void *gwg, struct xnet_msg *msg)
{
    return -ENOSYS;
}
#endif
