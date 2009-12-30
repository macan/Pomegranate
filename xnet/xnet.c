/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-30 17:47:12 macan>
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

struct xnet_msg *xnet_alloc_msg(u8 alloc_flag)
{
    struct xnet_msg *msg;

    /* fast method */
    if (alloc_flag == XNET_MSG_CACHE)
        return NULL;
    
    /* slow method */
    if (alloc_flag != XNET_MSG_NORMAL)
        return NULL;
    
    msg = xzalloc(sizeof(struct xnet_msg));
    if (!msg) {
        hvfs_err(xnet, "xzalloc() struct xnet_msg failed\n");
        return NULL;
    }

    return msg;
}

void xnet_free_msg(struct xnet_msg *msg)
{
    /* FIXME: we should check the alloc_flag and auto free flag */
    if (msg->pair)
        xnet_free_msg(msg->pair);
    xfree(msg);
}

#ifndef USE_XNET_SIMPLE
int xnet_msg_add_sdata(struct xnet_msg *msg, void *addr, int len)
{
    return 0;
}

int xnet_send(struct xnet_context *xc, struct xnet_msg *msg)
{
    return -ENOSYS;
}
#endif
