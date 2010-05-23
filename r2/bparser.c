/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-22 10:48:06 macan>
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
#include "root.h"

int bparse_hxi(void *data, union hvfs_x_info **hxi)
{
    u32 len;

    if (!data || !hxi)
        return -EINVAL;

    len = *(int *)data;
    if (len != sizeof(union hvfs_x_info)) {
        hvfs_err(root, "bparse hxi failed, hxi length mismatch!\n");
        return -EINVAL;
    }
    *hxi = data + sizeof(u32);

    return len + sizeof(u32);
}

int bparse_ring(void *data, struct chring_tx **ring)
{
    u32 len;
    
    if (!data || !ring)
        return -EINVAL;

    len = *(int *)data;
    *ring = data + sizeof(u32);
    if (len != sizeof(struct chring_tx) + (*ring)->nr * sizeof(struct chp)) {
        hvfs_err(root, "bparse ring failed, chring length mismatch!\n");
        return -EINVAL;
    }

    return len + sizeof(u32);
}

int bparse_root(void *data, struct root_tx **rt)
{
    u32 len;

    if (!data || !rt)
        return -EINVAL;

    len = *(int *)data;
    if (len != sizeof(struct root_tx)) {
        hvfs_err(root, "bparse root failed, root length mismatch!\n");
        return -EINVAL;
    }
    *rt = data + sizeof(u32);
    
    return len + sizeof(u32);
}

int bparse_bitmap(void *data, void **bitmap)
{
    u32 len;

    if (!data || !bitmap)
        return -EINVAL;

    len = *(int *)data;
    *bitmap = data + sizeof(u32);

    return len + sizeof(u32);
}

int bparse_addr(void *data, struct hvfs_site_tx **hst)
{
    u32 len;

    if (!data || !hst)
        return -EINVAL;

    len = *(int *)data;
    *hst = data + sizeof(u32);

    return len + sizeof(u32);
}
