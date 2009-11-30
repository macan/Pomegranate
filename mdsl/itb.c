/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 19:28:19 macan>
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
#include "mdsl_api.h"
#include "mdsl.h"

struct storage_result *mdsl_read_itb(struct storage_index *si)
{
    struct mmap_window *mw;
    struct storage_result *sr;
    char *path;

    path = __getname();
    if (!mpath) {
        hvfs_err(mdsl, "__getname() failed\n");
        return ERR_PTR(-ENOMEM);
    }
    mpath = sprintf("%s/%d/md", HVFS_HOME, si->sic.uuid);
    /* FIXME: how to get the range max quickly? max range based! */
    mw = find_get_md_memwin(path, MD_RANGE, si->sic.arg0);
    max = *(u64 *)(mw->addr + mw->offset);
    min = *(u64 *)(mw->addr + mw->offset + sizeof(u64));
    put_range_memwin(mw);

    /* FIXME: check whether itbid is in the range (min, max] */
    path = sprintf("%s/%d/range.[%016d]", HVFS_HOME, si->sic.uuid, max);
    /* get the range memory window */
    mw = find_get_range_memwin(path, si->sic.arg0);
    itb_offset = *(u64 *)(mw->addr + mw->offset);
    put_range_memwin(mw);

    /* get the ITB */
    path = sprintf("%s/%d/itb", HVFS_HOME, si->sic.uuid);
    sr = get_free_sr();
    sr->flag = SR_ITB;
    sr->data = get_itb(path, itb_offset, &sr->len);
    if (!sr->data)
        sr->err = -ENOENT;

    __putname(path);
    return sr;
}

