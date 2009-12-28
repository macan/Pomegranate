/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-28 20:53:29 macan>
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
#include "xtable.h"
#include "xnet.h"
#include "mds.h"

#ifdef UNIT_TEST
int dh_insert(u64 uuid)
{
    struct hvfs_index hi, *rhi;
    struct hvfs_md_reply *hmr;
    struct dhe *e;
    int err = 0, no;

    memset(&hi, 0, sizeof(hi));
    hi.puuid = uuid;

    hmr = xzalloc(sizeof(*hmr) + sizeof(hi));
    if (!hmr) {
        hvfs_err(mds, "xzalloc() hmr failed.\n");
        err = -ENOMEM;
        goto out;
    }
    hmr->flag = MD_REPLY_WITH_HI;
    hmr->data = (void *)hmr + sizeof(*hmr);

    rhi = hmr_extract(hmr, EXTRACT_HI, &no);
    ASSERT(rhi == hmr->data, mds);
    rhi->uuid = hi.puuid;
    rhi->puuid = hi.puuid - 1;
    rhi->psalt = hi.puuid - 2;

    e = mds_dh_insert(&hmo.dh, rhi);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_info(mds, "Insert dir:%ld in DH w/  %p\n", uuid, e);
out:
    return err;
}

int dh_search(u64 uuid)
{
    struct hvfs_index hi;
    struct dhe *e;
    int err = 0;

    memset(&hi, 0, sizeof(hi));
    hi.puuid = uuid;

    e = mds_dh_search(&hmo.dh, &hi);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    hvfs_info(mds, "Search dir:%ld in DH hit %p\n", uuid, e);
out:
    return err;
}

int dh_remove(u64 uuid)
{
    return mds_dh_remove(&hmo.dh, uuid);
}

int main(int argc, char *argv[])
{
    int err = 0;
    int hsize, i, tc;

    if (argc == 3) {
        hsize = atoi(argv[1]);
        tc = atoi(argv[2]);
    } else {
        hsize = 1024;
        tc = 20;
    }

    hvfs_info(mds, "DH UNIT TESTing (%d)...\n", hsize);

    /* init mds unit test */
    lib_init();
    err = mds_init(10);
    if (err) {
        hvfs_err(mds, "mds_init() failed %d\n", err);
        goto out;
    }

    /* insert to DH */
    for (i = 0; i < tc; i++) {
        dh_insert(i);
    }

    /* search in DH */
    for (i = 0; i < tc; i++) {
        dh_search(i);
    }
    
    /* remove from DH */
    for (i = 0; i < tc; i++) {
        dh_remove(10);
    }
    
    /* re-search in DH */
    for (i = 0; i < tc; i++) {
        dh_search(10);
    }

    mds_destroy();
out:    
    return err;
}

#endif
