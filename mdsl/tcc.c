/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-15 18:54:32 macan>
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
#include "mdsl.h"

int mdsl_tcc_init(void)
{
    struct txg_open_entry *toe;
    int i;
    
    INIT_LIST_HEAD(&hmo.tcc.free_list);
    INIT_LIST_HEAD(&hmo.tcc.active_list);
    INIT_LIST_HEAD(&hmo.tcc.wbed_list);
    INIT_LIST_HEAD(&hmo.tcc.tmp_list);
    xlock_init(&hmo.tcc.free_lock);
    xlock_init(&hmo.tcc.active_lock);
    xlock_init(&hmo.tcc.wbed_lock);

    if (!hmo.conf.tcc_size)
        hmo.conf.tcc_size = 32;

    toe = xzalloc(sizeof(*toe) * hmo.conf.tcc_size);
    if (!toe) {
        hvfs_warning(mdsl, "Init TCC failed, ignore it.\n");
        atomic_set(&hmo.tcc.size, 0);
        atomic_set(&hmo.tcc.used, 0);
        return 0;
    }
    for (i = 0; i < hmo.conf.tcc_size; i++) {
        INIT_LIST_HEAD(&((toe + i)->list));
        list_add_tail(&((toe + i)->list), &hmo.tcc.free_list);
    }
    atomic_set(&hmo.tcc.size, hmo.conf.tcc_size);
    atomic_set(&hmo.tcc.used, 0);

    return 0;
}

void mdsl_tcc_destroy(void)
{
    /* do not need to free any items */
    xlock_destroy(&hmo.tcc.free_lock);
    xlock_destroy(&hmo.tcc.active_lock);
    xlock_destroy(&hmo.tcc.wbed_lock);
}

struct txg_open_entry *get_txg_open_entry(struct txg_compact_cache *tcc)
{
    struct list_head *l = NULL;
    struct txg_open_entry *toe = ERR_PTR(-EINVAL);
    
    xlock_lock(&tcc->free_lock);
    if (!list_empty(&tcc->free_list)) {
        l = tcc->free_list.next;
        ASSERT(l != &tcc->free_list, mdsl);
        list_del_init(l);
    }
    xlock_unlock(&tcc->free_lock);

    if (l) {
        toe = list_entry(l, struct txg_open_entry, list);
        atomic_inc(&tcc->used);
    } else {
        /* we should alloc a new TOE here! */
        if (unlikely(hmo.conf.option & HVFS_MDSL_MEMLIMIT)) {
            if (hmo.conf.memlimit <= atomic_read(&tcc->size) * 
                sizeof(struct txg_open_entry)) {
                /* if we do not have enough space, we should just write the
                 * entry to a temp disk file for restore */
                return ERR_PTR(-ENOMEM);
            }
        }
        toe = xzalloc(sizeof(struct txg_open_entry));
        if (!toe) {
            hvfs_err(mdsl, "xzalloc() txg_open_entry failed\n");
            return ERR_PTR(-ENOMEM);
        }
    }

    /* init the TOE now */
    INIT_LIST_HEAD(&toe->list);
    INIT_LIST_HEAD(&toe->itb);
    atomic_set(&toe->itb_nr, 0);
    
    return toe;
}

void put_txg_open_entry(struct txg_open_entry *toe)
{
    ASSERT(list_empty(&toe->list), mdsl);
    if (toe->other_region)
        xfree(toe->other_region);
    list_add_tail(&toe->list, &hmo.tcc.free_list);
    atomic_dec(&hmo.tcc.used);
}

struct txg_open_entry *toe_lookup(u64 site, u64 txg)
{
    struct txg_open_entry *toe;
    int found = 0;
    
    xlock_lock(&hmo.tcc.active_lock);
    list_for_each_entry(toe, &hmo.tcc.active_list, list) {
        if (site == toe->begin.site_id && txg == toe->begin.txg) {
            found = 1;
            break;
        }
    }
    xlock_unlock(&hmo.tcc.active_lock);
    if (!found)
        toe = NULL;

    return toe;
}

int itb_append(struct itb *itb, struct itb_info *ii, u64 site, u64 txg)
{
    int fd, err = 0;
    
    if (ii) {
        struct fdhash_entry *fde;
        
        /* prepare write to the file: "[target dir]/itb" */
        fde = mdsl_storage_fd_lookup_create(itb->h.puuid, MDSL_STORAGE_ITB, 0);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create failed w/ %ld\n", PTR_ERR(fde));
            goto write_to_tmpfile;
        }
        /* write here */
        err = mdsl_storage_fd_write(fde, ii);
        if (err) {
            hvfs_err(mdsl, "storage_fd_write failed w/ %d\n", err);
            mdsl_storage_fd_put(fde);
            goto write_to_tmpfile;
        }
        hvfs_err(mdsl, "Write ITB %ld to storage file %s/%ld/itb.\n",
                   itb->h.itbid, HVFS_MDSL_HOME, itb->h.puuid);
        mdsl_storage_fd_put(fde);
    } else {
    write_to_tmpfile:
        /* write to tmp file */
        toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_ITB, site, txg, itb);
    }
    
    return err;
}

int toe_to_tmpfile(int flag, u64 site, u64 txg, void *data)
{
    return 0;
}
