/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-05 11:05:32 macan>
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

    atomic_set(&hmo.prof.misc.tcc_size, hmo.conf.tcc_size);

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
        atomic_inc(&hmo.prof.misc.tcc_size);
        atomic_inc(&tcc->size);
    }

    atomic_inc(&tcc->used);
    atomic_inc(&hmo.prof.misc.tcc_used);
    /* init the TOE now */
    INIT_LIST_HEAD(&toe->list);
    INIT_LIST_HEAD(&toe->itb);
    toe->other_region = NULL;
    mcond_init(&toe->cond);
    xcond_init(&toe->wcond);
    xlock_init(&toe->itb_lock);
    atomic_set(&toe->itb_nr, 0);
    atomic_set(&toe->ref, 1);

    return toe;
}

void toe_put(struct txg_open_entry *toe)
{
    if (atomic_dec_return(&toe->ref) == 0 && toe->state)
        put_txg_open_entry(toe);
}

void put_txg_open_entry(struct txg_open_entry *toe)
{
    ASSERT(list_empty(&toe->list), mdsl);
    if (toe->other_region)
        xfree(toe->other_region);
    list_add_tail(&toe->list, &hmo.tcc.free_list);
    mcond_destroy(&toe->cond);
    xcond_broadcast(&toe->wcond);
    xcond_destroy(&toe->wcond);
    xlock_destroy(&toe->itb_lock);
    atomic_dec(&hmo.tcc.used);
    atomic_dec(&hmo.prof.misc.tcc_used);
}

void toe_active(struct txg_open_entry *toe)
{
    xlock_lock(&hmo.tcc.active_lock);
    list_add(&toe->list, &hmo.tcc.active_list);
    xlock_unlock(&hmo.tcc.active_lock);
}

void toe_deactive(struct txg_open_entry *toe)
{
    xlock_lock(&hmo.tcc.active_lock);
    list_del_init(&toe->list);
    xlock_unlock(&hmo.tcc.active_lock);
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

struct txg_open_entry *toe_lookup_recent(u64 site)
{
    struct txg_open_entry *toe = NULL, *pos;
    u64 txg = 0;

    xlock_lock(&hmo.tcc.active_lock);
    list_for_each_entry(pos, &hmo.tcc.active_list, list) {
        if (site == pos->begin.site_id && txg <= pos->begin.txg) {
            txg = pos->begin.txg;
            toe = pos;
        }
    }
    /* FIXME: this toe may be already freed @.@ */
    if (toe)
        atomic_inc(&toe->ref);
    xlock_unlock(&hmo.tcc.active_lock);

    return toe;
}

void toe_wait(struct txg_open_entry *toe, int nr)
{
    struct timespec ts, begin;
    int cnt;

    cnt = nr - atomic_read(&toe->itb_nr);
    while (cnt-- > 0) {
        clock_gettime(CLOCK_REALTIME, &begin);
        begin.tv_sec += 60;         /* total timeout time */
        
        for (; atomic_read(&toe->itb_nr) < nr; ) {
            clock_gettime(CLOCK_REALTIME, &ts);
            if (ts.tv_sec >= begin.tv_sec) {
                hvfs_err(mdsl, "TOE <%lx,%lx> wait timeout(%d) "
                         "for 60 seconds.\n", toe->begin.site_id,
                         toe->begin.txg, cnt);
                break;
            }
            ts.tv_nsec += 8000;     /* ns */
            mcond_timedwait(&toe->cond, &ts);
        }
    }
}

int itb_append(struct itb *itb, struct itb_info *ii, u64 site, u64 txg)
{
    int err = 0;
    
    if (unlikely(hmo.conf.option & HVFS_MDSL_WDROP))
        return 0;
    
    if (ii) {
        struct fdhash_entry *fde;
        struct iovec itb_iov = {
            .iov_base = itb,
            .iov_len = atomic_read(&itb->h.len),
        };
        struct mdsl_storage_access msa = {
            .iov = &itb_iov,
            .arg = ii,
            .iov_nr = 1,
        };
        u32 master;
        
        /* setup overwrite flag */
        if (itb->h.flag == ITB_JUST_SPLIT)
            ii->overwrite = 0;
        else
            ii->overwrite = 1;
        
        /* prepare write to the file: "[target dir]/itb" */
        fde = mdsl_storage_fd_lookup_create(itb->h.puuid, MDSL_STORAGE_MD, 0);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create MD file failed w/ %ld\n", 
                     PTR_ERR(fde));
            goto write_to_tmpfile;
        }
        master = fde->mdisk.itb_master;
        ii->master = master;
        mdsl_storage_fd_put(fde);
        
        fde = mdsl_storage_fd_lookup_create(itb->h.puuid, MDSL_STORAGE_ITB, 
                                            master);
        if (IS_ERR(fde)) {
            hvfs_err(mdsl, "lookup create failed w/ %ld\n", PTR_ERR(fde));
            goto write_to_tmpfile;
        }
        /* write here */
        err = mdsl_storage_fd_write(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "storage_fd_write failed w/ %d\n", err);
            mdsl_storage_fd_put(fde);
            goto write_to_tmpfile;
        }
        hvfs_debug(mdsl, "Write ITB %ld[%lx] len %d to storage file off "
                   "%ld fde ST %x.\n",
                   itb->h.itbid, itb->h.puuid, 
                   atomic_read(&itb->h.len), ii->location, 
                   fde->state);
        /* FIXME: this should be assertion */
        if (unlikely(ii->location == 0)) {
            hvfs_err(mdsl, "Write ITB %ld[%lx] len %d to storage file off "
                   "%ld fde ST %x.\n",
                   itb->h.itbid, itb->h.puuid, 
                   atomic_read(&itb->h.len), ii->location, 
                   fde->state);
            HVFS_BUGON("zero location!");
        }
        mdsl_storage_fd_put(fde);
        /* accumulate to hmi */
        atomic64_add(itb_iov.iov_len, &hmi.mi_bused);
    } else {
    write_to_tmpfile:
        /* write to tmp file */
        toe_to_tmpfile(TXG_OPEN_ENTRY_DISK_ITB, site, txg, itb);
    }
    
    return err;
}

int toe_to_tmpfile(int flag, u64 site, u64 txg, void *data)
{
    if (unlikely(hmo.conf.option & HVFS_MDSL_WDROP))
        return 0;

    return 0;
}

int toe_to_tmpfile_N(int flag, u64 site, u64 txg, void *data, int nr)
{
    if (unlikely(hmo.conf.option & HVFS_MDSL_WDROP))
        return 0;
    if (!nr)
        return 0;

    return 0;
}
