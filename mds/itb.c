/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-26 14:01:57 macan>
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
#include "xtable.h"
#include "xnet.h"
#include "mds.h"
#include "lib.h"
#include "ring.h"

void ite_create(struct hvfs_index *hi, struct ite *e);

/* mds_loadin_control()
 */
int mds_loadin_control(void)
{
    if (unlikely(hmo.conf.option & HVFS_MDS_MEMLIMIT)) {
        if (unlikely(hmo.conf.memlimit < atomic_read(&hmo.prof.cbht.aitb) *
                     (sizeof(struct itb) + ITB_SIZE * sizeof(struct ite)))) {
            if (!hmo.spool_modify_pause) {
                hmo.spool_modify_pause = 1;
                hmo.mp_ts = time(NULL);
                hvfs_warning(mds, "Pause modify operations "
                             "(loadin control) @ %s", 
                             ctime(&hmo.mp_ts));
            }
            return 1;
        }
    }

    return 0;
}

/* mds_read_itb() load the itb from mdsl.
 *
 * Note: if a itb is split but has not been commited to disk, and the node
 * crashed. Then, on reloading the itb, we should check and resplit the
 * itb. This resplit itb will be selectively commited to mdsl and not be
 * transfered to other mds.
 *
 * Err convention: Kernel err-ptr convention
 */
struct itb *mds_read_itb(u64 puuid, u64 psalt, u64 itbid)
{
    struct storage_index si;
    struct xnet_msg *msg;
    struct chp *p;
    struct itb *i;
    int ret;

    if (unlikely(hmo.conf.option & HVFS_MDS_MEMONLY))
        return ERR_PTR(-EINVAL);

    /* itb loadin control, we should balance the loadin ITB to not exhausted
     * the memory. */
    ret = mds_loadin_control();
    if (unlikely(ret)) {
        /* should return -EHWAIT */
        return ERR_PTR(-EHWAIT);
    }
    
    si.sic.uuid = puuid;
    si.sic.arg0 = itbid;
    si.sm.cnr = 0;              /* no data */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return ERR_PTR(-ENOMEM); /* return the err */
        }
    }
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_debug(mds, "ring_get_point() failed with %ld\n", PTR_ERR(p));
        i = ERR_PTR(-ECHP);
        goto out_free;
    }
    /* prepare the msg */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.xc->site_id, p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDSL_ITB, puuid, itbid);
    msg->tx.reserved = p->vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &si, sizeof(si));
    
    /* recheck the cbht state */
    if (mds_cbht_exist_check(&hmo.cbht, puuid, itbid) == -EEXIST) {
        i = ERR_PTR(-EAGAIN);
        goto out_free;
    }
    
    ret = xnet_send(hmo.xc, msg);
    if (ret) {
        hvfs_err(mds, "xnet_send() failed with %d\n", ret);
        i = ERR_PTR(ret);
        goto out_free;
    }
    /* ok, we get the reply: ITB.len is the length */
    ASSERT(msg->pair, mds);
    if (msg->pair->tx.err) {
        hvfs_err(mds, "MDSL %lx respond %d w/ uuid %lx salt %ld ITB %ld "
                 "read request.\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err, 
                 puuid, psalt, itbid);
        i = ERR_PTR(msg->pair->tx.err);
    } else {
        struct hvfs_txg *t;
        
        /* sanity checking */
        if (msg->pair->tx.len < sizeof(struct itbh)) {
            hvfs_err(mds, "Invalid ITB load reply received from %lx\n",
                     msg->pair->tx.ssite_id);
            atomic64_dec(&hmo.prof.cbht.aitb);
            i = ERR_PTR(-EIO);
            xnet_set_auto_free(msg->pair);
            goto out_free;
        }
        if (msg->pair->xm_datacheck)
            i = (struct itb *)(msg->pair->xm_data);
        else {
            hvfs_err(mds, "Internal error, data lossing ..\n");
            atomic64_dec(&hmo.prof.cbht.aitb);
            i = ERR_PTR(-EIO);
            xnet_set_auto_free(msg->pair);
            goto out_free;
        }
        /* do not free the new ITB */
        xnet_clear_auto_free(msg->pair);

        /* checking the ITB */
        ASSERT(msg->pair->tx.len == atomic_read(&i->h.len), mds);
        if (i->h.compress_algo == COMPR_LZO) {
            /* decompress the ITB */
            int err;
            
            err = itb_lzo_decompress(i);
            if (err) {
                hvfs_err(mds, "itb_lzo_decompress() failed w/ %d\n", err);
                atomic64_dec(&hmo.prof.cbht.aitb);
                i = ERR_PTR(-EFAULT);
                xnet_set_auto_free(msg->pair);
                goto out_free;
            }
        }

        hvfs_debug(mds, "Load ITB %ld w/ txg %ld\n", 
                   i->h.itbid, i->h.txg);

        /* changing the dirty info */
        t = mds_get_open_txg(&hmo);
        i->h.txg = t->txg;
        i->h.state = ITB_STATE_CLEAN;
        /* re-init */
        itb_reinit(i);
        if (atomic_read(&i->h.entries) == 0)
            itb_idx_bmp_reinit(i);
        txg_put(t);

        atomic64_add(atomic_read(&i->h.entries), &hmo.prof.cbht.aentry);
    }

    atomic64_inc(&hmo.prof.mdsl.itb_load);
out_free:
    xnet_free_msg(msg);
    
    return i;
}

/* mds_pick_itb()
 */
struct itb *mds_pick_itb(u64 puuid, u64 itbid)
{
    struct dhe *e;
    u64 salt;

    e = mds_dh_search(&hmo.dh, puuid);
    if (unlikely(IS_ERR(e))) {
        hvfs_err(mds, "mds_dh_search(dir %lx) failed w/ %ld\n",
                 puuid, PTR_ERR(e));
        return NULL;
    }
    salt = e->salt;
    mds_dh_put(e);

    return mds_read_itb(puuid, salt, itbid);
}

/* __itb_get_free_index
 */
long __itb_get_free_index(struct itb *i)
{
    long nr;
    int c, d;
    
#ifdef _USE_SPINLOCK
    xspinlock_lock(&i->h.ilock);
#else
    xlock_lock(&i->h.ilock);
#endif
    nr = i->h.inf;
    if (nr >= (1 << i->h.adepth))
        nr = 0;
    d = c = (1 << i->h.adepth);

    while (c) {
        if (i->index[nr + d].flag == ITB_INDEX_FREE) {
            i->h.inf = nr + 1;
            i->h.itu++;
#ifdef _USE_SPINLOCK
            xspinlock_unlock(&i->h.ilock);
#else
            xlock_unlock(&i->h.ilock);
#endif
            return nr + d;
        }
        c--;
        nr++;
        if (nr == d)
            nr = 0;
    }
#ifdef _USE_SPINLOCK
    xspinlock_unlock(&i->h.ilock);
#else
    xlock_unlock(&i->h.ilock);
#endif

    /* failed to get a free index, internal error! */
    hvfs_err(mds, "Internal error, failed to get a free index.\n");
    return d + d;
}

/* __itb_add_index()
 *
 * holding the bucket.rlock and be.rlock and itb.rlock AND ite.wlock
 */
void __itb_add_index(struct itb *i, u64 offset, long nr, char *name)
{
    struct itb_index *ii = i->index;
    long f;

    /* check the ENTRY index entry's flag */
    if (ii[offset].flag == ITB_INDEX_FREE) {
        /* ok, this entry is free, and nobody can race w/ me */
        ii[offset].flag = ITB_INDEX_UNIQUE;
        ii[offset].entry = nr;
        hvfs_debug(mds, "FREE     ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_UNIQUE) {
        /* only ONE entry, change flag to CONFLICT */
        /* get a free index entry */
        f = __itb_get_free_index(i);
        ii[offset].flag = ITB_INDEX_CONFLICT;
        ii[offset].conflict = f;
        ii[f].flag = ITB_INDEX_UNIQUE;
        ii[f].entry = nr;
        /* update conflict state */
        atomic_inc(&i->h.pseudo_conflicts);
        hvfs_debug(mds, "UNIQUE   ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_CONFLICT) {
        /* FIXME: have SOME entries, check to see if we need change flag to
         * OVERFLOW */
        /* get a free index entry */
        f = __itb_get_free_index(i);
        /* insert to the head */
        ii[f] = ii[offset];
        ii[offset].entry = nr;
        ii[offset].conflict = f;
        /* it is hard to detemine the precise conflicts */
        atomic_inc(&i->h.pseudo_conflicts);
        hvfs_debug(mds, "CONFLICT ITB %p: %ld %ld, %s offset %ld, nr %ld\n",
                   i, i->h.puuid, i->h.itbid, name, offset, nr);
    } else if (ii[offset].flag == ITB_INDEX_OVERFLOW) {
        hvfs_err(mds, "Hoo, this ITB overflowed, for now we can't "
                 "handle it!\n");
    } else {
        hvfs_err(mds, "Invalid ITE flag 0x%x\n", ii[offset].flag);
    }
#ifdef _USE_SPINLOCK
    xspinlock_lock(&i->h.ilock);
#else
    xlock_lock(&i->h.ilock);
#endif
    /* NOTE: we use '<=' here for max_offset == 0; because the init value of
     * max_offset is 0, you should update the length when nr is exactly
     * ZERO. */
    if (atomic_read(&i->h.max_offset) <= nr) {
        atomic_set(&i->h.max_offset, nr);
        atomic_set(&i->h.len, sizeof(struct itb) + 
                   (nr + 1) * sizeof(struct ite));
    }
#ifdef _USE_SPINLOCK
    xspinlock_unlock(&i->h.ilock);
#else
    xlock_unlock(&i->h.ilock);
#endif
}

/*
 * itb_add_ite()
 *
 * holding the bucket.rlock and be.rlock and itb.rlock AND ite.wlock
 */
static
int itb_add_ite(struct itb *i, struct hvfs_index *hi, void *data, 
                struct itb_lock *l, struct hvfs_txg *txg,
                struct ite **dtite)
{
    u64 offset;
    struct ite *ite;
    long nr;
    int err;

    offset = hi->hash & ((1 << i->h.adepth) - 1);

    /* Step1: get a free ITE entry */
    /* Step1.0: check whether this ITB is full */
    if (atomic_inc_return(&i->h.entries) <= (1 << i->h.adepth)) {
    retry:
        nr = find_first_zero_bit((unsigned long *)i->bitmap, 
                                 (1 << i->h.adepth));
        if (nr < (1 << i->h.adepth)) {
            /* ok, find one */
            /* test and set the bit now */
            if (lib_bitmap_tas(i->bitmap, nr)) {
                /* someone has set this bit, let us retry */
                goto retry;
            }
            hvfs_verbose(mds, "ITB %p: %ld, %ld, 0x%lx %s, offset %ld, "
                         "nr %ld\n", 
                         i, i->h.puuid, i->h.itbid, hi->hash, 
                         hi->name, offset, nr);
            /* now we got a free ITE entry at position nr */
            ite = &i->ite[nr];
            *dtite = ite;
            memset(ite, 0, sizeof(struct ite));
            ite->hash = hi->hash;
            /* setting up the ITE fields */
            if (unlikely(hi->flag & INDEX_CREATE_LINK)) {
                ite->flag |= ITE_FLAG_LS;
            } else if (unlikely(hi->flag & INDEX_SYMLINK)) {
                ite->flag |= ITE_FLAG_SYM;
            } else if (unlikely((hi->flag & INDEX_KV) ||
                                (hi->flag & INDEX_CREATE_KV))) {
                ite->flag |= ITE_FLAG_KV;
            } else 
                ite->flag |= ITE_FLAG_NORMAL;
            
            if (unlikely(hi->flag & INDEX_CREATE_COPY)) {
                if (hi->flag & INDEX_CREATE_GDT)
                    ite->flag |= ITE_FLAG_GDT;
                ite->uuid = hi->uuid;
            } else {
                if (hi->flag & INDEX_BY_NAME) {
                    ite->uuid = atomic64_inc_return(&hmi.mi_uuid) | 
                        hmi.uuid_base;
                    if (hi->flag & INDEX_CREATE_DIR) {
                        ite->flag |= ITE_FLAG_SDT;
                        ite->uuid |= HVFS_UUID_HIGHEST_BIT;
                        atomic64_inc(&hmi.mi_dnum);
                    } else {
                        atomic64_inc(&hmi.mi_fnum);
                    }
                } else if (hi->flag & INDEX_BY_UUID) {
                    ite->uuid = hi->uuid;
                    if (hi->flag & INDEX_CREATE_DIR) {
                        ite->flag |= ITE_FLAG_SDT;
                        if (ite->uuid != hmi.root_uuid)
                            ite->uuid |= HVFS_UUID_HIGHEST_BIT;
                    }
                }
            }
            if (likely(hi->flag & INDEX_CREATE_SMALL)) {
                ite->flag |= ITE_FLAG_SMALL;
            } else if (hi->flag & INDEX_CREATE_OBJ) {
                ite->flag |= ITE_FLAG_OBJ;
            } else if (hi->flag & INDEX_CREATE_LARGE) {
                ite->flag |= ITE_FLAG_LARGE;
            }
            
            /* next step: we try to get a free index entry */
            __itb_add_index(i, offset, nr, hi->name);
            /* set up the mdu base on hi->data */
            ite_create(hi, ite);
            if (hi->flag & INDEX_CREATE_DIR) {
                atomic64_inc(&hmi.mi_dnum);
            } else {
                atomic64_inc(&hmi.mi_fnum);
            }
            /* copy the mdu into the hmr buffer */
            hi->uuid = ite->uuid;
            /* FIXME: we can optimize the kv memcpy here! */
            if (hi->flag & INDEX_KV)
                memcpy(data, &(ite->v), KV_HEADER_LEN +
                       ite->v.len);
            else
                memcpy(data, &(ite->g), HVFS_MDU_SIZE);
        } else {
            /* NOTE: if there is no zero bit, it means that ourself is racing
             * with other threads, we should force the ITB split actually!
             *
             * However, I have observed the silly racing if we do ITB split
             * here, so I disable the ITB split here.
             */
            if (unlikely(atomic_read(&i->h.entries) < (1 << (ITB_DEPTH - 1)))) {
                hvfs_err(mds, "Internal Fatal Error, no free bits? nr %ld, "
                         "entries %d\n", nr, atomic_read(&i->h.entries));
            }
            /* NOTE: you can NOT return the EAGAIN, because it has nothing to
             * help the retring. */
#if 0
            static int a = 0;
            int j, l;
            a++;
            if (a >= 1999999) {
                char line[1024];
                memset(line, 0, sizeof(line));
                for (j = 0, l = 0; j < (1 << (ITB_DEPTH - 3)); j++) {
                    l += sprintf(line + l, "%x", i->bitmap[j]);
                }
                hvfs_err(mds, ". ITB %p id %ld, state %d, entries %d nr %ld [%s]\n", 
                         i, i->h.itbid, i->h.state, 
                         atomic_read(&i->h.entries), nr, line);
                a = 0;
            }
#endif
            goto retry;
        }
    } else {
        /* already full, should split */
        /* FIXME: ITB SPLIT! */

        atomic_dec(&i->h.entries);
        hvfs_debug(mds, "ITB itbid %ld, depth %d, entries %d\n", 
                   i->h.itbid, i->h.depth, atomic_read(&i->h.entries));
        err = itb_split_local(i, i->h.depth, l, txg, hi);
        if (!err)
            err = -ESPLIT;
        goto out;
    }

    atomic64_inc(&hmo.prof.cbht.aentry);

    /* Now, we know that we have create a new ITE entry, if we created is a
     * SDT entry, then we should send a async dir delta update to the dest
     * site. We can just add the dir delta entry to the TXG's list. The txg
     * should be dirtied by this insertion. If we insert the entry in the txg
     * which is not the txg we dirty the ITE, it should be ok either. Aftal
     * all, the txg we inserted must be a txg which can make sure the dirty
     * region is either on the disk or going to be on the disk. */
    if (hi->flag & INDEX_CREATE_DIR) {
        err = txg_add_update_ddelta(txg, hi->puuid, 1, 
                                    DIR_DELTA_NLINK | DIR_DELTA_CTIME 
                                    | DIR_DELTA_MTIME);
        if (err) {
            hvfs_err(mds, "Update dir delta %ld on create failed w/ %d,"
                     " data loss\n",
                     hi->puuid, err);
            /* FIXME: we should return the err and revoke the inserted ITE! */
        }
    } else {
        /* FIXME: we should update the parent directory's mtime and ctime */
    }
    err = 0;
    
out:
    return err;
}

/* 
 * __itb_add_ite_blob()
 *
 * NOTE: this function can only used in the spliting code, we do not check ANY
 * condition. You should not call this API!
 */
int __itb_add_ite_blob(struct itb *i, struct ite *e)
{
    u64 offset;
    struct ite *ite;
    long nr;
    int err = 0;

    /* the entry is in the ite:e */
    offset = e->hash & ((1 << i->h.adepth) - 1);

retry:
    nr = find_first_zero_bit((unsigned long *)i->bitmap, (1 << i->h.adepth));
    if (nr < (1 << i->h.adepth)) {
        /* ok, find one */
        /* test and set the bit now */
        if (lib_bitmap_tas(i->bitmap, nr)) {
            /* someone has set this bit, let us retry */
            goto retry;
        }
        /* now we got a free ITB entry at position nr */
        ite = &i->ite[nr];
        memcpy(ite, e, sizeof(struct ite));
        /* next step: we try to get a free index entry */
        __itb_add_index(i, offset, nr, e->s.name);
        atomic_inc(&i->h.entries);
    } else {
        /* hoo, there is no zero bit! */
        err = -EINVAL;
    }
    
    return err;
}

/*
 * __itb_find()
 *
 * Note: this function is out of date. You should not call this API!
 */
int __itb_find(struct itb *i, struct ite *e)
{
    struct itb_index *ii;
    u64 offset, total = 1 << (ITB_DEPTH + 1);

    offset = e->hash & ((1 << i->h.adepth) - 1);
    while (offset < total) {
        ii = &i->index[offset];
        if (ii->flag == ITB_INDEX_FREE)
            break;
        /* compare by uuid and hash */
        if (e->hash == i->ite[ii->entry].hash &&
            e->uuid == i->ite[ii->entry].uuid) {
            return 1;
        }

        if (ii->flag == ITB_INDEX_UNIQUE)
            return 0;
        else
            offset = ii->conflict;
    }

    return 0;
}

/*
 * ITE unlink internal
 */
static inline void __ite_unlink(struct itb *i, u64 offset)
{
    struct itb_index *ii;
    
    ii = &i->index[offset];
    ii->flag = ITB_INDEX_FREE;
    if (offset >= (1 << i->h.adepth)) {
        atomic_dec(&i->h.pseudo_conflicts);
        i->h.itu--;
    }
    if (atomic_read(&i->h.max_offset) == ii->entry)
        atomic_dec(&i->h.max_offset);
    atomic_dec(&i->h.entries);
    if (atomic_read(&i->h.entries) == 0) {
        atomic_set(&i->h.max_offset, 0);
        atomic_set(&i->h.len, sizeof(struct itb));
    } else {
        atomic_set(&i->h.len, sizeof(struct itb) + 
                   (atomic_read(&i->h.max_offset) + 1) * sizeof(struct ite));
    }
    /* clear the bitmap */
    if (unlikely(!lib_bitmap_tac(i->bitmap, ii->entry))) {
        hvfs_err(mds, "Test-and-Clear a zero bit?\n");
    }
    atomic64_dec(&hmo.prof.cbht.aentry);
}

/* 
 * itb_del_ite()
 *
 * NOTE: this function has NOT tested well yet, we may just fallback to the
 * async unlink in the LS path of ite_unlink().
 *
 * NOTE: holding the itb.index_lock_w and other upper layer locks
 */
void itb_del_ite(struct itb *i, struct ite *e, u64 offset, u64 pos)
{
    struct itb_index *ii;
    u64 total = 1 << (i->h.adepth + 1);

    hvfs_debug(mds, "Try to del %ld @ pos %ld\n", offset, pos);

    /* NOTE that the offset is the target to del, and io is the offset! */
    ii = &i->index[pos];
    if (unlikely(ii->flag == ITB_INDEX_FREE)) {
        /* hooray, nothing should be deleted */
        return;
    }
    if (likely(ii->flag == ITB_INDEX_UNIQUE)) {
        if (offset == pos) {
            __ite_unlink(i, offset);
        }
    } else {
        /* ho, we should loop in the list to find and delete the entry */
        u64 saved = pos;
        u64 prev = pos;
        int quit = 0, needswap = 0, hit = 0;

        pos = offset;
        offset = saved;
        do {
        retry:
            ii = &i->index[offset];
            hvfs_debug(mds, "offset %ld <%x,%d,%d>, prev %ld\n", 
                       offset, ii->flag, ii->entry, ii->conflict, prev);
            if (ii->flag == ITB_INDEX_FREE)
                break;
            if ((pos == offset) || hit) {
                /* ok, we get the unlink target */
                if (offset == saved) {
                    needswap = 1;
                    prev = offset;
                } else if (ii->flag == ITB_INDEX_UNIQUE) {
                    i->index[prev].flag = ITB_INDEX_UNIQUE;
                    __ite_unlink(i, offset);
                    quit = 1;
                } else {
                    i->index[prev].conflict = ii->conflict;
                    __ite_unlink(i, offset);
                    quit = 1;
                }
            } else {
                /* this is not the unlink target */
                if (needswap) {
                    u32 saved_entry = ii->entry;
                    ii->entry = i->index[saved].entry;
                    i->index[saved].entry = saved_entry;
                    needswap = 0;
                    hit = 1;
                    hvfs_debug(mds, "swap %ld and %ld\n", offset, saved);
                    goto retry;
                }
                if (ii->flag == ITB_INDEX_UNIQUE)
                    quit = 1;
                prev = offset;
            }
            offset = ii->conflict;
        } while (offset < total && (!quit));
        if (needswap) {
            ii = &i->index[saved];
            ASSERT(ii->flag == ITB_INDEX_UNIQUE, mds);
            __ite_unlink(i, saved);
        }
    }
}

/*
 * ITE unlink
 */
void ite_unlink(struct ite *e, struct itb *i, u64 offset, u64 pos)
{
    if (likely(e->flag & ITE_FLAG_NORMAL || e->flag & ITE_FLAG_SYM)) {
        /* normal file */
        e->s.mdu.nlink--;
        if (e->s.mdu.mode & S_IFDIR)
            e->s.mdu.nlink--;
        if (!e->s.mdu.nlink) {
            /* ok, we add this itb in the async_unlink list if the
             * configration saied that :) */
            if (hmo.conf.async_unlink) {
                e->flag = ((e->flag & ~ITE_STATE_MASK) | ITE_UNLINKED);
                if (unlikely(list_empty(&i->h.unlink)))
                    list_add_tail(&i->h.unlink, &hmo.async_unlink);
            } else {
                /* delete the entry imediately */
                itb_del_ite(i, e, offset, pos);
            }
        } else
            e->flag = ((e->flag & ~ITE_STATE_MASK) | ITE_SHADOW);
    } else if (e->flag & ITE_FLAG_LS) {
        /* FIXME: hard link file, nobody refer it, just delete it */
        e->s.mdu.nlink = 0;
        itb_del_ite(i, e, offset, pos);
    } 
    if (e->flag & ITE_FLAG_KV) {
        /* for KVS, we ignore the nlink handling for table(dir) */
        itb_del_ite(i, e, offset, pos);
        if (e->flag & ITE_FLAG_SDT) {
            goto do_delta;
        }
    }

    /* FIXME: should we do async dir delta update here? */
    if (e->flag & ITE_FLAG_SDT) {
        struct hvfs_txg *txg;
        int err = 0;

        /* unlink the entry now */
        if (likely(e->s.mdu.nlink == 0)) {
            ASSERT(e->flag & ITE_FLAG_NORMAL, mds);
        do_delta:
            /* then, update the dir delta to remote site */
            txg = mds_get_open_txg(&hmo);
            err = txg_add_rdir(txg, e->uuid);
            err = txg_add_update_ddelta(txg, i->h.puuid, -1,
                                        DIR_DELTA_NLINK | DIR_DELTA_CTIME
                                        | DIR_DELTA_MTIME);
            txg_put(txg);
            if (err) {
                hvfs_err(mds, "Update dir delta %ld on unlink failed w/ %d,"
                         " data loss\n",
                         i->h.puuid, err);
            }
        } else {
            /* we have already dec the nlink, just return now */
            ;
        }
    }
}

/*
 * ITE create with HI
 */
void ite_create(struct hvfs_index *hi, struct ite *e)
{
    /* there is always a struct mdu_update with normal create request */

    if (unlikely(hi->flag & INDEX_KV)) {
        e->v.key = hi->hash;
        if (hi->flag & INDEX_COLUMN) {
            /* set to key length */
            e->v.len = hi->uuid;
            /* we should write the value content to MDSL, for now we just keep
             * the data length */
            if (hi->kvflag & HVFS_KV_STR) {
                /* copy the key content to e->v.value */
                memcpy(&e->v.value, hi->data, hi->uuid);
                /* copy the value offset content to the column cell */
                memcpy(&(e->column[hi->kvflag & HVFS_KV_MAX_COLUMN]),
                       hi->data + hi->uuid, sizeof(struct column));
            } else {
                memcpy(&(e->column[hi->kvflag & HVFS_KV_MAX_COLUMN]),
                       hi->data, sizeof(struct column));
            }
        } else {
            /* this is the 0th column access */
            e->v.len = hi->namelen;
            memcpy(&e->v.value, hi->data, e->v.len);
        }

        if (hi->kvflag & HVFS_KV_STR) {
            e->v.flags = HVFS_KV_STR;
            /* you know that hi->uuid saved the key length */
            e->v.klen = hi->uuid;
        } else {
            e->v.flags = HVFS_KV_NORMAL;
        }

        return;
    }
    
    e->namelen = hi->namelen;
    if (likely(hi->namelen)) {
        memcpy(&e->s.name, hi->name, hi->namelen);
        if (hi->namelen < HVFS_MAX_NAME_LEN)
            e->s.name[hi->namelen] = '\0';
    }
    
    if (unlikely(hi->flag & INDEX_CREATE_COPY)) {
        /* hi->data is MDU */
        if (hi->flag & INDEX_CREATE_GDT) {
            memcpy(&e->g, hi->data, HVFS_MDU_SIZE);
            if (unlikely(hi->flag & INDEX_CREATE_KV)) {
                e->g.salt = e->g.mdu.dev;
            } else {
                if (!(hi->auxflag & AUX_RECOVERY))
                    e->g.salt = lib_random(0xfffffff);
            }
        } else {
            memcpy(&e->s.mdu, hi->data, sizeof(struct mdu));
        }
    } else if (unlikely(hi->flag & INDEX_CREATE_LINK)) {
        /* hi->data is LS */
        memcpy(&e->s.ls, hi->data, sizeof(struct link_source));
        e->s.ls.dtime = 0;
        e->s.ls.flags |= (HVFS_MDU_IF_LINKT | HVFS_MDU_IF_NORMAL);
    } else if (unlikely(hi->flag & INDEX_SYMLINK)) {
        /* hi->data is mdu_update w/ symname */
        struct mdu_update *mu = (struct mdu_update *)hi->data;
        struct timeval tv;

        e->s.mdu.flags |= (HVFS_MDU_IF_NORMAL | HVFS_MDU_IF_SYMLINK);
        if (e->flag & ITE_FLAG_SMALL)
            e->s.mdu.flags |= HVFS_MDU_IF_SMALL;
        else if (e->flag & ITE_FLAG_OBJ)
            e->s.mdu.flags |= HVFS_MDU_IF_OBJ;
        else if (e->flag & ITE_FLAG_LARGE)
            e->s.mdu.flags |= HVFS_MDU_IF_LARGE;
        e->s.mdu.nlink = 1;

        if (!mu || !mu->valid)
            return;
        gettimeofday(&tv, NULL);

        if (mu->valid & MU_FLAG_ADD)
            e->s.mdu.flags |= mu->flags;
        if (mu->valid & MU_FLAG_CLR)
            e->s.mdu.flags &= ~(mu->flags);

        if (mu->valid & MU_UID)
            e->s.mdu.uid = mu->uid;
        if (mu->valid & MU_GID)
            e->s.mdu.gid = mu->gid;

        if (mu->valid & MU_MODE)
            e->s.mdu.mode = mu->mode;
        else
            e->s.mdu.mode = HVFS_DEFAULT_UMASK | S_IFLNK;

        if (mu->valid & MU_SIZE)
            e->s.mdu.size = mu->size;

        if (mu->valid & MU_VERSION)
            e->s.mdu.version = mu->version;

        if (mu->valid & MU_ATIME)
            e->s.mdu.atime = mu->atime;
        else
            e->s.mdu.atime = tv.tv_sec;
        if (mu->valid & MU_CTIME)
            e->s.mdu.ctime = mu->ctime;
        else
            e->s.mdu.ctime = tv.tv_sec;
        if (mu->valid & MU_MTIME)
            e->s.mdu.mtime = mu->mtime;
        else
            e->s.mdu.mtime = tv.tv_sec;

        if (mu->valid & MU_SYMNAME) {
            if (mu->namelen > sizeof(e->s.mdu.symname)) {
                /* FIXME: we do not support long symlink :( */
                hvfs_warning(mds, "Long SYMLINK not supported yet, and "
                             "we do not fail at this:(\n");
            } else 
                memcpy(e->s.mdu.symname, (void *)mu + sizeof(*mu),
                       mu->namelen);
        } else {
            /* loop to the default symlink file */
            memcpy(e->s.mdu.symname, "/tmp/not_exist", 14);
        }
    } else {
        /* INDEX_CREATE_DIR and non-flag, mdu_update */
        struct mdu_update *mu = (struct mdu_update *)hi->data;
        struct timeval tv;
        int coffset = 0;

        /* default fields */
        e->s.mdu.flags |= HVFS_MDU_IF_NORMAL;
        if (e->flag & ITE_FLAG_SMALL)
            e->s.mdu.flags |= HVFS_MDU_IF_SMALL;
        else if (e->flag & ITE_FLAG_OBJ)
            e->s.mdu.flags |= HVFS_MDU_IF_OBJ;
        else if (e->flag & ITE_FLAG_LARGE)
            e->s.mdu.flags |= HVFS_MDU_IF_LARGE;

        /* for kv table */
        if (unlikely(hi->flag & INDEX_CREATE_KV)) {
            e->s.mdu.dev = lib_random(0xfffffff);
        }

        /* we should not change this region, otherwise the name is changing
         * :(  The caller now must set the puuid and psalt themself. */
        if (unlikely(hi->flag & INDEX_CREATE_DIR)) {
            e->s.mdu.nlink = 2;
            e->s.mdu.mode = HVFS_DIR_UMASK | S_IFDIR;
#if 0
            e->g.puuid = hi->puuid;
            e->g.psalt = hi->psalt;
#endif
        } else {
            e->s.mdu.nlink = 1;
            e->s.mdu.mode = HVFS_DEFAULT_UMASK | S_IFREG;
        }

        gettimeofday(&tv, NULL);
        if (!mu || !mu->valid) {
            e->s.mdu.atime = tv.tv_sec;
            e->s.mdu.ctime = tv.tv_sec;
            e->s.mdu.mtime = tv.tv_sec;
            return;
        }

        if (mu->valid & MU_FLAG_ADD)
            e->s.mdu.flags |= mu->flags;
        if (mu->valid & MU_FLAG_CLR)
            e->s.mdu.flags &= ~(mu->flags);

        if (mu->valid & MU_UID)
            e->s.mdu.uid = mu->uid;
        if (mu->valid & MU_GID)
            e->s.mdu.gid = mu->gid;

        if (mu->valid & MU_MODE)
            e->s.mdu.mode = mu->mode;
        else
            e->s.mdu.mode = HVFS_DEFAULT_UMASK | S_IFREG;

        if (mu->valid & MU_SIZE)
            e->s.mdu.size = mu->size;
        if (mu->valid & MU_VERSION)
            e->s.mdu.version = mu->version;

        if (mu->valid & MU_ATIME)
            e->s.mdu.atime = mu->atime;
        else
            e->s.mdu.atime = tv.tv_sec;
        if (mu->valid & MU_CTIME)
            e->s.mdu.ctime = mu->ctime;
        else
            e->s.mdu.ctime = tv.tv_sec;
        if (mu->valid & MU_MTIME)
            e->s.mdu.mtime = mu->mtime;
        else
            e->s.mdu.mtime = tv.tv_sec;

        if (mu->valid & MU_OI) {
            e->s.mdu.oi = *(struct obj_info *)(hi->data +
                                               sizeof(struct mdu_update));
        }
        
        if (mu->valid & MU_LLFS) {
            e->s.mdu.lr = *(struct llfs_ref *)(hi->data +
                                               sizeof(struct mdu_update));
            coffset = sizeof(struct llfs_ref);
        }
        if (unlikely(mu->valid & MU_COLUMN)) {
            struct mu_column *mc = (struct mu_column *)(
                hi->data + coffset + sizeof(struct mdu_update));
            int i;

            for (i = 0; i < mu->column_no; i++) {
                /* copy to the dst location */
                e->column[(mc + i)->cno] = (mc + i)->c;
            }
        }
    }
}

/*
 * ITE update with HI
 */
void ite_update(struct hvfs_index *hi, struct ite *e)
{
    if (hi->flag & INDEX_KV) {
        /* note that, for KV/KVS, on update the key length should not
         * changed */

        if (hi->flag & INDEX_COLUMN) {
            if (hi->kvflag & HVFS_KV_STR) {
                /* ok, you know, the key content can not be updated, so we
                 * just copy the value content(column actually) */
                e->v.flags = HVFS_KV_STR;
                memcpy(&(e->column[hi->kvflag & HVFS_KV_MAX_COLUMN]),
                       hi->data + hi->uuid, sizeof(struct column));
            } else {
                e->v.flags = HVFS_KV_NORMAL;
                memcpy(&(e->column[hi->kvflag & HVFS_KV_MAX_COLUMN]),
                       hi->data, sizeof(struct column));
            }
        } else {
            e->v.len = hi->namelen;
            memcpy(&e->v.value, hi->data, e->v.len);
            
            if (hi->kvflag & HVFS_KV_STR) {
                e->v.flags = HVFS_KV_STR;
            } else {
                e->v.flags = HVFS_KV_NORMAL;
            }
        }
    } else if (hi->flag & INDEX_MDU_UPDATE) {
        /* hi->data is mdu_update */
        struct mdu_update *mu = (struct mdu_update *)hi->data;
        struct timeval tv;
        int coffset = 0;

        /* time update */
        gettimeofday(&tv, NULL);

        if (mu->valid & (MU_MODE | MU_UID | MU_GID | 
                         MU_NLINK | MU_NLINK_DELTA)) {
            e->s.mdu.ctime = tv.tv_sec;
        }
        if (mu->valid & (MU_SIZE | MU_COLUMN)) {
            e->s.mdu.mtime = tv.tv_sec;
        }
        
        if (mu->valid & MU_FLAG_ADD)
            e->s.mdu.flags |= mu->flags;
        if (mu->valid & MU_FLAG_CLR)
            e->s.mdu.flags &= ~(mu->flags);

        if (mu->valid & MU_UID) {
            e->s.mdu.uid = mu->uid;
        }
        if (mu->valid & MU_GID) {
            e->s.mdu.gid = mu->gid;
        }
        if (mu->valid & MU_MODE) {
            e->s.mdu.mode = mu->mode;
        }
        if (mu->valid & MU_NLINK) {
            e->s.mdu.nlink = mu->nlink;
        }
        if (mu->valid & MU_NLINK_DELTA) {
            e->s.mdu.nlink += mu->nlink;
        }
        if (mu->valid & MU_SIZE) {
            e->s.mdu.size = mu->size;
        }

        if (mu->valid & MU_VERSION)
            e->s.mdu.version = mu->version;
        else
            e->s.mdu.version++;

        if (mu->valid & MU_ATIME)
            e->s.mdu.atime = mu->atime;
        if (mu->valid & MU_CTIME)
            e->s.mdu.ctime = mu->ctime;
        if (mu->valid & MU_MTIME)
            e->s.mdu.mtime = mu->mtime;

        if (mu->valid & MU_OI) {
            e->s.mdu.oi = *(struct obj_info *)(hi->data +
                                               sizeof(struct mdu_update));
        }
        
        if (mu->valid & MU_LLFS) {
            e->s.mdu.lr = *(struct llfs_ref *)(hi->data + 
                                               sizeof(struct mdu_update));
            coffset = sizeof(struct llfs_ref);
        }
        if (mu->valid & MU_COLUMN) {
            struct mu_column *mc = (struct mu_column *)(
                hi->data + coffset + sizeof(struct mdu_update));
            int i;

            for (i = 0; i < mu->column_no; i++) {
                /* copy to the dst location */
                e->column[(mc + i)->cno] = (mc + i)->c;
            }
            /* finally, reset the mdu.rr magic */
            if (!(mu->valid & MU_SRR)) {
                if (e->s.mdu.flags & HVFS_MDU_IF_RR) {
                    e->s.mdu.flags &= ~HVFS_MDU_IF_RR;
                    memset(&e->s.mdu.rr, 0, sizeof(e->s.mdu.rr));
                }
            }
        }

    } else if (hi->flag & INDEX_CREATE_COPY) {
        /* hi->data is MDU */
        memcpy(&e->s.mdu, hi->data, sizeof(struct mdu));
    } else if (hi->flag & INDEX_CREATE_LINK) {
        /* hi->data is LS */
        memcpy(&e->s.ls, hi->data, sizeof(struct link_source));
        e->s.ls.flags |= HVFS_MDU_IF_LINKT;
    }
}

/*
 * ITE match
 *
 * Return: ITE_MATCH_MISS/ITE_MATCH_HIT
 */
inline int ite_match(struct ite *e, struct hvfs_index *hi)
{
    /* for kv store, we just compare the key with the hash value */
    if (unlikely(hi->flag & INDEX_KV)) {
        if (hi->kvflag & HVFS_KV_STR) {
            if (hi->hash != e->v.key)
                return ITE_MATCH_MISS;
            else {
                /* we reuse hi->uuid as the key length */
                if (e->v.klen != hi->uuid || !hi->data)
                    return ITE_MATCH_MISS;
                if (memcmp((const void *)hi->data, 
                           (const void *)e->v.value, (size_t)hi->uuid) == 0) {
                    return ITE_MATCH_HIT;
                } else
                    return ITE_MATCH_MISS;
            }
        } else {
            /* defaults to KV_NORMAL */
            if (hi->hash == e->v.key)
                return ITE_MATCH_HIT;
            else
                return ITE_MATCH_MISS;
        }
    }
    
    /* compare the name or uuid */
    if (unlikely(hi->flag & INDEX_ITE_SHADOW)) { 
        if (((e->flag & ITE_STATE_MASK) != ITE_SHADOW) && 
            ((e->flag & ITE_STATE_MASK) != ITE_UNLINKED))
            return ITE_MATCH_MISS;
    }
    
    if ((hi->flag & INDEX_ITE_ACTIVE) && 
        ((e->flag & ITE_STATE_MASK) != ITE_ACTIVE))
        return ITE_MATCH_MISS;

    /* we default to access the ACTIVE ite, the shadow ite is excluded! */
    if (unlikely((e->flag & ITE_STATE_MASK) == ITE_UNLINKED)) {
        if (!(hi->flag & INDEX_ITE_SHADOW))
            return ITE_MATCH_MISS;
    }

    if (hi->flag & INDEX_BY_UUID) {
        if (e->uuid == hi->uuid && e->hash == hi->hash) {
            return ITE_MATCH_HIT;
        } else
            return ITE_MATCH_MISS;
    } else if (hi->flag & INDEX_BY_NAME) {
        if (hi->namelen == e->namelen && 
            memcmp(e->s.name, hi->name, hi->namelen) == 0) {
            return ITE_MATCH_HIT;
        } else
            return ITE_MATCH_MISS;
    } else {
        return ITE_MATCH_MISS;
    }
}

/* ITB Cache init
 *
 * There may be (< hint_size) memory allocated!
 */
int itb_cache_init(struct itb_cache *ic, int hint_size)
{
    struct itb *i;
    int j;
    
    INIT_LIST_HEAD(&ic->lru);
    atomic_set(&ic->csize, 0);
    xlock_init(&ic->lock);
    if (!hint_size)
        return 0;
    
    /* pre-allocate the ITBs */
    for (j = 0; j < hint_size; j++) {
        i = xzalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
        if (!i) {
            hvfs_info(mds, "xzalloc() ITBs failed, continue ...\n");
            continue;
        }
        list_add_tail(&i->h.list, &ic->lru);
        atomic_inc(&ic->csize);
    }
    return 0;
}

/* ITB Cache destroy
 */
int itb_cache_destroy(struct itb_cache *ic)
{
    struct itbh *pos, *n;

    list_for_each_entry_safe(pos, n, &ic->lru, list) {
        list_del(&pos->list);
        xfree(pos);
    }

    return 0;
}

/* get_free_itb_fast()
 */
struct itb *get_free_itb_fast(void)
{
    struct itb *n;
    struct list_head *l = NULL;

    xlock_lock(&hmo.ic.lock);
    if (!list_empty(&hmo.ic.lru)) {
        l = hmo.ic.lru.next;
        ASSERT(l != &hmo.ic.lru, mds);
        list_del_init(l);
    }
    xlock_unlock(&hmo.ic.lock);

    if (l) {
        /* remove from the CBHT */
        n = (struct itb *)(list_entry(l, struct itbh, list));
        if (!hlist_unhashed(&n->h.cbht))
            mds_cbht_del(&hmo.cbht, n);
    } else {
        /* try to malloc() one */
        n = xmalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
        if (!n) {
            hvfs_err(mds, "xmalloc() ITB failed\n");
            return NULL;
        }
        atomic_inc(&hmo.ic.csize);
    }

    atomic64_inc(&hmo.prof.cbht.aitb);
    return n;
}

/* get_free_itb()
 */
struct itb *get_free_itb(struct hvfs_txg *txg)
{
    struct itb *n;
    struct list_head *l = NULL;
    int i;

    xlock_lock(&hmo.ic.lock);
    if (!list_empty(&hmo.ic.lru)) {
        l = hmo.ic.lru.next;
        ASSERT(l != &hmo.ic.lru, mds);
        list_del_init(l);
    }
    xlock_unlock(&hmo.ic.lock);

    if (l) {
        /* remove from the CBHT */
        n = (struct itb *)(list_entry(l, struct itbh, list));
        if (!hlist_unhashed(&n->h.cbht))
            mds_cbht_del(&hmo.cbht, n);
        memset(n, 0, sizeof(struct itbh));
        memset(n->bitmap, 0, (1 << (ITB_DEPTH - 3)));
        memset(n->index, 0, sizeof(struct itb_index) * (2 << ITB_DEPTH));
    } else {
        /* there is no freed ITB in the cache, we must check if we should
         * control the incoming modify requests */
        if (unlikely(hmo.conf.option & HVFS_MDS_MEMLIMIT)) {
            if (!hmo.spool_modify_pause && 
                (unlikely(hmo.conf.memlimit <= atomic_read(&hmo.prof.cbht.aitb) * 
                          (sizeof(struct itb) + ITB_SIZE * sizeof(struct ite))))) {
                hmo.spool_modify_pause = 1;
                hmo.mp_ts = time(NULL);
                hvfs_err(mds, "Pause modify operations @ %s", ctime(&hmo.mp_ts));
                return NULL;
            }
        }
        /* try to malloc() one */
        n = xzalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
        if (!n) {
            hvfs_err(mds, "xzalloc() ITB failed\n");
            return NULL;
        }
        atomic_inc(&hmo.ic.csize);
    }

    atomic_set(&n->h.len, sizeof(struct itb));
    n->h.adepth = ITB_DEPTH;
    n->h.flag = ITB_ACTIVE;       /* 0 */
    n->h.state = ITB_STATE_CLEAN; /* 0 */
    if (likely(txg))
        n->h.txg = txg->txg;
    xrwlock_init(&n->h.lock);
#ifdef _USE_SPINLOCK
    xspinlock_init(&n->h.ilock);
#else
    xlock_init(&n->h.ilock);
#endif

    INIT_HLIST_NODE(&n->h.cbht);
    INIT_LIST_HEAD(&n->h.list);
    INIT_LIST_HEAD(&n->h.unlink);
    INIT_LIST_HEAD(&n->h.overflow);
    /* init the lock region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xrwlock_init((xrwlock_t *)(&n->lock[i]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xlock_init((xlock_t *)(&n->lock[i]));
        }
    }

    atomic_set(&n->h.ref, 1);
    atomic64_inc(&hmo.prof.cbht.aitb);
    return n;
}

/* itb_reinit()
 *
 * NOTE: this function only used for reinit the headers and lock region for a
 * transfered ITB.
 */
void itb_reinit(struct itb *n)
{
    int i;
    
    xrwlock_init(&n->h.lock);
#ifdef _USE_SPINLOCK
    xspinlock_init(&n->h.ilock);
#else
    xlock_init(&n->h.ilock);
#endif
    
    INIT_HLIST_NODE(&n->h.cbht);
    INIT_LIST_HEAD(&n->h.list);
    INIT_LIST_HEAD(&n->h.unlink);
    INIT_LIST_HEAD(&n->h.overflow);

    /* init the lock region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xrwlock_init((xrwlock_t *)(&n->lock[i]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xlock_init((xlock_t *)(&n->lock[i]));
        }
    }
    atomic_set(&n->h.ref, 1);
    n->h.twin = 0;
}

/* itb_idx_bmp_reinit()
 *
 * NOTE: this function only used for reinit the index and bitmap region of the
 * uninited ITB loaded from MDSL
 */
void itb_idx_bmp_reinit(struct itb *n)
{
    memset(n->bitmap, 0, (1 << (ITB_DEPTH - 3)));
    memset(n->index, 0, (2 << ITB_DEPTH) * sizeof(struct itb_index));
}

/* itb_free()
 */
void itb_free(struct itb *i)
{
    int j;

    /* free the locks, but do not touch the locks in the header region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (j = 0; j < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); j++) {
            xrwlock_destroy((xrwlock_t *)(&i->lock[j]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (j = 0; j < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); j++) {
            xlock_destroy((xlock_t *)(&i->lock[j]));
        }
    }

    xrwlock_destroy(&i->h.lock);
    
    /* check if we should truely free this itb */
    if (hlist_unhashed(&i->h.cbht) && hmo.conf.memlimit <= 
        atomic_read(&hmo.ic.csize) *
        (sizeof(struct itb) + ITB_SIZE * sizeof(struct ite))) {
        xfree(i);
        atomic_dec(&hmo.ic.csize);
    } else {
        /* add to the free list */
        xlock_lock(&hmo.ic.lock);
        list_add_tail(&i->h.list, &hmo.ic.lru);
        xlock_unlock(&hmo.ic.lock);
    }
    atomic64_dec(&hmo.prof.cbht.aitb);
}

/* ITB COW
 */
struct itb *itb_cow(struct itb *itb, struct hvfs_txg *txg)
{
    struct itb *n;

    n = get_free_itb(txg);
    if (!n) {
        return ERR_PTR(-ERESTART);
    }

    /* do NOT copy the ref and flag! */
    memcpy(n, itb, sizeof(struct itbh) - sizeof(atomic_t));
    atomic_set(&n->h.ref, 1);
    n->h.flag = ITB_ACTIVE;

    /* init ITB header */
    xrwlock_init(&n->h.lock);
#ifdef _USE_SPINLOCK
    xspinlock_init(&n->h.ilock);
#else
    xlock_init(&n->h.ilock);
#endif
    INIT_HLIST_NODE(&n->h.cbht);
    INIT_LIST_HEAD(&n->h.list);
    INIT_LIST_HEAD(&n->h.unlink);
    INIT_LIST_HEAD(&n->h.overflow);
    
    return n;
}

/**
 * ITB COW RECOPY
 *
 * Holding the BE.wlock, and the old ITB has beed removed from the be list.
 *
 * NOTE: in itb_cow() we do not finish copying the ITE region, now let us
 * retry to copy the remain regions.
 */
void itb_cow_recopy(struct itb *oi, struct itb *ni)
{
    int i;
    
    hvfs_debug(mds, "copied max_offset is %d, len %d\n", 
               atomic_read(&oi->h.max_offset),
               atomic_read(&oi->h.len));
    
    memcpy(ni->bitmap, oi->bitmap, ITB_COW_BITMAP_LEN);
    memcpy(ni->index, oi->index, ITB_COW_INDEX_LEN);
    memcpy(ni->ite, oi->ite,
           atomic_read(&oi->h.len) - sizeof(struct itb));

    /* adjust the header for ITB split */
    atomic_set(&ni->h.entries, atomic_read(&oi->h.entries));
    ni->h.depth = oi->h.depth;
    ni->h.split_rlink = 0;
    
    /* some changes in header region */
    if (atomic_read(&ni->h.len) != atomic_read(&oi->h.len)) {
        atomic_set(&ni->h.len, atomic_read(&oi->h.len));
        ni->h.inf = oi->h.inf;
        ni->h.itu = oi->h.itu;
        atomic_set(&ni->h.max_offset, atomic_read(&oi->h.max_offset));
        atomic_set(&ni->h.conflicts, atomic_read(&oi->h.conflicts));
        atomic_set(&ni->h.pseudo_conflicts, atomic_read(&oi->h.pseudo_conflicts));
    }
    
    /* init lock region */
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xrwlock_init((xrwlock_t *)(&ni->lock[i]));
        }
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        for (i = 0; i < ((1 << ITB_DEPTH) / ITB_LOCK_GRANULARITY); i++) {
            xlock_init((xlock_t *)(&ni->lock[i]));
        }
    }

}

/**
 * ITB Dirty, core function!
 *
 * @itb:ITB
 * @t:  TXG
 * @be: bucket_entry
 *
 * Note: dirty and cow the ITB as needed; return the dirtied ITB for using
 *
 * Note: holding the bucket.rlock and be.rlock and itb.rlock and ite.wlock
 *
 * Note: we should release the ite.wlock when we are doing COW! Lesson of
 * bloods~
 */
struct itb *itb_dirty(struct itb *itb, struct hvfs_txg *t, struct itb_lock *l,
                      struct hvfs_txg **otxg)
{
    *otxg = t;

    if (likely(t->txg == itb->h.txg)) {
        /* ITB accessed in this TXG */
        if (likely(itb->h.state == ITB_STATE_DIRTY))
            return itb;
        else {
            hvfs_debug(mds, "Hoo, ITB %ld state 0x%x in TXG: 0x%lx\n", 
                       itb->h.itbid, itb->h.state, 
                       t->txg);
            if (itb->h.state == ITB_STATE_CLEAN) {
                /* init TXG, corner case */
                txg_add_itb(t, itb);
            } else if (itb->h.state == ITB_STATE_COWED) {
                HVFS_BUG();
            }
            itb->h.state = ITB_STATE_DIRTY;
        }
    } else if (t->txg == itb->h.txg + 1) {
        /* ITB accessed in the last TXG */
        ASSERT(itb->h.state != ITB_STATE_COWED, mds);
        if (itb->h.state == ITB_STATE_CLEAN) {
            /* clean or already write-backed, free to use */
            hvfs_debug(mds, "clean or already write-backed, free to use.\n");
            itb->h.txg = t->txg;
            itb->h.state = ITB_STATE_DIRTY;
            txg_add_itb(t, itb);
        } else if (itb->h.state == ITB_STATE_DIRTY) {
            /* need COW */
            struct itb *n;
            struct bucket_entry *be;
            int should_retry = 0;

#if 1
            n = itb_cow(itb, t);
            if (IS_ERR(n)) {
                itb_index_wunlock(l);
                return n;
            }

            /* MAGIC: exchange the old ITB with new ITB */
            /* Step1: release BE.rlock & ITB.rlock */
            be = itb->h.be;
            itb_index_wunlock(l);
            xrwlock_runlock(&itb->h.lock);
            xrwlock_runlock(&be->lock);

            /* NOTE: we can split here! */

            /* Step2: get BE.wlock & ITB.wlock */
            xrwlock_wlock(&be->lock);
            xrwlock_wlock(&itb->h.lock);

            /* Step3: check the ITB txg */

            /* Step3.0: is this ITB deleted or moved? */

            if (itb->h.be != be) /* moved or deleted */
                should_retry = 1;
            else {
                /* not moved/deleted, just COWed */
                if ((t->txg != itb->h.txg + 1) 
                    || (itb->h.state != ITB_STATE_DIRTY)) {
                    /* somebody already do cow (win us), we need just retrieve
                     * itb */
                    should_retry = 1;
                } else {
                    /* refresh the pointers, and atomic change the pprev */
                    hlist_del_init(&itb->h.cbht);
                    itb->h.state = ITB_STATE_COWED;
                    itb->h.be = NULL;

                    n->h.txg = t->txg;
                    n->h.state = ITB_STATE_DIRTY;
                    n->h.be = be;
                    hlist_add_head(&n->h.cbht, &be->h);

                    /* ok, recopy the new ITEs */
                    itb_cow_recopy(itb, n);
                    hvfs_debug(mds, "T %ld ITB COWing %ld %p to %p [%d]\n",
                               t->txg, 
                               itb->h.itbid, itb, n, list_empty(&itb->h.list));
                    mds_itb_prof_cow();
                }
            }
            
            /* Step4: release BE.wlock */
            xrwlock_wunlock(&itb->h.lock);
            xrwlock_wunlock(&be->lock);

            /* Step5: loser should retry the access */
            if (should_retry) {
                itb_free(n);
                hvfs_debug(mds, "loser cow ITB %ld from %p TXG %ld -> %ld, "
                           "S %0x, BE %p %p\n", 
                           n->h.itbid, itb, t->txg, itb->h.txg, itb->h.state,
                           be, itb->h.be);
                xrwlock_rlock(&be->lock);
                xrwlock_rlock(&itb->h.lock);
                return NULL;
            }
            /* Step6: get BE.rlock */
            xrwlock_rlock(&be->lock);
            xrwlock_rlock(&n->h.lock);
            /* NOTE THAT: if the new ITB's state is COWED, it means that the
             * new ITB is dirtied by the next TXG. We should not return the
             * new ITB for writing, and we should restart the access. */
            if (unlikely(n->h.state != ITB_STATE_DIRTY)) {
                hvfs_err(mds, "New ITB's state is %x, re-COWed\n.", n->h.state);
                if (likely(n->h.state == ITB_STATE_COWED)) {
                    xrwlock_runlock(&n->h.lock);
                    xrwlock_rlock(&itb->h.lock);
                    return ERR_PTR(-ERESTART);
                }
            }

            txg_add_itb(t, n);
            itb = n;
#else
            itb->h.txg = t->txg;
            itb->h.state = ITB_STATE_DIRTY;
            txg_add_itb(t, itb);
#endif
        }
    } else if (t->txg > itb->h.txg + 1) {
        ASSERT(itb->h.state != ITB_STATE_COWED, mds);
        itb->h.txg = t->txg;
        itb->h.state = ITB_STATE_DIRTY;
        txg_add_itb(t, itb);
    } else if (t->txg == itb->h.txg - 1) {
        /* ITB accessed in the next TXG, this can happen on the changing
         * TXG. we should put ourself on the new TXG to diminish the
         * complexity of TXG state machine */
        struct hvfs_txg *nt;
        
        hvfs_debug(mds, "TXG %ld <-- ITB(%ld) %ld, reassign the TXG\n", 
                   t->txg, itb->h.itbid, itb->h.txg);
        nt = mds_get_open_txg(&hmo);
        txg_put(t);
        *otxg = nt;
        /* FIXME: itb accessed in the next TXG, so it must be dirty! */
        ASSERT((itb->h.state == ITB_STATE_DIRTY || itb->h.state == ITB_STATE_CLEAN), mds);
        ASSERT(nt->txg == itb->h.txg, mds);
        /* Bug github.com Issue 6: incorrect aentry count.
         *
         * We have a newly loaded in itb, but we had not set it to dirty! This
         * means that we leak some entry in cbht.aentry:(
         *
         * What's more, the entries we addin or deletefrom this itb would be
         * lost. I have observed this case in my test.
         */
        if (itb->h.state == ITB_STATE_CLEAN) {
            /* this is a newly loadin itb, we dirty it and add it to the txg's
             * dirty list */
            itb->h.state = ITB_STATE_DIRTY;
            txg_add_itb(nt, itb);
        }
    }

    return itb;
}

static inline
void __data_column_hook(struct hvfs_index *hi, struct itb *itb,
                        struct itb_index *ii, void *data)
{
    if (unlikely(hi->flag & INDEX_COLUMN)) {
        if (unlikely(hi->flag & INDEX_KV)) {
            if (hi->kvflag & HVFS_KV_STR) {
                memcpy(data + sizeof(struct kv),
                       &(itb->ite[ii->entry].column[hi->kvflag & 
                                                    HVFS_KV_MAX_COLUMN]),
                       sizeof(struct column));
            } else {
                memcpy(data + sizeof(struct kv),
                       &(itb->ite[ii->entry].column[hi->kvflag &
                                                    HVFS_KV_MAX_COLUMN]), 
                       sizeof(struct column));
            }
        } else {
            memcpy(data + HVFS_MDU_SIZE, 
                   &(itb->ite[ii->entry].column[hi->column]), 
                   sizeof(struct column));
        }
    }
}

#define LEASE_IS_TIMEOUT(v)     ((hmo.tick -                            \
                                  (v & ~(LEASE_MASK | LEASE_SEQNO_MASK))) >= 60)
#define LEASE_SEQNO(v)          (atomic_inc_return(v))

static inline
void ite_lease_set(struct ite *e, u64 value)
{
    /* must be atomic operation here */
    e->s.mdu.dtime = value;
}

static inline
u64 ite_lease_get(struct ite *e)
{
    return e->s.mdu.dtime;
}

static inline
int ite_lease_check_setup(struct hvfs_index *hi, struct itb *i, struct ite *e)
{
    u64 value = 0;
    
    /* lease ts is ZERO, we accept this request */
    if (!e->s.mdu.dtime)
        goto setup_lease;
    /* lease magic is ok! */
    if (e->s.mdu.dtime == hi->dlen)
        goto setup_lease;
    if (LEASE_IS_TIMEOUT(e->s.mdu.dtime)) {
        goto setup_lease;
    }
    /* check if this entry is shared */
    if (e->s.mdu.dtime & LEASE_EXCLUDE) {
        return -ELOCKED;
    }
    if ((e->s.mdu.dtime & LEASE_SHARED) &&
        (hi->flag & INDEX_INTENT_EXCLUDE)) {
        return -ELOCKED;
    }

setup_lease:
    if (unlikely(hi->flag & (INDEX_INTENT_EXCLUDE | 
                             INDEX_INTENT_SHARED |
                             INDEX_INTENT_RELEASE))) {
        value = LEASE_SEQNO(&hmo.lease_seqno);
        if (hi->flag & INDEX_INTENT_EXCLUDE)
            value |= hmo.tick | LEASE_EXCLUDE;
        else if (hi->flag & INDEX_INTENT_SHARED)
            value |= hmo.tick | LEASE_SHARED;
        else if (hi->flag & INDEX_INTENT_RELEASE)
            value = 0;
        ite_lease_set(e, value);
        if (ite_lease_get(e) != value)
            return -ERACE;
    }

    return 0;
}

/**
 * Search ITE in the ITB, matched by hvfs_index
 *
 * Err Convention: 0 means no error, other MINUS number means error
 *
 * Note: holding the bucket.rlock and be.rlock and itb.rlock
 *
 * NOTE: this is the very HOT path for LOOKUP/CREATE/UNLINK/....
 */
int itb_search(struct hvfs_index *hi, struct itb *itb, void *data, 
               struct hvfs_txg *txg, struct itb **oi,
               struct hvfs_txg **otxg)
{
    u64 offset, pos;
    u64 total = 1 << (ITB_DEPTH + 1);
    atomic64_t *as;
    struct itb_index *ii;
    struct itb_lock *l;
    struct ite *dtite;
    int ret = -ENOENT;

    /* NOTE: if we are in retrying, we know that the ITB will not COW
     * again! */
retry:
    if (likely(hmo.conf.itbid_check)) {
        if (((hi->hash >> ITB_DEPTH) & ((1 << itb->h.depth) - 1)) !=
            itb->h.itbid) {
            /* This means the ITB we choose has completed one split, and it is
             * not the target location we should resident in. We need restart
             * our access. */
            ret = -ESPLIT;
            hvfs_debug(mds, "Under SPLIT, Location Changed.(%ld vs %ld)"
                       " %s retry\n",
                       ((hi->hash >> ITB_DEPTH) & ((1 << itb->h.depth) - 1)),
                       itb->h.itbid,
                       hi->name);
            goto out_nolock;
        }
    }

    pos = offset = hi->hash & ((1 << itb->h.adepth) - 1);
    /* get the ITE lock */
    l = &itb->lock[offset / ITB_LOCK_GRANULARITY];
    if (hi->flag & INDEX_LOOKUP) {
        itb_index_rlock(l);
        as = &hmo.prof.itb.rsearch_depth;
    } else {
        itb_index_wlock(l);
        as = &hmo.prof.itb.wsearch_depth;
    }
    
    while (offset < total) {
        ii = &itb->index[offset];
        if (ii->flag == ITB_INDEX_FREE)
            break;
        atomic64_inc(as);
        ret = ite_match(&itb->ite[ii->entry], hi);

        if (ii->flag == ITB_INDEX_UNIQUE) {
            if (ret == ITE_MATCH_MISS) {
                break;
            }
        } else {
            /* CONFLICT & OVERFLOW */
            if (ret == ITE_MATCH_MISS) {
                offset = ii->conflict;
                continue;
            }
        }
        /* OK, found it, already lock it then do xxx on it */
        hvfs_verbose(mds, "OK, the ITE do exist in the ITB.\n");
        if (hi->flag & INDEX_LOOKUP) {
            /* check if it has been locked yet */
            ret = ite_lease_check_setup(hi, itb, &itb->ite[ii->entry]);
            if (unlikely(ret)) {
                goto out;
            }
            /* read MDU to buffer */
            hi->uuid = itb->ite[ii->entry].uuid;
            if (hi->flag & INDEX_KV)
                memcpy(data, &(itb->ite[ii->entry].v),
                       KV_HEADER_LEN + itb->ite[ii->entry].v.len);
            else
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            /* FIXME: we should add symlink handling here! */
            __data_column_hook(hi, itb, ii, data);
        } else if (unlikely(hi->flag & INDEX_CREATE)) {
            /* already exist, so... */
            if (!(hi->flag & INDEX_CREATE_FORCE)) {
                /* should return -EEXIST */
                ret = -EEXIST;
                goto out;
            }
            /* FIXME: ok, forcely do it */
            if (hi->flag & INDEX_CREATE_DIR) {
                hvfs_debug(mds, "Forcely create dir now \n");
                /* Forcely create dir? should not happen! */
                ret = -EEXIST;
                goto out;
            } else if (hi->flag & INDEX_CREATE_COPY) {
                hvfs_debug(mds, "Forcely create with MDU ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (unlikely((*oi) != itb)) {
                    if (!(*oi)) {
                        ret = -EAGAIN;  /* w/ itb.rlocked */
                        goto out_nolock;
                    } else {
                        /* this means the itb is cowed, we should refresh
                         * ourself */
                        /* w/ itb.runlocked and oi->rlocked */
                        goto refresh;
                    }
                }
                ite_update(hi, &itb->ite[ii->entry]);
                hi->uuid = itb->ite[ii->entry].uuid;
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            } else if (hi->flag & INDEX_CREATE_LINK) {
                hvfs_verbose(mds, "Forcely create hard link ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (!(*oi)) {
                    ret = -EAGAIN;
                    goto out_nolock;
                } else if ((*oi) != itb) {
                    /* this measn the itb is cowed, we should refresh ourself */
                    goto refresh;
                }
                ite_update(hi, &itb->ite[ii->entry]);
                hi->uuid = itb->ite[ii->entry].uuid;
                memcpy(data, &(itb->ite[ii->entry].g), 
                       sizeof(struct link_source));
            }
        } else if (hi->flag & INDEX_MDU_UPDATE) {
            /* setattr, no failure */
            hvfs_verbose(mds, "Find the ITE and update the MDU.\n");
            /* if it is a link target, client should restat the truely link
             * source! */
            if (itb->ite[ii->entry].flag & ITE_FLAG_LS) {
                ret = -EACCES;
                goto out;
            }
            *oi = itb_dirty(itb, txg, l, otxg);
            if (unlikely((*oi) != itb)) {
                if (!(*oi)) {
                    ret = -EAGAIN;  /* w/ itb.rlocked */
                    goto out_nolock;
                } else {
                    /* this means the itb is cowed, we should refresh ourself */
                    /* w/ itb.runlocked and oi->rlocked */
                    goto refresh;
                }
            }
            ite_update(hi, &itb->ite[ii->entry]);
            if (unlikely((itb->ite[ii->entry].s.mdu.mode & S_IFDIR) && 
                         (itb->ite[ii->entry].s.mdu.nlink == 0))) {
                /* BUG: we should unlink this dir now, is it? */
                itb_del_ite(itb, &itb->ite[ii->entry], offset, pos);
            }
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            __data_column_hook(hi, itb, ii, data);
        } else if (hi->flag & INDEX_UNLINK) {
            /* unlink */
            hvfs_verbose(mds, "Find the ITE and unlink it.\n");
            *oi = itb_dirty(itb, txg, l, otxg);
            if (unlikely((*oi) != itb)) {
                if (!(*oi)) {
                    ret = -EAGAIN;  /* w/ itb.rlocked */
                    goto out_nolock;
                } else {
                    /* this means the itb is cowed, we should refresh ourself */
                    /* w/ itb.runlocked and oi->rlocked */
                    goto refresh;
                }
            }
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            /* BUG-xxxxxx:
             *
             * ite_unlink() reset the bitmap, thus after ite_unlink() the old
             * ite is free to be assigned to another entry. Then, we get a
             * WRONG reply.
             */
            ite_unlink(&itb->ite[ii->entry], itb, offset, pos);
        } else if (hi->flag & INDEX_LINK_ADD) {
            /* hard link */
            hvfs_verbose(mds, "Find the ITE and hard link it.\n");
            /* check if this is a hard link ITE */
            if (itb->ite[ii->entry].flag & ITE_FLAG_LS) {
                ret = -EACCES;
                goto out;
            }
            *oi = itb_dirty(itb, txg, l, otxg);
            if (!(*oi)) {
                ret = -EAGAIN;
                goto out_nolock;
            } else if ((*oi) != itb) {
                /* this means the itb is cowed, we should refresh ourself */
                goto refresh;
            }
            /* ok, this is an ugly API, the client put the nlink delta in the
             * msg->tx.arg0, and mds_linkadd() copy it to hi->dlen, because in
             * this function we cant access the msg :( */
            itb->ite[ii->entry].s.mdu.nlink += (int)hi->dlen;
            if (unlikely(itb->ite[ii->entry].s.mdu.nlink == 0 &&
                         !(itb->ite[ii->entry].flag & ITE_FLAG_GDT))) {
                /* Hoo, we should unlink the entry now, make sure that you
                 * must not unlink the directory entry */
                itb_del_ite(itb, &itb->ite[ii->entry], offset, pos);
            }
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
        } else if (unlikely(hi->flag & INDEX_ACQUIRE)) {
            /* Note that, we have already been wlock protected */
            if (hi->dlen & LEASE_MASK) {
                u64 value;
                
                if (!LEASE_IS_TIMEOUT(itb->ite[ii->entry].s.mdu.dtime)) {
                    if (hi->dlen != itb->ite[ii->entry].s.mdu.dtime) {
                        if (hi->dlen & LEASE_EXCLUDE) {
                            if (itb->ite[ii->entry].s.mdu.dtime & 
                                LEASE_MASK) {
                                ret = -ELOCKED;
                                goto out;
                            }
                        } else if (hi->dlen & LEASE_SHARED) {
                            if (itb->ite[ii->entry].s.mdu.dtime & 
                                LEASE_EXCLUDE) {
                                ret = -ELOCKED;
                                goto out;
                            }
                        }
                    }
                }
                /* ok to set the new lease lock now */
                value = LEASE_SEQNO(&hmo.lease_seqno);
                if (hi->dlen & LEASE_EXCLUDE)
                    value |= hmo.tick | LEASE_EXCLUDE;
                else if (hi->dlen & LEASE_SHARED)
                    value |= hmo.tick | LEASE_SHARED;
                ite_lease_set(&itb->ite[ii->entry], value);
                /* note that, we do not have to compare value with return
                 * value! */
                *(u64 *)data = value;
            } else {
                ret = -EINVAL;
                goto out;
            }
        } else if (unlikely(hi->flag & INDEX_RELEASE)) {
            if (hi->dlen & LEASE_MASK) {
                if (hi->dlen == itb->ite[ii->entry].s.mdu.dtime) {
                    ite_lease_set(&itb->ite[ii->entry], 0);
                } else {
                    /* it is ok to get the EINVAL result for shared lease
                     * lock. only the last access can release the lock, if it
                     * releases the shared lock firstly, other clients may got
                     * wrong result. However, this behaver is acceptable for
                     * the RACE of empty directory removal and new file
                     * create. Thus, FIXME! */
                    if (itb->ite[ii->entry].s.mdu.dtime & LEASE_SHARED)
                        ret = 0;
                    else
                        ret = -EINVAL;
                    goto out;
                }
            } else {
                ret = -EINVAL;
                goto out;
            }
        } else if (hi->flag & INDEX_SYMLINK) {
            /* symlink */
            hvfs_err(mds, "Find the ITE and can NOT symlink it.\n");
            ret = -EEXIST;
            goto out;
        } else {
            hvfs_err(mds, "Hooo, what is your type: 0x%x\n", hi->flag);
            ret = -EINVAL;
            goto out;
        }
        ret = 0;
        goto out;
    }
    /* OK, can not find it, so ... */
    hvfs_verbose(mds, "OK, the ITE do NOT exist in the ITB.\n");
    if (likely(hi->flag & INDEX_CREATE || hi->flag & INDEX_SYMLINK)) {
        hvfs_verbose(mds, "Not find the ITE and create/symlink it.\n");
        /* checking the split status */
        *oi= itb_dirty(itb, txg, l, otxg);
        if (unlikely((*oi) != itb)) {
            if (!(*oi)) {
                ret = -EAGAIN;  /* w/ itb.rlocked, index lock dropped */
                goto out_nolock;
            } else {
                /* this means the itb is cowed, we should refresh ourself */
                /* w/ itb.runlocked and oi->rlocked */
                /* NOTE: maybe return -ERESTART to redo the access */
                goto refresh;
            }
        }
        ret = itb_add_ite(itb, hi, data, l, *otxg, &dtite);
    } else {
        /* other operations means ENOENT */
        if (itb->h.flag == ITB_JUST_SPLIT)
            ret = -ESPLIT;
        else
            ret = -ENOENT;
    }
out:
    /* put the lock */
    if (hi->flag & INDEX_LOOKUP)
        itb_index_runlock(l);
    else
        itb_index_wunlock(l);
out_nolock:
    *oi = itb;
    return ret;
refresh:
    /* already released index.lock */
    if (unlikely((*oi) == ERR_PTR(-ERESTART))) {
        ret = -ERESTART;
        goto out_nolock;
    } else {
        itb = *oi;
        goto retry;
    }
}

/* itb_search_dtriggered() is a directory triggered version of itb_search()
 */
int itb_search_dtriggered(struct hvfs_index *hi, struct itb *itb, 
                          void *data, struct hvfs_txg *txg, 
                          struct itb **oi, struct hvfs_txg **otxg)
{
    u64 offset, pos;
    u64 total = 1 << (ITB_DEPTH + 1);
    atomic64_t *as;
    struct itb_index *ii;
    struct itb_lock *l;
    struct dhe *e;
    struct ite *dtite;
    int ret = -ENOENT;

    PREPARE_DIR_TRIGGER(e, hi);
    
    /* NOTE: if we are in retrying, we know that the ITB will not COW
     * again! */
retry:
    if (likely(hmo.conf.itbid_check)) {
        if (((hi->hash >> ITB_DEPTH) & ((1 << itb->h.depth) - 1)) !=
            itb->h.itbid) {
            /* This means the ITB we choose has completed one split, and it is
             * not the target location we should resident in. We need restart
             * our access. */
            ret = -ESPLIT;
            hvfs_debug(mds, "Under SPLIT, Location Changed.(%ld vs %ld)"
                       " %s retry\n",
                       ((hi->hash >> ITB_DEPTH) & ((1 << itb->h.depth) - 1)),
                       itb->h.itbid,
                       hi->name);
            goto out_nolock;
        }
    }

    pos = offset = hi->hash & ((1 << itb->h.adepth) - 1);
    /* get the ITE lock */
    l = &itb->lock[offset / ITB_LOCK_GRANULARITY];
    if (hi->flag & INDEX_LOOKUP) {
        itb_index_rlock(l);
        as = &hmo.prof.itb.rsearch_depth;
    } else {
        itb_index_wlock(l);
        as = &hmo.prof.itb.wsearch_depth;
    }
    
    while (offset < total) {
        ii = &itb->index[offset];
        if (ii->flag == ITB_INDEX_FREE)
            break;
        atomic64_inc(as);
        ret = ite_match(&itb->ite[ii->entry], hi);

        if (ii->flag == ITB_INDEX_UNIQUE) {
            if (ret == ITE_MATCH_MISS) {
                break;
            }
        } else {
            /* CONFLICT & OVERFLOW */
            if (ret == ITE_MATCH_MISS) {
                offset = ii->conflict;
                continue;
            }
        }
        /* OK, found it, already lock it then do xxx on it */
        hvfs_verbose(mds, "OK, the ITE do exist in the ITB.\n");
        if (hi->flag & INDEX_LOOKUP) {
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_LOOKUP, itb, 
                              &itb->ite[ii->entry], hi, 
                              ret, out);
            /* check if it has been locked yet */
            ret = ite_lease_check_setup(hi, itb, &itb->ite[ii->entry]);
            if (unlikely(ret)) {
                goto out;
            }
            /* read MDU to buffer */
            hi->uuid = itb->ite[ii->entry].uuid;
            if (hi->flag & INDEX_KV)
                memcpy(data, &(itb->ite[ii->entry].v),
                       KV_HEADER_LEN + itb->ite[ii->entry].v.len);
            else
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            /* FIXME: we should add symlink handling here! */
            __data_column_hook(hi, itb, ii, data);
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_LOOKUP, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (unlikely(hi->flag & INDEX_CREATE)) {
            /* already exist, so... */
            if (!(hi->flag & INDEX_CREATE_FORCE)) {
                /* should return -EEXIST */
                ret = -EEXIST;
                goto out;
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_FORCE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            /* FIXME: ok, forcely do it */
            if (hi->flag & INDEX_CREATE_DIR) {
                hvfs_debug(mds, "Forcely create dir now \n");
                /* Forcely create dir? should not happen! */
                ret = -EEXIST;
                goto out;
            } else if (hi->flag & INDEX_CREATE_COPY) {
                hvfs_debug(mds, "Forcely create with MDU ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (unlikely((*oi) != itb)) {
                    if (!(*oi)) {
                        ret = -EAGAIN;  /* w/ itb.rlocked */
                        goto out_nolock;
                    } else {
                        /* this means the itb is cowed, we should refresh
                         * ourself */
                        /* w/ itb.runlocked and oi->rlocked */
                        goto refresh;
                    }
                }
                ite_update(hi, &itb->ite[ii->entry]);
                hi->uuid = itb->ite[ii->entry].uuid;
                memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            } else if (hi->flag & INDEX_CREATE_LINK) {
                hvfs_verbose(mds, "Forcely create hard link ...\n");
                *oi = itb_dirty(itb, txg, l, otxg);
                if (!(*oi)) {
                    ret = -EAGAIN;
                    goto out_nolock;
                } else if ((*oi) != itb) {
                    /* this measn the itb is cowed, we should refresh ourself */
                    goto refresh;
                }
                ite_update(hi, &itb->ite[ii->entry]);
                hi->uuid = itb->ite[ii->entry].uuid;
                memcpy(data, &(itb->ite[ii->entry].g), 
                       sizeof(struct link_source));
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_FORCE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (hi->flag & INDEX_MDU_UPDATE) {
            /* setattr, no failure */
            hvfs_verbose(mds, "Find the ITE and update the MDU.\n");
            /* if it is a link target, client should restat the truely link
             * source! */
            if (itb->ite[ii->entry].flag & ITE_FLAG_LS) {
                ret = -EACCES;
                goto out;
            }
            *oi = itb_dirty(itb, txg, l, otxg);
            if (unlikely((*oi) != itb)) {
                if (!(*oi)) {
                    ret = -EAGAIN;  /* w/ itb.rlocked */
                    goto out_nolock;
                } else {
                    /* this means the itb is cowed, we should refresh ourself */
                    /* w/ itb.runlocked and oi->rlocked */
                    goto refresh;
                }
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_UPDATE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            ite_update(hi, &itb->ite[ii->entry]);
            if (unlikely((itb->ite[ii->entry].s.mdu.mode & S_IFDIR) && 
                         (itb->ite[ii->entry].s.mdu.nlink == 0))) {
                /* BUG: we should unlink this dir now, is it? */
                itb_del_ite(itb, &itb->ite[ii->entry], offset, pos);
            }
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            __data_column_hook(hi, itb, ii, data);
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_UPDATE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (hi->flag & INDEX_UNLINK) {
            /* unlink */
            hvfs_verbose(mds, "Find the ITE and unlink it.\n");
            *oi = itb_dirty(itb, txg, l, otxg);
            if (unlikely((*oi) != itb)) {
                if (!(*oi)) {
                    ret = -EAGAIN;  /* w/ itb.rlocked */
                    goto out_nolock;
                } else {
                    /* this means the itb is cowed, we should refresh ourself */
                    /* w/ itb.runlocked and oi->rlocked */
                    goto refresh;
                }
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_UNLINK, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            ite_unlink(&itb->ite[ii->entry], itb, offset, pos);
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_UNLINK, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (hi->flag & INDEX_LINK_ADD) {
            /* hard link */
            hvfs_verbose(mds, "Find the ITE and hard link it.\n");
            /* check if this is a hard link ITE */
            if (itb->ite[ii->entry].flag & ITE_FLAG_LS) {
                ret = -EACCES;
                goto out;
            }
            *oi = itb_dirty(itb, txg, l, otxg);
            if (!(*oi)) {
                ret = -EAGAIN;
                goto out_nolock;
            } else if ((*oi) != itb) {
                /* this means the itb is cowed, we should refresh ourself */
                goto refresh;
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_LINKADD, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            /* ok, this is an ugly API, the client put the nlink delta in the
             * msg->tx.arg0, and mds_linkadd() copy it to hi->dlen, because in
             * this function we cant access the msg :( */
            itb->ite[ii->entry].s.mdu.nlink += (int)hi->dlen;
            if (unlikely(itb->ite[ii->entry].s.mdu.nlink == 0 &&
                         !(itb->ite[ii->entry].flag & ITE_FLAG_GDT))) {
                /* Hoo, we should unlink the entry now, make sure that you
                 * must not unlink the directory entry */
                itb_del_ite(itb, &itb->ite[ii->entry], offset, pos);
            }
            hi->uuid = itb->ite[ii->entry].uuid;
            memcpy(data, &(itb->ite[ii->entry].g), HVFS_MDU_SIZE);
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_LINKADD, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (unlikely(hi->flag & INDEX_ACQUIRE)) {
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_ACQUIRE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            /* Note that, we have already been wlock protected */
            if (hi->dlen & LEASE_MASK) {
                u64 value;
                
                if (!LEASE_IS_TIMEOUT(itb->ite[ii->entry].s.mdu.dtime)) {
                    if (hi->dlen != itb->ite[ii->entry].s.mdu.dtime) {
                        if (hi->dlen & LEASE_EXCLUDE) {
                            if (itb->ite[ii->entry].s.mdu.dtime & 
                                LEASE_MASK) {
                                ret = -ELOCKED;
                                goto out;
                            }
                        } else if (hi->dlen & LEASE_SHARED) {
                            if (itb->ite[ii->entry].s.mdu.dtime & 
                                LEASE_EXCLUDE) {
                                ret = -ELOCKED;
                                goto out;
                            }
                        }
                    }
                }
                /* ok to set the new lease lock now */
                value = LEASE_SEQNO(&hmo.lease_seqno);
                if (hi->dlen & LEASE_EXCLUDE)
                    value |= hmo.tick | LEASE_EXCLUDE;
                else if (hi->dlen & LEASE_SHARED)
                    value |= hmo.tick | LEASE_SHARED;
                ite_lease_set(&itb->ite[ii->entry], value);
                /* note that, we do not have to compare value with return
                 * value! */
                *(u64 *)data = value;
            } else {
                ret = -EINVAL;
                goto out;
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_ACQUIRE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (unlikely(hi->flag & INDEX_RELEASE)) {
            SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_RELEASE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
            if (hi->dlen & LEASE_MASK) {
                if (hi->dlen == itb->ite[ii->entry].s.mdu.dtime) {
                    ite_lease_set(&itb->ite[ii->entry], 0);
                } else {
                    /* it is ok to get the EINVAL result for shared lease
                     * lock. only the last access can release the lock, if it
                     * releases the shared lock firstly, other clients may got
                     * wrong result. However, this behaver is acceptable for
                     * the RACE of empty directory removal and new file
                     * create. Thus, FIXME! */
                    if (itb->ite[ii->entry].s.mdu.dtime & LEASE_SHARED)
                        ret = 0;
                    else
                        ret = -EINVAL;
                    goto out;
                }
            } else {
                ret = -EINVAL;
                goto out;
            }
            SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_RELEASE, itb,
                              &itb->ite[ii->entry], hi,
                              ret, out);
        } else if (hi->flag & INDEX_SYMLINK) {
            /* symlink */
            hvfs_err(mds, "Find the ITE and can NOT symlink it.\n");
            ret = -EEXIST;
            goto out;
        } else {
            hvfs_err(mds, "Hooo, what is your type: 0x%x\n", hi->flag);
            ret = -EINVAL;
            goto out;
        }
        ret = 0;
        goto out;
    }
    /* OK, can not find it, so ... */
    hvfs_verbose(mds, "OK, the ITE do NOT exist in the ITB.\n");
    if (likely(hi->flag & INDEX_CREATE || hi->flag & INDEX_SYMLINK)) {
        hvfs_verbose(mds, "Not find the ITE and create/symlink it.\n");
        /* checking the split status */
        *oi= itb_dirty(itb, txg, l, otxg);
        if (unlikely((*oi) != itb)) {
            if (!(*oi)) {
                ret = -EAGAIN;  /* w/ itb.rlocked, index lock dropped */
                goto out_nolock;
            } else {
                /* this means the itb is cowed, we should refresh ourself */
                /* w/ itb.runlocked and oi->rlocked */
                /* NOTE: maybe return -ERESTART to redo the access */
                goto refresh;
            }
        }
        SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_CREATE, itb,
                          NULL, hi, ret, out);
        ret = itb_add_ite(itb, hi, data, l, *otxg, &dtite);
        SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_CREATE, itb,
                          dtite, hi, ret, out);
    } else {
        /* other operations means ENOENT */
        if (itb->h.flag == ITB_JUST_SPLIT)
            ret = -ESPLIT;
        else
            ret = -ENOENT;
    }
out:
    /* put the lock */
    if (hi->flag & INDEX_LOOKUP)
        itb_index_runlock(l);
    else
        itb_index_wunlock(l);
out_nolock:
    FINA_DIR_TRIGGER(e);
    *oi = itb;
    return ret;
refresh:
    /* already released index.lock */
    if (unlikely((*oi) == ERR_PTR(-ERESTART))) {
        ret = -ERESTART;
        goto out_nolock;
    } else {
        itb = *oi;
        goto retry;
    }
}

/* __readdir_filter() filter whether this ite entry should be return
 *
 * Return Value: 1: true and dump, 0: false and not dump
 */
static inline
int __readdir_filter(struct hvfs_index *hi, struct itb *i, 
                     int idx, int op, void *arg)
{
    switch (op) {
    default:
    case KV_OP_SCAN:
    case KV_OP_SCAN_CNT:
        return 1;
        break;
    case KV_OP_GREP:
    case KV_OP_GREP_CNT:
    {
        char needle[hi->namelen + 1];
    
        memcpy(needle, arg, hi->namelen);
        needle[hi->namelen] = '\0';

        if (i->ite[idx].v.flags & HVFS_KV_NORMAL) {
            if (strstr((char *)(i->ite[idx].v.value), needle) 
                == NULL) {
                return 0;
            } else
                return 1;
        } else if (i->ite[idx].v.flags &HVFS_KV_STR) {
            if (strstr((char *)(i->ite[idx].v.value) + i->ite[idx].v.klen, 
                       needle) == NULL) {
                return 0;
            } else
                return 1;
        }
        break;
    }
    }

    return 1;
}

/* itb_readdir()
 *
 * NOTE: holding the bucket.rlock, be.rlock, itb.rlock
 */
int itb_readdir(struct hvfs_index *hi, struct itb *i, 
                struct hvfs_md_reply *hmr)
{
    int err = 0;
    
    /* Note that, if we are in the KV store mode, we just return the names in
     * this itb. If we are in the FS mode, we should return the dentries to
     * the server. */
    if (hi->flag & INDEX_KV) {
        char kbuf[128];
        void *p;
        int idx;
        
        /* Step 1: we calculate the buffer length */
        hmr->len = atomic_read(&i->h.entries) * sizeof(u32);
        if (!hmr->len) {
            /* no active entries in this ITB */
            goto out;
        }
        for (idx = 0; idx < (1 << i->h.adepth); idx++) {
            if (test_bit(idx, (void *)i->bitmap)) {
                if (i->ite[idx].v.flags & HVFS_KV_NORMAL) {
                    /* this is a kv table entry */
                    snprintf(kbuf, 127, "%ld", i->ite[idx].v.key);
                    hmr->len += strlen(kbuf);
                } else if (i->ite[idx].v.flags & HVFS_KV_STR) {
                    /* this is a kvs table entry */
                    hmr->len += i->ite[idx].v.klen;
                } else {
                    hmr->len += i->ite[idx].namelen;
                }
            }
        }
        /* Step 2: alloc the space now */
        hmr->data = xzalloc(hmr->len);
        if (!hmr->data) {
            hvfs_err(mds, "xzalloc hmr->data len %d failed.\n",
                     hmr->len);
            hmr->len = 0;
            err = -ENOMEM;
            goto out;
        }
        /* Step 3: copy the names */
        p = hmr->data;
        for (idx = 0; idx < (1 << i->h.adepth); idx++) {
            if (test_bit(idx, (void *)i->bitmap)) {
                if (i->ite[idx].v.flags & HVFS_KV_NORMAL) {
                    if (__readdir_filter(hi, i, idx, hi->op, hi->data)) {
                        snprintf(kbuf, 127, "%ld", i->ite[idx].v.key);
                        *(u32 *)p = strlen(kbuf);
                        p += sizeof(u32);
                        memcpy(p, kbuf, strlen(kbuf));
                        p += strlen(kbuf);
                    }
                } else if (i->ite[idx].v.flags & HVFS_KV_STR) {
                    if (__readdir_filter(hi, i, idx, hi->op, hi->data)) {
                        *(u32 *)p = i->ite[idx].v.klen;
                        p += sizeof(u32);
                        memcpy(p, i->ite[idx].v.value, i->ite[idx].v.klen);
                        p += i->ite[idx].v.klen;
                    }
                } else {
                    *(u32 *)p = i->ite[idx].namelen;
                    p += sizeof(u32);
                    memcpy(p, i->ite[idx].s.name, i->ite[idx].namelen);
                    p += i->ite[idx].namelen;
                }
            }
        }
        /* save # of entries to hmr->dnum */
        hmr->dnum = atomic_read(&i->h.entries);
    } else {
        void *p;
        int idx;
        
        /* Step 1: we calculate the buffer length */
        hmr->len = atomic_read(&i->h.entries) * sizeof(struct dentry_info);
        if (!hmr->len) {
            /* no active entries in this ITB */
            goto out;
        }
        for (idx = 0; idx < (1 << i->h.adepth); idx++) {
            if (test_bit(idx, (void *)i->bitmap)) {
                if (((i->ite[idx].flag & ITE_STATE_MASK) != 
                     ITE_ACTIVE) || 
                    (i->ite[idx].flag & ITE_FLAG_KV)) {
                    continue;
                } else {
                    hmr->len += i->ite[idx].namelen;
                }
            }
        }
        /* Step 2: alloc the space now */
        hmr->data = xzalloc(hmr->len);
        if (!hmr->data) {
            hvfs_err(mds, "xzalloc hmr->data len %d failed.\n",
                     hmr->len);
            hmr->len = 0;
            err = -ENOMEM;
            goto out;
        }
        /* Step 3: copy dentry_info and the names */
        p = hmr->data;
        for (idx = 0; idx < (1 << i->h.adepth); idx++) {
            if (test_bit(idx, (void *)i->bitmap)) {
                if (((i->ite[idx].flag & ITE_STATE_MASK) !=
                     ITE_ACTIVE) ||
                    (i->ite[idx].flag & ITE_FLAG_KV)) {
                    err++;
                    continue;
                } else {
                    struct dentry_info *di = p;

                    di->uuid = i->ite[idx].uuid;
                    di->mode = i->ite[idx].s.mdu.mode;
                    di->namelen = i->ite[idx].namelen;
                    p += sizeof(*di);
                    memcpy(p, i->ite[idx].s.name, i->ite[idx].namelen);
                    p += i->ite[idx].namelen;
                }
            }
        }
        /* save # of entries to hmr->dnum */
        hmr->dnum = atomic_read(&i->h.entries) - err;
        err = 0;
    }

out:
    return err;
}

/* itb_readdir_dtriggered()
 *
 * NOTE: holding the bucket.rlock, be.rlock, itb.rlock
 */
int itb_readdir_dtriggered(struct hvfs_index *hi, struct itb *i, 
                           struct hvfs_md_reply *hmr)
{
    struct dhe *e;
    int err = 0;

    PREPARE_DIR_TRIGGER(e, hi);
    
    SETUP_DIR_TRIGGER(e, DIR_TRIG_PRE_LIST, i, NULL, hi, err, out);
    
    err = itb_readdir(hi, i, hmr);

    SETUP_DIR_TRIGGER(e, DIR_TRIG_POST_LIST, i, NULL, hi, err, out);
out:
    FINA_DIR_TRIGGER(e);
    
    return err;
}

/* itb_dump()
 *
 * NOTE: this function is written for debuging, no locking
 */
void itb_dump(struct itb *i)
{
    char *line;
    struct itb_index *ii;
    int j, l;
    
    /* dump the itb header */
    hvfs_info(mds, "Header of ITB %p:\n", i);
    hvfs_info(mds, "flag %x state %x depth %d adepth %d\n",
              i->h.flag, i->h.state, i->h.depth, i->h.adepth);
    hvfs_info(mds, "entries %s%d%s, max_offset %d, conflicts %d, "
              "pseudo_conflicts %d\n",
              HVFS_COLOR_RED, atomic_read(&i->h.entries), HVFS_COLOR_END, 
              atomic_read(&i->h.max_offset),
              atomic_read(&i->h.conflicts), 
              atomic_read(&i->h.pseudo_conflicts));
    hvfs_info(mds, "txg %ld puuid %ld itbid %ld hash %lx\n",
              i->h.txg, i->h.puuid, i->h.itbid, i->h.hash);
    hvfs_info(mds, "be %p len %d inf %d itu %d\n",
              i->h.be, atomic_read(&i->h.len), i->h.inf, i->h.itu);

    /* dump the bitmap */
    line = xzalloc(128 * 1024);
    if (!line)
        return;
    for (j = 0, l = 0; j < (1 << (ITB_DEPTH - 3)); j++) {
        l += sprintf(line + l, "%x", i->bitmap[j]);
    }
    hvfs_info(mds, "Bitmap of ITB %p:\n%s\n", i, line);
    /* dump the index region */
    hvfs_info(mds, "Index of ITB %p:\n", i);
    for (j = 0, l = 0; j < (1 << ITB_DEPTH); j++, l = 0) {
        ii = &i->index[j];
        if (ii->flag == ITB_INDEX_FREE)
            continue;
        l += sprintf(line + l, "offset %4d: ", j);
        do {
            l += sprintf(line + l, "<%x,%d,%d,%s>", ii->flag, ii->entry, 
                         ii->conflict, i->ite[ii->entry].s.name);
        } while (ii->flag != ITB_INDEX_UNIQUE && 
                 (ii = &i->index[ii->conflict]));
        line[l] = '\0';
        hvfs_info(mds, "%s\n", line);
    }
    xfree(line);
    return;
}

/* async_unlink()
 */
void async_unlink(time_t t)
{
    if (!hmo.conf.async_unlink)
        return;
    if (!hmo.conf.unlink_interval)
        return;
    if (t < hmo.unlink_ts + hmo.conf.unlink_interval) {
        return;
    }
    hmo.unlink_ts = t;
    hvfs_debug(mds, "Do unlink dangling ITEs.\n");
    sem_post(&hmo.unlink_sem);
}

/* async_unlink_ite()
 *
 * NOTE: holding the itb.rlock
 */
void async_unlink_ite(struct itb *i, int *dc)
{
    u64 offset = 0;
    u64 total = 1 << (i->h.adepth);
    atomic64_t *as;
    struct itb_index *ii;
    struct itb_lock *l;
    struct ite *e;

    as = &hmo.prof.itb.async_unlink;

    /* FIXME: we need to dirty the ITBs, it is a dirty work */

    while (offset < total) {
        l = &i->lock[offset & (ITB_LOCK_GRANULARITY - 1)];
        itb_index_wlock(l);

        ii = &i->index[offset];
        if (ii->flag == ITB_INDEX_FREE) {
            /* this offset is a hole */
            offset++;
            itb_index_wunlock(l);
            continue;
        }
        if (ii->flag == ITB_INDEX_UNIQUE) {
            /* this offset only have one entry */
            e = &i->ite[ii->entry];
            if ((e->flag & ITE_STATE_MASK) == ITE_UNLINKED) {
                __ite_unlink(i, offset);
                (*dc)++;
                atomic64_inc(as);
                hvfs_debug(mds, "UNIQUE unlink w/ AU %ld\n", 
                           atomic64_read(as));
            }
        } else {
            /* this offset has at least two entries */
            u64 saved = offset;
            u64 prev = offset;
            int quit = 0, needswap = 0;
            
            hvfs_debug(mds, "Hooray offset %ld\n", offset);
            do {
            retry:
                ii = &i->index[offset];
                hvfs_debug(mds, "offset %ld <%x,%d,%d>\n", 
                           offset, ii->flag, ii->entry, ii->conflict);
                if (ii->flag == ITB_INDEX_FREE)
                    break;
                e = &i->ite[ii->entry];
                hvfs_debug(mds, "e->flag %x %ld\n", e->flag & ITE_STATE_MASK, 
                           atomic64_read(&hmo.prof.itb.async_unlink));
                if ((e->flag & ITE_STATE_MASK) == ITE_UNLINKED) {
                    hvfs_debug(mds, "prev %ld offset %ld\n", prev, offset);
                    if (offset == saved) {
                        /* unlink the head, and we know that there is a next
                         * entry. we must loop in the list and swap the first
                         * unlinked entry to this location */
                        needswap = 1;
                        prev = offset;
                    } else if (ii->flag == ITB_INDEX_UNIQUE) {
                        /* unlink the tail */
                        i->index[prev].flag = ITB_INDEX_UNIQUE;
                        __ite_unlink(i, offset);
                        quit = 1;
                    } else {
                        /* unlink the middle entry */
                        i->index[prev].conflict = ii->conflict;
                        __ite_unlink(i, offset);
                        hvfs_debug(mds, "del offset %ld prev %ld, next %d\n", 
                                   offset, prev, ii->conflict);
                    }
                    (*dc)++;
                    atomic64_inc(as);
                } else {
                    if (needswap) {
                        u32 saved_entry = ii->entry;
                        ii->entry = i->index[saved].entry;
                        i->index[saved].entry = saved_entry;
                        needswap = 0;
                        hvfs_debug(mds, "swap %ld and %ld\n", offset, saved);
                        /* ok, we need restart the unlink process */
                        goto retry;
                    }
                    if (ii->flag == ITB_INDEX_UNIQUE)
                        quit = 1;
                    prev = offset;
                }
                offset = ii->conflict;
            } while (offset < (total << 1) && (!quit));
            if (needswap) {
                /* this means we need free the head now */
                ii = &i->index[saved];
                if (ii->flag !=  ITB_INDEX_UNIQUE) {
                    hvfs_info(mds, "saved %ld\n", saved);
                    itb_dump(i);
                }
                ASSERT(ii->flag == ITB_INDEX_UNIQUE, mds);
                __ite_unlink(i, saved);
            }
            offset = saved;
        }
        offset++;
        itb_index_wunlock(l);
        if (*dc >= hmo.conf.max_async_unlink) {
            break;
        }
    }

    hvfs_debug(mds, "async unlink %d entries in ITB %ld.\n", 
               *dc, i->h.itbid);
}

/* async_unlink_local()
 *
 * Delete the dangling ITEs within this local node periodically
 */
void *async_unlink_local(void *arg)
{
    sigset_t set;
    struct itbh *ih;
    int dc = 0;                 /* counter for the dealt ITEs */
    int err = 0;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    while (!hmo.unlink_thread_stop) {
        dc = 0;
        err = sem_wait(&hmo.unlink_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Unlink thread wakeup to clean the dangling ITEs.\n");
        /* ok, let us scan the ITBs */
        list_for_each_entry(ih, &hmo.async_unlink, unlink) {
            xrwlock_rlock(&ih->lock);
            if (ih->state == ITB_STATE_COWED) {
                /* ok, this ITB is stale, we just drop this guy and gc it in
                 * the next unlink chance. So, the unlink may dangling for a
                 * very long time if this ITB never touched again soon. */
                xrwlock_runlock(&ih->lock);
                continue;
            }
            /* hooray, let us deal with this itb */
#if 0
            itb_dump((struct itb *)ih);
#endif
            async_unlink_ite((struct itb *)ih, &dc);
            xrwlock_runlock(&ih->lock);
            if (dc >= hmo.conf.max_async_unlink)
                break;
        }
        if (dc)
            hvfs_info(mds, "In this wave we unlink %d ITEs\n", dc);
    }

    return ERR_PTR(err);
}

/* unlink_thread_init()
 */
int unlink_thread_init(void)
{
    pthread_attr_t attr;
    int err = 0, stacksize;

    /* init the thread stack size */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(mds, "Init pthread attr failed\n");
        goto out;
    }
    stacksize = (hmo.conf.stacksize > (1 << 20) ? 
                 hmo.conf.stacksize : (2 << 20));
    err = pthread_attr_setstacksize(&attr, stacksize);
    if (err) {
        hvfs_err(mds, "set thread stack size to %d failed w/ %d\n", 
                 stacksize, err);
        goto out;
    }

    if (!hmo.conf.async_unlink)
        return 0;
    
    sem_init(&hmo.unlink_sem, 0, 0);
    hmo.unlink_thread_stop = 0;
    hmo.unlink_ts = 0;

    err = pthread_create(&hmo.unlink_thread, &attr, &async_unlink_local,
                         NULL);
    if (err) {
        hvfs_err(mds, "create unlink thread failed %d\n", err);
        goto out;
    }
out:
    return err;
}

/* unlink_thread_destroy()
 */
void unlink_thread_destroy()
{
    if (!hmo.conf.async_unlink)
        return;
    hmo.unlink_thread_stop = 1;
    sem_post(&hmo.unlink_sem);
    if (hmo.unlink_thread)
        pthread_join(hmo.unlink_thread, NULL);

    sem_destroy(&hmo.unlink_sem);
}

/* LZO region */
int itb_lzo_compress(struct itb *in, struct itb *tmp, struct itb **oi)
{
    void *workmem;
    lzo_uint zlen = 0, inlen;
    int err = 0;

    *oi = in;

    /* got the work memory */
    workmem = pthread_getspecific(hmo.lzo_workmem);
    if (!workmem) {
        hvfs_err(mds, "LZO work memory lost?!\n");
        return -EFAULT;
    }
    
    /* copy the itb header */
    memcpy(&tmp->h, &in->h, sizeof(tmp->h));
    inlen = atomic_read(&in->h.len) - sizeof(in->h);

    err = lzo1x_1_compress((void *)in->lock, inlen,
                           (void *)tmp->lock, &zlen, workmem);
    if (err == LZO_E_OK) {
        err = 0;
    } else {
        hvfs_err(mds, "LZO compress failed w/ %d\n", err);
        goto out;
    }

    if (zlen >= inlen) {
        hvfs_warning(mds, "This ITB %ld is impossible to compress!\n", 
                     in->h.itbid);
        goto out;
    }
    /* exchange the zlen and len */
    atomic_set(&tmp->h.zlen, atomic_read(&tmp->h.len));
    atomic_set(&tmp->h.len, sizeof(tmp->h) + zlen);
    tmp->h.compress_algo = COMPR_LZO;
    *oi = tmp;
    
out:
    return err;
}

/* in-position unpack the ITB
 */
int itb_lzo_decompress(struct itb *in)
{
    lzo_uint outlen, inlen;
    int err = 0;
    void *p;

    inlen = atomic_read(&in->h.len) - sizeof(in->h);
    p = xmalloc(inlen);
    if (!p) {
        hvfs_err(mds, "Unable to alloc the memory to decompress ITB!\n");
        err = -ENOMEM;
        goto out;
    }
    memcpy(p, (void *)in->lock, inlen);
    
    err = lzo1x_decompress(p, inlen, 
                           (void *)in->lock, &outlen, NULL);
    if (err == LZO_E_OK && 
        outlen == atomic_read(&in->h.zlen) - sizeof(in->h)) {
        err = 0;
    } else {
        hvfs_err(mds, "LZO decompress failed w/ %d\n", err);
    }
    /* clear the compress flag */
    in->h.compress_algo = COMPR_NONE;
    /* exchange the len back */
    atomic_set(&in->h.len, outlen + sizeof(in->h));
    xfree(p);
    
out:
    return err;
}

