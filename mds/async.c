/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-18 22:45:54 macan>
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
#include "tx.h"
#include "mds.h"
#include "lib.h"
#include "async.h"
#include "ring.h"
#include "bitmapc.h"

struct async_update_mlist g_aum;
/* g_bitmap_deltas saves the requested(but not replied) bitmap deltas, we
 * should do resends on it.
 *
 * Callback function xxx should be called on the AUR bitmap replies to remove
 * the delta entry from g_bitmap_deltas list.
 */
LIST_HEAD(g_bitmap_deltas);
xlock_t g_bitmap_deltas_lock;

LIST_HEAD(g_dir_deltas);
xlock_t g_dir_deltas_lock;

void async_update_checking(time_t t)
{
    static time_t last_ts;
    static int last_requested, last_handled;

    if (atomic64_read(&hmo.prof.itb.split_submit) == 
        atomic64_read(&hmo.prof.itb.split_local)) {
        last_ts = t;
        /* for now, we do not go back to fast mode */
#if 0
        if (hmo.conf.cbht_slow_down) {
            hmo.conf.cbht_slow_down = 0;
            hvfs_info(mds, "OK, back to fast mode @ %s", ctime(&t));
        }
#endif
        last_requested = last_handled = 
            atomic64_read(&hmo.prof.itb.split_submit);
    }
    
    if (t < last_ts + 30) {
        last_requested = atomic64_read(&hmo.prof.itb.split_submit);
        last_handled = atomic64_read(&hmo.prof.itb.split_local);
        return;
    }
    
    if (atomic64_read(&hmo.prof.itb.split_submit) >= last_requested &&
        atomic64_read(&hmo.prof.itb.split_local) == last_handled) {
        /* going into slow mode now */
        if (!hmo.conf.cbht_slow_down) {
            hvfs_info(mds, "Ho, going into slow mode @ %s", ctime(&t));
            hmo.conf.cbht_slow_down = 1;
        }
    }
}

int __aur_itb_split(struct async_update_request *aur)
{
    struct itb *i = (struct itb *)aur->arg;
    struct dhe *e;
    struct chp *p;
    int err = 0;

    if (!i)
        return -EINVAL;

    /* first, we should find the destination MDS of the ITB */
    e = mds_dh_search(&hmo.dh, i->h.puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "We can not find the DH of PUUID %ld.\n",
                 i->h.puuid);
        err = PTR_ERR(e);
        goto out;
    }
    p = ring_get_point(i->h.itbid, e->salt, hmo.chring[CH_RING_MDS]);
    mds_dh_put(e);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto out;
    }
    
    /* then, we send the ITB or insert it in the local CBHT */
    if (hmo.site_id != p->site_id) {
        /* FIXME: need truely AU, for now we just ignore the mismatch */
        /* NOTE: we should transfer the ITB to the dest site w/ bitmap flip
         * notification. */
        struct xnet_msg *msg;
        /* Step 0: preparing */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_warning(xnet, "xnet_alloc_msg() failed, re-submit the"
                         " AU request.\n");
            au_submit(aur);
            return -ENOMEM;
        }
        /* Step 1: we should update the local bitmap */
        mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid,
                             MDS_BITMAP_SET);
        /* Step 2: we begin to transfer the ITB to the dest site */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                         hmo.site_id, p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_SPITB, i->h.itbid, 
                          ((struct itb *)i->h.twin)->h.itbid);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        hvfs_warning(mds, "Send the AU split %ld request to %lx. self salt %lx\n", 
                     i->h.itbid, msg->tx.dsite_id, e->salt);
        /* FIXME: for now we just send the whole ITB */
        ASSERT(list_empty(&i->h.list), mds);
        xnet_msg_add_sdata(msg, i, atomic_read(&i->h.len));
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mds, "AU split ITB sending failed w/ %d\n", err);
            goto msg_free;
        }
        /* Step 3: we waiting for the reply to confirm the delivery and
         * release the splitted ITB */
        ASSERT(msg->pair, mds);
        if (msg->pair->tx.err) {
            hvfs_err(mds, "Site %lx handle AUSplit failed w/ %d\n",
                     p->site_id, msg->pair->tx.err);
        }
        /* Step 3.inf we should free the ITB */
        itb_put((struct itb *)i->h.twin);
        hvfs_warning(mds, "Receive the AU split %ld reply from %lx.\n", 
                     i->h.itbid, msg->pair->tx.ssite_id);
        itb_free(i);
        atomic64_inc(&hmo.prof.mds.split);
    msg_free:
        xnet_free_msg(msg);
        if (err) {
            /* FIXME: we re-submit the request! */
            au_submit(aur);
        }
    } else {
        struct bucket *nb;
        struct bucket_entry *nbe;
        struct itb *ti, *saved_oi;
        struct hvfs_txg *t;

        /* pre-dirty this itb */
        t = mds_get_open_txg(&hmo);
        i->h.txg = t->txg;
        i->h.state = ITB_STATE_DIRTY;
        INIT_LIST_HEAD(&i->h.list);
        txg_add_itb(t, i);
        txg_put(t);
        /* change the splited ITB's state to NORMAL */
        saved_oi = (struct itb *)i->h.twin;
        i->h.twin = 0;

        /* insert into the CBHT */
        err = mds_cbht_insert_bbrlocked(&hmo.cbht, i, &nb, &nbe, &ti);
        if (err == -EEXIST) {
            /* someone create the new ITB, we have data losing */
            hvfs_err(mds, "Someone create ITB %ld(%ld), data losing ... "
                     "[failed fatal error]\n",
                     i->h.itbid, saved_oi->h.itbid);
        } else if (err) {
            hvfs_err(mds, "Internal error %d, data losing. "
                     "[failed fatal error]\n", err);
            /* FIXME: do not need to unlock */
            itb_put(saved_oi);
            goto out;
        }

        /* it is ok, we need free the locks */
        xrwlock_runlock(&nbe->lock);
        xrwlock_runlock(&nb->lock);

        /* FIXME: should we just use the rlock? */
        itb_put(saved_oi);
        /* then, we set the bitmap now */
        mds_dh_bitmap_update(&hmo.dh, i->h.puuid, i->h.itbid, 
                             MDS_BITMAP_SET);
        atomic64_inc(&hmo.prof.itb.split_local);
        atomic64_add(atomic_read(&i->h.entries), &hmo.prof.cbht.aentry);

        hvfs_warning(mds, "We update the bit of ITB %ld locally\n", i->h.itbid);
/*         mds_dh_bitmap_dump(&hmo.dh, i->h.puuid); */
    }
    
out:
    return err;
}

static inline
int __customized_send_request(struct bc_delta *bd)
{
    struct xnet_msg *msg;
    int err = 0;

    /* Step 1: prepare the xnet_msg */
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        hvfs_err(mds, "xnet_alloc_msg() failed.\n");
        err = -ENOMEM;
        goto out;
    }

    /* Step 2: construct the xnet_msg to send it to the destination */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hmo.site_id, bd->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_AUBITMAP, bd->uuid, bd->itbid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "Request to AU update the uuid %ld flip %ld "
                 "failed w/ %d\n",
                 bd->uuid, bd->itbid, err);
        goto out_free_msg;
    }

    /* we should got the reply to confirm and delete the bc_delta, but we do
     * not do this operation here. We use send w/o XNET_NEED_REPLY because the
     * reply maybe delievered very late. */
out_free_msg:
    xnet_free_msg(msg);
out:    
    return err;
}

/*
 * AUR BITMAP is used to do async bitmap flip. In this function we should send
 * the request to the target MDS, then wait for the reply. ONLY AFTER
 * receiving the reply we can safely free the bitmap delta.
 */
int __aur_itb_bitmap(struct async_update_request *aur)
{
    struct bitmap_delta_buf *pos;
    struct bc_delta *bd;
    struct dhe *gdte;
    struct chp *p;
    struct hvfs_txg *txg = (struct hvfs_txg *)aur->arg;
    u64 hash, itbid;
    int err = 0, i, local = 0, remote = 0, r2 = 0, skip = 0;

    /* we should iterate on the wbt->bdb list and transform each entry to
     * bc_delta and adding to the g_bitmap_deltas list and sending each entry
     * to the destination site. */
    list_for_each_entry(pos, &txg->bdb, list) {
        for (i = 0; i < pos->asize; i++) {
            /* Step 1: alloc the bc_delta */
            bd = mds_bc_delta_alloc();
            if (!bd) {
                hvfs_err(mds, "bc delta alloc failed on uuid %ld itbid %ld.\n",
                         pos->buf[i].uuid, pos->buf[i].nitb);
                continue;
            }
            /* Step 2: transform the bitmap_delta to bc_delta */
            /* FIXME: we should do the site_id recalculation! */
            bd->site_id = pos->buf[i].site_id;
            bd->uuid = pos->buf[i].uuid;
            bd->itbid = pos->buf[i].nitb;
            /* Step 3: add it to the g_bitmap_deltas */
            list_add(&bd->list, &g_bitmap_deltas);
        }
        atomic64_add(pos->asize, &hmo.prof.misc.au_bitmap);
    }

    txg_free(txg);

    if (unlikely(hmo.conf.option & HVFS_MDS_LIMITED)) {
        return 0;
    }
    
    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out;
    }

    /* Iterate on the g_bitmap_deltas list to send the request now. */
    xlock_lock(&g_bitmap_deltas_lock);
    list_for_each_entry(bd, &g_bitmap_deltas, list) {
        /* Step 0: we check if the uuid is the gdt_uuid */
        if (unlikely(bd->uuid == hmi.gdt_uuid)) {
            bd->site_id = mds_select_ring(&hmo);
            err = __customized_send_request(bd);
            if (err) {
                hvfs_err(mds, "send AU bitmap flip request failed w/ %d\n",
                         err);
            }
            r2++;
            continue;
        }
        /* Step 1: recalculate the dest site_id */
        hash = hvfs_hash_gdt(bd->uuid, hmi.gdt_salt);
        itbid = mds_get_itbid(gdte, hash);
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            skip++;
            continue;
        }
        bd->site_id = p->site_id;
        /* Step 2: send it to dest site, using isend(ONESHOT) */
        if (bd->site_id == hmo.site_id) {
            /* self shortcut */
            struct bc_delta *nbd;
            struct bc_entry *be;
            u64 offset;

            nbd = mds_bc_delta_alloc();
            if (!nbd) {
                hvfs_err(mds, "mds_bc_delta_alloc() failed.\n");
            }
            nbd->site_id = bd->site_id;
            nbd->uuid = bd->uuid;
            nbd->itbid = bd->itbid;

            xlock_lock(&hmo.bc.delta_lock);
            list_add(&nbd->list, &hmo.bc.deltas);
            xlock_unlock(&hmo.bc.delta_lock);
            /* finally, we should update the bc_entry if it exists */
            offset = BITMAP_ROUNDDOWN(nbd->itbid);
            be = mds_bc_get(nbd->uuid, offset);
            if (IS_ERR(be)) {
                if (be == ERR_PTR(-ENOENT)) {
                    hvfs_err(mds, "Warning: bc_entry %ld offset %ld does not "
                             "exist.\n", nbd->uuid, offset);
                } else {
                    hvfs_err(mds, "bc_get() %ld failed w/ %d\n", nbd->uuid, err);
                }
            } else {
                /* update the bits in bitmap */
                __set_bit(nbd->itbid - offset, (unsigned long *)be->array);
                mds_bc_put(be);
            }
            local++;
        } else {
            err = __customized_send_request(bd);
            if (err) {
                hvfs_err(mds, "send AU bitmap flip request failed w/ %d\n",
                         err);
            }
            remote++;
        }
    }
    xlock_unlock(&g_bitmap_deltas_lock);
    hvfs_warning(mds, "local %d remote %d r2 %d skip %d\n", 
                 local, remote, r2, skip);
    mds_dh_put(gdte);
    
out:
    return err;
}

void async_aubitmap_cleanup(u64 uuid, u64 itbid)
{
    struct bc_delta *bd, *n;
    
    xlock_lock(&g_bitmap_deltas_lock);
    list_for_each_entry_safe(bd, n, &g_bitmap_deltas, list) {
        if (uuid == bd->uuid && itbid == bd->itbid) {
            list_del(&bd->list);
            xfree(bd);
            break;
        }
    }
    xlock_unlock(&g_bitmap_deltas_lock);
}

/* AUR DIR_DELTA is used to do async dir updates. In this function we should
 * send the request to the target MDS, then wait for the reply. ONLY AFTER
 * receiving the reply we can safely free the dir delta
 */
int __aur_dir_delta(struct async_update_request *aur)
{
    struct hvfs_dir_delta_buf *pos;
    struct dir_delta_au *dda, *n;
    struct dhe *gdte;
    struct chp *p;
    struct list_head *tl = (struct list_head *)aur->arg;
    u64 hash, itbid;
    int new = 0, local = 0, remote = 0;
    int err = 0, i;

    /* we should iterate on the wbt->ddb list and transform each entry to
     * dir_delta_au and adding to the g_dir_deltas and sending each entry to
     * the destination site. */
    list_for_each_entry(pos, tl, list) {
        for (i = 0; i < pos->asize; i++) {
            /* Step 1: allco the dir_delta_au */
            dda = txg_dda_alloc();
            if (!dda) {
                hvfs_err(mds, "dir delta au alloc failed on uuid %ld\n",
                         pos->buf[i].duuid);
                continue;
            }
            /* Step 2: transform the dir delta to dir delta au */
            /* FIXME: we should do the site_id recalculation */
            dda->dd = pos->buf[i];
            dda->dd.salt = lib_random(0x3fffffab);
            /* Step 3: add it to the g_dir_deltas */
            list_add(&dda->list, &g_dir_deltas);
            new++;
        }
        atomic64_add(pos->asize, &hmo.prof.misc.au_dd);
    }

    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(mds, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out;
    }

    /* Interate on the g_dir_deltas list to send the request now. */
    xlock_lock(&g_dir_deltas_lock);
    list_for_each_entry_safe(dda, n, &g_dir_deltas, list) {
        /* Step 1: recalculate the dest site_id, actually the site_id is not
         * set on the first sending. */
        hash = hvfs_hash_gdt(dda->dd.duuid, hmi.gdt_salt);
        itbid = mds_get_itbid(gdte, hash);
        p = ring_get_point(itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            continue;
        }
        dda->dd.site_id = p->site_id;
        /* Step 2: send it to dest site, using isend(ONESHOT) */
        if (dda->dd.site_id == hmo.site_id) {
            /* 
             * Self update? If this happend, it means that the target MDS is
             * down and myself take cover of the GDT ITBs of the original
             * site. We known that the update should be done localy, then just
             * waiting for the next TXG acks.
             */
            struct hvfs_txg *t;

            /* NOTE THAT:
             *
             * add the dir delta to the local DDC is just one step, we should
             * update the local ITB!
             */
            err = txg_ddc_update_cbht(dda);
            if (err) {
                hvfs_err(mds, "DDA %ld update CBHT failed w/ %d\n",
                         dda->dd.duuid, err);
            }

            /* add to the txg->rddb list */
            t = mds_get_open_txg(&hmo);
            err = txg_rddb_add(t, dda, DIR_DELTA_REMOTE_UPDATE);
            txg_put(t);
            if (err) {
                hvfs_err(mds, "Self update add uuid %ld to rddb failed w/ %d\n",
                         dda->dd.duuid, err);
            }

            /* we have updated the cbht before. if we do not remove this
             * entry, another update will be triggered, and the update maybe
             * not idempotent ... So, we need to remove the entry! */
            list_del(&dda->list);
            xfree(dda);

            local++;
        } else {
            err = txg_ddc_send_request(dda);
            if (err) {
                hvfs_err(mds, "send AU dir delta request failed w/ %d\n",
                         err);
            }
            remote++;
        }
    }
    xlock_unlock(&g_dir_deltas_lock);
    hvfs_warning(mds, "new %d local %d remote %d\n", new, local, remote);
    mds_dh_put(gdte);

out:
    return err;
}

/*
 * This function should be called in m2m_audirdelta_r() to clean the
 * g_dir_deltas list.
 */
void async_audirdelta_cleanup(u64 uuid, u64 salt)
{
    struct dir_delta_au *dda, *n;
    struct hvfs_txg *txg;
    int found = 0, err = 0;

    xlock_lock(&g_dir_deltas_lock);
    list_for_each_entry_safe(dda, n, &g_dir_deltas, list) {
        if (uuid == dda->dd.duuid && salt == dda->dd.salt) {
            list_del(&dda->list);
            found = 1;
            break;
        }
    }
    xlock_unlock(&g_dir_deltas_lock);

    /* we should insert the acked entries into the current txg's rddb list */
    if (found) {
        txg = mds_get_open_txg(&hmo);
        err = txg_rddb_add(txg, dda, DIR_DELTA_REMOTE_ACK);
        txg_put(txg);
        if (err) {
            hvfs_err(mds, "Add remote(%lx) dir delta uuid %ld txg %ld "
                     "failed w/ %d\n",
                     dda->dd.site_id, dda->dd.duuid, dda->dd.txg, err);
        }
        /* then, release the acked dir delta au */
        xfree(dda);
    } else {
        hvfs_err(mds, "Orphan dir delta uuid %ld salt %ld\n",
                 uuid, salt);
    }
}

/* 
 * AUR DIR_DELTA_REPLY is used to do async dir updates' reply. In this
 * function we should send the reply message to the target MDS, then clean the
 * local queue.
 *
 * Note that all the entries should be freed on exit!
 */
int __aur_dir_delta_reply(struct async_update_request *aur)
{
    struct hvfs_dir_delta_buf *pos, *n;
    struct list_head *tl = (struct list_head *)aur->arg;
    int total = 0, skip = 0, acked = 0;
    int err = 0, i;

    /* we should iterate on the rddb list: first, we should select all the
     * flag UPDATE entries and send them to the destination. */
    list_for_each_entry_safe(pos, n, tl, list) {
        list_del(&pos->list);
        for (i = 0; i < pos->asize; i++) {
            /* Step 1: check the flag */
            if (pos->buf[i].flag & DIR_DELTA_REMOTE_UPDATE) {
                /* ok, we should send the reply now */
                if (pos->buf[i].site_id != hmo.site_id) {
                    err = txg_ddc_send_reply(&pos->buf[i]);
                    if (err) {
                        hvfs_err(mds, "Send AU dir delta uuid %ld reply "
                                 "failed w %d\n",
                                 pos->buf[i].duuid, err);
                    }
                    total++;
                } else {
                    skip++;
                }
            } else {
                acked++;
            }
        }
        atomic64_add(pos->asize, &hmo.prof.misc.au_ddr);
        xfree(pos);
    }
    hvfs_warning(mds, "total = %d, skip = %d, acked = %d\n", 
                 total, skip, acked);

    return err;
}

int __aur_txg_wb(struct async_update_request *aur)
{
    hvfs_err(mds, "AU TXG write-back has not been implemented yet.\n");
    return 0;
}

int __au_req_handle(void)
{
    struct async_update_request *aur = NULL, *n;
    int err = 0;

    xlock_lock(&g_aum.lock);
    if (!list_empty(&g_aum.aurlist)) {
        list_for_each_entry_safe(aur, n, &g_aum.aurlist, list) {
            list_del(&aur->list);
            break;
        }
    }
    xlock_unlock(&g_aum.lock);

    if (!aur)
        return -EHSTOP;
    
    /* ok, deal with it */
    switch (aur->op) {
        /* the following is the MDS used async operations */
    case AU_ITB_SPLIT:
        err = __aur_itb_split(aur);
        break;
    case AU_ITB_BITMAP:
        err = __aur_itb_bitmap(aur);
        break;
    case AU_TXG_WB:
        err = __aur_txg_wb(aur);
        break;
    case AU_DIR_DELTA:
        err = __aur_dir_delta(aur);
        break;
    case AU_DIR_DELTA_REPLY:
        err = __aur_dir_delta_reply(aur);
        break;
        /* the following is the BRANCH used async operations */
    default:
        hvfs_err(mds, "Invalid AU Request: op %ld arg 0x%lx\n",
                     aur->op, aur->arg);
    }
    atomic64_inc(&hmo.prof.misc.au_handle);
    return err;
}

/* Handle the split in synchronous mode
 */
void au_handle_split_sync(void)
{
    struct async_update_request *aur = NULL, *n;
    int err = 0;

    /* test only */
    if (list_empty(&g_aum.aurlist))
        return;

    xlock_lock(&g_aum.lock);
    if (!list_empty(&g_aum.aurlist)) {
        list_for_each_entry_safe(aur, n, &g_aum.aurlist, list) {
            if (aur->op == AU_ITB_SPLIT ||
                aur->op == AU_ITB_BITMAP) {
                list_del(&aur->list);
                break;
            }
        }
    }
    xlock_unlock(&g_aum.lock);

    if (!aur)
        return;

    switch (aur->op) {
    case AU_ITB_SPLIT:
        err = __aur_itb_split(aur);
        break;
    case AU_ITB_BITMAP:
        err = __aur_itb_bitmap(aur);
        break;
    default:
        err = -EINVAL;
    }

    if (err) {
        hvfs_err(mds, "AU (split) handle error %d\n", err);
    }

    return;
}

int au_lookup(int op, u64 arg)
{
    struct async_update_request *aur = NULL;
    struct itb *i;
    int found = 0;
    
    if (op == AU_ITB_SPLIT) {
        xlock_lock(&g_aum.lock);
        list_for_each_entry(aur, &g_aum.aurlist, list) {
            i = (struct itb *)aur->arg;
            if (aur->op == op && i->h.itbid == arg) {
                found = 1;
                break;
            }
        }
        xlock_unlock(&g_aum.lock);
    }

    return found;
}

int au_submit(struct async_update_request *aur)
{
    xlock_lock(&g_aum.lock);
    list_add_tail(&aur->list, &g_aum.aurlist);
    xlock_unlock(&g_aum.lock);
    atomic64_inc(&hmo.prof.misc.au_submit);
    sem_post(&hmo.async_sem);

    return 0;
}

void *async_update(void *arg)
{
    struct async_thread_arg *ata = (struct async_thread_arg *)arg;
    sigset_t set;
    int err, c;

    /* first, let us block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */

    while (!hmo.async_thread_stop) {
        err = sem_wait(&hmo.async_sem);
        if (err == EINTR)
            continue;
        hvfs_debug(mds, "Async update thread %d wakeup to progress the AUs.\n",
                   ata->tid);
        /* processing N request in the list */
        for (c = 0; c < hmo.conf.async_update_N; c++) {
            err = __au_req_handle();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(mds, "AU handle error %d\n", err);
            }
        }
    }
    pthread_exit(0);
}

/* async_tp_init()
 */
int async_tp_init(void)
{
    struct async_thread_arg *ata;
    int i, err = 0;

    /* init the global manage structure */
    INIT_LIST_HEAD(&g_aum.aurlist);
    xlock_init(&g_aum.lock);
    xlock_init(&g_bitmap_deltas_lock);
    xlock_init(&g_dir_deltas_lock);
    
    sem_init(&hmo.async_sem, 0, 0);

    /* init async threads' pool */
    if (!hmo.conf.async_threads)
        hmo.conf.async_threads = 4;

    hmo.async_thread = xzalloc(hmo.conf.async_threads * sizeof(pthread_t));
    if (!hmo.async_thread) {
        hvfs_err(mds, "xzalloc() pthread_t failed\n");
        return -ENOMEM;
    }

    ata = xzalloc(hmo.conf.async_threads * sizeof(struct async_thread_arg));
    if (!ata) {
        hvfs_err(mds, "xzalloc() struct async_thread_arg failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    for (i = 0; i < hmo.conf.async_threads; i++) {
        (ata + i)->tid = i;
        err = pthread_create(hmo.async_thread + i, NULL, &async_update,
                             ata + i);
        if (err)
            goto out;
    }
    
out:
    return err;
out_free:
    xfree(hmo.async_thread);
    goto out;
}

void async_tp_destroy(void)
{
    int i;

    hmo.async_thread_stop = 1;
    for (i = 0; i < hmo.conf.async_threads; i++) {
        sem_post(&hmo.async_sem);
    }
    for (i = 0; i < hmo.conf.async_threads; i++) {
        pthread_join(*(hmo.async_thread + i), NULL);
    }
    sem_destroy(&hmo.async_sem);
}
