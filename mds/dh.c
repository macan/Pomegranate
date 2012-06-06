/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-11 06:54:29 macan>
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
#include "mds.h"
#include "xnet.h"
#include "ring.h"

static inline
u64 SELECT_SITE(u64 itbid, u64 psalt, int type, u32 *vid)
{
    struct chp *p;

    p = ring_get_point(itbid, psalt, hmo.chring[type]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -1UL;
    }
    *vid = p->vid;
    return p->site_id;
}

/* mds_dh_data_read()
 *
 * try to read the column data from MDSL
 */
/* BUG-xxxxx:
 *
 * for dtriggers of a directory, we use GDT_UUID and self.salt to
 * route the request! Be sure to keep this convention works with
 * dh.c->__mds_dh_data_read().
 */
int __mds_dh_data_read(struct hvfs_index *hi, int column, 
                       void **data, struct column *c)
{
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    u32 vid = 0;
    int err = 0;

    /* make sure we have loaded the root_salt now */
    if (hmi.root_salt == 0xffffffffffffffff) {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hmi.root_uuid);
        if (IS_ERR(e)) {
            hvfs_err(mds, "The DHE(%lx) is not exist.\n", hmi.root_uuid);
            return -EFAULT;
        }
        hmi.root_salt = e->salt;
        mds_dh_put(e);
    }

    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return -ENOMEM;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    /* fill the parent (dir) uuid to si.uuid. If the column is
     * HVFS_TRIG_COLUMN, we should reset the puuid to gdt_uuid. */
    if (column == HVFS_TRIG_COLUMN) {
        si->sic.uuid = hmi.gdt_uuid;
    } else {
        si->sic.uuid = hi->puuid;
    }
    si->sic.arg0 = hi->uuid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = column;
    si->scd.cr[0].stored_itbid = c->stored_itbid;
    si->scd.cr[0].file_offset = c->offset;
    si->scd.cr[0].req_offset = 0;
    si->scd.cr[0].req_len = c->len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(c->stored_itbid, hi->ssalt, CH_RING_MDSL, &vid);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_READ, 0, 0);
    msg->tx.reserved = vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, si, sizeof(*si) +
                       sizeof(struct column_req));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    /* recv the reply, parse the data now */
    ASSERT(msg->pair->tx.len == c->len, xnet);
    if (msg->pair->xm_datacheck) {
        *data = xmalloc(c->len);
        if (!*data) {
            hvfs_err(xnet, "xmalloc value region failed.\n");
            err = -ENOMEM;
            goto out_msg;
        }
        memcpy(*data, msg->pair->xm_data, c->len);
    } else {
        hvfs_err(xnet, "recv data read reply ERROR %d\n",
                 msg->pair->tx.err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    }

out_msg:
    xnet_free_msg(msg);
out_free:
    xfree(si);

    return err;
}

/* mds_dh_init()
 *
 * NOTE: we do not provide any fast allocation
 */
int mds_dh_init(struct dh *dh, int hsize)
{
    int err = 0, i;
    
    /* regular hash init */
    hsize = (hsize == 0) ? MDS_DH_DEFAULT_SIZE : hsize;
    i = fls64(hsize);
    if ((u64)hsize != (1UL << i)) {
        hvfs_err(mds, "You should set the hash table size to "
                 "2^N.\n");
        return -EINVAL;
    }
    dh->ht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!dh->ht) {
        hvfs_err(mds, "DH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&dh->ht[i].h);
        xlock_init(&dh->ht[i].lock);
    }
    dh->hsize = hsize;
    atomic_set(&dh->asize, 0);
out:
    return err;
}

void mds_dh_destroy(struct dh *dh)
{
    if (dh->ht)
        xfree(dh->ht);
}

void mds_dh_evict(struct dh *dh)
{
    struct regular_hash *rh;
    struct itbitmap *b, *m;
    struct dhe *tpos;
    struct hlist_node *pos, *n;
    int i;

    for (i = 0; i < dh->hsize; i++) {
        rh = dh->ht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            if (tpos->uuid == hmi.gdt_uuid)
                continue;
            /* wait for the reference down to zero */
            while (atomic_read(&tpos->ref) > 0)
                xsleep(10);
            hlist_del_init(&tpos->hlist);
            /* we should iterate the bitmap list and release all the
             * bitmap slices */
            list_for_each_entry_safe(b, m, &tpos->bitmap, list) {
                list_del(&b->list);
                xfree(b);
            }
            xfree(tpos);
            atomic_dec(&dh->asize);
        }
        xlock_unlock(&rh->lock);
    }
}

/* mds_dh_hash()
 */
static inline
u32 mds_dh_hash(u64 uuid)
{
    return hvfs_hash_dh(uuid) & (hmo.dh.hsize - 1);
}

/* mds_dh_insert()
 *
 * Return value: -EEXIST or new dhe w/ ref+1
 */
static inline
struct dhe *mds_dh_insert_ex(struct dh *dh, struct hvfs_index *hi,
                             u32 mdu_flags)
{
    struct regular_hash *rh;
    struct dhe *e, *tpos;
    struct hlist_node *pos;
    int i;

    i = mds_dh_hash(hi->uuid);
    rh = dh->ht + i;

    e = xzalloc(sizeof(struct dhe));
    if (unlikely(!e))
        return ERR_PTR(-ENOMEM);

    INIT_HLIST_NODE(&e->hlist);
    INIT_LIST_HEAD(&e->bitmap);
    xlock_init(&e->lock);
    e->uuid = hi->uuid;
    e->puuid = hi->puuid;
    /* NOTE: this is the self salt! */
    e->salt = hi->ssalt;
    e->life = lib_rdtsc();
    e->mdu_flags = mdu_flags;
    atomic_set(&e->ref, 1);

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (e->uuid == tpos->uuid) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&e->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i) {
        xfree(e);
        return ERR_PTR(-EEXIST);
    }
    atomic_inc(&dh->asize);
    
    return e;
}

struct dhe *mds_dh_insert(struct dh *dh, struct hvfs_index *hi)
{
    return mds_dh_insert_ex(dh, hi, 0);
}

/* mds_dh_dt_update() update the e->data pointer as needed
 *
 * Return value: 0: updated; 1: unused;
 */
int mds_dh_dt_update(struct dh *dh, u64 duuid, struct dir_trigger_mgr *dtm)
{
    struct dhe *e = ERR_PTR(-EINVAL);
    struct regular_hash *rh;
    struct hlist_node *l;
    struct dir_trigger_mgr *tmp = NULL;
    int i, found = 0;

    if (!dtm)
        return 1;
    
    i = mds_dh_hash(duuid);
    rh = dh->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(e, l, &rh->h, hlist) {
        if (e->uuid == duuid) {
            /* wait for the referenct down to zero and update DTM */
            while (atomic_read(&e->ref) > 0)
                xsleep(10);
            tmp = e->data;
            e->data = dtm;
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (tmp) {
        mds_dt_destroy(tmp);
        xfree(tmp);
    }

    return !found;
}

/* mds_dh_remove()
 */
int mds_dh_remove(struct dh *dh, u64 uuid)
{
    struct regular_hash *rh;
    struct dhe *e;
    struct hlist_node *pos, *n;
    struct itbitmap *b, *pos2;
    int i;

    i = mds_dh_hash(uuid);
    rh = dh->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(e, pos, n, &rh->h, hlist) {
        if (e->uuid == uuid) {
            /* wait on the reference */
            while (atomic_read(&e->ref) > 0)
                xsleep(10);
            hlist_del(&e->hlist);
            hvfs_debug(mds, "Remove dir:%8ld in DH w/  %p\n", uuid, e);
            /* free the bitmap list */
            list_for_each_entry_safe(b, pos2, &e->bitmap, list) {
                list_del(&b->list);
                mds_bitmap_free(b);
            }
            xlock_destroy(&e->lock);
            xfree(e);
            atomic_dec(&dh->asize);
        }
    }
    xlock_unlock(&rh->lock);

    return 0;
}

/* check if a dh entry is long lived. If it is, then we evict it out!
 */
void mds_dh_check(time_t cur)
{
    struct dh *dh = &hmo.dh;
    struct regular_hash *rh;
    struct itbitmap *b, *m;
    struct dhe *tpos;
    struct hlist_node *pos, *n;
    static time_t last_chk = 0;
    static int last_idx = 0;
    u64 tsc = lib_rdtsc(), gap;
    int i, err = 0;

    /* we trigger the check every 30 seconds */
    if (cur - last_chk < 30) {
        last_chk = cur;
        return;
    }
    
    for (i = 0; i < dh->hsize; i++) {
        rh = dh->ht + i;
    retry:
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            if (tpos->uuid == hmi.gdt_uuid)
                continue;
            /* check the life time, compare with invalidate interval */
            gap = (tsc > tpos->life ? (tsc - tpos->life) : 
                   (tpos->life - tsc));
            if (gap > cpu_frequency * hmo.conf.dh_ii) {
                hvfs_warning(mds, "Invalidate DH %lx start @ %lx w/ %d\n", 
                             tpos->uuid, 
                             gap,
                             atomic_read(&tpos->ref));
                /* wait for the reference down to zero */
                while (atomic_read(&tpos->ref) > 0)
                    xsleep(10);
                hvfs_warning(mds, "Invalidate DH %lx end\n", tpos->uuid);
                hlist_del_init(&tpos->hlist);
                /* we should iterate the bitmap list and release all the
                 * bitmap slices */
                list_for_each_entry_safe(b, m, &tpos->bitmap, list) {
                    list_del(&b->list);
                    xfree(b);
                }
                xfree(tpos);
                atomic_dec(&dh->asize);
            } else if (last_idx == i && 
                       (cur - tpos->update > hmo.conf.dhupdatei)) {
                atomic_inc(&tpos->ref);
                xlock_unlock(&rh->lock);
                hvfs_debug(mds, "PREReload %lx @ %ld w/ %p ref %d\n", 
                           tpos->uuid, cur, tpos->data, 
                           atomic_read(&tpos->ref));
                err = mds_dh_reload_nolock(tpos);
                if (err == -ENOENT) {
                    /* we should remove this DHE from the table, we have to
                     * relock the dh table */
                    xlock_lock(&rh->lock);
                    mds_dh_put(tpos);
                    while (atomic_read(&tpos->ref) > 0) {
                        xlock_unlock(&rh->lock);
                        xsleep(20);
                        xlock_lock(&rh->lock);
                    }

                    hlist_del_init(&tpos->hlist);
                    xlock_unlock(&rh->lock);

                    list_for_each_entry_safe(b, m, &tpos->bitmap, list) {
                        list_del(&b->list);
                        xfree(b);
                    }
                    xfree(tpos);
                    atomic_dec(&dh->asize);
                    goto retry;
                }
                hvfs_debug(mds, "POSTReload %lx @ %ld w/ %p ref %d\n", 
                           tpos->uuid, cur, tpos->data, 
                           atomic_read(&tpos->ref));
                mds_dh_put(tpos);
                tpos->update = cur;
                goto retry;
            }
        }
        xlock_unlock(&rh->lock);

        last_idx++;
        last_idx %= dh->hsize;
    }
}

void __dh_gossip_bitmap(struct itbitmap *bitmap, u64 duuid)
{
    struct ibmap ibmap;
    struct xnet_msg *msg;
    struct chp *p;
    u64 point;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(mds, "xnet_alloc_msg() in low memory.\n");
            return;
        }
    }

    /* select a random site from the mds ring */
    point = hvfs_hash(lib_random(0xfffffff),
                      lib_random(0xfffffff), 0, HASH_SEL_GDT);
    p = ring_get_point2(point, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point2() failed w/ %ld\n",
                 PTR_ERR(p));
        goto out_free;
    }

    if (p->site_id == hmo.xc->site_id) {
        /* self gossip? do not do it */
        goto out_free;
    }

    /* send the request to the selected site */
    memcpy(&ibmap, bitmap, sizeof(ibmap));

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0, hmo.xc->site_id,
                     p->site_id);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_GB, duuid, bitmap->offset);
    xnet_msg_add_sdata(msg, &ibmap, sizeof(ibmap));
    xnet_msg_add_sdata(msg, bitmap->array, XTABLE_BITMAP_BYTES);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
    }

    xnet_free_msg(msg);
    return;
out_free:
    xnet_raw_free_msg(msg);
}

/* mds_dh_load() w/ ref+1
 *
 * NOTE: load the directory info from the GDT server
 *
 * Error Conversion: kernel err-ptr
 */
struct dhe *mds_dh_load(struct dh *dh, u64 duuid)
{
    struct hvfs_md_reply *hmr = NULL;
    struct hvfs_index thi, *rhi;
    struct xnet_msg *msg;
    struct chp *p;
    struct dhe *e = ERR_PTR(-ENOTEXIST);
    struct dir_trigger_mgr *dtm = NULL;
    u64 tsid;                   /* target site id */
    u32 mdu_flags = 0;
    int err = 0, no;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return ERR_PTR(-ENOMEM);
        }
    }

    /* check if we are loading the GDT DH */
    if (unlikely(duuid == hmi.gdt_uuid)) {
        /* ok, we should send the request to the ROOT server */
        tsid = mds_select_ring(&hmo);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id,
                         tsid);
        xnet_msg_fill_cmd(msg, HVFS_R2_LGDT, hmo.xc->site_id, hmo.fsid);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        goto send_msg;
    }

    /* prepare the hvfs_index */
    memset(&thi, 0, sizeof(thi));
    thi.flag = INDEX_BY_UUID;
    thi.puuid = hmi.gdt_uuid;
    thi.psalt = hmi.gdt_salt;
    thi.uuid = duuid;
    thi.hash = hvfs_hash(duuid, hmi.gdt_salt, 0, HASH_SEL_GDT);

    e = mds_dh_search(dh, hmi.gdt_uuid);
    if (unlikely(IS_ERR(e))) {
        hvfs_err(mds, "Hoo, we can NOT find the GDT uuid %ld(%ld).\n",
                 hmi.gdt_uuid, duuid);
        hvfs_err(mds, "This is a fatal error %ld! We must die.\n", 
                 PTR_ERR(e));
        ASSERT(0, mds);
    }
    thi.itbid = mds_get_itbid(e, thi.hash);
    mds_dh_put(e);

    /* find the MDS server */
    p = ring_get_point(thi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (unlikely(IS_ERR(p))) {
        hvfs_err(mds, "ring_get_point(%ld) failed with %ld\n", 
                 thi.itbid, PTR_ERR(p));
        e = ERR_PTR(-ECHP);
        goto out_free;
    }
    if (p->site_id == hmo.site_id) {
        struct hvfs_txg *txg;
        
        hvfs_warning(mds, "Load DH (self): uuid %lx itbid %ld, site %lx "
                     "=> \n", 
                     thi.uuid, thi.itbid, p->site_id);
        /* the GDT service MDS server is myself, so we just lookup the entry
         * in my CBHT. */
        hmr = get_hmr();
        if (!hmr) {
            hvfs_err(mds, "get_hmr() failed\n");
            e = ERR_PTR(-ENOMEM);
            goto out_free;
        }
        
        thi.flag |= INDEX_LOOKUP | INDEX_COLUMN;
        thi.column = HVFS_TRIG_COLUMN;
    retry:
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(&thi, hmr, txg, &txg);
        txg_put(txg);

        if (unlikely(err)) {
            if (err == -EAGAIN || err == -ESPLIT ||
                err == -ERESTART) {
                /* have a breath */
                sched_yield();
                goto retry;
            } else if (err == -EHWAIT) {
                /* deep wait now */
                sleep(1);
                goto retry;
            }
            hvfs_err(mds, "lookup uuid %lx failed w/ %d.\n",
                     thi.uuid, err);
            e = ERR_PTR(err);
            goto out_free_hmr;
        }

        /* Note that we should set the salt manually */
        {
            struct gdt_md *m;
            struct column *c = NULL;
            void *data;
            
            m = hmr_extract_local(hmr, EXTRACT_MDU, &no);
            if (!m) {
                hvfs_err(mds, "Extract MDU failed\n");
                e = ERR_PTR(-EFAULT);
                goto out_free_hmr;
            }
            if (hmr->flag & MD_REPLY_WITH_DC) {
                c = hmr_extract_local(hmr, EXTRACT_DC, &no);
            }
            
            if (thi.uuid == hmi.root_uuid)
                thi.puuid = hmi.gdt_uuid;
            thi.ssalt = m->salt;
            if ((m->mdu.flags & HVFS_MDU_IF_TRIG) && c &&
                HVFS_IS_MDS(hmo.site_id)) {
                /* load the trigger content from MDSL */
                err = __mds_dh_data_read(&thi, HVFS_TRIG_COLUMN, &data, c);
                if (err) {
                    hvfs_err(mds, "mds_dh_data_read() failed w/ %d\n", err);
                } else {
                    /* construct the directory trigger now */
                    dtm = mds_dtrigger_parse(data, c->len);
                    if (IS_ERR(dtm)) {
                        hvfs_err(mds, "mds_dtrigger_parse failed w/ %ld\n",
                                 PTR_ERR(dtm));
                        dtm = NULL;
                    }
                    xfree(data);
                }
            }
            /* setup mdu_flags */
            mdu_flags = m->mdu.flags;
        }
        
        e = mds_dh_insert_ex(dh, &thi, mdu_flags);
        if (IS_ERR(e)) {
            if (e != ERR_PTR(-EEXIST)) {
                hvfs_err(mds, "mds_dh_insert_ex() failed %ld\n", PTR_ERR(e));
            } else {
                /* already exist, update or free dtm if needed */
                if (dtm) {
                    err = mds_dh_dt_update(dh, thi.uuid, dtm);
                    if (err) {
                        hvfs_err(mds, "mds_dh_dt_update DTM "
                                 "failed w/ %d\n", err);
                        mds_dt_destroy(dtm);
                        xfree(dtm);
                    }
                }
            }
        } else {
            /* install the trigger now */
            e->data = dtm;
        }
        hvfs_warning(mds, "=> uuid %lx salt %lx mdu_flags %x\n", 
                     thi.uuid, thi.ssalt, mdu_flags);
    out_free_hmr:
        xfree(hmr);
    } else {
        /* ok, we should send the request to the remote site now */
        hvfs_warning(mds, "Load DH (remote): uuid %lx itbid %ld, site %lx "
                     "=> \n", 
                     thi.uuid, thi.itbid, p->site_id);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id, 
                         p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LD, duuid, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_add_sdata(msg, &thi, sizeof(thi));

        tsid = p->site_id;
    send_msg:
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mds, "xnet_send() failed with %d\n", err);
            e = ERR_PTR(err);
            goto out_free;
        }

        /* ok, we get the reply: have the mdu in the reply msg */
        ASSERT(msg->pair, mds);

        if (msg->pair->tx.err) {
            hvfs_err(mds, "mds_dh_load() from site %lx failed w/ %d\n",
                     tsid, msg->pair->tx.err);
            e = ERR_PTR(msg->pair->tx.err);
        } else {
            struct gdt_md *m;
            struct column *c = NULL;
            void *data;

            hmr = (struct hvfs_md_reply *)(msg->pair->xm_data);
            if (!hmr || hmr->err) {
                hvfs_err(mds, "dh_load request failed %d\n", 
                         !hmr ? -ENOTEXIST : hmr->err);
                e = !hmr ? ERR_PTR(-ENOTEXIST) : ERR_PTR(hmr->err);
                goto out_free;
            }
            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(mds, "hmr_extract HI failed, do not found this "
                         "subregion.\n");
                e = ERR_PTR(-EFAULT);
                goto out_free;
            }
            m = hmr_extract(hmr, EXTRACT_MDU, &no);
            if (!m) {
                hvfs_err(mds, "Extract MDU failed\n");
                e = ERR_PTR(-EFAULT);
                goto out_free;
            }
            if (rhi->uuid == hmi.root_uuid)
                rhi->puuid = hmi.gdt_uuid;
            /* do we need to load triggers? */
            {
                rhi->psalt = m->salt;
                c = hmr_extract(hmr, EXTRACT_DC, &no);
                if (!c) {
                    hvfs_err(mds, "hmr_extract DC failed, do not found this "
                             "subretion.\n");
                }
                if ((m->mdu.flags & HVFS_MDU_IF_TRIG) && c && 
                    HVFS_IS_MDS(hmo.site_id)) {
                    /* load the trigger content from MDSL */
                    hvfs_debug(mds, "Read in DT itbid %ld offset %ld len %ld from %lx\n",
                               c->stored_itbid, c->offset, c->len, tsid);
                    err = __mds_dh_data_read(rhi, HVFS_TRIG_COLUMN, &data, c);
                    if (err) {
                        hvfs_err(mds, "mds_dh_data_read() failed w/ %d\n", err);
                    } else {
                        dtm = mds_dtrigger_parse(data, c->len);
                        if (IS_ERR(dtm)) {
                            hvfs_err(mds, "mds_dtrigger_parse failed w/ %ld\n",
                                     PTR_ERR(dtm));
                            dtm = NULL;
                        }
                        xfree(data);
                    }
                }
                /* setup mdu_flags */
                mdu_flags = m->mdu.flags;
            }
            
            /* Note that, we know that the LDH will return the HI with ssalt
             * set. */
            
            /* key, we got the mdu, let us insert it to the dh table */
            e = mds_dh_insert_ex(dh, rhi, mdu_flags);
            if (IS_ERR(e)) {
                if(e != ERR_PTR(-EEXIST)) {
                    hvfs_err(mds, "mds_dh_insert_ex() failed %ld\n", PTR_ERR(e));
                    goto out_free;
                } else {
                    /* already exist, update or free dtm if needed */
                    if (dtm) {
                        err = mds_dh_dt_update(dh, rhi->uuid, dtm);
                        if (err) {
                            hvfs_err(mds, "mds_dh_dt_update DTM "
                                     "failed w/ %d\n", err);
                            mds_dt_destroy(dtm);
                            xfree(dtm);
                        }
                    }
                }
            } else {
                /* install the trigger now */
                e->data = dtm;
            }
            hvfs_warning(mds, "=> uuid %lx salt %lx mdu_flags %x\n", 
                         rhi->uuid, rhi->ssalt, mdu_flags);
        }
    }
    
out_free:
    xnet_free_msg(msg);
    return e;
}

/* mds_dh_reload_nolock() try to update the DH state
 */
int mds_dh_reload_nolock(struct dhe *ue)
{
    struct hvfs_md_reply *hmr = NULL;
    struct hvfs_index thi, *rhi;
    struct xnet_msg *msg;
    struct chp *p;
    struct dhe *e = ERR_PTR(-ENOTEXIST);
    struct dir_trigger_mgr *dtm = NULL;
    u64 tsid;
    int err = 0, no, unreg = 0;

    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_debug(mds, "xnet_alloc_msg() in low memory.\n");
            return -ENOMEM;
        }
    }

    /* check if we are loading the GDT DH */
    if (unlikely(ue->uuid == hmi.gdt_uuid)) {
        /* ok, we should send the request to the ROOT server */
        tsid = mds_select_ring(&hmo);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id,
                         tsid);
        xnet_msg_fill_cmd(msg, HVFS_R2_LGDT, hmo.xc->site_id, hmo.fsid);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        goto send_msg;
    }

    /* prepare the hvfs_index */
    memset(&thi, 0, sizeof(thi));
    thi.flag = INDEX_BY_UUID;
    thi.puuid = hmi.gdt_uuid;
    thi.psalt = hmi.gdt_salt;
    thi.uuid = ue->uuid;
    thi.hash = hvfs_hash(ue->uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);

    e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "Hoo, we can NOT find the GDT uuid %ld(%ld).\n",
                 hmi.gdt_uuid, ue->uuid);
        hvfs_err(mds, "This is a fatal error %ld! We must die.\n", 
                 PTR_ERR(e));
        ASSERT(0, mds);
    }
    thi.itbid = mds_get_itbid(e, thi.hash);
    mds_dh_put(e);

    /* find the MDS server */
    p = ring_get_point(thi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point(%ld) failed with %ld\n", 
                 thi.itbid, PTR_ERR(p));
        err = -ECHP;
        goto out_free;
    }
    if (p->site_id == hmo.site_id) {
        struct hvfs_txg *txg;
        
        hvfs_debug(mds, "Load DH (self): uuid %lx itbid %ld, site %lx\n", 
                   thi.uuid, thi.itbid, p->site_id);
        /* the GDT service MDS server is myself, so we just lookup the entry
         * in my CBHT. */
        hmr = get_hmr();
        if (!hmr) {
            hvfs_err(mds, "get_hmr() failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        
        thi.flag |= INDEX_LOOKUP | INDEX_COLUMN;
        thi.column = HVFS_TRIG_COLUMN;
    retry:
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(&thi, hmr, txg, &txg);
        txg_put(txg);

        if (err) {
            if (err == -EAGAIN || err == -ESPLIT ||
                err == -ERESTART) {
                /* have a breath */
                sched_yield();
                goto retry;
            }
            hvfs_err(mds, "lookup uuid %lx failed w/ %d.\n",
                     thi.uuid, err);
            goto out_free_hmr;
        }

        /* Note that we should set the salt manually */
        {
            struct gdt_md *m;
            struct column *c = NULL;
            void *data;
            
            m = hmr_extract_local(hmr, EXTRACT_MDU, &no);
            if (!m) {
                hvfs_err(mds, "Extract MDU failed\n");
                err = -EINVAL;
                goto out_free_hmr;
            }
            if (hmr->flag & MD_REPLY_WITH_DC) {
                c = hmr_extract_local(hmr, EXTRACT_DC, &no);
            }
            
            if (thi.uuid == hmi.root_uuid)
                thi.puuid = hmi.gdt_uuid;
            thi.ssalt = m->salt;

            if ((m->mdu.flags & HVFS_MDU_IF_TRIG) && c &&
                HVFS_IS_MDS(hmo.site_id)) {
                /* load the trigger content from MDSL */
                hvfs_debug(mds, "Read in DT itbid %ld offset %ld len %ld\n",
                           c->stored_itbid, c->offset, c->len);
                err = __mds_dh_data_read(&thi, HVFS_TRIG_COLUMN, &data, c);
                if (err) {
                    hvfs_err(mds, "mds_dh_data_read() failed w/ %d\n", err);
                } else {
                    /* construct the directory trigger now */
                    dtm = mds_dtrigger_parse(data, c->len);
                    if (IS_ERR(dtm)) {
                        hvfs_err(mds, "mds_dtrigger_parse failed w/ %ld\n",
                                 PTR_ERR(dtm));
                        dtm = NULL;
                        xfree(data);
                    }
                }
            } else {
                unreg = 1;
            }
        }
        
        /* already exist, update or free dtm if needed */
        if (dtm) {
            while (atomic_read(&ue->ref) > 1)
                xsleep(10);
            if (ue->data) {
                mds_dt_destroy(ue->data);
                xfree(ue->data);
            }
            /* install the trigger now */
            ue->data = dtm;
        } else if (unreg) {
            while (atomic_read(&ue->ref) > 1)
                xsleep(10);
            if (ue->data) {
                mds_dt_destroy(ue->data);
                xfree(ue->data);
            }
            ue->data = NULL;
        }
    out_free_hmr:
        xfree(hmr);
    } else {
        /* ok, we should send the request to the remote site now */
        hvfs_debug(mds, "Load DH (remote): uuid %lx itbid %ld, site %lx\n", 
                   thi.uuid, thi.itbid, p->site_id);

        /* prepare the msg */
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.xc->site_id, 
                         p->site_id);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_LD, ue->uuid, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_add_sdata(msg, &thi, sizeof(thi));

        tsid = p->site_id;
    send_msg:
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(mds, "xnet_send() failed with %d\n", err);
            goto out_free;
        }

        /* ok, we get the reply: have the mdu in the reply msg */
        ASSERT(msg->pair, mds);

        if (msg->pair->tx.err) {
            hvfs_err(mds, "mds_dh_load(%lx) from site %lx "
                     "failed w/ %d. (maybe remove it from DH)\n",
                     ue->uuid, tsid, msg->pair->tx.err);
            err = msg->pair->tx.err;
        } else {
            struct gdt_md *m;
            struct column *c = NULL;
            void *data;

            hmr = (struct hvfs_md_reply *)(msg->pair->xm_data);
            if (!hmr || hmr->err) {
                hvfs_err(mds, "dh_load request failed %d\n", 
                         !hmr ? -ENOTEXIST : hmr->err);
                err = !hmr ? -ENOTEXIST : hmr->err;
                goto out_free;
            }
            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(mds, "hmr_extract MDU failed, do not found this "
                         "subregion.\n");
                err = -EINVAL;
                goto out_free;
            }
            m = hmr_extract(hmr, EXTRACT_MDU, &no);
            if (!m) {
                hvfs_err(mds, "Extract MDU failed\n");
            }
            if (rhi->uuid == hmi.root_uuid)
                rhi->puuid = hmi.gdt_uuid;
            rhi->ssalt = m->salt;
            if (m) {
                c = hmr_extract(hmr, EXTRACT_DC, &no);
                if (!c) {
                    hvfs_err(mds, "hmr_extract DC failed, do not found this "
                             "subretion.\n");
                }
                if ((m->mdu.flags & HVFS_MDU_IF_TRIG) && c &&
                    HVFS_IS_MDS(hmo.site_id)) {
                    /* load the trigger content from MDSL */
                    err = __mds_dh_data_read(rhi, HVFS_TRIG_COLUMN, &data, c);
                    if (err) {
                        hvfs_err(mds, "mds_dh_data_read() failed w/ %d\n", err);
                    } else {
                        dtm = mds_dtrigger_parse(data, c->len);
                        if (IS_ERR(dtm)) {
                            hvfs_err(mds, "mds_dtrigger_parse failed w/ %ld\n",
                                     PTR_ERR(dtm));
                            dtm = NULL;
                        }
                        xfree(data);
                    }
                } else {
                    unreg = 1;
                }
            }
            
            if (dtm) {
                while (atomic_read(&ue->ref) > 1)
                    xsleep(10);
                if (ue->data) {
                    mds_dt_destroy(ue->data);
                    xfree(ue->data);
                }
                /* install the trigger now */
                ue->data = dtm;
            } else if (unreg) {
                while (atomic_read(&ue->ref) > 1)
                    xsleep(10);
                if (ue->data) {
                    mds_dt_destroy(ue->data);
                    xfree(ue->data);
                }
                ue->data = NULL;
            }
        }
    }
    
out_free:
    xnet_free_msg(msg);

    return err;
}

/* mds_dh_search() may block on dh_load
 *
 * Search in the DH(dir hash) to find the dir entry which contains
 * bitmap/salt/... etc
 *
 * NOTE: for now, we do NOT evict any dh entries. If the memory is low, we
 * first try to free the bitmap slices.
 *
 * Error Conversion: kernel err-ptr
 */
struct dhe *mds_dh_search(struct dh *dh, u64 duuid)
{
    struct dhe *e = ERR_PTR(-EINVAL);
    struct regular_hash *rh;
    struct hlist_node *l;
    int i, found = 0;

    i = mds_dh_hash(duuid);
    rh = dh->ht + i;

retry:
    xlock_lock(&rh->lock);
    hlist_for_each_entry(e, l, &rh->h, hlist) {
        if (e->uuid == duuid) {
            atomic_inc(&e->ref);
            e->life = lib_rdtsc();
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (unlikely(!found)) {
        /* Hoo, we have not found the directory. We need to request the
         * directory information from the GDT server */
        e = mds_dh_load(dh, duuid);
        if (e == ERR_PTR(-EEXIST)) {
            /* this means the entry is load by another thread, it is ok to
             * research in the cache */
            goto retry;
        } else if (IS_ERR(e)) {
            hvfs_err(mds, "Hoo, loading DH %lx failed\n", duuid);
            goto out;
        }
    }

    /* OK, we have get the dh entry, just return it */
out:
    return e;
}

void mds_dh_gossip(struct dh *dh)
{
    struct dhe *e = ERR_PTR(-EINVAL);
    struct itbitmap *b;
    struct regular_hash *rh;
    struct hlist_node *l;
    int i, j, stop = atomic_read(&dh->asize);

    if (!stop)
        return;
    stop = lib_random(stop) + 1;
    
    for (i = 0, j = 0; i < dh->hsize; i++) {
        rh = dh->ht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry(e, l, &rh->h, hlist) {
            j++;
            if (j >= stop) {
                atomic_inc(&e->ref);
                break;
            }
        }
        xlock_unlock(&rh->lock);
        if (j >= stop)
            break;
    }
    if (j >= stop) {
        /* ok, we find the dhe, we just send all the bitmap slices for now */
        hvfs_debug(mds, "selected the dhe %lx to gossip (%d/%d)\n", 
                   e->uuid, stop, atomic_read(&dh->asize));
        /* FIXME: maybe there is a race with new bitmap slice inserting. */
        list_for_each_entry(b, &e->bitmap, list) {
            __dh_gossip_bitmap(b, e->uuid);
        }
        mds_dh_put(e);
    }
}

/* mds_get_itbid() may block on bitmap load
 *
 * Convert the hash to itbid by lookup the bitmap. This is a hot path that we
 * should optimize it hardly.
 */
u64 mds_get_itbid(struct dhe *e, u64 hash)
{
    struct itbitmap *b;
    u64 offset = hash >> ITB_DEPTH;
    int err;

retry:
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
        if (b->offset <= offset && offset < b->offset + XTABLE_BITMAP_SIZE) {
            /* ok, we get the bitmap slice, let us test it */
            if (mds_bitmap_lookup(b, offset)) {
                xlock_unlock(&e->lock);
                return offset;
            } else {
                /* hoo, we should reset the offset and restart the access */
                xlock_unlock(&e->lock);
                offset = mds_bitmap_fallback(offset);
                goto retry;
            }
            /* NOTE: we are sure that we can not run into here! */
        } else if (offset >= b->offset + XTABLE_BITMAP_SIZE) {
            if (likely(b->flag & BITMAP_END)) {
                /* ok, let us just fallbacking */
                xlock_unlock(&e->lock);
                offset = mds_bitmap_cut(offset,
                                        b->offset + XTABLE_BITMAP_SIZE);
                goto retry;
            } else if (b->list.next == &e->bitmap) {
                /* ok, this means that b is the last entry, we should load the
                 * next bitmap slice */
                xlock_unlock(&e->lock);
                err = mds_bitmap_load(e, b->offset + XTABLE_BITMAP_SIZE);
                if (err == -ENOTEXIST) {
                    /* FIXME: FATAL error this maybe a hole? */
                    offset = mds_bitmap_fallback(offset);
                } else if (err) {
                    hvfs_err(mds, "Hoo, load DHE %lx Bitmap %ld failed w/ %d\n",
                             e->uuid, 
                             (u64)b->offset + XTABLE_BITMAP_SIZE, 
                             err);
                    goto out;
                }
                goto retry;
            }
        } else if (b->offset > offset) {
            /* it means that we need to load the missing slice */
            xlock_unlock(&e->lock);
            err = mds_bitmap_load(e, offset);
            if (err == -ENOTEXIST) {
                offset = mds_bitmap_fallback(offset);
            } else if (err) {
                /* some error occurs, we failed to the 0 position */
                hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n", 
                         e->uuid, offset);
                goto out;
            }
            goto retry;
        }
    }
    xlock_unlock(&e->lock);

    /* Hoo, we have not found the bitmap slice. We need to request the
     * bitmap slice from the GDT server */
    err = mds_bitmap_load(e, offset);
    if (err == -ENOTEXIST) {
        offset = mds_bitmap_fallback(offset);
    } else if (err) {
        hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n", 
                 e->uuid, offset);
        goto out;
    }
    goto retry;
out:
    return 0;
}

/* mds_dh_bitmap_test()
 *
 * This function return the bit value of the position
 */
int mds_dh_bitmap_test(struct dh *dh, u64 puuid, u64 itbid)
{
    struct itbitmap *b;
    struct dhe *e;
    int err = -EINVAL;

    e = mds_dh_search(dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "The DHE(%lx) is not exist.\n", puuid);
        return -EINVAL;
    }
    /* check if the list is empty */
    xlock_lock(&e->lock);
    if (list_empty(&e->bitmap)) {
        xlock_unlock(&e->lock);
        err = mds_bitmap_load(e, 0);
        if (err == -ENOTEXIST) {
            hvfs_err(mds, "Hoo, loading DHE %lx Bitmap 0 failed, "
                     "not exists\n",
                     e->uuid);
            goto out;
        } else if (err) {
            hvfs_err(mds, "Hoo, loading DHE %lx Bitmap 0 failed w/ %d\n",
                     e->uuid, err);
            goto out;
        }
    } else {
        xlock_unlock(&e->lock);
    }
retry:
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
        if (b->offset <= itbid && itbid < b->offset + XTABLE_BITMAP_SIZE) {
            /* ok, we get the bitmap slice, just do it */
            err = mds_bitmap_test_bit(b, itbid);
            break;
        } else if (b->offset > itbid) {
            /* it means that we need to load the missing slice */
            xlock_unlock(&e->lock);
            err = mds_bitmap_load(e, itbid);
            if (err == -EISEMPTY) {
                err = 0;
                goto out;
            } else if (err) {
                hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed w/ %d\n",
                         e->uuid, itbid, err);
                goto out;
            }
            goto retry;
        } else if (itbid >= b->offset + XTABLE_BITMAP_SIZE) {
            if (b->flag & BITMAP_END) {
                /* ok, just create the slice now */
                xlock_unlock(&e->lock);
                err = 0;
                break;
            } else if (b->list.next == &e->bitmap) {
                /* load the next slice */
                xlock_unlock(&e->lock);
                err = mds_bitmap_load(e, itbid);
                if (err == -ENOTEXIST) {
                    hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n",
                             e->uuid, itbid);
                    goto out;
                } else if (err == -EISEMPTY) {
                    err = 0;
                    break;
                } else if (err) {
                    hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n",
                             e->uuid, itbid);
                    goto out;
                }
                goto retry;
            }
        }
    }
    xlock_unlock(&e->lock);
out:
    mds_dh_put(e);
    
    return err;
}

/* mds_dh_bitmap_update()
 *
 * This function only support one bit change on the bitmap region. If the
 * bitmap slice is not loaded in, we will load it automatically
 */
int mds_dh_bitmap_update(struct dh *dh, u64 puuid, u64 itbid, u8 op)
{
    struct itbitmap *b;
    struct dhe *e;
    int err = 0;

    hvfs_debug(mds, "bitmap updating puuid %lx itbid %ld.\n", puuid, itbid);
    e = mds_dh_search(dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "The DHE(%lx) is not exist.\n", puuid);
        return -EINVAL;
    }
    /* check if the list is empty */
    xlock_lock(&e->lock);
    if (list_empty(&e->bitmap)) {
        xlock_unlock(&e->lock);
        err = mds_bitmap_load(e, 0);
        if (err == -ENOTEXIST) {
            hvfs_err(mds, "Hoo, loading DHE %lx Bitmap 0 failed, "
                     "not exists\n",
                     e->uuid);
            goto out;
        } else if (err) {
            hvfs_err(mds, "Hoo, loading DHE %lx Bitmap 0 failed w/ %d\n",
                     e->uuid, err);
            goto out;
        }
    } else {
        xlock_unlock(&e->lock);
    }
retry:
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
        if (b->offset <= itbid && itbid < b->offset + XTABLE_BITMAP_SIZE) {
            /* ok, we get the bitmap slice, just do it */
            mds_bitmap_update_bit(b, itbid, op);
            break;
        } else if (b->offset > itbid) {
            /* it means that we need to load the missing slice */
            xlock_unlock(&e->lock);
            err = mds_bitmap_load(e, itbid);
            if (err == -ENOTEXIST) {
                /* we just create the slice now */
                err = mds_bitmap_create(e, itbid, 0);
                if (err == -EEXIST) {
                    /* ok, we just retry */
                    goto retry;
                } else if (err) {
                    goto out;
                }
            } else if (err) {
                hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n",
                         e->uuid, itbid);
                goto out;
            }
            goto retry;
        } else if (itbid >= b->offset + XTABLE_BITMAP_SIZE) {
            if (b->flag & BITMAP_END) {
                /* ok, just create the slice now */
                xlock_unlock(&e->lock);
                hvfs_err(mds, "try to create BS @ %ld\n", itbid);
                err = mds_bitmap_create(e, itbid, 1);
                if (err == -EEXIST) {
                    /* ok, we just break */
                    b->flag &= ~BITMAP_END;
                    break;
                } else if (err) {
                    goto out;
                }
                /* clear and reset the END flag */
                b->flag &= ~BITMAP_END;
                goto retry;
            } else if (b->list.next == &e->bitmap) {
                /* load the next slice */
                xlock_unlock(&e->lock);
                err = mds_bitmap_load(e, itbid);
                if (err == -ENOTEXIST) {
                    hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n",
                             e->uuid, itbid);
                    goto out;
                } else if (err) {
                    hvfs_err(mds, "Hoo, loading DHE %lx Bitmap %ld failed\n",
                             e->uuid, itbid);
                    goto out;
                }
                goto retry;
            }
        }
    }
    xlock_unlock(&e->lock);
out:
    mds_dh_put(e);
    
    return err;
}

/* mds_dh_bitmap_dump()
 */
void mds_dh_bitmap_dump(struct dh *dh, u64 puuid)
{
    struct itbitmap *b;
    struct dhe *e;
    char line[4096];
    int i, len = 0;

    e = mds_dh_search(dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "The DHE(%ld) is not exist.\n", puuid);
        return;
    }

    memset(line, 0, 4096);
    xlock_lock(&e->lock);
    list_for_each_entry(b, &e->bitmap, list) {
/*         for (i = 0; i < XTABLE_BITMAP_SIZE / 8; i++) { */
        for (i = 0; i < 32; i++) {
            len += snprintf(line + len, 4096, "%x", b->array[i]);
        }
        hvfs_plain(mds, "offset: %s\n", line);
    }
    xlock_unlock(&e->lock);
    mds_dh_put(e);
}
