/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-13 04:04:23 macan>
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
#include "mds.h"
#include "ring.h"
#include "lib.h"
#include "root.h"
#include "amc_api.h"
#include "branch.h"

#define BRANCH_HT_DEFAULT_SIZE          (1024)

static struct branch_local_op branch_default_blo = {
    .stat = __hvfs_stat,
    .create = __hvfs_create,
    .update = __hvfs_update,
    .read = __hvfs_fread_local,
    .write = __hvfs_fwrite_local,
};

struct branch_mgr
{
    struct regular_hash_rw *bht;
    int hsize;
    atomic_t asize;
    struct branch_local_op op;
    struct branch_processor *bp;
    struct list_head qin;
    xlock_t qlock;
    sem_t qsem;
    
    pthread_t schedt;           /* scheduler thread */
    pthread_t processt;         /* processor thread */
    
    /* the following region is the branch memory table */
#define BRANCH_MGR_DEFAULT_MEMLIMIT     (64 * 1024 * 1024)
    u64 memlimit;

#define BRANCH_MGR_DEFAULT_BTO          (600) /* ten minutes */
    int bto;                    /* branch entry timeout value */
#define BRANCH_MGR_DEFAULT_DIRTY_TO     (10)
    int dirty_to;               /* branch entry dirty timeout value */
#define BRANCH_MGR_DEFAULT_SENT_TO      (30)
    int sent_to;                /* branch entry sent timeout value */

    u8 schedt_stop:1;
    u8 processt_stop:1;
};

static inline
u64 BRANCH_GET_ID(void)
{
    return atomic64_inc_return(&hmi.mi_bid);
}

static inline
int BL_IS_CKPTED(struct branch_line *bl)
{
    return (bl->state & BL_CKPTED);
}

#define BL_SET_CKPTED(bl) do {                  \
        (bl)->state |= BL_CKPTED;               \
    } while (0)

struct branch_mgr bmgr;

static inline
u32 __branch_hash(char *str, u32 len)
{
    return JSHash(str, len) % bmgr.hsize;
}

/* Region for BP primary site locating (BP is always co-located w/ MDSL)
 *
 * We use branch_name and current site's id to locate a BP site. Thus, we can
 * use bulk push for the source site.
 */
static inline
u64 SELECT_BP_SITE(char *branch_name, u64 site_id)
{
    struct chp *p;
    u64 hash;
    
    hash = __murmurhash64a(branch_name, strlen(branch_name), site_id);
    p = ring_get_point(hash, site_id, hmo.chring[CH_RING_BP]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -1UL;
    }

    return p->site_id;
}

static 
void __branch_err_reply(struct xnet_msg *msg, int err)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_set_err(rpy, err);
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.xc->site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(xnet, "xnet_send() failed\n");
        /* do not retry my self */
    }
    xnet_free_msg(rpy);
}

void *branch_scheduler(void *arg);
void *branch_processor(void *arg);

int branch_init(int hsize, int bto, u64 memlimit, 
                struct branch_local_op *op)
{
    int err = 0, i;

    /* local operations */
    if (op)
        bmgr.op = *op;
    else
        bmgr.op = branch_default_blo;

    /* regular hash init */
    hsize = (hsize == 0) ? BRANCH_HT_DEFAULT_SIZE : hsize;
    bmgr.bht = xzalloc(hsize * sizeof(struct regular_hash_rw));
    if (!bmgr.bht) {
        hvfs_err(xnet, "BRANCH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&bmgr.bht[i].h);
        xrwlock_init(&bmgr.bht[i].lock);
    }
    bmgr.hsize = hsize;

    atomic_set(&bmgr.asize, 0);
    if (bto)
        bmgr.bto = bto;
    else
        bmgr.bto = BRANCH_MGR_DEFAULT_BTO;
    if (memlimit)
        bmgr.memlimit = memlimit;
    else
        bmgr.memlimit = BRANCH_MGR_DEFAULT_MEMLIMIT;

    bmgr.dirty_to = BRANCH_MGR_DEFAULT_DIRTY_TO;
    INIT_LIST_HEAD(&bmgr.qin);
    xlock_init(&bmgr.qlock);
    sem_init(&bmgr.qsem, 0, 0);

    err = pthread_create(&bmgr.schedt, NULL, &branch_scheduler, NULL);
    if (err)
        goto out;
    err = pthread_create(&bmgr.processt, NULL, &branch_processor, NULL);
    if (err)
        goto out;
    
out:
    return err;
}

int branch_final_flush(void);

void branch_destroy(void)
{
    bmgr.schedt_stop = 1;
    bmgr.processt_stop = 1;
    if (!HVFS_IS_BP(hmo.site_id)) {
        pthread_kill(bmgr.schedt, SIGUSR1);
    }
    pthread_join(bmgr.schedt, NULL);
    sem_post(&bmgr.qsem);
    pthread_join(bmgr.processt, NULL);
    
    branch_final_flush();

    if (bmgr.bht)
        xfree(bmgr.bht);
    sem_destroy(&bmgr.qsem);
}

void branch_install_bp(struct branch_entry *be,
                       struct branch_processor *bp)
{
    be->bp = bp;
    bp->be = be;
}

/* basic functions for reading and writing metadata and data */
int hvfs_stat_eh(u64 puuid, u64 psalt, int column, 
                 struct hstat *hs)
{
    struct dhe *e;
    struct chp *p;
    u64 hash, itbid;
    
    if (!hs->uuid) {
        hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                         HASH_SEL_EH);
    } else {
        if (!hs->hash)
            hash = hvfs_hash(hs->uuid, psalt, 0, HASH_SEL_GDT);
        else
            hash = hs->hash;
    }

    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        return PTR_ERR(e);
    }
    itbid = mds_get_itbid(e, hash);
    mds_dh_put(e);

    /* check if we are in the local site */
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -EINVAL;
    }

    if (p->site_id == hmo.site_id) {
        /* oh, local access */
        return __hvfs_stat_local(puuid, psalt, column, hs);
    } else {
        /* call api.c */
        return __hvfs_stat(puuid, psalt, column, hs);
    }
}

int hvfs_create_eh(u64 puuid, u64 psalt, struct hstat *hs,
                   u32 flag, struct mdu_update *imu)
{
    struct dhe *e;
    struct chp *p;
    u64 hash, itbid;

    if (flag & INDEX_CREATE_GDT) {
        hash = hvfs_hash(hs->uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);
    } else {
        /* SYMLINK, LINK, DIR, OTHERWISE */
        hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                         HASH_SEL_EH);
    }

    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        return PTR_ERR(e);
    }
    itbid = mds_get_itbid(e, hash);
    mds_dh_put(e);

    /* check if we are in the local site */
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -EINVAL;
    }

    if (p->site_id == hmo.site_id) {
        /* oh, local access */
        return __hvfs_create_local(puuid, psalt, hs, flag, imu);
    } else {
        /* call api.c */
        return __hvfs_create(puuid, psalt, hs, flag, imu);
    }
}

int hvfs_update_eh(u64 puuid, u64 psalt, struct hstat *hs,
                   struct mdu_update *imu)
{
    struct dhe *e;
    struct chp *p;
    u64 hash, itbid;

    if (!hs->uuid)
        hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                         HASH_SEL_EH);
    else {
        if (!hs->hash)
            hash = hvfs_hash(hs->uuid, psalt, 0, HASH_SEL_GDT);
        else
            hash = hs->hash;
    }

    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        return PTR_ERR(e);
    }
    itbid = mds_get_itbid(e, hash);
    mds_dh_put(e);

    /* check if we are in the local site */
    p = ring_get_point(itbid, psalt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(e));
        return -EINVAL;
    }

    if (p->site_id == hmo.site_id) {
        /* oh, local access */
        return __hvfs_update_local(puuid, psalt, hs, imu);
    } else {
        /* call api.c */
        return __hvfs_update(puuid, psalt, hs, imu);
    }
}

ssize_t hvfs_fread_eh(struct hstat *hs, int column, void **data, 
                      struct column *c)
{
    struct chp *p;
    int err = 0;

    p = ring_get_point(c->stored_itbid, hs->psalt, 
                       hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", 
                 PTR_ERR(p));
        return -EINVAL;
    }

    if (p->site_id == hmo.site_id) {
        /* oh, this is a mdsl local access */
        struct storage_index si;
        struct iovec *iov;

        si.sic.uuid = hs->puuid;
        si.sic.arg0 = hs->uuid;
        if (hs->mdu.flags & HVFS_MDU_IF_PROXY)
            si.scd.flag = SCD_PROXY;
        si.scd.cnr = 1;
        si.scd.cr[0].cno = column;
        si.scd.cr[0].stored_itbid = c->stored_itbid;
        si.scd.cr[0].file_offset = c->offset;
        si.scd.cr[0].req_offset = 0;
        si.scd.cr[0].req_len = c->len;

        err = bmgr.op.read(&si, &iov);
        if (err) {
            hvfs_err(xnet, "local read failed w/ %d\n", err);
            return err;
        }
        *data = iov->iov_base;
        xfree(iov);
    } else {
        /* call api.c */
        return __hvfs_fread(hs, column, data, c, 0, c->len);
    }

    return c->len;
}

/* hvfs_fwrite_eh()
 *
 * It can recieve flags as described in mdsl_api.h (i.e. SCD_PROXY etc).
 */
int hvfs_fwrite_eh(struct hstat *hs, int column, u32 flag, 
                   void *data, size_t len, struct column *c)
{
    struct chp *p;
    int err = 0;

    p = ring_get_point(c->stored_itbid, hs->psalt, 
                       hmo.chring[CH_RING_MDSL]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", 
                 PTR_ERR(p));
        return -EINVAL;
    }

    if (p->site_id == hmo.site_id) {
        /* oh, local access */
        struct storage_index si;
        u64 *location;

        si.sic.uuid = hs->puuid;
        if (flag & SCD_PROXY) {
            si.scd.cr[0].file_offset = c->offset; /* maybe in append mode */
            si.sic.arg0 = hs->uuid;
        } else
            si.sic.arg0 = hs->uuid;
        si.scd.flag = flag;
        si.scd.cnr = 1;
        si.scd.cr[0].cno = column;
        si.scd.cr[0].stored_itbid = hs->hash;
        si.scd.cr[0].req_len = len;

        location = &c->offset;
        err = bmgr.op.write(&si, data, &location);
        if (err) {
            hvfs_err(xnet, "local write failed w/ %d\n", err);
            return err;
        }
        c->stored_itbid = hs->hash;
        c->len = len;
    } else {
        /* call api.c */
        return __hvfs_fwrite(hs, column, flag, data, len, c);
    }

    return err;
}

int __branch_insert(char *branch_name, struct branch_header *bh)
{
    struct regular_hash_rw *rh;
    struct branch_entry *be, *tpos;
    struct hlist_node *pos;
    int i;

    i = __branch_hash(branch_name, strlen(branch_name));
    rh = bmgr.bht + i;

    be = xzalloc(sizeof(struct branch_entry));
    if (unlikely(!be))
        return -ENOMEM;

    INIT_HLIST_NODE(&be->hlist);
    INIT_LIST_HEAD(&be->primary_lines);
    INIT_LIST_HEAD(&be->replica_lines);
    atomic_set(&be->ref, 0);
    xlock_init(&be->lock);
    be->branch_name = strdup(branch_name);
    be->update = time(NULL);
    be->bh = bh;

    i = 0;
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (strlen(branch_name) == strlen(tpos->branch_name) &&
            strcmp(tpos->branch_name, branch_name) == 0) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&be->hlist, &rh->h);
    xrwlock_wunlock(&rh->lock);

    if (i) {
        xfree(be);
        return -EEXIST;
    }
    atomic_inc(&bmgr.asize);
    
    return 0;
}

int __branch_remove(char *branch_name)
{
    struct regular_hash_rw *rh;
    struct branch_entry *tpos;
    struct hlist_node *pos, *n;
    int i;

    i = __branch_hash(branch_name, strlen(branch_name));
    rh = bmgr.bht + i;

retry:
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (strlen(branch_name) == strlen(tpos->branch_name) &&
            strcmp(tpos->branch_name, branch_name) == 0) {
            /* wait for the last reference */
            if (atomic_read(&tpos->ref) > 1) {
                xrwlock_wunlock(&rh->lock);
                /* not in the hot path, we can sleep longer */
                xsleep(1000);
                goto retry;
            }
            hlist_del(&tpos->hlist);
            xfree(tpos);
            atomic_dec(&bmgr.asize);
            break;
        }
    }
    xrwlock_wunlock(&rh->lock);
    
    return 0;
}

/* Note, you have to call __branch_put() to release the reference
 */
struct branch_entry *__branch_lookup(char *branch_name)
{
    struct branch_entry *be = NULL;
    struct regular_hash_rw *rh;
    struct hlist_node *pos;
    int i, len;

    len = strlen(branch_name);
    i = __branch_hash(branch_name, len);
    rh = bmgr.bht + i;

    i = 0;
    xrwlock_rlock(&rh->lock);
    hlist_for_each_entry(be, pos, &rh->h, hlist) {
        if (strlen(be->branch_name) == len &&
            memcmp(be->branch_name, branch_name, len) == 0) {
            atomic_inc(&be->ref);
            i = 1;
            break;
        }
    }
    xrwlock_runlock(&rh->lock);
    if (!i)
        be = NULL;

    return be;
}

void branch_put(struct branch_entry *be)
{
    atomic_dec(&be->ref);
}

/* Note, you have to call branch_put to release the reference
 */
struct branch_entry *branch_lookup_load(char *branch_name)
{
    struct branch_entry *be;
    int err = 0, mode = 0;

    if (HVFS_IS_MDSL(hmo.site_id) || HVFS_IS_BP(hmo.site_id))
        mode = 1;
    
retry:
    be = __branch_lookup(branch_name);
    if (!be) {
        /* ok, we should load the bh now */
        err = branch_load(branch_name, "", mode);
        if (!err || err == -EEXIST) {
            goto retry;
        } else {
            hvfs_err(xnet, "Load branch '%s' failed w/ %d\n",
                     branch_name, err);
            return ERR_PTR(err);
        }
    }

    return be;
}

int __branch_destroy(struct branch_entry *be)
{
    int err = 0;
    
    if (atomic_read(&be->ref) > 0) {
        return -EBUSY;
    }

    xlock_lock(&be->lock);
    if (list_empty(&be->primary_lines) && 
        list_empty(&be->replica_lines)) {
        /* it is ok to free this entry now */
        xfree(be->bh);
    } else {
        err = -EBUSY;
    }
    xlock_unlock(&be->lock);

    return err;
}

int branch_cleanup(time_t cur)
{
    struct regular_hash_rw *rh;
    struct branch_entry *tpos;
    struct hlist_node *pos, *n;
    int i, err = 0, errstate;

    for (i = 0; i < bmgr.hsize; i++) {
        rh = bmgr.bht + i;
        xrwlock_wlock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            if (cur - tpos->update > bmgr.bto) {
                if (atomic_read(&tpos->ref) > 0) {
                    hvfs_warning(xnet, "Branch '%s' lingering too long (busy?)\n",
                                 tpos->branch_name);
                    continue;
                }
                hlist_del(&tpos->hlist);
                errstate = BO_FLUSH;
                if (tpos->bp) {
                    xlock_lock(&tpos->bp->lock);
                    err = tpos->bp->bo_root.input(tpos->bp,
                                                  &tpos->bp->bo_root,
                                                  NULL, -1UL, 0, &errstate);
                    if (errstate == BO_STOP) {
                        /* ignore any errors */
                        if (err) {
                            hvfs_err(xnet, "Final flush on root branch "
                                     "failed w/ %d\n",
                                     err);
                        }
                    }
                    xlock_unlock(&tpos->bp->lock);
                }
                err = __branch_destroy(tpos);
                if (!err) {
                    if (tpos->bp)
                        bp_destroy(tpos->bp);
                    xfree(tpos->branch_name);
                    xfree(tpos);
                    atomic_dec(&bmgr.asize);
                } else {
                    hvfs_err(xnet, "Branch '%s' ref changing (busy?)\n",
                             tpos->branch_name);
                }
            }
        }
        xrwlock_wunlock(&rh->lock);
    }
    
    return 0;
}

int branch_final_flush(void)
{
    struct regular_hash_rw *rh;
    struct branch_entry *tpos;
    struct hlist_node *pos, *n;
    int i, err = 0, errstate;

    for (i = 0; i < bmgr.hsize; i++) {
        rh = bmgr.bht + i;
        xrwlock_wlock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            hlist_del(&tpos->hlist);
            /* for each branch_entry, we call root flush, left flush, and
             * right flush */
            errstate = BO_FLUSH;
            if (tpos->bp) {
                err = tpos->bp->bo_root.input(tpos->bp,
                                              &tpos->bp->bo_root,
                                              NULL, -1UL, 0, &errstate);
                if (errstate == BO_STOP) {
                    /* ignore any errors */
                    if (err) {
                        hvfs_err(xnet, "Final flush on root branch "
                                 "failed w/ %d\n",
                                 err);
                    }
                }
                bp_destroy(tpos->bp);
            }
            err = __branch_destroy(tpos);
            if (!err) {
                xfree(tpos->branch_name);
                xfree(tpos);
                atomic_dec(&bmgr.asize);
            }
        }
        xrwlock_wunlock(&rh->lock);
    }

    return 0;
}

static inline
struct xnet_group *__get_active_site(struct chring *r)
{
    struct xnet_group *xg = NULL;
    int i, err;

    for (i = 0; i < r->used; i++) {
        err = xnet_group_add(&xg, r->array[i].site_id);
    }

    return xg;
}

u64 __branch_get_replica(u64 *sg, int nr)
{
    struct xnet_group *xg;
    u64 dsite = -1UL;
    int i, j;
    
    /* get another site other than current site group */
    xg = __get_active_site(hmo.chring[CH_RING_MDS]);
    if (!xg) {
        /* oh, there is no active site now, failed myself */
        return -1UL;
    }

    if (nr + 1 >= xg->asize) {
        /* this means that active replica set is larger than active site
         * group, thus we just reject this requst */
        xfree(xg);
        return -1UL;
    }

reselect:
    i = lib_random(xg->asize);
    for (j = 0; j < nr; j++) {
        if (xg->sites[i].site_id == *(sg + j)) {
            /* conflict, reselect */
            goto reselect;
        }
    }
    dsite = xg->sites[i].site_id;
    xfree(xg);

    return dsite;
}

/* __branch_replicate() replicate one branch_line to dsite
 */
int __branch_replicate(struct branch_entry *be,
                       struct branch_line *bl, u64 dsite)
{
    struct xnet_msg *msg;
    struct branch_line_disk bld = {
        .bl = *bl,
    };
    int err = 0;

    /* setup the rest bld fields */
    if (bl->tag)
        bld.tag_len = strlen(bl->tag);
    else
        bld.tag_len = 0;
    bld.name_len = strlen(be->branch_name);
    
    bld.bl.position = BL_REPLICA;
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_REPLICA,
                      0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &bld, sizeof(bld));
    if (bld.name_len)
        xnet_msg_add_sdata(msg, be->branch_name, bld.name_len);
    if (bld.tag_len)
        xnet_msg_add_sdata(msg, bl->tag, bld.tag_len);
    if (bl->data_len)
        xnet_msg_add_sdata(msg, bl->data, bl->data_len);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() REPLICA '%s' id:%ld to %lx "
                 "failed w/ %d\n",
                 be->branch_name, bl->id, dsite, err);
        goto out_free;
    }

out_free:
    xnet_free_msg(msg);
    
out:
    return err;
}

/* do_replicate() handle the replicate request from other sites
 */
int __branch_do_replicate(struct xnet_msg *msg, 
                          struct branch_line_disk *bld)
{
    char *branch_name, *tag_name, *p;
    struct branch_entry *be;
    struct branch_line *bl;
    int err = 0;


    bl = &bld->bl;
    bl->life = time(NULL);
    
    branch_name = xzalloc(bld->name_len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }
    tag_name = xzalloc(bld->tag_len + 1);
    if (!tag_name) {
        hvfs_err(xnet, "xzalloc() tag failed\n");
        xfree(branch_name);
        return -ENOMEM;
    }

    p = (void *)bld + sizeof(*bld);
    memcpy(branch_name, p, bld->name_len);
    p += bld->name_len;
    memcpy(tag_name, p, bld->tag_len);
    p += bld->tag_len;

    /* re-init the branch line */
    INIT_LIST_HEAD(&bl->list);
    bl->tag = tag_name;
    bl->data = p;
    bl->position = BL_REPLICA;

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }

    /* add to the replica list */
    xlock_lock(&be->lock);
    list_add_tail(&bl->list, &be->replica_lines);
    xlock_unlock(&be->lock);
    be->update = time(NULL);

    branch_put(be);

    /* finally, send the reply now */
    __branch_err_reply(msg, 0);
    
out:
    xfree(branch_name);
    
    return err;
out_free:
    xfree(branch_name);
    xfree(tag_name);
    goto out;
}

/* __branch_push() will modify the bl->state. It is our's responsibility to
 * transfer the bl->state to BL_SENT.
 */
int __branch_push(struct branch_entry *be,
                  struct branch_line *bl, u64 dsite)
{
    struct xnet_msg *msg;
    struct branch_line_disk bld = {
        .bl = *bl,
    };
    int err = 0;

    /* check if there is another thread sending */
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        /* another thread is sending, give up */
        err = -EBUSY;
        xlock_unlock(&be->lock);
        goto out;
    } else {
        be->state = BE_SENDING;
    }
    xlock_unlock(&be->lock);

    /* setup the rest bld fields */
    if (bl->tag)
        bld.tag_len = strlen(bl->tag);
    else
        bld.tag_len = 0;
    bld.name_len = strlen(be->branch_name);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        /* reset state to BE_FREE */
        goto be_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_PUSH,
                      be->last_ack);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &bld, sizeof(bld));
    if (bld.name_len)
        xnet_msg_add_sdata(msg, be->branch_name, bld.name_len);
    if (bld.tag_len)
        xnet_msg_add_sdata(msg, bl->tag, bld.tag_len);
    if (bld.bl.data_len)
        xnet_msg_add_sdata(msg, bl->data, bl->data_len);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() PUSH '%s' id %ld to %lx "
                 "failed w/ %d\n",
                 be->branch_name, bl->id, dsite, err);
        goto out_free;
    }

    /* change bl->state to BL_SENT */
    xlock_lock(&be->lock);
    if ((bl->state & BL_STATE_MASK) == BL_NEW) {
        bl->state |= BL_SENT;
        bl->sent = time(NULL);
    }
    xlock_unlock(&be->lock);

out_free:
    xnet_free_msg(msg);
be_free:
    xlock_lock(&be->lock);
    be->state = BE_FREE;
    xlock_unlock(&be->lock);
    
out:
    return err;
}

static inline
int __branch_pack_bulk_push_header(struct xnet_msg *msg,
                                   struct branch_entry *be,
                                   struct branch_line_push_header *blph,
                                   int nr)
{
    blph->name_len = strlen(be->branch_name);
    /* reset blph->nr to ZERO */
    blph->nr = 0;

    xnet_msg_add_sdata(msg, blph, sizeof(*blph));
    if (blph->name_len)
        xnet_msg_add_sdata(msg, be->branch_name, blph->name_len);

    return 0;
}

/* |->name|->tag|->data|
 */
static inline
int __branch_pack_msg(struct xnet_msg *msg, 
                      struct branch_line_disk *bld,
                      struct branch_line *bl,
                      struct branch_line_push_header *blph)
{
    int err = 0;
    
    bld->bl = *bl;
    if (bl->tag)
        bld->tag_len = strlen(bl->tag);
    bld->name_len = 0;
    
    err = xnet_msg_add_sdata(msg, bld, sizeof(*bld));
    if (!err && bld->tag_len)
        err = xnet_msg_add_sdata(msg, bl->tag, bld->tag_len);
    if (!err && bl->data_len)
        err = xnet_msg_add_sdata(msg, bl->data, bl->data_len);
    if (!err)
        blph->nr++;

    return err;
}

/* __branch_bulk_push() try to send more branch_lines as a whole
 *
 */
int __branch_bulk_push(struct branch_entry *be, u64 dsite)
{
    struct branch_line *bl, *start_bl = NULL;
    int nr = 0, err = 0, remain = 0;
    
    /* calculate how many branch entry we can send */
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        /* another thread is sending, give up */
        err = -EBUSY;
    } else {
        list_for_each_entry(bl, &be->primary_lines, list) {
            if ((bl->state & BL_STATE_MASK) == BL_NEW) {
                if (nr == 0) {
                    start_bl = bl;
                }
                nr++;
            } else {
                if (nr > 0) {
                    hvfs_err(xnet, "Fatal error, unordered sending?\n");
                    err = -EFAULT;
                    break;
                }
            }
        }
        if (nr > 0)
            be->state = BE_SENDING;
    }
    xlock_unlock(&be->lock);

    if (!err && nr > 0) {
        /* we have got the # of branch lines, let us construct a buge message
         * and send it to the final location */
        /* Step 1: adjust the nr to a proper value */
        struct xnet_msg *msg;
        struct branch_line_disk *bld_array;
        struct branch_line_push_header blph;
        time_t __cur_ts = time(NULL);
        int iter = 0;

        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(xnet, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto exit_to_free;
        }
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0,
                         hmo.xc->site_id, dsite);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, 
                          BRANCH_CMD_BULK_PUSH, be->last_ack);
        
        bld_array = xzalloc(nr * sizeof(*bld_array));
        if (!bld_array) {
            hvfs_err(xnet, "xzalloc() bld array failed\n");
            err = -ENOMEM;
            goto out_free_msg;
        }
        
        err = __branch_pack_bulk_push_header(msg, be, &blph, nr);
        if (err) {
            hvfs_err(xnet, "pack bulk push header for '%s' "
                     "failed /w/ %d\n",
                     be->branch_name, err);
            xfree(bld_array);
            goto out_free_msg;
        }

        ASSERT(start_bl, xnet);
        bl = start_bl;
        while (iter < nr) {
            err = __branch_pack_msg(msg, bld_array + iter, bl, &blph);
            if (err)
                break;
            bl = list_entry(bl->list.next, struct branch_line, 
                            list);
            iter++;
        }
        if (iter < nr)
            remain = 1;
        nr = iter;

        /* Step 2: do sending now */
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(xnet, "xnet_send() BULK PUSH '%s' nr %d to "
                     "%lx failed w/ %d\n",
                     be->branch_name, nr, dsite, err);
            /* just fallback? do not set the BL_SENT flag! */
        }
        
        xfree(bld_array);

        /* Step 3: on receiving the reply, we set the bl->state to SENT. need
         * be->lock */
        if (!err) {
            bl = start_bl;
            xlock_lock(&be->lock);
            iter = 0;
            while (iter < nr) {
                ASSERT((bl->state & BL_STATE_MASK) == BL_NEW, xnet);
                bl->state |= BL_SENT;
                bl->sent = __cur_ts;
                bl = list_entry(bl->list.next, struct branch_line,
                                list);
                iter++;
            }
            xlock_unlock(&be->lock);
        }
        
    out_free_msg:
        xnet_free_msg(msg);

        /* Step 4: finally, we change be->state to FREE */
    exit_to_free:
        xlock_lock(&be->lock);
        be->state = BE_FREE;
        xlock_unlock(&be->lock);
    }

    if (!err && remain)
        return remain;
    else
        return err;
}

int __branch_line_bcast_ack(char *branch_name, u64 ack_id, 
                            struct xnet_group *xg)
{
    struct xnet_msg *msg;
    int err = 0, i;

    if (!xg)
        return 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH,
                      BRANCH_CMD_ACK_REPLICA, ack_id);
    xnet_msg_add_sdata(msg, branch_name, strlen(branch_name));
    
    for (i = 0; i < xg->asize; i++) {
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                         hmo.xc->site_id, xg->sites[i].site_id);
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(xnet, "xnet_send() ACK REPLICA '%s' %ld "
                     "failed w/ %d\n", 
                     branch_name, ack_id, err);
            /* ignore errors */
        }
        /* FIXME: should we chech the reply stat of replica? */
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
    }

    xnet_free_msg(msg);

    return 0;
}

int __branch_do_ack_replica(struct xnet_msg *msg)
{
    struct branch_entry *be;
    struct branch_line *bl, *n;
    char *branch_name;
    int err = 0;

    branch_name = xzalloc(msg->tx.len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }
    memcpy(branch_name, msg->xm_data, msg->tx.len);

    /* find the be and update the replica lines */
    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }

retry:
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        xlock_unlock(&be->lock);
        sleep(1);
        goto retry;
    }
    list_for_each_entry_safe(bl, n, &be->replica_lines, list) {
        if (bl->id <= msg->tx.arg1) {
            /* remove it */
            list_del(&bl->list);
            xfree(bl->tag);
            /* there is no need to free bl->data */
            xfree(bl);
        } else {
            /* already passed, do nothing and break */
            break;
        }
    }
    xlock_unlock(&be->lock);

    branch_put(be);

    /* finally, we send the reply now */
    __branch_err_reply(msg, 0);
    
out_free:
    xfree(branch_name);
    
    return err;
}

/* do_ack() handle the ACK request
 */
int __branch_do_ack(struct xnet_msg *msg,
                    struct branch_line_ack_header *blah)
{
    struct branch_entry *be;
    struct branch_line *bl, *n;
    struct xnet_group *xg = NULL;
    struct list_head ack_bcast;
    char *branch_name;
    int err = 0, i;

    branch_name = xzalloc(blah->name_len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }

    memcpy(branch_name, (void *)blah + sizeof(*blah), blah->name_len);

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }
    INIT_LIST_HEAD(&ack_bcast);

    /* Note that, we know the ACK is accumulative */
retry:
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        xlock_unlock(&be->lock);
        sleep(1);
        goto retry;
    }
    list_for_each_entry_safe(bl, n, &be->primary_lines, list) {
        if (bl->id <= blah->ack_id) {
            if ((bl->state & BL_STATE_MASK) == BL_SENT) {
                /* we can remove it now */
                list_del_init(&bl->list);
                list_add_tail(&bl->list, &ack_bcast);
            } else if ((bl->state & BL_STATE_MASK) == BL_NEW) {
                hvfs_err(xnet, "ACK a NEW state line %ld ACK %ld\n",
                         bl->id, blah->ack_id);
            } else {
                /* ACKed state ? remove it now */
                list_del_init(&bl->list);
                list_add_tail(&bl->list, &ack_bcast);
            }
            if (bl->id == blah->ack_id) {
                break;
            }
        } else {
            /* already passed, do nothing and break */
            break;
        }
    }
    /* update the last_ack value */
    be->last_ack = blah->ack_id;
    
    xlock_unlock(&be->lock);
    
    branch_put(be);

    /* we have got a bcast list, then we do bcast */
    list_for_each_entry_safe(bl, n, &ack_bcast, list) {
        for (i = 1; i < bl->replica_nr; i++) {
            err = xnet_group_add(&xg, bl->sites[i]);
        }
        list_del(&bl->list);
        xfree(bl->tag);
        /* there is no need to free bl->data */
        xfree(bl);
    }
    
    err = __branch_line_bcast_ack(branch_name, blah->ack_id, xg);
    if (err) {
        hvfs_err(xnet, "bcast ACK %ld to many sites failed w/ %d\n",
                 blah->ack_id, err);
        /* ignore the error */
    }
    
    /* finally, send the reply now */
    __branch_err_reply(msg, 0);
    
out_free:
    xfree(branch_name);
    
    return err;
}

/* do_adjust() handle the ADJUST request. It change the branch_entry's
 * last_ack to the specific ack_id, and reset branch lines' state to BL_NEW.
 */
int __branch_do_adjust(struct xnet_msg *msg, 
                       struct branch_adjust_entry *bae)
{
    struct branch_entry *be;
    struct branch_line *bl;
    int namelen = msg->tx.len - sizeof(*bae), err = 0;
    char __bname[namelen + 1];

    memcpy(__bname, (void *)bae + sizeof(*bae), namelen);
    __bname[namelen] = '\0';

    be = branch_lookup_load(__bname);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out;
    }

    /* reset branch lines' state */
retry:
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        xlock_unlock(&be->lock);
        sleep(1);
        goto retry;
    }
    if (be->last_ack > bae->ack_id) {
        hvfs_err(xnet, "branch '%s' last_ack has been updated to %ld(%ld)\n",
                 __bname, be->last_ack, bae->ack_id);
        err = -EIGNORE;
        goto out_unlock;
    }
    
    list_for_each_entry(bl, &be->primary_lines, list) {
        if (bl->id < bae->lid)
            continue;
        if ((bl->state & BL_STATE_MASK) == BL_NEW)
            break;
        if ((bl->state & BL_STATE_MASK) == BL_SENT) {
            bl->state &= (BL_STATE_MASK & ~(BL_SENT));
        }
    }

    be->last_ack = bae->ack_id;

out_unlock:
    xlock_unlock(&be->lock);
    branch_put(be);

    /* finally, send the reply now */
    __branch_err_reply(msg, 0);

out:
    return err;
}

int branch_send_bor(struct xnet_msg *msg, struct branch_op_result *bor,
                    size_t len)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.xc->site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, len, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;
    if (len)
        xnet_msg_add_sdata(rpy, bor, len);

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(xnet, "xnet_send() failed\n");
        /* do not retry my self */
    }
    xnet_free_msg(rpy);

    return 0;
}

int __branch_do_getbor(struct xnet_msg *msg, char *branch_name)
{
    struct branch_entry *be;
    struct branch_op_result *bor;
    struct branch_line_disk *bld = NULL;
    int errstate = 0;
    int len = 0, err = 0;

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        return err;
    }

    if (!be->bp) {
        hvfs_err(xnet, "BE %s's BP is not installed properly.\n",
                 branch_name);
        return -EFAULT;
    }

    err = be->bp->bo_root.output(be->bp,
                                 &be->bp->bo_root,
                                 NULL,
                                 &bld, &len, &errstate);
    if (errstate == BO_STOP) {
        if (err) {
            hvfs_err(xnet, "root's output failed w/ %d, still "
                     "trying to retrieve BLD\n", 
                     err);
        }
    }
    branch_put(be);
    if (len > 0) {
        struct branch_line_disk *p;
        struct branch_op_result_entry *bore;
        int nr = 0;
        
        /* we do have some BLD to return */
        bor = xzalloc(sizeof(*bor) + len);
        if (!bor) {
            hvfs_err(xnet, "xzalloc() BOR region failed\n");
            xfree(bld);
            return -ENOMEM;
        }

        p = bld;
        bore = (void *)bor + sizeof(*bor);
        while ((void *)p < (void *)bld + len) {
            bore->id = p->bl.id;
            bore->len = p->bl.data_len;
            memcpy(bore->data, p->data, bore->len);
            p = (void *)p + sizeof(*bld) + bore->len;
            bore = (void *)bore + sizeof(*bore) + bore->len;
            nr++;
        }
        bor->nr = nr;
        hvfs_err(xnet, "construct BOR w/ %d BORE len %d\n", nr, len);
        xfree(bld);
        
        err = branch_send_bor(msg, bor, (void *)bore - (void *)bor);
        if (err) {
            hvfs_err(xnet, "branch_send_bor(%d) to %lx BE %s "
                     "failed w/ %d\n",
                     bor->nr, msg->tx.ssite_id, branch_name, err);
        }
        xfree(bor);
    } else {
        err = branch_send_bor(msg, NULL, 0);
        if (err) {
            hvfs_err(xnet, "branch_send_bor(0) to %lx BE %s "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, branch_name, err);
        }
    }

    return err;
}

int branch_send_data(struct xnet_msg *msg, void *data, size_t len)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.xc->site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, len, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;
    if (len)
        xnet_msg_add_sdata(rpy, data, len);

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(xnet, "xnet_send() failed\n");
        /* do not retry my self */
    }
    xnet_free_msg(rpy);

    return 0;
}

int __branch_do_search(struct xnet_msg *msg, char *branch_name,
                       char *expr, char *dbname, char *prefix)
{
#ifdef USE_BDB
    struct branch_entry *bre;
    struct atomic_expr *pos, *n;
    struct basic_expr be = {.flag = 0,};
    struct set_entry_aux sea = {.size = 0, .array = NULL,};
    struct bdb *bdb;
    void *array = NULL;
    void *tree = NULL;
    size_t size = 0;
    int err = 0, type = BRANCH_SEARCH_OP_INIT, nr = 0;

    err = __expr_parser(expr, &be);
    if (err) {
        hvfs_err(xnet, "parse exprs failed w/ %d\n", err);
        return err;
    }

    /* find the branch and the bdb pointer */
    bre = branch_lookup_load(branch_name);
    if (IS_ERR(bre)) {
        err = PTR_ERR(bre);
        goto out_put;
    }

    if (!bre->bp) {
        hvfs_err(xnet, "BE %s's BP is not installed properly.\n",
                 branch_name);
        err = -EFAULT;
        goto out_put;
    }

    bdb = bp_find_bdb(bre->bp, dbname, prefix);
    if (!bdb) {
        hvfs_err(xnet, "Can't find the specific(%s-%s) BDB\n",
                 dbname, prefix);
        err = -EINVAL;
        branch_put(bre);
        goto out_put;
    }
    if (!bp_find_bdb_check(bre->bp, dbname, prefix, &be)) {
        hvfs_err(xnet, "Invalid subdatabase to search\n");
        err = -EINVAL;
        branch_put(bre);
        goto out_put;
    }

    list_for_each_entry(pos, &be.exprs, list) {
        nr++;
        if (be.flag == BRANCH_SEARCH_EXPR_POINT) {
            /* note that there are only one type for POINT query */
            type = pos->type;
        }
    }
    
    switch (tolower(expr[0])) {
    case 'p':
        ASSERT(be.flag == BRANCH_SEARCH_EXPR_POINT, xnet);
        if (type == BRANCH_SEARCH_OP_AND) {
            err = bdb_point_and(bdb, &be, &array, &size);
        } else if (type == BRANCH_SEARCH_OP_OR) {
            err = bdb_point_or(bdb, &be, &tree, &sea);
        } else {
            /* this means we only need a simple query */
            err = bdb_point_simple(bdb, &be, &array, &size);
        }
        break;
    case 'r':
        ASSERT(be.flag == BRANCH_SEARCH_EXPR_RANGE, xnet);
        err = bdb_range_andor(bdb, &be, &tree, &sea);
        break;
    default:
        hvfs_err(xnet, "Invalid query type, only support POINT/RANGE!\n");
        err = -EINVAL;
    }

    /* walk in the tree and destroy the tree */
    if (tree) {
        twalk(tree, __set_action_getall);
        array = sea.array;
        size = sea.size;
        tdestroy(tree, __set_free);
    }
    branch_put(bre);

    /* ok, the result is in array */
    if (array) {
        err = branch_send_data(msg, array, size);
        if (err) {
            hvfs_err(xnet, "branch_send_data(%ld) to %lx BE %s "
                     "failed w/ %d\n",
                     size, msg->tx.ssite_id, branch_name, err);
        }
    } else {
        err = branch_send_data(msg, NULL, 0);
        if (err) {
            hvfs_err(xnet, "branch_send_data(0) to %lx BE %s "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, branch_name, err);
        }
    }

out_put:
    list_for_each_entry_safe(pos, n, &be.exprs, list) {
        list_del(&pos->list);
        xfree(pos->attr);
        xfree(pos->value);
        xfree(pos);
    }
    
    return err;
#else
    int err = 0;
    
    hvfs_err(xnet, "Dummy BDB: do search on it\n");
    err = branch_send_data(msg, NULL, 0);
    if (err) {
        hvfs_err(xnet, "branch_send_data(0) to %lx BE %s "
                 "failed w/ %d\n",
                 msg->tx.ssite_id, branch_name, err);
    }

    return err;
#endif
}

int branch_send_ack(struct xnet_msg *msg, char *branch_name, 
                    u64 ack_id)
{
    struct xnet_msg *rpy;
    struct branch_line_ack_header blah = {
        .ack_id = ack_id,
        .name_len = strlen(branch_name),
    };
    int err = 0;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_REQ, XNET_NEED_REPLY, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_cmd(rpy, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_ACK, 0);
    xnet_msg_add_sdata(rpy, &blah, sizeof(blah));
    xnet_msg_add_sdata(rpy, branch_name, blah.name_len);

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(xnet, "xnet_send() ACK '%s' %ld failed w/ %d\n",
                 branch_name, ack_id, err);
        goto out;
    }

    ASSERT(rpy->pair, xnet);
    if (rpy->pair->tx.err) {
        hvfs_err(xnet, "Remote handle ACK failed w/ %d\n", 
                 rpy->pair->tx.err);
    }

out:
    xnet_free_msg(rpy);

    return 0;
}

/* Request BP.mode=0 to adjust its last_ack to ack_id, and reset branch
 * lines's state to BL_NEW (whose line id begin from lid).
 */
int branch_send_adjust(struct xnet_msg *msg, char *branch_name,
                       u64 ack_id, u64 lid)
{
    struct xnet_msg *rpy;
    struct branch_adjust_entry bae = {
        .ack_id = ack_id,
        .lid = lid,
    };
    int err = 0;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.xc->site_id, msg->tx.ssite_id);
    xnet_msg_fill_cmd(rpy, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_ADJUST, 0);
    xnet_msg_add_sdata(rpy, &bae, sizeof(bae));
    xnet_msg_add_sdata(rpy, branch_name, strlen(branch_name));

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(xnet, "xnet_send() ADJUST '%s' (%ld,%ld) failed w/ %d\n",
                 branch_name, ack_id, lid, err);
        goto out;
    }

    ASSERT(rpy->pair, xnet);
    if (rpy->pair->tx.err) {
        hvfs_err(xnet, "Remote handle ACK failed w/ %d\n", 
                 rpy->pair->tx.err);
    }

out:
    xnet_free_msg(rpy);

    return err;
}

/* branch_dispatch_split() works for BP mode or test AMC client to split the
 * message handling with message receiving.
 */
int branch_dispatch_split(void *arg)
{
    struct xnet_msg *msg = (struct xnet_msg *)arg;

    xlock_lock(&bmgr.qlock);
    list_add_tail(&msg->list, &bmgr.qin);
    xlock_unlock(&bmgr.qlock);
    sem_post(&bmgr.qsem);

    return 0;
}

/* branch_dispatch() act on the incomming message
 *
 * ABI:
 * @tx.arg0: branch operations
 */
int branch_dispatch(void *arg)
{
    struct xnet_msg *msg = (struct xnet_msg *)arg;
    int err = 0;

    switch (msg->tx.arg0) {
    case BRANCH_CMD_NOPE:       /* no need to reply */
        break;
    case BRANCH_CMD_PUSH:       /* no need to reply */
    {
        /* oh, this must be the process node */
        struct branch_line_disk *bld;

        if (msg->xm_datacheck) {
            bld = (struct branch_line_disk *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid PUSH request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            goto out;
        }
        
        /* Step 1: call the branch processor to do actions */
        {
            struct branch_entry *be;
            u64 ack_id;
            char __bname[bld->name_len + 1];

            memcpy(__bname, (void *)bld + sizeof(*bld), bld->name_len);
            __bname[bld->name_len] = '\0';
            
            be = branch_lookup_load(__bname);
            if (IS_ERR(be)) {
                err = PTR_ERR(be);
                goto out;
            }
            
            err = bp_handle_push(be->bp, msg, bld);
            if (err == -EADJUST) {
                ack_id = bp_get_ack(be->bp, msg->tx.ssite_id);
                ack_id == 0 ? ack_id = 1 : 0;
                err = branch_send_adjust(msg, __bname, ack_id, bld->bl.id);
                if (err) {
                    hvfs_err(xnet, "Branch send ADJUST (%ld,%ld) "
                             "failed w/ %d\n",
                             ack_id, bld->bl.id, err);
                }
                goto push_exit;
            } else if (err) {
                hvfs_err(xnet, "BP handle push for %s failed w/ %d\n",
                         __bname, err);
            }
            ack_id = bp_get_ack(be->bp, msg->tx.ssite_id);
            err = branch_send_ack(msg, __bname, ack_id);
            if (err) {
                hvfs_err(xnet, "Branch send ACK %ld to %lx failed w/ %d\n",
                         ack_id, msg->tx.ssite_id, err);
            }
        push_exit:        
            branch_put(be);
        }
        break;
    }
    case BRANCH_CMD_BULK_PUSH:  /* no need to reply */
    {
        /* this should be the process node */
        struct branch_line_push_header *blph;

        if (msg->xm_datacheck) {
            blph = (struct branch_line_push_header *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid BULK PUSH request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            goto out;
        }

        /* Step 1: call the branch processor to do actions */
        {
            struct branch_entry *be;
            u64 ack_id;
            struct branch_line_disk *bld;
            char __bname[blph->name_len + 1];

            memcpy(__bname, (void *)blph + sizeof(*blph), blph->name_len);
            __bname[blph->name_len] = '\0';

            be = branch_lookup_load(__bname);
            if (IS_ERR(be)) {
                err = PTR_ERR(be);
                goto out;
            }

            err = bp_handle_bulk_push(be->bp, msg, blph);
            if (err == -EADJUST) {
                ack_id = bp_get_ack(be->bp, msg->tx.ssite_id);
                ack_id == 0 ? ack_id = 1 : 0;
                bld = (struct branch_line_disk *)((void *)blph + 
                                                  sizeof(*blph) +
                                                  blph->name_len);
                err = branch_send_adjust(msg, __bname, ack_id, bld->bl.id);
                if (err) {
                    hvfs_err(xnet, "Branch send ADJUST (%ld,%ld) "
                             "failed w/ %d\n",
                             ack_id, bld->bl.id, err);
                }
                goto bulk_push_exit;
            } else if (err) {
                hvfs_err(xnet, "BP handle bulk push for '%s' failed w/ %d\n",
                         __bname, err);
            }
            ack_id = bp_get_ack(be->bp, msg->tx.ssite_id);
            err = branch_send_ack(msg, __bname, ack_id);
            if (err) {
                hvfs_err(xnet, "Branch send ACK %ld to %lx failed w/ %d\n",
                         ack_id, msg->tx.ssite_id, err);
            }
        bulk_push_exit:        
            branch_put(be);
        }
        break;
    }
    case BRANCH_CMD_ADJUST:     /* need to reply */
    {
        /* adjust branch_entry's last_ack and reset some branch lines' state
         * to BL_NEW to trigger resend */
        struct branch_adjust_entry *bae;

        if (msg->xm_datacheck) {
            bae = (struct branch_adjust_entry *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid ADJUST request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }

        err = __branch_do_adjust(msg, bae);
        if (err) {
            hvfs_err(xnet, "Self do ADJUST <%ld,%ld> failed w/ %d\n",
                     bae->ack_id, bae->lid, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_PULL:
    {
        /* pull command is just a reserved cmd */
        break;
    }
    case BRANCH_CMD_ACK:        /* need to reply */
    {
        struct branch_line_ack_header *blah;

        if (msg->xm_datacheck) {
            blah = (struct branch_line_ack_header *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid ACK request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        
        err = __branch_do_ack(msg, blah);
        if (err) {
            hvfs_err(xnet, "Self do ack <%lx> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_GETBOR:
    {
        /* ABI:
         * tx.arg1: name length
         * xmdata: branch name
         */
        char __bname[msg->tx.arg1 + 1];

        if (!msg->xm_datacheck) {
            hvfs_err(xnet, "Invalid GETBOR request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        
        memcpy(__bname, msg->xm_data, msg->tx.arg1);
        __bname[msg->tx.arg1] = '\0';

        err = __branch_do_getbor(msg, __bname);
        if (err) {
            hvfs_err(xnet, "Self do GETBOR for BE %s failed w/ %d\n",
                     __bname, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_SEARCH:
    {
        /* ABI:
         * tx.arg1: branch_search_expr_tx + branch name + expr length
         * xmdata: branch_search_expr_tx
         */
        struct branch_search_expr_tx *bset;

        if (!msg->xm_datacheck) {
            hvfs_err(xnet, "Invalid SEARCH request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }

        bset = (struct branch_search_expr_tx *)(msg->xm_data);
        {
            char bname[bset->name_len + 1];
            char expr[bset->expr_len + 1];
            char dbname[bset->dbname_len + 1];
            char prefix[bset->prefix_len + 1];

            memcpy(bname, bset->data, bset->name_len);
            bname[bset->name_len] = '\0';
            memcpy(expr, bset->data + bset->name_len, bset->expr_len);
            expr[bset->expr_len] = '\0';
            memcpy(dbname, bset->data + bset->name_len + bset->expr_len,
                   bset->dbname_len);
            dbname[bset->dbname_len] = '\0';
            memcpy(prefix, bset->data + bset->name_len + bset->expr_len +
                   bset->dbname_len, bset->prefix_len);
            prefix[bset->prefix_len] = '\0';

            hvfs_warning(xnet, "We got B(%s)(%s-%s) EXPR(%s)\n", bname, 
                         dbname, prefix, expr);

            err = __branch_do_search(msg, bname, expr, dbname, prefix);
            if (err) {
                hvfs_err(xnet, "Self do SEARCH for BE %s failed w/ %d\n",
                         bname, err);
                __branch_err_reply(msg, err);
            }
            break;
        }
        
        break;
    }
    case BRANCH_CMD_REPLICA:    /* need to reply */
    {
        struct branch_line_disk *bld;

        if (msg->xm_datacheck) {
            bld = (struct branch_line_disk *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid REPLICA request from %lx\n", 
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        
        err = __branch_do_replicate(msg, bld);
        if (err) {
            hvfs_err(xnet, "Self do replicate <%lx,%ld> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, bld->bl.id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_ACK_REPLICA: /* need to reply */
    {
        if (!msg->xm_datacheck) {
            hvfs_err(xnet, "Invalid REPLICA ACK request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        err = __branch_do_ack_replica(msg);
        if (err) {
            hvfs_err(xnet, "Self do ACK REPLICA <%lx> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    default:
        hvfs_err(xnet, "Invalid branch operations %ld from %lx\n",
                 msg->tx.arg0, msg->tx.ssite_id);
        err = -EINVAL;
        __branch_err_reply(msg, err);
    }

    xnet_free_msg(msg);
out:    
    return err;
}

/* branch_scheduler is a standalone thread for branch handling
 */
void *branch_scheduler(void *arg)
{
    sigset_t set;
    struct branch_entry *be;
    struct regular_hash_rw *rh;
    struct hlist_node *pos;
    time_t cur;
    int i, wait, err = 0, push_immediately = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    while (!bmgr.schedt_stop) {
        /* begin timing */
        wait = bmgr.dirty_to;
        cur = time(NULL);

        /* check the branch entries */
        for (i = 0; i < bmgr.hsize; i++) {
            rh = bmgr.bht + i;
            xrwlock_rlock(&rh->lock);
            hlist_for_each_entry(be, pos, &rh->h, hlist) {
                /* for bp.mode=0: we should push the branch lines to BP
                 * node */
                if (cur >= be->update + (push_immediately ? 
                                         push_immediately : bmgr.dirty_to)) {
                    err = __branch_bulk_push(be, 
                                             SELECT_BP_SITE(be->branch_name,
                                                            hmo.site_id));
                    if (err > 0) {
                        wait = 1;
                        push_immediately = 2;
                    } else {
                        push_immediately = 0;
                        if (err < 0) {
                            hvfs_err(xnet, "branch bulk push for %s "
                                     "failed w/ %d\n",
                                     be->branch_name, err);
                        }
                    }
                } else {
                    wait = min(wait, (int)(cur - be->update));
                }
                /* for bp.mode=1: we should do the flush for every 3*dirty_to
                 * seconds */
                if (cur >= be->update + bmgr.dirty_to * 3) {
                    int errstate = BO_FLUSH;

                    if (be->bp && BE_ISDIRTY(be)) {
                        err = be->bp->bo_root.input(be->bp,
                                                    &be->bp->bo_root,
                                                    NULL, -1UL, 0, &errstate);
                        if (errstate == BO_STOP) {
                            /* ignore any errors */
                            if (err) {
                                hvfs_err(xnet, "scheduled flush on BE %s "
                                         "failed w/ %d\n",
                                         be->branch_name, err);
                            }
                        }
                    }
                }
            }
            xrwlock_runlock(&rh->lock);
        }
        /* check if we should do some cleanups */
        branch_cleanup(cur);

        /* finally, wait for several seconds */
        do {
            wait = sleep(wait);
        } while (wait > 0 && !bmgr.schedt_stop);
    }
    
    pthread_exit(NULL);
}

/* branch_processor is a standalone thread for branch request handling
 */
void *branch_processor(void *arg)
{
    sigset_t set;
    struct xnet_msg *pos, *n;
    u64 ssite_id, cmd;
    int err = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    while (!bmgr.processt_stop) {
        err = sem_wait(&bmgr.qsem);
        if (err == EINTR)
            continue;

    retry:
        xlock_lock(&bmgr.qlock);
        list_for_each_entry_safe(pos, n, &bmgr.qin, list) {
            list_del_init(&pos->list);
            xlock_unlock(&bmgr.qlock);
            ssite_id = pos->tx.ssite_id;
            cmd = pos->tx.cmd;
            err = branch_dispatch(pos);
            if (err) {
                hvfs_err(xnet, "Dispatch branch msg from %lx: cmd %lx"
                         " failed w/ %d\n", 
                         ssite_id, cmd, err);
            }
            goto retry;
        }
        xlock_unlock(&bmgr.qlock);
    }
    
    pthread_exit(NULL);
}

/* branch_create()
 *
 * Create a new branch named 'branch_name' with a tag 'tag'. The new branch
 * select one primary server as the merging server. All the published
 * infomation are transfered to the primary server. At the primary server,
 * each item is processed with the predefined operations.
 *
 * The metadata of each branch is saved in the /.branches directory. Each site
 * can issue queries to fetch the metadata. All the streamed-in info are saved
 * to disk file as the first step. And then processed with the pre-defined
 * operations. Thus, the primary server should co-located at a MDSL server.
 */
int branch_create(u64 puuid, u64 uuid, char *branch_name, 
                  char *tag, u8 level, struct branch_ops *ops)
{
    struct hstat hs;
    struct branch_header *bh;
    u64 buuid, bsalt;
    void *offset;
    int dlen, nr, i;
    int err = 0;

    /* All the branches are in the same namespace, thus, you can't create
     * duplicated branches. */

    /* Step 0: arg checking */
    if (!tag || !strlen(tag) || strlen(tag) > 32)
        return -EINVAL;
    
    /* Step 1: check if this branch has already existed. */
relookup:
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err == -ENOENT) {
        void *data;
        
        hvfs_err(xnet, "Stat root branches failed, we make it!\n");
        /* make the dir now */
        err = hvfs_create("/", ".branches", &data, 1);
        if (err) {
            hvfs_err(xnet, "Create root branches failed w/ %d\n", err);
            goto out;
        }
        hvfs_free(data);
        goto relookup;
    } else if (err) {
        hvfs_err(xnet, "Stat roto branches failed w/ %d\n", err);
        goto out;
    }

    /* stat the GDT to find the salt */
    hs.hash = 0;
    err = hvfs_stat_eh(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                 "failed w/ %d\n", err);
        goto out;
    }

    /* Step 2: create the new branch by touch a new file in /.branches. */
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.name = branch_name;
    err = hvfs_create_eh(buuid, bsalt, &hs, 0, NULL);
    if (err) {
        hvfs_err(xnet, "Create branch '%s' failed w/ %s(%d)\n",
                 branch_name, strerror(-err), err);
        goto out;
    }

    /* Step 3: save the branch ops in the new branch file */
    /* calculate the file content length */
    if (!ops || !ops->nr) {
        dlen = 0;
        nr = 0;
    } else {
        dlen = 0;
        for (i = 0; i < ops->nr; i++) {
            dlen += ops->ops[i].len;
        }
        nr = ops->nr;
    }

    /* alloc the content buffer */
    bh = xmalloc(sizeof(*bh) + nr * sizeof(struct branch_op) +
                 dlen);
    if (!bh) {
        hvfs_err(xnet, "alloc the content buffer failed.\n");
        goto out;
    }

    /* Use the puuuid, uuid and tag to track the items flowing in */
    memset(bh, 0, sizeof(*bh));
    bh->puuid = puuid;
    bh->uuid = uuid;
    memcpy(bh->tag, tag, strlen(tag));
    bh->level = level;
    bh->ops.nr = nr;
    bh->id = (hmo.site_id << 44) | atomic64_read(&hmi.mi_bid);

    offset = (void *)bh + sizeof(*bh) + 
        nr * sizeof(struct branch_op);
    for (i = 0; i < nr; i++) {
        bh->ops.ops[i] = ops->ops[i];
        memcpy(offset, ops->ops[i].data, ops->ops[i].len);
        offset += ops->ops[i].len;
    }

    /* calculate which itbid we should stored it in */
    hs.hash = hvfs_hash(hs.puuid, (u64)branch_name, strlen(branch_name),
                        HASH_SEL_EH);
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hs.puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n",
                     PTR_ERR(e));
            err = PTR_ERR(e);
            xfree(bh);
            goto out;
        }
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }

    /* do the write now! */
    err = hvfs_fwrite_eh(&hs, 0, 0, bh, sizeof(*bh) + 
                         nr * sizeof(struct branch_op) + dlen, 
                         &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "write the branch file %s failed w/ %d\n",
                 branch_name, err);
        xfree(bh);
        goto out;
    }

    xfree(bh);
    /* finally, update the metadata */
    {
        struct mdu_update *mu;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mu->valid = MU_COLUMN | MU_SIZE;
        mu->size = hs.mc.c.len;
        mu->column_no = 1;
        hs.mc.cno = 0;

        hs.uuid = 0;
        hs.name = branch_name;
        err = hvfs_update_eh(hs.puuid, hs.psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     branch_name, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    }

out:
    return err;
}

/* branch_adjust_bid() is used to sync the self hmi.mi_bid to acked value. Get
 * the max value :)
 */
int branch_adjust_bid(struct branch_ack_cache_disk *bacd, int nr)
{
    int i;

    for (i = 0; i < nr; i++) {
        if (bacd[i].site_id == hmo.site_id) {
            atomic64_set(&hmi.mi_bid, 
                         max(bacd[i].last_ack,
                             (u64)atomic64_read(&hmi.mi_bid)) + 1);
            break;
        }
    }

    return 0;
}

/* branch_load()
 *
 * Load a branch metadata to current site. This operation is always called on
 * MDSs (and the targe BP). Based on the metadata, the MDSs can determine the
 * final location of the BRANCH (through itbid). While, MDSs can even do the
 * middle data pre-processing either (through branch_ops).
 *
 * Also note that, all the MDSs can NOT modify the branch metadata themselves.
 *
 * Note, the new BH is inserted to the hash table w/ a BE, you have to do one
 * more lookup to find it.
 *
 * Another note, please call branch_lookup_load() to be more efficient!
 */

/* @mode: 0 => non-bp mode; 1 => bp mode (for mdsl);
 */
int branch_load(char *branch_name, char *tag, int mode)
{
    struct hstat hs;
    struct branch_header *bh = NULL;
    struct branch_ack_cache_disk *bacd = NULL;
    struct branch_op_result *result = NULL;
    u64 buuid, bsalt;
    ssize_t rlen;
    int err = 0, nr;

    if (!branch_name)
        return -EINVAL;

    /* Step 1: find the root branch dir */
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "Root branche does not exist, w/ %d\n",
                 err);
        goto out;
    }
    hs.hash = 0;
    err = hvfs_stat_eh(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                 "failed w/ %d\n", err);
        goto out;
    }

    /* Step 2: find the branch now */
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.name = branch_name;
    err = hvfs_stat_eh(buuid, bsalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                 " failed w/ %d\n", branch_name, err);
        goto out;
    }

    /* Step 3: read in the branch data content */
    rlen = hvfs_fread_eh(&hs, 0, (void **)&bh, &hs.mc.c);
    if (rlen < 0) {
        hvfs_err(xnet, "read the branch '%s' c[0] failed w/ %ld\n",
                 branch_name, rlen);
        err = rlen;
        goto out;
    }
    /* fix the data pointer in branch_ops */
    if (bh->ops.nr) {
        void *offset = (void *)bh + sizeof(*bh) + bh->ops.nr *
            sizeof(struct branch_op);
        int i;
        for (i = 0; i < bh->ops.nr; i++) {
            if (bh->ops.ops[i].len)
                bh->ops.ops[i].data = offset;
            else
                bh->ops.ops[i].data = NULL;
            offset += bh->ops.ops[i].len;
            hvfs_err(xnet, "i=%d ID=%d rid=%d lor=%d dl %d data %s\n", 
                     i, bh->ops.ops[i].id,
                     bh->ops.ops[i].rid,
                     bh->ops.ops[i].lor,
                     bh->ops.ops[i].len,
                     (char *)bh->ops.ops[i].data);
        }
    }

    /* Step 3.1 read in the branch cache data */
    {
        memset(&hs, 0, sizeof(hs));
        hs.name = branch_name;
        err = hvfs_stat_eh(buuid, bsalt, 1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on "
                     "branch '%s' failed w/ %d\n", 
                     branch_name, err);
            xfree(bh);
            goto out;
        }
        nr = hs.mc.c.len / sizeof(*bacd);
        if (nr > 0) {
            rlen = hvfs_fread_eh(&hs, 1, (void **)&bacd, &hs.mc.c);
            if (rlen < 0) {
                hvfs_err(xnet, "read the branch '%s' c[1] failed w/ %ld\n",
                         branch_name, rlen);
                xfree(bh);
                err = rlen;
                goto out;
            }
        }
    }

    /* Step 3.2 read in the branch operation result data from this site's
     * result file (if it exists) */
    if (mode == 1) {
        char __fname[256];

        memset(&hs, 0, sizeof(hs));
        snprintf(__fname, 255, ".%s.%lx", branch_name, hmo.site_id);
        hs.name = __fname;
        err = hvfs_stat_eh(buuid, bsalt, 0, &hs);
        if (err == -ENOENT) {
            /* it is ok, just do not do read */
        } else if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on "
                     "branch '%s' failed w/ %d\n", 
                     __fname, err);
            xfree(bh);
            xfree(bacd);
            goto out;
        } else {
            if (hs.mc.c.len > 0) {
                rlen = hvfs_fread_eh(&hs, 0, (void **)&result, &hs.mc.c);
                if (rlen < 0) {
                    hvfs_err(xnet, "read the branch '%s' failed w/ %ld\n",
                             branch_name, rlen);
                    xfree(bh);
                    xfree(bacd);
                    err = rlen;
                    goto out;
                }
            }
        }
    }
    
    /* Step 4: register the loaded-in branch to memory hash table */
    err = __branch_insert(branch_name, bh);
    if (err) {
        hvfs_err(xnet, "add branch to hash table failed w/ %d\n",
                 err);
        xfree(bh);
        xfree(bacd);
        xfree(result);
        goto out;
    }

    if (mode == 1) {
        /* bp mode, we have to load the cache data to root operator */
        struct branch_entry *be;
        struct branch_processor *bp;

        be = __branch_lookup(branch_name);
        if (!be) {
            hvfs_err(xnet, "lookup inserted branch '%s' failed\n",
                     branch_name);
            xfree(bacd);
            xfree(result);
            goto out;
        }

        /* install the bp now */
        bp = bp_alloc_init(be, result);
        if (!bp) {
            hvfs_err(xnet, "alloc branch processor for '%s' failed\n",
                     branch_name);
            branch_put(be);
            xfree(bacd);
            xfree(result);
            goto out;
        }
        
        branch_install_bp(be, bp);
        branch_put(be);
        xfree(result);

        /* call bac_load to init cache */
        err = bac_load(&bp->bo_root, bacd, nr);
        if (err) {
            hvfs_err(xnet, "bac_load() failed w/ %d\n", err);
            xfree(bacd);
            goto out;
        }
    } else {
        /* non bp mode, we should adjust the hmi. */
        err = branch_adjust_bid(bacd, nr);
        if (err) {
            hvfs_err(xnet, "branch_adjust_bid failed w/ %d\n", err);
            xfree(bacd);
            goto out;
        }
        xfree(bacd);
    }

out:
    return err;
}

/* branch_publish() publish one branch line.
 *
 * Note, the caller should alloc the data region and do NOT free it
 *
 * Level will be satisfied with our best effort. Thus, if there is at least
 * one another replica has saved the branch line, we will return success
 * without considering the #N assigned in LEVEL. For example, you can only
 * have 2 replicas even if you have set the fanout factor to 3.
 */
int branch_publish(u64 puuid, u64 uuid, char *branch_name,
                   char *tag, u8 level, void *data, 
                   size_t data_len)
{
    struct branch_line *bl;
    struct branch_entry *be;
    int err = 0;

    bl = xzalloc(sizeof(*bl) + data_len);
    if (!bl) {
        hvfs_err(xnet, "xzalloc() branch_line failed\n");
        return -ENOMEM;
    }

    /* construct the branch_line and add it to the memory hash table */
    bl->life = time(NULL);
    INIT_LIST_HEAD(&bl->list);
    bl->data = (void *)bl + sizeof(*bl);
    memcpy(bl->data, data, data_len);
    bl->data_len = data_len;
    /* get the global unique id */
    bl->id = BRANCH_GET_ID();
    if (tag)
        bl->tag = strdup(tag);

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        xfree(bl);
        err = PTR_ERR(be);
        goto out;
    }
    /* fallback to default level */
    if (!level)
        level = be->bh->level;

    if ((level & BRANCH_LEVEL_MASK) == BRANCH_FAST) {
        /* it is ok to continue */
        ;
    } else {
        u64 dsite;
        int i, nr = 0;
        
        /* oh, we should transfer the branch_line to other sites */
        bl->replica_nr = level & BRANCH_NR_MASK;
        if (!bl->replica_nr) {
            /* adjust to 1 */
            bl->replica_nr = 1;
        }
        BL_SELF_SITE(bl) = hmo.site_id;
        
        for (i = 1; i < bl->replica_nr; i++) {
            /* find a target site to replicate */
            dsite = __branch_get_replica(bl->sites, i);
            if (dsite == -1UL) {
                bl->sites[i] = -1UL;
                continue;
            }
            /* send the branch_line to replicas */
            err = __branch_replicate(be, bl, dsite);
            if (err) {
                hvfs_err(xnet, "Replicate BL %ld to site %lx "
                         "failed w/ %d\n", bl->id, dsite, err);
                bl->sites[i] = -1UL;
            } else
                bl->sites[i] = dsite;
        }
        /* recalculate how many sites we have sent */
        for (i = 0; i < bl->replica_nr; i++) {
            if (bl->sites[i] != -1UL)
                nr++;
        }
        if (nr == 1 && bl->replica_nr > 1) {
            /* this means we degrade to the FAST mode, reject this publishment
             * now. Otherwise, even if we have degraded, we do not reject the
             * publishment, because we can not cancel the already sent BL to
             * other sites. */
            goto out_reject;
        }
    }

    /* Note that, the tid many be a little randomized, so we have to check if
     * we the max tid */
    xlock_lock(&be->lock);
    list_add_tail(&bl->list, &be->primary_lines);
    xlock_unlock(&be->lock);
    BE_UPDATE_TS(be, time(NULL));
    
out_put:
    branch_put(be);

out:
    return err;
out_reject:
    xfree(bl);
    err = -EINVAL;
    goto out_put;
}

int branch_subscribe(u64 puuid, u64 uuid, char *branch_name,
                     char *tag, u8 level, branch_callback_t bc)
{
    int err = 0;

    return err;
}

int branch_getbor(char *branch_name, u64 bpsite, 
                  struct branch_op_result **bor)
{
    struct xnet_msg *msg;
    int err = 0;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_GETBOR, 
                      strlen(branch_name));
    xnet_msg_add_sdata(msg, branch_name, strlen(branch_name));
    
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.site_id, bpsite);
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() GETBOR '%s' failed w/ %d\n",
                 branch_name, err);
        goto out_free;
    }
    ASSERT(msg->pair, xnet);
    ASSERT(msg->pair->tx.len == msg->pair->tx.arg0, xnet);
    if (msg->pair->tx.arg0) {
        *bor = msg->pair->xm_data;
        xnet_clear_auto_free(msg->pair);
    }

out_free:
    xnet_free_msg(msg);
    
    return err;
}

int branch_dumpbor(char *branch_name, u64 bpsite)
{
    struct branch_op_result *bor = NULL;
    struct branch_op_result_entry *bore;
    int err = 0, i;
    
    if (bpsite < HVFS_SITE_N_MASK)
        bpsite += HVFS_BP(0);
    err = branch_getbor(branch_name, bpsite, &bor);
    if (err) {
        hvfs_err(xnet, "branch_getbor() failed w/ %d\n", err);
        return err;
    }
    if (!bor) {
        hvfs_warning(xnet, "Zero length BOR for B'%s'\n", branch_name);
        return 0;
    }
    bore = (void *)bor + sizeof(*bor);
    for (i = 0; i < bor->nr; i++) {
        switch (bore->len) {
        case 1:
        case 2:
        case 4:
            hvfs_warning(xnet, "BO %8d dlen %8d => D(%d) X(%x)\n",
                         bore->id, bore->len,
                         bore->data[0], bore->data[0]);
            break;
        case 8:
            hvfs_warning(xnet, "BO %8d dlen %8d => D(%ld) X(%lx)\n",
                         bore->id, bore->len,
                         *(u64 *)bore->data, *(u64 *)bore->data);
            break;
        case 16:
            if (*(u64 *)(bore->data + sizeof(u64)) > 0) {
                hvfs_warning(xnet, "BO %8d dlen %8d => D(%ld) X(%lx) / "
                             "D(%ld) X(%lx) => AVG(%f)\n",
                             bore->id, bore->len,
                             *(u64 *)bore->data, *(u64 *)bore->data, 
                             *(u64 *)(bore->data + sizeof(u64)), 
                             *(u64 *)(bore->data + sizeof(u64)),
                             *(u64 *)bore->data / 
                             (double)(*(u64 *)(bore->data + sizeof(u64))));
            } else {
                hvfs_warning(xnet, "BO %8d dlen %8d => D(%ld) X(%lx) / "
                             "D(%ld) X(%lx)\n",
                             bore->id, bore->len,
                             *(u64 *)bore->data, *(u64 *)bore->data, 
                             *(u64 *)(bore->data + sizeof(u64)), 
                             *(u64 *)(bore->data + sizeof(u64)));
            }
            break;
        default:
        {
            struct branch_log_disk *bld;
            
            bld = (struct branch_log_disk *)bore->data;
            switch (bld->type) {
            case BRANCH_DISK_LOG:
            {
                /* we guess this is MAX/MIN operator's result */
                struct branch_log_entry_disk *bled;
                int i;
                
                hvfs_warning(xnet, "BO %8d dlen %8d => MAX/MIN Value: %ld "
                             "NR: %d Who:\n",
                             bore->id, bore->len, bld->value, bld->nr);
                bled = bld->bled;
                for (i = 0; i < bld->nr; i++) {
                    char tag[bled->tag_len + 1];
                    char data[bled->data_len + 1];
                    
                    memcpy(tag, bled->data, bled->tag_len);
                    memcpy(data, bled->data + bled->tag_len, bled->data_len);
                    tag[bled->tag_len] = '\0';
                    data[bled->data_len] = '\0';
                    hvfs_warning(xnet, "\t[%lx,%lx,%s,%s]\n", bled->ssite,
                                 bled->timestamp, tag, data);
                    bled = (void *)bled + sizeof(*bled) + bled->tag_len + 
                        bled->data_len;
                }
                break;
            }
            case BRANCH_DISK_KNN:
            {
                union branch_knn_disk *bkd;
                struct branch_knn_linear_disk *bkld;

                bkd = (union branch_knn_disk *)bore->data;
                bkld = (struct branch_knn_linear_disk *)bore->data;
                ASSERT(bkd->type == BRANCH_DISK_KNN, xnet);

                if ((bkld->flag & BKNN_LINEAR) ||
                    (bkld->flag & BKNN_XLINEAR)) {
                    struct branch_knn_linear_entry_disk *bkled;
                    int i;

                    hvfs_warning(xnet, "BO %8d dlen %8d => kNN NR: %d Who:\n",
                                 bore->id, bore->len, bkld->nr);

                    bkled = bkld->bkled;
                    for (i = 0; i < bkld->nr; i++) {
                        char tag[bkled->bled.tag_len + 1];
                        char data[bkled->bled.data_len + 1];
                        
                        memcpy(tag, bkled->bled.data, bkled->bled.tag_len);
                        memcpy(data, bkled->bled.data + bkled->bled.tag_len, 
                               bkled->bled.data_len);
                        tag[bkled->bled.tag_len] = '\0';
                        data[bkled->bled.data_len] = '\0';
                        hvfs_warning(xnet, "\t[%lx,%lx,%s,%s]\n", 
                                     bkled->bled.ssite,
                                     bkled->bled.timestamp, tag, data);
                        bkled = (void *)bkled + sizeof(*bkled) + 
                            bkled->bled.tag_len + 
                            bkled->bled.data_len;
                    }
                } else {
                    hvfs_err(xnet, "Invalid kNN type %x\n", bkd->type);
                }
                break;
            }
            case BRANCH_DISK_GB:
            {
                struct branch_groupby_disk *bgd;
                struct branch_groupby_entry_disk *bged;
                int i, j;

                bgd = (struct branch_groupby_disk *)bore->data;
                ASSERT(bgd->type == BRANCH_DISK_GB, xnet);

                hvfs_warning(xnet, "BO %8d dlen %8d => gb NR: %d\n",
                             bore->id, bore->len, bgd->nr);

                bged = bgd->bged;
                for (i = 0; i < bgd->nr; i++) {
                    char group[bged->len + 1];

                    memcpy(group, bged->group, bged->len);
                    group[bged->len] = '\0';
                    hvfs_warning(xnet, "\t[gp:%s", group);
                    for (j = 0; j < BGB_MAX_OP; j++) {
                        switch (bgd->ops[j]) {
                        case BGB_SUM:
                            hvfs_plain(xnet, "|sum:%ld", bged->values[j]);
                            break;
                        case BGB_MAX:
                            hvfs_plain(xnet, "|max:%ld", bged->values[j]);
                            break;
                        case BGB_MIN:
                            hvfs_plain(xnet, "|min:%ld", bged->values[j]);
                            break;
                        case BGB_AVG:
                            hvfs_plain(xnet, "|avg:%f", 
                                       (double)bged->values[j] / 
                                       bged->lnrs[j]);
                            break;
                        case BGB_COUNT:
                            hvfs_plain(xnet, "|count:%ld", bged->lnrs[j]);
                            break;
                        default:
                            ;
                        }
                    }
                    hvfs_plain(xnet, "]\n");
                    bged = (void *)bged + sizeof(*bged) + bged->len;
                }
                
                break;
            }
            case BRANCH_DISK_INDEXER:
            {
                union branch_indexer_disk *bid;

                bid = (union branch_indexer_disk *)bore->data;
                ASSERT(bid->s.type == BRANCH_DISK_INDEXER, xnet);

                hvfs_warning(xnet, "BO %8d dlen %8d => indexer %s NR %ld\n",
                             bore->id, bore->len, 
                             (bid->s.flag == BIDX_PLAIN ? "PLAIN" : 
                              "BerkeleyDB"), bid->s.nr);
                if (bid->s.flag == BIDX_BDB) {
                    char dbs[bid->bibd.dbs_len + 1];

                    memcpy(dbs, bid->bibd.data, bid->bibd.dbs_len);
                    dbs[bid->bibd.dbs_len] = '\0';
                    hvfs_warning(xnet, "\t{%s}\n", dbs);
                }
                break;
            }
            default:
                hvfs_warning(xnet, "BO %8d dlen %8d => S(%s)\n",
                             bore->id, bore->len,
                             (char *)bore->data);
            }
        }
        }
        bore = (void *)bore + sizeof(*bore) + bore->len;
    }
    xfree(bor);

    return err;
}

/* branch_search() issue a indexer (DB) search on BP site. You should follow
 * the expr rules:
 *
 * 1. Each query expr start with a character in set [p,r] means [point, range]
 * 2. Each query shoud have one valid atomic expr:
 *    A basic atomic expr is 'attr=value'
 * 3. Several operatores are: 'and/or'
 */
int branch_search(char *branch_name, u64 bpsite, char *dbname, char *prefix,
                  char *expr, void **outstr, size_t *outsize)
{
    struct xnet_msg *msg;
    struct branch_search_expr_tx *bset;
    struct basic_expr be = {.flag = BRANCH_SEARCH_EXPR_CHECK,};
    char *out = NULL;
    int err = 0, name_len, expr_len, dbname_len, prefix_len;

    if (bpsite < HVFS_SITE_N_MASK)
        bpsite += HVFS_BP(0);

    /* Step 1: parse and validate the expr  */
    err = __expr_parser(expr, &be);
    if (err) {
        hvfs_err(xnet, "parse exprs failed w/ %d\n", err);
        return err;
    }
    
    /* Step 2: send the request to dest server */
    name_len = strlen(branch_name);
    expr_len = strlen(expr);
    dbname_len = strlen(dbname);
    prefix_len = strlen(prefix);
    bset = xmalloc(sizeof(*bset) + name_len + expr_len + 
                   dbname_len + prefix_len);
    if (!bset) {
        hvfs_err(xnet, "xmalloc() branch_search_expr_tx failed\n");
        err = -ENOMEM;
        goto out_close;
    }
    bset->name_len = name_len;
    bset->expr_len = expr_len;
    bset->dbname_len = dbname_len;
    bset->prefix_len = prefix_len;
    memcpy(bset->data, branch_name, name_len);
    memcpy(bset->data + name_len, expr, expr_len);
    memcpy(bset->data + name_len + expr_len,
           dbname, dbname_len);
    memcpy(bset->data + name_len + expr_len + dbname_len,
           prefix, prefix_len);
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        xfree(bset);
        err = -ENOMEM;
        goto out_close;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_SEARCH,
                      sizeof(*bset) + name_len + expr_len);
    xnet_msg_add_sdata(msg, bset, sizeof(*bset) + name_len + expr_len +
                       dbname_len + prefix_len);

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.site_id, bpsite);
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() SEARCH B'%s'->'%s' failed w/ %d\n",
                 branch_name, expr, err);
        goto out_free;
    }
    ASSERT(msg->pair, xnet);
    ASSERT(msg->pair->tx.len == msg->pair->tx.arg0, xnet);

    /* copy the data out */
    if (msg->pair->tx.err) {
        err = msg->pair->tx.err;
        hvfs_err(xnet, "Search failed w/ %s(%d)\n",
                 strerror(-err), err);
    } else if (msg->pair->tx.len) {
        out = xzalloc(msg->pair->tx.len);
        if (!out) {
            hvfs_err(xnet, "xmalloc() data region failed\n");
            goto out_free;
        }
        memcpy(out, msg->pair->xm_data, msg->pair->tx.len);
        *outstr = out;
        *outsize = msg->pair->tx.len;
    }
    xnet_set_auto_free(msg->pair);

out_free:
    xnet_free_msg(msg);
out_close:
    __expr_close(&be);
    
    return err;
}

/* dump the current set of <file, key_value_list>
 */
void branch_dumpbase(void *data, size_t size, char **outstr)
{
    struct base_dbs *bd, *end;
    char *out;
    
    bd = (struct base_dbs *)data;
    end = (void *)bd + size;
    out = xzalloc(size + 1);
    if (!out) {
        hvfs_err(xnet, "xzalloc() data region failed\n");
        return;
    }
    *outstr = out;
    while (bd < end) {
        memcpy(out, bd->data, bd->tag_len);
        out += bd->tag_len;
        *out++ = '\t';
        memcpy(out, bd->data + bd->tag_len, bd->kvs_len);
        out += bd->kvs_len;
        *out++ = '\n';
        bd = (void *)bd + sizeof(*bd) + bd->tag_len + 
            bd->kvs_len;
    }
}

/* branch_base2fh() translate a base array to file_handle array
 */
int branch_base2fh(void *data, size_t size, struct file_handle **ofh, 
                   int *onr)
{
    struct base_dbs *bd, *end;
    struct file_handle *fh;
    char *regstr = "^([0-9a-fA-F]+):([^:]*):([0-9a-fA-F]+):([0-9a-fA-F]+)";
    regex_t reg;
    regmatch_t pmatch[5];
    char errbuf[100];
    int nr = 0, err = 0;

    bd = (struct base_dbs *)data;
    end = (void *)bd + size;
    while (bd < end) {
        nr++;
        bd = (void *)bd + sizeof(*bd) + bd->tag_len +
            bd->kvs_len;
    }

    if (!nr)
        return 0;

    /* prepare the reg */
    memset(pmatch, 0, sizeof(pmatch));
    err = regcomp(&reg, regstr, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp regstr failed w/ %d\n", err);
        return -EINVAL;
    }

    fh = xzalloc(nr * sizeof(*fh));
    if (!fh) {
        hvfs_err(xnet, "xzalloc() file_handle failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    nr = 0;
    bd = (struct base_dbs *)data;
    while (bd < end) {
        char tag[bd->tag_len + 1];

        memcpy(tag, bd->data, bd->tag_len);
        tag[bd->tag_len] = '\0';
        err = regexec(&reg, tag, 5, pmatch, 0);
        if (err == REG_NOMATCH) {
            hvfs_err(xnet, "regexec '%s' can NOT find a valid file handle\n",
                     tag);
            goto bypass;
        } else if (err) {
            regerror(err, &reg, errbuf, 100);
            hvfs_err(xnet, "regexec '%s' failed w/ %s\n", tag, errbuf);
            goto bypass;
        }
        /* parse the fields */
        fh[nr].puuid = strtoul(tag + pmatch[1].rm_so, NULL, 16);
        {
            int nlen = pmatch[2].rm_eo - pmatch[2].rm_so;
            char name[nlen + 1];

            memcpy(name, tag + pmatch[2].rm_so, nlen);
            name[nlen] = '\0';
            fh[nr].name = strdup(name);
        }
        fh[nr].uuid = strtoul(tag + pmatch[3].rm_so, NULL, 16);
        fh[nr].hash = strtoul(tag + pmatch[4].rm_so, NULL, 16);
        nr++;
    bypass:
        bd = (void *)bd + sizeof(*bd) + bd->tag_len +
            bd->kvs_len;
    }
    *ofh = fh;
    *onr = nr;
    
out_free:
    regfree(&reg);
    
    return err;
}

/* for basic expr string, we expect it look like "[pr]:attr0=xxx [&|]
 * attr1=yyy"
 */
int __expr_parser(char *expr, struct basic_expr *be)
{
    char *reg_header = "^[pr]+[ \t]*(:)";
    char *reg_expr = "[ \t]*([@]*[_a-zA-Z0-9:.]+)[ \t]*([@><=]+)[ \t]*([_a-zA-Z0-9:.]+)[ \t]*";
    char *reg_op = "[ \t]*([^_a-zA-Z @\t]+)";
    char *p = expr, *end;
    regex_t hreg, ereg, oreg;
    regmatch_t pmatch[4];
    struct atomic_expr *ae = NULL;
    char errbuf[100];
    u32 last_type = BRANCH_SEARCH_OP_INIT, op = 0;
    int mode = 0, err = 0, len;

    /* sanity check */
    if (!expr || !be || strlen(expr) == 0)
        return -EINVAL;
    INIT_LIST_HEAD(&be->exprs);

    if (be->flag & BRANCH_SEARCH_EXPR_CHECK) {
        mode = 1;
    }
    memset(pmatch, 0, sizeof(pmatch));
    err = regcomp(&hreg, reg_header, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp header failed w/ %d\n", err);
        return -EINVAL;
    }
    err = regcomp(&ereg, reg_expr, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp expr failed w/ %d\n", err);
        goto out_free_hreg;
    }
    err = regcomp(&oreg, reg_op, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp op failed w/ %d\n", err);
        goto out_free_ereg;
    }
    
    err = regexec(&hreg, expr, 3, pmatch, 0);
    if (err == REG_NOMATCH) {
        hvfs_err(xnet, "regexec '%s' can NOT find a valid header\n",
                 expr);
        err = -EINVAL;
        goto out;
    } else if (err) {
        regerror(err, &hreg, errbuf, 100);
        hvfs_err(xnet, "regexec '%s' failed w/ %s\n", expr, errbuf);
        goto out;
    }

    p += pmatch[1].rm_eo;
    end = expr + strlen(expr);
    
    /* scan the exprs */
    while (p < end) {
        if (!mode) {
            /* need saving */
            ae = xzalloc(sizeof(*ae));
            if (!ae) {
                hvfs_err(xnet, "xzalloc() atomic_expr failed\n");
                goto out_clean;
            }
            INIT_LIST_HEAD(&ae->list);
            ae->type = last_type;
        }
        /* match EXPR */
        memset(pmatch, 0, sizeof(pmatch));
        err = regexec(&ereg, p, 4, pmatch, 0);
        if (err == REG_NOMATCH) {
            hvfs_err(xnet, "regexec '%s' can NOT find a valid expr\n",
                     p);
            goto out_clean;
        } else if (err) {
            regerror(err, &ereg, errbuf, 100);
            hvfs_err(xnet, "regexec '%s' failed w/ %s\n", p, errbuf);
            goto out_clean;
        }
        /* save attr and value we got */
        len = pmatch[1].rm_eo - pmatch[1].rm_so;
        memcpy(errbuf, p + pmatch[1].rm_so, len);
        errbuf[len] = '\0';
        if (!mode)
            ae->attr = strdup(errbuf);
        else
            hvfs_warning(xnet, "Got EXPR: OP %s %s ",
                         BS_I2S(last_type), errbuf);
        len = pmatch[2].rm_eo - pmatch[2].rm_so;
        memcpy(errbuf, p + pmatch[2].rm_so, len);
        errbuf[len] = '\0';
        switch (len) {
        case 1:
            /* one byte operator */
            switch (errbuf[0]) {
            case '>':
                op = AE_GT;
                break;
            case '<':
                op = AE_LT;
                break;
            case '=':
                op = AE_EQ;
                break;
            default:
                hvfs_err(xnet, "Invalid EXPR operation '%s'\n", errbuf);
                goto out_clean;
            }
            break;
        case 2:
            /* two byte operator */
            if (strcmp(errbuf, ">=") == 0) {
                op = AE_GE;
            } else if (strcmp(errbuf, "<=") == 0) {
                op = AE_LE;
            } else if (strcmp(errbuf, "@=") == 0) {
                op = AE_NEQ;
            } else if (strcmp(errbuf, "@>") == 0) {
                op = AE_NGT;
            } else if (strcmp(errbuf, "@<") == 0) {
                op = AE_NLT;
            } else {
                hvfs_err(xnet, "Invalid EXPR operation '%s'\n", errbuf);
                goto out_clean;
            }
            break;
        case 3:
            /* three byte operator */
            if (strcmp(errbuf, "@>=") == 0) {
                op = AE_NGE;
            } else if (strcmp(errbuf, "@<=") == 0) {
                op = AE_NLE;
            } else if (strcmp(errbuf, "@<>") == 0) {
                op = AE_NUE;
            } else {
                hvfs_err(xnet, "Invalid EXPR operation '%s'\n", errbuf);
                goto out_clean;
            }
            break;
        default:
            hvfs_err(xnet, "Invalid EXPR operation '%s'\n", errbuf);
            goto out_clean;
        }
        if (!mode) {
            ae->op = op;
        } else 
            hvfs_plain(xnet, "%s", errbuf);

        len = pmatch[3].rm_eo - pmatch[3].rm_so;
        memcpy(errbuf, p + pmatch[3].rm_so, len);
        errbuf[len] = '\0';
        if (!mode) {
            ae->value = strdup(errbuf);
            list_add_tail(&ae->list, &be->exprs);
        } else
            hvfs_plain(xnet, " %s\n", errbuf);
        
        p += pmatch[3].rm_eo;

        /* match OP */
        if (p >= end) {
            break;
        }
        memset(pmatch, 0, sizeof(pmatch));
        err = regexec(&oreg, p, 3, pmatch, 0);
        if (err == REG_NOMATCH) {
            /* it is ok, we just stop scan any more items */
            err = 0;
            break;
        } else if (err) {
            regerror(err, &oreg, errbuf, 100);
            hvfs_err(xnet, "regexec '%s' failed w/ %s\n", p, errbuf);
            goto out_clean;
        }
        if (pmatch[1].rm_eo - pmatch[1].rm_so > 1) {
            hvfs_err(xnet, "Invalid operator found, larger than 1Byte\n");
            err = -EINVAL;
            goto out_clean;
        }
        switch (*(p + pmatch[1].rm_so)) {
        case '&':
            last_type = BRANCH_SEARCH_OP_AND;
            break;
        case '|':
            last_type = BRANCH_SEARCH_OP_OR;
            break;
        default:
            hvfs_err(xnet, "Invalid operator found '%c'\n", 
                     *(p + pmatch[1].rm_so));
            err = -EINVAL;
            goto out_clean;
        }
        p += pmatch[1].rm_eo;
    }

    switch (tolower(expr[0])) {
    case 'p':
    {
        /* point query */
        be->flag = BRANCH_SEARCH_EXPR_POINT;
        /* for POINT query, we do not support AND and OR mixing
         */
        {
            struct atomic_expr *n;
            int type = BRANCH_SEARCH_OP_INIT;

            list_for_each_entry_safe(ae, n, &be->exprs, list) {
                if (ae->type == BRANCH_SEARCH_OP_INIT) {
                    continue;
                }
                if (type == BRANCH_SEARCH_OP_INIT) {
                    type = ae->type;
                    continue;
                }
                if ((type == BRANCH_SEARCH_OP_AND && 
                     ae->type != BRANCH_SEARCH_OP_AND) ||
                    (type == BRANCH_SEARCH_OP_OR &&
                     ae->type != BRANCH_SEARCH_OP_OR)) {
                    hvfs_err(xnet, "Invalid search operator mixing.\n");
                    hvfs_err(xnet, "For point query, we do NOT support "
                             "AND and OR mixing!\n");
                    err = -EINVAL;
                    goto out_clean;
                }
            }
        }
        break;
    }
    case 'r':
        /* range query */
        be->flag = BRANCH_SEARCH_EXPR_RANGE;
        /* for RANGE query, we support AND and OR mixing. However, there is
         * no leveling at this moment */
        break;
    default:
        hvfs_err(xnet, "Invalid query type, only support POINT/RANGE!\n");
        err = -EINVAL;
        goto out;
    }

out:
    regfree(&oreg);
out_free_ereg:
    regfree(&ereg);
out_free_hreg:
    regfree(&hreg);

    return err;
out_clean:
    {
        struct atomic_expr *n;

        list_for_each_entry_safe(ae, n, &be->exprs, list) {
            list_del(&ae->list);
            xfree(ae->attr);
            xfree(ae->value);
            xfree(ae);
        }
    }
    goto out;
}

void __expr_close(struct basic_expr *be)
{
    struct atomic_expr *pos, *n;

    list_for_each_entry_safe(pos, n, &be->exprs, list) {
        list_del(&pos->list);
        xfree(pos->attr);
        xfree(pos->value);
        xfree(pos);
    }
}
