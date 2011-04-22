/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-21 17:31:14 macan>
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

#include "branch.h"
#include "mdsl.h"

/* Branch Processor is a line processing framework, which feeds the input
 * lines through a list of operators. Operators can be predefined analysis
 * functions, foreign indexers, loggers, or other tools which implemented the
 * callback function.
 */

void __bp_bld_dump(char *str, struct branch_line_disk *bld, u64 site)
{
    char bname[bld->name_len + 1];
    char tag[bld->tag_len + 1];
    
    memcpy(bname, (void *)bld->data, bld->name_len);
    bname[bld->name_len] = '\0';
    memcpy(tag, (void *)bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    
    hvfs_info(xnet, "<%7s> B %s T %s L %ld F %lx: %s\n", 
              str, bname, tag, bld->bl.id, site, 
              (char *)bld->data + bld->name_len + bld->tag_len);
}

int bac_init(struct branch_operator *bo, int hsize)
{
    int err = 0, i;
    
    hsize = (hsize == 0) ? BAC_DEFAULT_SIZE : hsize;
    bo->bac.ht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!bo->bac.ht) {
        hvfs_err(xnet, "BAC (ack cache) hash table allocation "
                 "failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&bo->bac.ht[i].h);
        xlock_init(&bo->bac.ht[i].lock);
    }
    bo->bac.hsize = hsize;
    atomic_set(&bo->bac.asize, 0);
    
out:
    return err;
}

void bac_destroy(struct branch_operator *bo)
{
    xfree(bo->bac.ht);
}

static inline 
u32 __bac_hash(u64 key, struct branch_ack_cache *bac)
{
    return RSHash((char *)(&key), sizeof(u64)) % bac->hsize;
}

int bac_insert(struct branch_ack_cache_entry *bace,
               struct branch_ack_cache *bac)
{
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos;
    int i;
    
    i = __bac_hash(bace->bacd.site_id, bac);
    rh = bac->ht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (bace->bacd.site_id == tpos->bacd.site_id) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&bace->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i) {
        return -EEXIST;
    }
    atomic_inc(&bac->asize);

    return 0;
}

struct branch_ack_cache_entry *bac_remove(u64 site_id,
                                          struct branch_ack_cache *bac)
{
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos, *n;
    int i;

    i = __bac_hash(site_id, bac);
    rh = bac->ht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (site_id == tpos->bacd.site_id) {
            hlist_del(&tpos->hlist);
            atomic_dec(&bac->asize);
            xlock_lock(&rh->lock);
            return tpos;
        }
    }
    xlock_lock(&rh->lock);

    return ERR_PTR(-ENOTEXIST);
}

int bac_update(u64 site_id, u64 ack, struct branch_ack_cache *bac)
{
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos;
    int i, err = 0;

    i = __bac_hash(site_id, bac);
    rh = bac->ht + i;

retry:
    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (site_id == tpos->bacd.site_id) {
            /* FIXME: rewind of ack and id */
            tpos->bacd.last_ack = max(tpos->bacd.last_ack,
                                      ack);
            i = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (!i) {
        struct branch_ack_cache_entry *bace;

        hvfs_warning(xnet, "WARNING: this should not happen: "
                     "update is always after lookup, cache entry "
                     "is missing?\n");

        bace = xzalloc(sizeof(*bace));
        if (!bace) {
            hvfs_err(xnet, "xzalloc() ack cache entry failed\n");
            err = -ENOMEM;
            goto out;
        }
        INIT_HLIST_NODE(&bace->hlist);
        bace->bacd.site_id = site_id;
        bace->bacd.last_ack = ack;
        if (ack != 0)
            hvfs_err(xnet, "create ack entry %ld which "
                     "largger than 0\n",
                     ack);
        err = bac_insert(bace, bac);
        if (err) {
            hvfs_err(xnet, "insert ack cache entry %lx "
                     "failed w/ %d\n",
                     site_id, err);
            xfree(bace);
            goto out;
        }
        goto retry;
    }

out:
    return err;
}

int bac_lookup_create(u64 site_id, u64 ack, u64 id, 
                      struct branch_ack_cache *bac)
{
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos;
    int i, err = 0;

    i = __bac_hash(site_id, bac);
    rh = bac->ht + i;

retry:
    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (site_id == tpos->bacd.site_id) {
            /* follow the ruls noted at 12/4/2010. please refer to the
             * notebook. */
            /* FIXME: rewind of ack and id */
            if (ack == 0) {
                hvfs_warning(xnet, "detect BE restarting, "
                             "reset BE.last_ack to %ld or 1(if zero)\n",
                             tpos->bacd.last_ack);
                err = -EADJUST;
            } else if (ack == tpos->bacd.last_ack) {
                if (id <= tpos->bacd.last_ack) {
                    err = -EIGNORE;
                }
            } else if (ack < tpos->bacd.last_ack) {
                if (id <= tpos->bacd.last_ack) {
                    err = -EADJUST;
                } else {
                    /* FIXME: if there is a ACk recievied by the original
                     * site, the ack handler should resend this branch line
                     * immedidately */
                    err = -EHWAIT;
                }
            } else {
                /* ack > bp.last_ack */
                hvfs_warning(xnet, "detect BP restarting, "
                             "reset BP.last_ack to %ld\n",
                             ack);
                tpos->bacd.last_ack = ack;
            }
            i = 1;
        }
    }
    xlock_unlock(&rh->lock);

    if (!i) {
        /* we should create a new branch ack cache entry */
        struct branch_ack_cache_entry *bace;
        
        bace = xzalloc(sizeof(*bace));
        if (!bace) {
            hvfs_err(xnet, "xzalloc() ack cache entry failed\n");
            err = -ENOMEM;
            goto out;
        }
        INIT_HLIST_NODE(&bace->hlist);
        bace->bacd.site_id = site_id;
        bace->bacd.last_ack = ack;
        if (ack != 0)
            hvfs_warning(xnet, "create ack entry %ld which "
                         "largger than 0\n",
                         ack);
        err = bac_insert(bace, bac);
        if (err) {
            hvfs_err(xnet, "insert ack cache entry %lx "
                     "failed w/ %d\n",
                     site_id, err);
            xfree(bace);
            goto out;
        }
        goto retry;
    }

out:
    return err;
}

/* bac_lookup() return the current ack_id
 */
static inline
u64 bac_lookup(u64 site_id, struct branch_ack_cache *bac)
{
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos;
    u64 ack_id = 0;
    int i;

    i = __bac_hash(site_id, bac);
    rh = bac->ht + i;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (site_id == tpos->bacd.site_id) {
            ack_id = tpos->bacd.last_ack;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    return ack_id;
}

/* bac_load() should be called ONCE at the init phase.
 */
int bac_load(struct branch_operator *bo, 
             struct branch_ack_cache_disk *bacd, int nr)
{
    struct branch_ack_cache_entry *bace;
    int err = 0, i;
    
    /* update the hash table now */
    for (i = 0; i < nr; i++) {
        bace = xzalloc(sizeof(*bace));
        if (!bace) {
            hvfs_err(xnet, "xzalloc() ack cache entry failed\n");
            err = -ENOMEM;
            goto out_clean;
        }
        INIT_HLIST_NODE(&bace->hlist);
        bace->bacd = *(bacd + i);

        /* insert to the hash table */
        err = bac_insert(bace, &bo->bac);
        if (err) {
            hvfs_err(xnet, "insert ack cache entry %lx "
                     "failed w/ %d\n",
                     (bacd + i)->site_id, err);
            xfree(bace);
            goto out_clean;
        }
    }

    return 0;
out_clean:
    for (i--; i >= 0; i--) {
        bace = bac_remove((bacd + i)->site_id, &bo->bac);
        if (IS_ERR(bace)) {
            hvfs_err(xnet, "lookup ack cache entry %lx "
                     "failed w/ %ld\n",
                     (bacd + i)->site_id, PTR_ERR(bace));
        } else 
            xfree(bace);
    }

    return err;
}

/* flush the branch ack cache to a buffer */
int bac_flush(struct branch_ack_cache *bac, void **data, size_t *len)
{
    struct branch_ack_cache_disk *bacd;
    struct regular_hash *rh;
    struct branch_ack_cache_entry *tpos;
    struct hlist_node *pos;
    int i, j;

    /* we are sure that there is no other operation access this cache. all the
     * accesses to this cache is sequential with out ANY race. */
    *len = atomic_read(&bac->asize) * 
        sizeof(struct branch_ack_cache_disk);

    bacd = xmalloc(*len);
    if (!bacd) {
        hvfs_err(xnet, "xmalloc() result buffer for bac failed\n");
        return -ENOMEM;
    }
    
    for (i = 0, j = 0; i < bac->hsize; i++) {
        rh = bac->ht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
            /* copy this entry to the result buffer */
            *(bacd + j) = tpos->bacd;
            j++;
        }
        xlock_unlock(&rh->lock);
    }
    ASSERT(j * sizeof(*bacd) <= *len, xnet);

    *data = bacd;

    return 0;
}

/* branch operator functions
 */
struct branch_operator *bo_alloc(void)
{
    struct branch_operator *bo;

    bo = xzalloc(sizeof(*bo));
    if (!bo) {
        hvfs_err(xnet, "alloc branch operator failed\n");
        return NULL;
    }

    INIT_LIST_HEAD(&bo->list);
    
    return bo;
}

void bo_free(struct branch_operator *bo)
{
    xfree(bo);
}

int bo_init(struct branch_processor *bp, 
            struct branch_operator *bo, 
            struct branch_op_result *bor,
            struct branch_op *bop, char *name,
            struct branch_operator *left,
            struct branch_operator *right)
{
    int err = 0;
    
    /* Step 0: setup the callback functions */
    err = __bo_install_cb(bo, name);
    if (err) {
        hvfs_err(xnet, "BO install '%s' callback functions "
                 "failed w/ %d\n",
                 name, err);
        goto out;
    }

    /* Step 1: preprocessing the branch_op_result by call the open callback
     * function */
    if (bo->open) {
        err = bo->open(bp, bo, bor, bop);
        if (err) {
            hvfs_err(xnet, "callback BO->open() failed w/ %d\n",
                     err);
            goto out;
        }
    }
    
    /* Step 2: init the other fileds in bo */
    bo->left = left;
    bo->right = right;
    /* we do not duplicate the name string */
    bo->name = name;

    /* Step 3: init the ack cache now */
    err = bac_init(bo, 0);
    if (err) {
        hvfs_err(xnet, "init branch ack cache failed w/ %d\n",
                 err);
        goto out;
    }

out:
    return err;
}

void bo_destroy(struct branch_operator *bo)
{
    /* close the left and right subtree */
    if (bo->left)
        bo_destroy(bo->left);
    if (bo->right)
        bo_destroy(bo->right);
    
    if (bo->close) {
        bo->close(bo);
    }
    bac_destroy(bo);
}

int bo_root_flush(struct branch_processor *bp,
                  struct branch_operator *bo, void **oresult,
                  size_t *osize)
{
    struct branch_entry *be;
    void *data;
    size_t len = 0;
    int err = 0;

    /* Step 1: get the branch ack cache content */
    err = bac_flush(&bo->bac, &data, &len);
    if (err) {
        hvfs_err(xnet, "branch ack cache flush failed w/ %d\n",
                 err);
        goto out;
    }

    bp->bor_len = sizeof(struct branch_op_result);
    bp->bor = xzalloc(bp->bor_len);
    if (!bp->bor) {
        hvfs_err(xnet, "xzalloc() BOR header failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    /* Step 2: write to the branch file column 1 */
    be = bp->be;
    {
        struct hstat hs;
        struct mdu_update *mu = NULL;
        u64 buuid, bsalt;

        /* find the root branch dir */
        memset(&hs, 0, sizeof(hs));
        hs.name = ".branches";
        hs.puuid = hmi.root_uuid;
        hs.psalt = hmi.root_salt;

        err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "Root branch does not exist, w/ %d\n",
                     err);
            goto out_free;
        }
        hs.hash = 0;
        err = hvfs_stat_eh(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                     "failed w/ %d\n", err);
            goto out_free;
        }

        /* find the branch now */
        buuid = hs.uuid;
        bsalt = hs.ssalt;
        memset(&hs, 0, sizeof(hs));
        hs.puuid = buuid;
        hs.psalt = bsalt;
        hs.name = be->branch_name;
        err = hvfs_stat_eh(buuid, bsalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                     " failed w/ %d\n",
                     be->branch_name, err);
            goto out_free;
        }

        /* write the ack cache entry to column[1] */
        err = hvfs_fwrite_eh(&hs, 1, 0, data, len, &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "write the branch '%s' c[1] failed w/ %d\n",
                     be->branch_name, err);
            goto out_free;
        }
        /* update the metadata */
        mu = xzalloc(sizeof(*mu));
        if (!mu) {
            hvfs_err(xnet, "alloc mdu_update failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        mu->valid = MU_COLUMN;
        mu->column_no = 1;      /* update column 1, do not update mdu.size */
        hs.mc.cno = 1;          /* make sure we update column[1] */
        
        hs.name = NULL;
        /* access SDT, using the old hs.hash value */
        err = hvfs_update_eh(buuid, bsalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     be->branch_name, err);
            goto out_free2;
        }
    out_free2:
        xfree(mu);
        if (err)
            goto out_free;
    }

    /* Step 2: push the flush request to other operatores */
    {
        int errstate = BO_FLUSH;
        
        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on root's left branch %d "
                             "failed w/ %d\n",
                             bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on root's right branch %d "
                             "failed w/ %d\n",
                             bo->right->id, err);
                }
            }
        }
    }
    BE_UNDIRTY(bp->be);

    /* Step 3: write back the bor result area now */
    if (bp->bor && ((struct branch_op_result *)bp->bor)->nr) {
        struct hstat hs;
        struct mdu_update *mu = NULL;
        u64 buuid, bsalt;
        char __fname[256];

        /* find the root branch dir */
        memset(&hs, 0, sizeof(hs));
        hs.name = ".branches";
        hs.puuid = hmi.root_uuid;
        hs.psalt = hmi.root_salt;

        err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "Root branch does not exist, w/ %d\n",
                     err);
            goto out_free;
        }
        hs.hash = 0;
        err = hvfs_stat_eh(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                     "failed w/ %d\n", err);
            goto out_free;
        }

        /* find the branch now */
        buuid = hs.uuid;
        bsalt = hs.ssalt;
        snprintf(__fname, 255, ".%s.%lx", be->branch_name, hmo.site_id);
    stat_retry:
        memset(&hs, 0, sizeof(hs));
        hs.name = __fname;
        err = hvfs_stat_eh(buuid, bsalt, -1, &hs);
        if (err == -ENOENT) {
            /* we should create it first and retry */
            err = hvfs_create_eh(buuid, bsalt, &hs, 0, NULL);
            if (err) 
                goto stat_retry;
        } else if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                     " failed w/ %d\n",
                     __fname, err);
            goto out_free;
        }

        /* write the BOR region to site file: using hs.hash as the
         * stored_itbid */
        err = hvfs_fwrite_eh(&hs, 0, 0, bp->bor, bp->bor_len, &hs.mc.c);
        if (err) {
            hvfs_err(xnet, "write the branch '%s' c[1] failed w/ %d\n",
                     be->branch_name, err);
            goto out_free;
        }
        /* use hs.uuid to update the metadata */
        mu = xzalloc(sizeof(*mu));
        if (!mu) {
            hvfs_err(xnet, "alloc mdu_update failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        mu->valid = MU_COLUMN | MU_SIZE;
        mu->size = hs.mc.c.len;
        mu->column_no = 1;      /* update column 0, and mdu.size */
        hs.mc.cno = 0;          /* make sure we update column[0] now! */
        
        hs.name = NULL;
        /* access SDT, using the old hs.hash value */
        err = hvfs_update_eh(buuid, bsalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     be->branch_name, err);
            goto out_free3;
        }
    out_free3:
        xfree(mu);
        if (err)
            goto out_free;

        xfree(bp->bor);
        bp->bor = NULL;
        bp->bor_len = 0;
    }
    
out_free:
    xfree(data);
out:
    return err;
}

/* @site: this site should be the original site, not msg->tx.ssite_id!
 */
int bo_root_input(struct branch_processor *bp,
                  struct branch_operator *bo,
                  struct branch_line_disk *bld, 
                  u64 site, u64 ack, int *errstate)
{
    int err = 0, left_stop = 0;
    
    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;
        
        if (err) {
            hvfs_err(xnet, "flush ack cache of operator %s failed"
                     " w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }
    
    /* for root operator, reset the errstate to OK */
    *errstate = 0;

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }
    /* check the ack cache */
    err = bac_lookup_create(site, ack, bld->bl.id, &bo->bac);
    if (err) {
        /* this means we can't deal with this bld */
        *errstate = BO_STOP;
        goto out;
    } else {
        /* we should update the last ACK to current line */
        err = bac_update(site, bld->bl.id, &bo->bac);
        if (err) {
            hvfs_err(xnet, "bac_update(%lx, %ld) failed w/ %d\n",
                     site, ack, err);
        }
    }
    
    /* Step 1: deal with data now, actually do nothing */
    __bp_bld_dump("root", bld, site);

    /* Step 2: push the branch line to other operatores */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "root's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "root's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->left->name, site, site, bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
            left_stop = 1;
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "root's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "root's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    } else if (left_stop) {
        *errstate = BO_STOP;
    }
    
    err = 0;
    
out:
    return err;
}

int bo_root_output(struct branch_processor *bp,
                   struct branch_operator *bo,
                   struct branch_line_disk *bld,
                   struct branch_line_disk **obld,
                   int *len, int *errstate)
{
    int err = 0;
    
    /* Step 1: init the arguments */
    *len = 0;
    *obld = NULL;
    *errstate = 0;

    /* Step 2: push the request to the downstream layer */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

/* output function deal with the input branch line and transform the input
 * to new format. For root operator, do not change the input */

/* filter_open() to load in the metadata for filter rules and output file
 *
 * API: (string in branch_op->data)
 * 1. rule:regular_expression_list
 * 2. output:/path/to/name
 *
 * regular_expression_list: regex1;regex2;regex3;
 *
 * Note that: all the regexes are AND connected! But, at this moment, we just
 * support ONE regex!
 */
int bo_filter_open(struct branch_processor *bp,
                   struct branch_operator *bo,
                   struct branch_op_result *bor,
                   struct branch_op *op)
{
    /* Note that, filter operation do not save anything in the global branch
     * result file (c[2]). All the filtered lines are saved in the dedicated
     * output file specified by user. Thus, for this open function, we must
     * get the metadata from branch_op structure */
    struct bo_filter *bf;
    char *regex = "rule:([^;]*);+output_filename:([^;]*);*";
    char *p, *sp, dup[op->len + 1];
    int err = 0;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data) {
        return -EINVAL;
    }

    bf = xzalloc(sizeof(*bf));
    if (!bf) {
        hvfs_err(xnet, "xzalloc() bo_filter failed\n");
        return -ENOMEM;
    }

    bf->buffer = xzalloc(BO_FILTER_CHUNK);
    if (!bf->buffer) {
        hvfs_err(xnet, "xzalloc() bo_filter buffer failed\n");
        xfree(bf);
        return -ENOMEM;
    }
    bf->size = BO_FILTER_CHUNK;
    
    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    p = dup;
    p = strtok_r(p, "rule:", &sp);
    if (!p) {
        /* no rule means that we will accept all the input lines */
        bf->accept_all = 1;
        regex = "output_filename:([^;]*);*";
    }
    p = strtok_r(p, "output_filename:", &sp);
    if (!p) {
        /* no output file name means we can just ignore this op */
        bf->accept_all = -1;
        regex = NULL;
    }
    
    memcpy(dup, op->data, op->len);

    if (regex) {
        /* parse the regex strings */
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, len;

        pmatch = xzalloc(3 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 3, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_clean;
        }

        for (i = 1; i < 3; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            if (bf->accept_all == 1 && i == 1) {
                bf->filename = strdup(errbuf);
                break;
            } else {
                if (i == 1) {
                    hvfs_err(xnet, "rule=%s\n", errbuf);
                    /* get rule, thus compute the regex_t */
                    err = regcomp(&bf->preg, errbuf, REG_EXTENDED);
                    if (err) {
                        hvfs_err(xnet, "regcomp failed w/ %d\n",
                                 err);
                        goto out_clean;
                    }
                } else {
                    /* output_filename */
                    bf->filename = strdup(errbuf);
                    hvfs_err(xnet, "filename=%s\n", errbuf);
                }
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bf to gdata */
    xlock_init(&bf->lock);
    bo->gdata = bf;
    return 0;
    
out_free:
    xfree(bf);

    return err;
}

int bo_filter_close(struct branch_operator *bo)
{
    struct bo_filter *bf = bo->gdata;
    
    /* fileter close just release all the internal states */
    if (bf->accept_all == 0)
        regfree(&bf->preg);
    if (bf->accept_all != -1)
        xfree(bf->filename);
    if (bf->buffer)
        xfree(bf->buffer);

    xfree(bf);

    return 0;
}

/* Generate the filtered result buffer to flush. Note that we will write the
 * internal buffer to the output file (of course, in append mode).
 */
int bo_filter_flush(struct branch_processor *bp,
                    struct branch_operator *bo, void **oresult,
                    size_t *osize)
{
    struct bo_filter *bf = (struct bo_filter *)bo->gdata;
    struct hstat hs;
    struct mdu mdu;
    u64 buuid, bsalt;
    off_t offset;
    int err = 0;
    char fname[256];

    if (!bf->size || bf->accept_all == -1)
        return 0;

    /* in bp mode, we are sure that we are NOT in MDSL. Thus, we should pay a
     * little patient for api calls*/
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "Root branch does not exist, w/ %d\n",
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

    /* find the output file now */
    sprintf(fname, ".%s.filter.%s", bp->be->branch_name, bf->filename);
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.puuid = buuid;
    hs.psalt = bsalt;
    hs.name = fname;
    err = hvfs_stat_eh(buuid, bsalt, 0, &hs);
    if (err == -ENOENT) {
        /* create the file now */
        hs.uuid = 0;
        err = hvfs_create_eh(buuid, bsalt, &hs, 0, NULL);
        if (err) {
            hvfs_err(xnet, "do internal file create (SDT) on branch '%s'"
                     " failed w/ %d\n",
                     fname, err);
            goto out;
        }
    } else if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                 " failed w/ %d\n",
                 fname, err);
        goto out;
    }
    mdu = hs.mdu;
    
    /* proxy file in append write mode */
    hs.mc.c.offset = -1;
    offset = bf->offset;
    err = hvfs_fwrite_eh(&hs, 0, SCD_PROXY, bf->buffer, offset, 
                         &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "flush filter buffer to %s failed w/ %d\n",
                 fname, err);
        goto out;
    }

    /* well, update the file metadata now */
    {
        struct mdu_update mu;

        memset(&mu, 0, sizeof(mu));
        mu.valid = MU_COLUMN | MU_FLAG_ADD | MU_SIZE;
        mu.flags = HVFS_MDU_IF_PROXY;
        mu.column_no = 1;
        mu.size = offset + mdu.size;
        hs.mc.cno = 0;          /* write to zero column */
        hs.mc.c.len = mu.size;

        hs.name = NULL;
        /* access SDT, using the old hs.hash value */
        err = hvfs_update_eh(buuid, bsalt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     fname, err);
            goto out;
        }
    }

    /* then, it is ok to clean and reset the buffer now */
    xlock_lock(&bf->lock);
    if (bf->offset == offset)
        bf->offset = 0;
    else {
        memmove(bf->buffer, bf->buffer + offset, bf->offset - offset);
        bf->offset -= offset;
    }
    xlock_unlock(&bf->lock);

    /* Step 2: push the flush request to other operatores */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }

out:
    return err;
}

int bo_filter_input(struct branch_processor *bp,
                    struct branch_operator *bo,
                    struct branch_line_disk *bld,
                    u64 site, u64 ack, int *errstate)
{
    struct bo_filter *bf;
    int err = 0, len;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush filter buffer of operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("filter", bld, site);

    bf = (struct bo_filter *)bo->gdata;
    xlock_lock(&bf->lock);
    if (bf->accept_all > 0) {
        /* save the input data to the buffer */
        len = bld->bl.data_len + bld->tag_len + 8 + 3; /* 8B for site id, 2B
                                                        * '\t' and 1B '\n' */
    retry:
        if (bf->offset + len > bf->size) {
            /* need to realloc the buffer now */
            void *p = xrealloc(bf->buffer, 
                               max(len, bf->size + BO_FILTER_CHUNK));
            if (!p) {
                hvfs_err(xnet, "realloc buffer space to %d failed\n",
                         bf->size + BO_FILTER_CHUNK);
                *errstate = BO_STOP;
                xlock_unlock(&bf->lock);
                return -ENOMEM;
            }
            bf->size += BO_FILTER_CHUNK;
            bf->buffer = p;
            goto retry;
        }
        sprintf(bf->buffer + bf->offset, "%08lx\t", bld->bl.sites[0]);
        bf->offset += 9;
        memcpy(bf->buffer + bf->offset, bld->data + bld->name_len, 
               bld->tag_len);
        bf->offset += bld->tag_len;
        *(char *)(bf->buffer + bf->offset) = '\t';
        bf->offset += 1;
        memcpy(bf->buffer + bf->offset, bld->bl.data,
               bld->bl.data_len);
        bf->offset += bld->bl.data_len;
        *(char *)(bf->buffer + bf->offset) = '\n';
        bf->offset += 1;
    } else if (bf->accept_all < 0) {
        /* ignore this operator! do not change the OP */
        ;
    } else {
        char string[bld->bl.data_len + 1];

        memcpy(string, bld->bl.data, bld->bl.data_len);
        string[bld->bl.data_len + 1] = '\0';
        err = regexec(&bf->preg, string, 0, NULL, 0);
        if (!err) {
            /* matched, just log current entry and continue */
            len = bld->bl.data_len + bld->tag_len + 8 + 3; /* 8B for site id,
                                                            * 2B '\t' and 1B
                                                            * '\n' */
        retry_again:
            if (bf->offset + len > bf->size) {
                /* need to realloc the buffer now */
                void *p = xrealloc(bf->buffer, 
                                   max(len, bf->size + BO_FILTER_CHUNK));
                if (!p) {
                    hvfs_err(xnet, "realloc buffer space to %d failed\n",
                             bf->size + BO_FILTER_CHUNK);
                    *errstate = BO_STOP;
                    xlock_unlock(&bf->lock);
                    return -ENOMEM;
                }
                bf->size += BO_FILTER_CHUNK;
                bf->buffer = p;
                goto retry_again;
            }
            sprintf(bf->buffer + bf->offset, "%08lx\t", bld->bl.sites[0]);
            bf->offset += 9;
            memcpy(bf->buffer + bf->offset, bld->data + bld->name_len, 
                   bld->tag_len);
            bf->offset += bld->tag_len;
            *(char *)(bf->buffer + bf->offset) = '\t';
            bf->offset += 1;
            memcpy(bf->buffer + bf->offset, bld->bl.data,
                   bld->bl.data_len);
            bf->offset += bld->bl.data_len;
            *(char *)(bf->buffer + bf->offset) = '\n';
            bf->offset += 1;
        } else if (err == REG_NOMATCH) {
            /* not matched, swallow this entry */
            *errstate = BO_STOP;
            err = 0;
        } else if (err) {
            *errstate = BO_STOP;
            xlock_unlock(&bf->lock);
            return -EHSTOP;
        }
    }
    xlock_unlock(&bf->lock);

    /* Step 2: push the branch line to other operatores */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }

out:
    return err;
}

/* sum_open() to load in the metadata for sum rules
 *
 * API: (string in branch_op->data)
 * 1. rule: <regex> for tag fields
 * 2. lor: left or right or all or match
 *         all means (or); match means (and)
 */
int __sum_open(struct branch_processor *bp,
               struct branch_operator *bo,
               struct branch_op_result *bor,
               struct branch_op *op, int flag)
{
    struct bo_sum *bs;
    char *regex = "rule:([^;]*);+lor:([^;]*);*";
    char dup[op->len + 1];
    int err = 0, i;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data)
        return -EINVAL;

    bs = xzalloc(sizeof(*bs));
    if (!bs) {
        hvfs_err(xnet, "xzalloc() bo_sum failed\n");
        return -ENOMEM;
    }

    bs->flag = flag;

    /* load in the bor value */
    if (bor) {
        struct branch_op_result_entry *bore = bor->bore;
        
        for (i = 0; i < bor->nr; i++) {
            if (bo->id == bore->id) {
                ASSERT(bore->len == sizeof(u64) * 2, xnet);
                bs->value = *(u64 *)bore->data;
                bs->lnr = *(u64 *)(bore->data + sizeof(u64));
                hvfs_warning(xnet, "BO %d sum value load in <%ld/%ld>\n", 
                             bo->id, bs->value, bs->lnr);
                break;
            }
            bore = (void *)bore + sizeof(*bore) + bore->len;
        }
    }

    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    /* parse the regex strings */
    {
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, len;

        pmatch = xzalloc(3 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 3, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_clean;
        }

        for (i = 1; i < 3; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the rule */
                hvfs_err(xnet, "rule=%s\n", errbuf);
                err = regcomp(&bs->preg, errbuf, REG_EXTENDED);
                if (err) {
                    hvfs_err(xnet, "regcomp failed w/ %d\n",
                             err);
                    goto out_clean;
                }
                break;
            case 2:
                /* this is the lor */
                hvfs_err(xnet, "lor=%s\n", errbuf);
                if (strcmp(errbuf, "left") == 0) {
                    bs->lor = BS_LEFT;
                } else if (strcmp(errbuf, "right") == 0) {
                    bs->lor = BS_RIGHT;
                } else if (strcmp(errbuf, "all") == 0) {
                    bs->lor = BS_ALL;
                } else if (strcmp(errbuf, "match") == 0) {
                    bs->lor = BS_MATCH;
                } else {
                    hvfs_err(xnet, "Invalid lor value '%s', "
                             "reset to 'match'\n",
                             errbuf);
                    bs->lor = BS_MATCH;
                }
                break;
            default:
                continue;
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bs to gdata */
    bo->gdata = bs;
    return 0;

out_free:
    xfree(bs);

    return err;
}

int bo_count_open(struct branch_processor *bp,
                  struct branch_operator *bo,
                  struct branch_op_result *bor,
                  struct branch_op *op)
{
    return __sum_open(bp, bo, bor, op, BS_COUNT);
}

int bo_sum_open(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_op_result *bor,
                struct branch_op *op)
{
    return __sum_open(bp, bo, bor, op, BS_SUM);
}

int bo_avg_open(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_op_result *bor,
                struct branch_op *op)
{
    return __sum_open(bp, bo, bor, op, BS_AVG);
}

int bo_sum_close(struct branch_operator *bo)
{
    struct bo_sum *bs = bo->gdata;

    regfree(&bs->preg);
    xfree(bs);

    return 0;
}

/* Generate the BOR region entry to flush. Note that we will realloc the
 * bp->bor region.
 */
int bo_sum_flush(struct branch_processor *bp,
                 struct branch_operator *bo, void **oresult,
                 size_t *osize)
{
    struct bo_sum *bs = (struct bo_sum *)bo->gdata;
    struct branch_op_result_entry *bore;
    void *nbor;
    int len = sizeof(*bore) + (sizeof(u64) << 1), err = 0;

    /* Step 1: self handling */
    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = sizeof(u64) << 1;
    *(u64 *)bore->data = bs->value;
    *(u64 *)(bore->data + sizeof(u64)) = bs->lnr;

    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    /* Step 2: push the flush request to my children */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }

    return err;
}

/* Note that we want to reuse the TAG variable, thus we have to use MACRO
 * instead of function call */
#define __sum_update(bs, tag) do {                      \
        if ((bs)->flag & BS_COUNT)                      \
            (bs)->value++;                              \
        else if ((bs)->flag & BS_SUM) {                 \
            char *p;                                    \
            long value = 0;                             \
            sscanf(tag, "%a[_a-zA-Z].%ld", &p, &value); \
            xfree(p);                                   \
            (bs)->value += value;                       \
        } else if ((bs)->flag & BS_AVG) {               \
            char *p;                                    \
            long value = 0;                             \
            sscanf(tag, "%a[_a-zA-Z].%ld", &p, &value); \
            xfree(p);                                   \
            (bs)->value += value;                       \
            (bs)->lnr++;                                \
        }                                               \
    } while (0)

int bo_sum_input(struct branch_processor *bp,
                 struct branch_operator *bo,
                 struct branch_line_disk *bld,
                 u64 site, u64 ack, int *errstate) 
{
    struct bo_sum *bs;
    char *tag;
    int err = 0, sample = 0, left_stop = 0;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush sum operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("sum", bld, site);

    bs = (struct bo_sum *)bo->gdata;

    /* check if the tag match the rule */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    err = regexec(&bs->preg, tag, 0, NULL, 0);
    if (!err) {
        /* matched, just mark the sample variable */
        sample = 1;
    }

    if (sample && bs->lor == BS_ALL) {
        __sum_update(bs, tag);
    }

    /* push the branch line to other operatores */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
            left_stop = 1;
        } else if (sample) {
            if (bs->lor == BS_LEFT)
                __sum_update(bs, tag);
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        } else if (sample) {
            if (bs->lor == BS_RIGHT)
                __sum_update(bs, tag);
            if (bs->lor == BS_MATCH && !left_stop)
                __sum_update(bs, tag);
        }
    } else if (left_stop) {
        *errstate = BO_STOP;
    }

out:
    return err;
}

/* sum_output() dump the current sum operator's value to the branch_line_disk
 * structure.
 */
int bo_sum_output(struct branch_processor *bp,
                  struct branch_operator *bo,
                  struct branch_line_disk *bld,
                  struct branch_line_disk **obld,
                  int *len, int *errstate)
{
    struct branch_line_disk *nbld, *__tmp;
    int err = 0;

    nbld = xzalloc(sizeof(*nbld) + sizeof(u64) * 2);
    if (!nbld) {
        hvfs_err(xnet, "xzalloc() branch_line_disk failed\n");
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    nbld->bl.id = bo->id;
    nbld->bl.data = nbld->data;
    nbld->bl.data_len = sizeof(u64) << 1;
    *(u64 *)nbld->bl.data = ((struct bo_sum *)bo->gdata)->value;
    *(u64 *)(nbld->bl.data + sizeof(u64)) = ((struct bo_sum *)bo->gdata)->lnr;

    if (!(*len))
        *obld = NULL;
    __tmp = xrealloc(*obld, *len + sizeof(*nbld) + sizeof(u64) * 2);
    if (!__tmp) {
        hvfs_err(xnet, "xrealloc() BLD failed\n");
        xfree(nbld);
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    memcpy((void *)__tmp + *len, nbld, sizeof(*nbld) + sizeof(u64) * 2);
    *len += sizeof(*nbld) + sizeof(u64) * 2;
    *obld = __tmp;
    xfree(nbld);

    /* push the request to my children */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

/* mm_open() to load in the metadata for max/min rules
 *
 * API: (string in branch_op->data)
 * 1. rule: <regex> for tag fields
 * 2. lor: left or right or all or match
 *
 * For TAGs to do MAX/MIN, you should obey the following rules:
 * TAG format:
 *     <id>.<num>
 *
 * we use <regex> to match the tag. If the tag is match, we extract the 
 */
static inline
int __bo_mm_open(struct branch_processor *bp,
                 struct branch_operator *bo,
                 struct branch_op_result *bor,
                 struct branch_op *op, int flag)
{
    struct bo_mm *bm;
    char *regex = "rule:([^;]*);+lor:([^;]*);*";
    char dup[op->len + 1];
    int err = 0, i, j;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data)
        return -EINVAL;

    bm = xzalloc(sizeof(*bm));
    if (!bm) {
        hvfs_err(xnet, "xzalloc() bo_mm failed\n");
        return -ENOMEM;
    }
    bm->flag = flag;

    /* load in the bor value */
    if (bor) {
        struct branch_op_result_entry *bore = bor->bore;
        struct branch_log_disk *bld;
        struct branch_log_entry_disk *bled;
        struct branch_log_entry *ble;

        for (i = 0; i < bor->nr; i++) {
            if (bo->id == bore->id) {
                ASSERT(bore->len >= sizeof(struct branch_log_disk), xnet);
                bld = (struct branch_log_disk *)(bore->data);
                bled = bld->bled;
                /* prepare the ble region */
                bm->bl.ble = xzalloc(bld->nr * 
                                     sizeof(struct branch_log_entry));
                if (!bm->bl.ble) {
                    hvfs_err(xnet, "prepare BLE region failed\n");
                    err = -ENOMEM;
                    goto out_free;
                }
                ble = bm->bl.ble;

                for (j = 0; j < bld->nr; j++) {
                    (ble + j)->ssite = bled->ssite;
                    (ble + j)->timestamp = bled->timestamp;
                    (ble + j)->data_len = bled->data_len;
                    {
                        char __tag[bled->tag_len + 1];
                        
                        memcpy(__tag, bled->data, bled->tag_len);
                        __tag[bled->tag_len] = '\0';
                        (ble + j)->tag = strdup(__tag);
                    }
                    {
                        void *__data = xmalloc(bled->data_len);
                        
                        if (!__data) {
                            err = -ENOMEM;
                            xfree(ble);
                            goto out_free;
                        }
                        memcpy(__data, bled->data + bled->tag_len, 
                               bled->data_len);
                        (ble + j)->data = __data;
                    }
                    bled = (void *)bled + sizeof(*bled) + bled->tag_len + 
                        bled->data_len;
                }
                bm->bl.value = bld->value;
                bm->bl.nr = bld->nr;
                hvfs_warning(xnet, "Load BLD value %ld nr %d\n", 
                             bld->value, bld->nr);
                break;
            }
            bore = (void *)bore + sizeof(*bore) + bore->len;
        }
    }

    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    /* parse the regex strings */
    {
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, len;

        pmatch = xzalloc(3 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 3, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_clean;
        }

        for (i = 1; i < 3; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the rule */
                hvfs_err(xnet, "rule=%s\n", errbuf);
                err = regcomp(&bm->preg, errbuf, REG_EXTENDED);
                if (err) {
                    hvfs_err(xnet, "regcomp failed w/ %d\n",
                             err);
                    goto out_clean;
                }
                break;
            case 2:
                /* this is the lor */
                hvfs_err(xnet, "lor=%s\n", errbuf);
                if (strcmp(errbuf, "left") == 0) {
                    bm->lor = BMM_LEFT;
                } else if (strcmp(errbuf, "right") == 0) {
                    bm->lor = BMM_RIGHT;
                } else if (strcmp(errbuf, "all") == 0) {
                    bm->lor = BMM_ALL;
                } else if (strcmp(errbuf, "match") == 0) {
                    bm->lor = BMM_MATCH;
                } else {
                    hvfs_err(xnet, "Invalid lor value '%s', "
                             "reset to 'match'\n",
                             errbuf);
                    bm->lor = BMM_MATCH;
                }
                break;
            default:
                continue;
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bm to gdata */
    bo->gdata = bm;
    return 0;
    
out_free:
    xfree(bm);

    return err;
}

/* MAX/MIN wrappers for __bo_mm_open()
 */
int bo_max_open(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_op_result *bor,
                struct branch_op *op)
{
    return __bo_mm_open(bp, bo, bor, op, BMM_MAX);
}

int bo_min_open(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_op_result *bor,
                struct branch_op *op)
{
    return __bo_mm_open(bp, bo, bor, op, BMM_MIN);
}

int bo_mm_close(struct branch_operator *bo)
{
    struct bo_mm *bm = bo->gdata;
    int i;

    regfree(&bm->preg);
    for (i = 0; i < bm->bl.nr; i++) {
        xfree((bm->bl.ble + i)->tag);
        xfree((bm->bl.ble + i)->data);
    }
    xfree(bm->bl.ble);
    xfree(bm);

    return 0;
}

/* Generate the BOR region entry to flush. Note that we will realloc the
 * bp->bor region.
 *
 * Inside the region entry, we construct and write a branch_log_disk entry!
 */
int bo_mm_flush(struct branch_processor *bp,
                struct branch_operator *bo, void **oresult,
                size_t *osize)
{
    struct bo_mm *bm = (struct bo_mm *)bo->gdata;
    struct branch_op_result_entry *bore;
    struct branch_log_disk *bld;
    struct branch_log_entry_disk *bled;
    void *nbor;
    int len = sizeof(*bore) + sizeof(*bld), tag_len, err = 0, i;

    /* Step 1: self handling to calculate the region length */
    if (!bm->bl.nr)
        return 0;
    len += bm->bl.nr * sizeof(*bled);
    for (i = 0; i < bm->bl.nr; i++) {
        len += strlen((bm->bl.ble + i)->tag);
        len += (bm->bl.ble + i)->data_len;
    }
    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = len - sizeof(*bore);

    /* construct branch_log_disk and copy it */
    bld = (void *)bore->data;
    bld->type = BRANCH_DISK_LOG;
    bld->nr = bm->bl.nr;
    bld->value = bm->bl.value;
    bled = bld->bled;

    for (i = 0; i < bm->bl.nr; i++) {
        bled->ssite = (bm->bl.ble + i)->ssite;
        bled->timestamp = (bm->bl.ble + i)->timestamp;
        bled->data_len = (bm->bl.ble + i)->data_len;
        tag_len = strlen((bm->bl.ble + i)->tag);
        bled->tag_len = tag_len;

        memcpy(bled->data, (bm->bl.ble + i)->tag, tag_len);
        memcpy(bled->data + tag_len, (bm->bl.ble + i)->data,
               bled->data_len);
        bled = (void *)bled + sizeof(*bled) + tag_len +
            bled->data_len;
    }

    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    /* Step 2: push the flush request to my children */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }

    return err;
}

void __bmm_update(struct bo_mm *bm, struct branch_line_disk *bld)
{
    char *tag, *p = NULL;
    long value = 0;
    /* Action: 0 => replace, 1 => append */
    int action = 0;

    /* Step 1: process the branch line to regexec the tag name and get the
     * value */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    sscanf(tag, "%a[_a-zA-Z].%ld", &p, &value);
    xfree(p);

    switch (bm->flag) {
    case BMM_MAX:
        if (value < bm->bl.value) {
            if (bm->bl.nr > 0)
                return;
        } else if (value == bm->bl.value)
            action = 1;
        break;
    case BMM_MIN:
        if (value > bm->bl.value) {
            if (bm->bl.nr > 0)
                return;
        } else if (value == bm->bl.value)
            action = 1;
        break;
    default:
        hvfs_err(xnet, "bmm invalid operator: %x\n", bm->flag);
        return;
    }

    /* Step 2: update bo_mm if needed */
    if (!action) {
        /* do replace, it is easy */
        struct branch_log_entry *ble;
        int i;
        
        ble = xmalloc(sizeof(struct branch_log_entry));
        if (!ble) {
            hvfs_err(xnet, "xmalloc() branch_log_entry failed\n");
            return;
        }

        ble->ssite = bld->bl.sites[0];
        ble->timestamp = bld->bl.life;
        ble->data_len = bld->bl.data_len;
        ble->tag = strdup(tag);

        ble->data = xmalloc(ble->data_len);
        if (!ble->data) {
            hvfs_err(xnet, "xmalloc() data region %ld failed\n",
                     ble->data_len);
            xfree(ble);
            return;
        }
        memcpy(ble->data, bld->data + bld->name_len + bld->tag_len,
               ble->data_len);

        for (i = 0; i < bm->bl.nr; i++) {
            xfree((bm->bl.ble + i)->tag);
            xfree((bm->bl.ble + i)->data);
        }
        xfree(bm->bl.ble);

        bm->bl.ble = ble;
        bm->bl.nr = 1;
        bm->bl.value = value;
        hvfs_warning(xnet, "MM replace max/min value to %ld\n", value);
    } else {
        /* do append, it is a little complicated */
        struct branch_log_entry *ble;

        ble = xrealloc(bm->bl.ble, (bm->bl.nr + 1) * sizeof(*ble));
        if (!ble) {
            hvfs_err(xnet, "xrealloc() BLE region failed\n");
            return;
        }

        bm->bl.ble = ble;
        (ble + bm->bl.nr)->ssite = bld->bl.sites[0];
        (ble + bm->bl.nr)->timestamp = bld->bl.life;
        (ble + bm->bl.nr)->data_len = bld->bl.data_len;
        (ble + bm->bl.nr)->tag = strdup(tag);

        (ble + bm->bl.nr)->data = xmalloc(bld->bl.data_len);
        if (!(ble + bm->bl.nr)) {
            hvfs_err(xnet, "xmalloc() data region %ld failed\n",
                     bld->bl.data_len);
            return;
        }
        memcpy((ble + bm->bl.nr)->data, bld->data + bld->name_len + 
               bld->tag_len,
               bld->bl.data_len);

        bm->bl.nr++;
        hvfs_warning(xnet, "MM append max/min value to %ld\n", value);
    }

    return;
}

int bo_mm_input(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_line_disk *bld,
                u64 site, u64 ack, int *errstate)
{
    struct bo_mm *bm;
    char *tag;
    int err = 0, sample = 0, left_stop = 0;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush mm operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("mm", bld, site);

    bm = (struct bo_mm *)bo->gdata;

    /* check if the tag match the rule */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    err = regexec(&bm->preg, tag, 0, NULL, 0);
    if (!err) {
        /* matched, just mark the sample variable */
        sample = 1;
    }

    if (sample && bm->lor == BMM_ALL) {
        __bmm_update(bm, bld);
    }

    /* push the branch line to other operatorers */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
            left_stop = 1;
        } else if (sample) {
            if (bm->lor == BMM_LEFT)
                __bmm_update(bm, bld);
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        } else if (sample) {
            if (bm->lor == BMM_RIGHT)
                __bmm_update(bm, bld);
            if (bm->lor == BMM_MATCH && !left_stop)
                __bmm_update(bm, bld);
        }
    } else if (left_stop) {
        *errstate = BO_STOP;
    }

out:
    return err;
}

/* mm_output() dump the current MAX/MIN operator's value to the
 * branch_line_disk structure.
 */
int bo_mm_output(struct branch_processor *bp,
                 struct branch_operator *bo,
                 struct branch_line_disk *bld,
                 struct branch_line_disk **obld,
                 int *len, int *errstate)
{
    /* Note that, we pack the whole mm BLE region to one branch_line, user who
     * want to prase the BLE region should extract the info from it */
    struct branch_line_disk *nbld, *__tmp;
    struct bo_mm *bm = (struct bo_mm *)bo->gdata;
    struct branch_log_disk *blogd;
    struct branch_log_entry_disk *bled;
    int err = 0, nlen = sizeof(struct branch_log_disk), i, tag_len;

    /* calculate the data length */
    nlen += bm->bl.nr * sizeof(*bled);
    for (i = 0; i < bm->bl.nr; i++) {
        nlen += strlen((bm->bl.ble + i)->tag);
        nlen += (bm->bl.ble + i)->data_len;
    }
    
    nbld = xzalloc(sizeof(*nbld) + nlen);
    if (!nbld) {
        hvfs_err(xnet, "xzalloc() branch_line_disk failed\n");
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    nbld->bl.id = bo->id;
    nbld->bl.data = nbld->data;
    nbld->bl.data_len = nlen;

    /* setup the values */
    blogd = (void *)nbld->data;
    blogd->type = BRANCH_DISK_LOG;
    blogd->nr = bm->bl.nr;
    blogd->value = bm->bl.value;
    bled = blogd->bled;
    for (i = 0; i < blogd->nr; i++) {
        bled->ssite = (bm->bl.ble + i)->ssite;
        bled->timestamp = (bm->bl.ble + i)->timestamp;
        bled->data_len = (bm->bl.ble + i)->data_len;
        tag_len = strlen((bm->bl.ble + i)->tag);
        bled->tag_len = tag_len;

        memcpy(bled->data, (bm->bl.ble + i)->tag, tag_len);
        memcpy(bled->data + tag_len, (bm->bl.ble + i)->data, bled->data_len);

        bled = (void *)bled + sizeof(*bled) + tag_len + bled->data_len;
    }

    if (!(*len))
        *obld = NULL;
    __tmp = xrealloc(*obld, *len + sizeof(*nbld) + nlen);
    if (!__tmp) {
        hvfs_err(xnet, "xrealloc() BLD failed\n");
        xfree(nbld);
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    memcpy((void *)__tmp + *len, nbld, sizeof(*nbld) + nlen);
    *len += sizeof(*nbld) + nlen;
    *obld = __tmp;
    xfree(nbld);

    /* push the request to my children */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

static inline
void __knn_loadin(struct branch_operator *bo,
                  struct branch_op_result *bor,
                  struct bo_knn *bk)
{
    struct branch_op_result_entry *bore = bor->bore;
    union branch_knn_disk *bkd;
    struct branch_knn_linear_entry_disk *bkled;
    int i, j;
    

    for (i = 0; i < bor->nr; i++) {
        if (bo->id == bore->id) {
            ASSERT(bore->len >= sizeof(union branch_knn_disk), xnet);
            bkd = (union branch_knn_disk *)(bore->data);
            if ((bkd->bkld.flag & BKNN_LINEAR) ||
                (bkd->bkld.flag & BKNN_XLINEAR)) {
                struct branch_knn_linear_disk *bkld;
                struct branch_knn_linear_entry *nbkle;

                bkld = (struct branch_knn_linear_disk *)bkd;
                if (bkd->bkld.flag & BKNN_LINEAR)
                    bk->flag = BKNN_LINEAR;
                else if (bkd->bkld.flag & BKNN_XLINEAR)
                    bk->flag = BKNN_XLINEAR;
                INIT_LIST_HEAD(&bk->bkn.bkl.ke);
                bk->bkn.bkl.center = bkld->center;
                bk->bkn.bkl.distance = bkld->distance;
                bk->bkn.bkl.direction = bkld->direction;
                bk->bkn.bkl.nr = bkld->nr;

                bkled = bkld->bkled;
                for (j = 0; j < bkld->nr; j++) {
                retry:
                    nbkle = xzalloc(sizeof(struct branch_knn_linear_entry));
                    if (!nbkle) {
                        hvfs_err(xnet, "xzalloc() branch_knn_linear_entry "
                                 "failed\n");
                        goto retry;
                    }
                    INIT_LIST_HEAD(&nbkle->list);
                    nbkle->value = bkled->value;
                    nbkle->ble.ssite = bkled->bled.ssite;
                    nbkle->ble.timestamp = bkled->bled.timestamp;
                    nbkle->ble.data_len = bkled->bled.data_len;
                    {
                        char tag[bkled->bled.tag_len + 1];

                        memcpy(tag, bkled->bled.data, bkled->bled.tag_len);
                        tag[bkled->bled.tag_len] = '\0';
                        nbkle->ble.tag = strdup(tag);
                    }
                    {
                        void *data;

                    xmalloc_retry:
                        data = xmalloc(bkled->bled.data_len);
                        if (!data) {
                            hvfs_err(xnet, "xmalloc() BKLED data region "
                                     "failed\n");
                            goto xmalloc_retry;
                        }
                        memcpy(data, bkled->bled.data + bkled->bled.tag_len,
                               bkled->bled.data_len);
                        nbkle->ble.data = data;
                    }
                    /* add to branch_knn_linear's list */
                    list_add_tail(&nbkle->list, &bk->bkn.bkl.ke);
                    /* adjust pointer now */
                    bkled = (void *)bkled + sizeof(*bkled) + 
                        bkled->bled.tag_len + bkled->bled.data_len;
                }
                hvfs_warning(xnet, "Load kNN center %ld nr %d\n", 
                             bkld->center, bkld->nr);
                break;
            } else {
                hvfs_err(xnet, "Invalid kNN type %x, reject load in\n", 
                         bkd->bkld.flag);
                return;
            }
        }
        bore = (void *)bore + sizeof(*bore) + bore->len;
    }
}

/* knn_open() to load in the metadata for KNN rules
 *
 * API: (string in branch_op->data)
 * 1. rule: <regex> for tag fields
 * 2. lor: left or right or all or match
 * 3. knn: <type:NUM1:+/-NUM2> type is "linear", value NUM1 for the center, 
 *                             NUM2 for the range
 *                             type is "xlinear", value NUM1 for the center,
 *                             NUM2 for # of items
 */
int bo_knn_open(struct branch_processor *bp,
                struct branch_operator *bo,
                struct branch_op_result *bor,
                struct branch_op *op)
{
    struct bo_knn *bk;
    char *regex = "rule:([^;]*);+lor:([^;]*);+"
        "knn:([^:]+):([0-9]+):([\\+\\-]+)([0-9]+);*";
    char dup[op->len + 1];
    int err = 0;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data)
        return -EINVAL;

    bk = xzalloc(sizeof(*bk));
    if (!bk) {
        hvfs_err(xnet, "xzalloc() bo_knn failed\n");
        return -ENOMEM;
    }

    /* load in the bor value */
    if (bor) {
        __knn_loadin(bo, bor, bk);
    }

    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    /* parse the regex strings */
    {
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, j, len;

        pmatch = xzalloc(7 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 7, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec '%s' failed w/ '%s'\n", dup, errbuf);
            err = -EINVAL;
            goto out_clean;
        }

        for (i = 1; i < 7; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the rule */
                hvfs_err(xnet, "rule=%s\n", errbuf);
                err = regcomp(&bk->preg, errbuf, REG_EXTENDED);
                if (err) {
                    hvfs_err(xnet, "regcomp failed w/ %d\n",
                             err);
                    goto out_clean;
                }
                break;
            case 2:
                /* this is the lor */
                hvfs_err(xnet, "lor=%s\n", errbuf);
                if (strcmp(errbuf, "left") == 0) {
                    bk->lor = BKNN_LEFT;
                } else if (strcmp(errbuf, "right") == 0) {
                    bk->lor = BKNN_RIGHT;
                } else if (strcmp(errbuf, "all") == 0) {
                    bk->lor = BKNN_ALL;
                } else if (strcmp(errbuf, "match") == 0) {
                    bk->lor = BKNN_MATCH;
                } else {
                    hvfs_err(xnet, "Invalid lor value '%s', "
                             "reset to 'match'\n",
                             errbuf);
                    bk->lor = BKNN_MATCH;
                }
                break;
            case 3:
                /* this is the TYPE */
                hvfs_err(xnet, "knn=%s:", errbuf);
                if (strcmp(errbuf, "linear") == 0) {
                    bk->flag = BKNN_LINEAR;
                    if (!bk->bkn.bkl.ke.next) {
                        INIT_LIST_HEAD(&bk->bkn.bkl.ke);
                    }
                    xlock_init(&bk->bkn.bkl.klock);
                } else if (strcmp(errbuf, "xlinear") == 0) {
                    bk->flag = BKNN_XLINEAR;
                    if (!bk->bkn.bkl.ke.next) {
                        INIT_LIST_HEAD(&bk->bkn.bkl.ke);
                    }
                    xlock_init(&bk->bkn.bkl.klock);
                } else {
                    hvfs_err(xnet, "Invalid kNN type value '%s', "
                             "reset to 'linear'\n",
                             errbuf);
                    bk->flag = BKNN_LINEAR;
                }
                break;
            case 4:
                /* this is the center value */
                hvfs_plain(xnet, "%s:", errbuf);
                if ((bk->flag & BKNN_LINEAR) ||
                    (bk->flag & BKNN_XLINEAR))
                    bk->bkn.bkl.center = atol(errbuf);
                break;
            case 5:
                /* this is +/-/+- */
                hvfs_plain(xnet, "%s", errbuf);
                if (!(bk->flag & BKNN_LINEAR ||
                      bk->flag & BKNN_XLINEAR)) {
                    hvfs_err(xnet, "+/- must in a (x)linear kNN environment!\n");
                    regfree(&bk->preg);
                    err = -EINVAL;
                    goto out_clean;
                }
                /* Note that, the following code suites for XLINEAR */
                for (j = 0; j < strlen(errbuf); j++) {
                    if (errbuf[j] == '+')
                        bk->bkn.bkl.direction |= BKNN_POSITIVE;
                    else if (errbuf[j] == '-')
                        bk->bkn.bkl.direction |= BKNN_MINUS;
                }
                break;
            case 6:
                /* this is range K */
                hvfs_plain(xnet, "%s\n", errbuf);
                if ((bk->flag & BKNN_LINEAR) ||
                    (bk->flag & BKNN_XLINEAR))
                    bk->bkn.bkl.distance = atol(errbuf);
                break;
            default:
                continue;
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bk to gdata */
    bo->gdata = bk;
    return 0;

out_free:
    xfree(bk);

    return err;
}

int bo_knn_close(struct branch_operator *bo)
{
    struct bo_knn *bk = bo->gdata;
    struct branch_knn_linear_entry *pos, *n;

    regfree(&bk->preg);
    if ((bk->flag & BKNN_LINEAR) ||
        (bk->flag & BKNN_XLINEAR)) {
        if (bk->bkn.bkl.nr || !list_empty(&bk->bkn.bkl.ke)) {
            list_for_each_entry_safe(pos, n, &bk->bkn.bkl.ke, list) {
                list_del(&pos->list);
                xfree(pos->ble.tag);
                xfree(pos->ble.data);
                xfree(pos);
            }
        }
    } else {
        hvfs_err(xnet, "Invalid kNN type %x\n", bk->flag);
    }
    xfree(bk);

    return 0;
}

int __knn_linear_flush(struct branch_processor *bp,
                       struct branch_operator *bo, void **oresult,
                       size_t *osize)
{
    struct bo_knn *bk = (struct bo_knn *)bo->gdata;
    struct branch_op_result_entry *bore;
    struct branch_knn_linear_entry *pos;
    struct branch_knn_linear_entry_disk *bkled;
    struct branch_knn_linear_disk *bkld;
    void *nbor;
    int len = sizeof(*bore) + sizeof(union branch_knn_disk), tag_len;
    int err = 0, i = 0;

    /* Step 1: self handling to calculate the region length */
    if (!bk->bkn.bkl.nr)
        return 0;
    len += bk->bkn.bkl.nr * sizeof(*bkled);
    list_for_each_entry(pos, &bk->bkn.bkl.ke, list) {
        len += strlen(pos->ble.tag);
        len += pos->ble.data_len;
        i++;
    }
    if (i != bk->bkn.bkl.nr) {
        hvfs_err(xnet, "kNN linear entry NR mismatch: %d vs %d(iter)\n",
                 bk->bkn.bkl.nr, i);
        return -EFAULT;
    }

    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = len - sizeof(*bore);

    /* construct branch_knn_linear_disk and copy it */
    bkld = (void *)bore->data;
    bkld->type = BRANCH_DISK_KNN;
    bkld->flag = bk->flag;
    bkld->direction = bk->bkn.bkl.direction;
    bkld->nr = bk->bkn.bkl.nr;
    bkld->center = bk->bkn.bkl.center;
    bkld->distance = bk->bkn.bkl.distance;

    bkled = bkld->bkled;
    list_for_each_entry(pos, &bk->bkn.bkl.ke, list) {
        bkled->value = pos->value;
        bkled->bled.ssite = pos->ble.ssite;
        bkled->bled.timestamp = pos->ble.timestamp;
        bkled->bled.data_len = pos->ble.data_len;
        tag_len = strlen(pos->ble.tag);
        bkled->bled.tag_len = tag_len;

        memcpy(bkled->bled.data, pos->ble.tag, tag_len);
        memcpy(bkled->bled.data + tag_len, pos->ble.data,
               pos->ble.data_len);
        bkled = (void *)bkled + sizeof(*bkled) + tag_len +
            pos->ble.data_len;
    }

    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    /* Step 2: push the flush request to my children */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }
    
    return err;
}

/* Generate the BOR region entry to flush. Note that we will realloc the
 * bp->bor region.
 *
 * Inside the region entry, we construct and write the branch_knn_disk struct!
 */
int bo_knn_flush(struct branch_processor *bp,
                 struct branch_operator *bo, void **oresult,
                 size_t *osize)
{
    struct bo_knn *bk = (struct bo_knn *)bo->gdata;
    int err = -EINVAL;

    if ((bk->flag & BKNN_LINEAR) ||
        (bk->flag & BKNN_XLINEAR)) {
        return __knn_linear_flush(bp, bo, oresult, osize);
    } else {
        hvfs_err(xnet, "Invalid kNN type %x\n", bk->flag);
    }

    return err;
}

void __knn_linear_update(struct bo_knn *bk, struct branch_line_disk *bld)
{
    char *tag, *p = NULL;
    struct branch_knn_linear_entry *bkle;
    long value = 0, low, high;

    /* Step 1: process the branch line to regexec the tag name and get the
     * value */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    sscanf(tag, "%a[_a-zA-Z].%ld", &p, &value);
    xfree(p);

    high = low = bk->bkn.bkl.center;
    if (bk->bkn.bkl.direction & BKNN_POSITIVE) {
        high = bk->bkn.bkl.center + bk->bkn.bkl.distance;
    }
    if (bk->bkn.bkl.direction & BKNN_MINUS) {
        low = bk->bkn.bkl.center - bk->bkn.bkl.distance;
    }

    if (value > high || value < low) {
        return;
    }
    
    /* Step 2: update bo_knn if needed: we add current bld to the linked
     * list */
    bkle = xzalloc(sizeof(*bkle));
    if (!bkle) {
        hvfs_err(xnet, "xzalloc() BKLE failed, this update is lossing\n");
        return;
    }
    INIT_LIST_HEAD(&bkle->list);
    bkle->value = value;
    bkle->ble.ssite = bld->bl.sites[0];
    bkle->ble.timestamp = bld->bl.life;
    bkle->ble.data_len = bld->bl.data_len;
    bkle->ble.tag = strdup(tag);

    bkle->ble.data = xmalloc(bld->bl.data_len);
    if (!bkle->ble.data) {
        hvfs_err(xnet, "xmalloc() data region %ld failed\n",
                 bkle->ble.data_len);
        xfree(bkle);
        return;
    }
    memcpy(bkle->ble.data, bld->data + bld->name_len + bld->tag_len,
           bkle->ble.data_len);

    /* add this bkle to the linked list */
    xlock_lock(&bk->bkn.bkl.klock);
    list_add_tail(&bkle->list, &bk->bkn.bkl.ke);
    xlock_unlock(&bk->bkn.bkl.klock);
    bk->bkn.bkl.nr++;
    hvfs_warning(xnet, "kNN add value %ld which in [%ld,%ld]\n", 
                 value, low, high);

    return;
}

void __knn_xlinear_update(struct bo_knn *bk, struct branch_line_disk *bld)
{
    char *tag, *p = NULL;
    struct branch_knn_linear_entry *bkle, *pos;
    long value = 0, low, high;
    int inserted = 0;

    /* Step 1: process the branch line to regexec the tag name and get the
     * value */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    sscanf(tag, "%a[_a-zA-Z].%ld", &p, &value);
    xfree(p);

    if (!list_empty(&bk->bkn.bkl.ke)) {
        bkle = list_entry(bk->bkn.bkl.ke.next, 
                          struct branch_knn_linear_entry, list);
        high = bkle->value;
        bkle = list_entry(bk->bkn.bkl.ke.prev, 
                          struct branch_knn_linear_entry, list);
        low = bkle->value;
    } else {
        low = high = 0;
    }

    if (value >= bk->bkn.bkl.center)
        value -= bk->bkn.bkl.center;
    else
        value = bk->bkn.bkl.center - value;

    if (bk->bkn.bkl.nr >= bk->bkn.bkl.distance) {
        if (value > high || value < low)
            return;
    }

    /* Step 2: update bo_knn if needed: we add current bld to the linked
     * list */
    bkle = xzalloc(sizeof(*bkle));
    if (!bkle) {
        hvfs_err(xnet, "xzalloc() BKLE failed, this update is lossing\n");
        return;
    }
    INIT_LIST_HEAD(&bkle->list);
    bkle->value = value;
    bkle->ble.ssite = bld->bl.sites[0];
    bkle->ble.timestamp = bld->bl.life;
    bkle->ble.data_len = bld->bl.data_len;
    bkle->ble.tag = strdup(tag);

    bkle->ble.data = xmalloc(bld->bl.data_len);
    if (!bkle->ble.data) {
        hvfs_err(xnet, "xmalloc() data region %ld failed\n",
                 bkle->ble.data_len);
        xfree(bkle);
        return;
    }
    memcpy(bkle->ble.data, bld->data + bld->name_len + bld->tag_len,
           bkle->ble.data_len);

    /* add this bkle to the linked list */
    xlock_lock(&bk->bkn.bkl.klock);
    list_for_each_entry(pos, &bk->bkn.bkl.ke, list) {
        if (pos->value < value) {
            list_add_tail(&bkle->list, &pos->list);
            inserted = 1;
            break;
        }
    }
    if (!inserted) {
        list_add_tail(&bkle->list, &bk->bkn.bkl.ke);
    }
    xlock_unlock(&bk->bkn.bkl.klock);
    
    bk->bkn.bkl.nr++;
    hvfs_warning(xnet, "kNN add value %ld which in [%ld,%ld] xlinear\n", 
                 value, low, high);
    xlock_lock(&bk->bkn.bkl.klock);
    while (bk->bkn.bkl.nr > bk->bkn.bkl.distance) {
        /* we should remove one entry from the list */
        pos = list_entry(bk->bkn.bkl.ke.next,
                         struct branch_knn_linear_entry, list);
        list_del(&pos->list);
        xfree(pos->ble.tag);
        xfree(pos->ble.data);
        xfree(pos);
        bk->bkn.bkl.nr--;
    }
    xlock_unlock(&bk->bkn.bkl.klock);

    return;
}

void __knn_update(struct bo_knn *bk, struct branch_line_disk *bld)
{
    if (bk->flag & BKNN_LINEAR)
        return __knn_linear_update(bk, bld);
    else if (bk->flag & BKNN_XLINEAR)
        return __knn_xlinear_update(bk, bld);
    else {
        hvfs_err(xnet, "kNN invalid type %x\n", bk->flag);
    }
}

int bo_knn_input(struct branch_processor *bp,
                 struct branch_operator *bo,
                 struct branch_line_disk *bld,
                 u64 site, u64 ack, int *errstate)
{
    struct bo_knn *bk;
    char *tag;
    int err = 0, sample = 0, left_stop = 0;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush knn operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("knn", bld, site);

    bk = (struct bo_knn *)bo->gdata;

    /* check if the tag match the rule */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    err = regexec(&bk->preg, tag, 0, NULL, 0);
    if (!err) {
        /* matched, just mark the sample value */
        sample = 1;
    }

    if (sample && bk->lor == BKNN_ALL) {
        __knn_update(bk, bld);
    }

    /* push the branch line to other operatorers */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
            left_stop = 1;
        } else if (sample) {
            if (bk->lor == BKNN_LEFT)
                __knn_update(bk, bld);
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        } else if (sample) {
            if (bk->lor == BKNN_RIGHT)
                __knn_update(bk, bld);
            if (bk->lor == BKNN_MATCH && !left_stop)
                __knn_update(bk, bld);
        }
    } else if (left_stop) {
        *errstate = BO_STOP;
    }

out:
    return err;
}

/* knn_output() dump the current kNN operator's value to the branch_line_disk
 * structure.
 */
int __knn_linear_output(struct branch_processor *bp,
                        struct branch_operator *bo,
                        struct branch_line_disk *bld,
                        struct branch_line_disk **obld,
                        int *len, int *errstate)
{
    /* Note that, we pack the whole knn-linear region to one branch_line, user
     * who want to parse the knn region should extract the info from it */
    struct branch_line_disk *nbld, *__tmp;
    struct bo_knn *bk = (struct bo_knn *)bo->gdata;
    struct branch_knn_linear_disk *bkld;
    struct branch_knn_linear_entry_disk *bkled;
    struct branch_knn_linear_entry *pos;
    int err = 0, nlen = sizeof(*bkld), tag_len;

    /* calculate the data length */
    nlen += bk->bkn.bkl.nr * sizeof(*bkled);
    xlock_lock(&bk->bkn.bkl.klock);
    list_for_each_entry(pos, &bk->bkn.bkl.ke, list) {
        nlen += strlen(pos->ble.tag);
        nlen += pos->ble.data_len;
    }
    xlock_unlock(&bk->bkn.bkl.klock);

    nbld = xzalloc(sizeof(*nbld) + nlen);
    if (!nbld) {
        hvfs_err(xnet, "xzalloc() branch_line_disk failed\n");
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    nbld->bl.id = bo->id;
    nbld->bl.data = nbld->data;
    nbld->bl.data_len = nlen;

    /* setup the values */
    bkld = (void *)nbld->data;
    bkld->type = BRANCH_DISK_KNN;
    bkld->direction = bk->bkn.bkl.direction;
    bkld->flag = bk->flag;
    bkld->nr = bk->bkn.bkl.nr;
    bkld->center = bk->bkn.bkl.center;
    bkld->distance = bk->bkn.bkl.distance;

    bkled = bkld->bkled;
    xlock_lock(&bk->bkn.bkl.klock);
    list_for_each_entry(pos, &bk->bkn.bkl.ke, list) {
        bkled->bled.ssite = pos->ble.ssite;
        bkled->bled.timestamp = pos->ble.timestamp;
        bkled->bled.data_len = pos->ble.data_len;
        tag_len = strlen(pos->ble.tag);
        bkled->bled.tag_len = tag_len;

        memcpy(bkled->bled.data, pos->ble.tag, tag_len);
        memcpy(bkled->bled.data + tag_len, pos->ble.data,
               bkled->bled.data_len);

        bkled = (void *)bkled + sizeof(*bkled) + tag_len +
            pos->ble.data_len;
    }
    xlock_unlock(&bk->bkn.bkl.klock);

    if (!(*len))
        *obld = NULL;
    __tmp = xrealloc(*obld, *len + sizeof(*nbld) + nlen);
    if (!__tmp) {
        hvfs_err(xnet, "xrealloc() BLD failed\n");
        xfree(nbld);
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    memcpy((void *)__tmp + *len, nbld, sizeof(*nbld) + nlen);
    *len += sizeof(*nbld) + nlen;
    *obld = __tmp;
    xfree(nbld);

    /* push the request to my children */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

int bo_knn_output(struct branch_processor *bp,
                  struct branch_operator *bo,
                  struct branch_line_disk *bld,
                  struct branch_line_disk **obld,
                  int *len, int *errstate)
{
    struct bo_knn *bk = (struct bo_knn *)bo->gdata;
    int err = -EINVAL;

    if ((bk->flag & BKNN_LINEAR) ||
        (bk->flag & BKNN_XLINEAR)) {
        return __knn_linear_output(bp, bo, bld, obld, len, errstate);
    } else {
        hvfs_err(xnet, "kNN invalid type %x\n", bk->flag);
        *errstate = BO_STOP;
    }

    return err;
}

static inline
void __groupby_loadin(struct branch_operator *bo,
                      struct branch_op_result *bor,
                      struct bo_groupby *bg)
{
    struct branch_op_result_entry *bore = bor->bore;
    struct branch_groupby_disk *bgd;
    struct branch_groupby_entry_disk *bged;
    struct branch_groupby_entry *bge;
    int i, j, k;

    for (i = 0; i < bor->nr; i++) {
        if (bo->id == bore->id) {
            ASSERT(bore->len >= sizeof(*bgd), xnet);
            bgd = (struct branch_groupby_disk *)(bore->data);
            for (k = 0; k < BGB_MAX_OP; k++) {
                bg->bgb.ops[k] = bgd->ops[k];
            }

            bged = bgd->bged;
            for (j = 0; j < bgd->nr; j++) {
            retry:
                bge = xzalloc(sizeof(*bge));
                if (!bge) {
                    hvfs_err(xnet, "xzalloc() branch_groupby_entry "
                             "failed\n");
                    goto retry;
                }
                INIT_HLIST_NODE(&bge->hlist);
                for (k = 0; k < BGB_MAX_OP; k++) {
                    bge->values[k] = bged->values[k];
                    bge->lnrs[k] = bged->lnrs[k];
                }
                {
                    char group[bged->len + 1];

                    memcpy(group, bged->group, bged->len);
                    group[bged->len] = '\0';
                    bge->group = strdup(group);
                }
                /* add to branch_groupby's list */
                BGB_HT_ADD(bge, bg);
                /* adjust the pointer now */
                bged = (void *)bged + sizeof(*bged) +
                    bged->len;
            }
            if (bg->bgb.nr != bgd->nr) {
                /* the former is calculated, while the latter is saved */
                hvfs_warning(xnet, "Internal error on saved groups (%d), "
                             "reset nr to %d\n",
                             bgd->nr, bg->bgb.nr);
            } else {
                hvfs_warning(xnet, "Load in %d groups from disk\n", bgd->nr);
            }
            break;
        }
        bore = (void *)bore + sizeof(*bore) + bore->len;
    }
}

/* groupby_open() to load in the metadata for groupby rules
 *
 * API: (string in branch_op->data)
 * 1. rule: <regex> for tag fields
 * 2. lor: left or right or all or match
 * 3. groupby: <aggr_operator> => sum/avg/max/min/count
 */
int bo_groupby_open(struct branch_processor *bp,
                    struct branch_operator *bo,
                    struct branch_op_result *bor,
                    struct branch_op *op)
{
    struct bo_groupby *bg;
    char *regex = "rule:([^;]*);+lor:([^;]*);+groupby:([^;]*);*";
    char dup[op->len + 1];
    int err = 0, i;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data)
        return -EINVAL;

    bg = xzalloc(sizeof(*bg));
    if (!bg) {
        hvfs_err(xnet, "xzalloc() bo_groupby failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < BGB_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&bg->bgb.ht[i].h);
        xlock_init(&bg->bgb.ht[i].lock);
    }

    /* load in the bor value */
    if (bor) {
        __groupby_loadin(bo, bor, bg);
    }

    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    /* parse the regex strings */
    {
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, len;

        pmatch = xzalloc(4 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 4, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_clean;
        }

        for (i = 1; i < 4; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the rule */
                hvfs_err(xnet, "rule=%s\n", errbuf);
                err = regcomp(&bg->preg, errbuf, REG_EXTENDED);
                if (err) {
                    hvfs_err(xnet, "regcomp failed w/ %d\n",
                             err);
                    goto out_clean;
                }
                break;
            case 2:
                /* this is the lor */
                hvfs_err(xnet, "lor=%s\n", errbuf);
                if (strcmp(errbuf, "left") == 0) {
                    bg->lor = BGB_LEFT;
                } else if (strcmp(errbuf, "right") == 0) {
                    bg->lor = BGB_RIGHT;
                } else if (strcmp(errbuf, "all") == 0) {
                    bg->lor = BGB_ALL;
                } else if (strcmp(errbuf, "match") == 0) {
                    bg->lor = BGB_MATCH;
                } else {
                    hvfs_err(xnet, "Invalid lor value '%s', "
                             "reset to 'match'\n",
                             errbuf);
                    bg->lor = BGB_MATCH;
                }
                break;
            case 3:
            {
                /* this is the groupby operators, at most BGB_MAX_OP! */
                char *p = errbuf, *s;
                int j = 0;
                
                hvfs_err(xnet, "groupby=%s\n", errbuf);
                do {
                    p = strtok_r(p, "/-", &s);
                    if (!p)
                        break;
                    hvfs_err(xnet, "OP:%s\n", p);
                    if (strcmp(p, "sum") == 0) {
                        bg->bgb.ops[j++] = BGB_SUM;
                    } else if (strcmp(p, "avg") == 0) {
                        bg->bgb.ops[j++] = BGB_AVG;
                    } else if (strcmp(p, "max") == 0) {
                        bg->bgb.ops[j++] = BGB_MAX;
                    } else if (strcmp(p, "min") == 0) {
                        bg->bgb.ops[j++] = BGB_MIN;
                    } else if (strcmp(p, "count") == 0) {
                        bg->bgb.ops[j++] = BGB_COUNT;
                    } else {
                        hvfs_err(xnet, "Invalid AGGR operator '%s'\n", p);
                        p = NULL;
                        continue;
                    }
                    p = NULL;
                } while (j < BGB_MAX_OP);
                break;
            }
            default:
                continue;
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bs to gdata */
    bo->gdata = bg;
    return 0;

out_free:
    xfree(bg);

    return err;
}

int bo_groupby_close(struct branch_operator *bo)
{
    struct bo_groupby *bg = bo->gdata;

    regfree(&bg->preg);
    if (bg->bgb.nr) {
        BGB_HT_CLEANUP(bg);
    }
    xfree(bg);

    return 0;
}

/* Generate the BOR region entry to flush. Note that we will realloc the
 * bp->bor region.
 *
 * Inside the region entry, we construct and write the branch_groupby struct!
 */
int bo_groupby_flush(struct branch_processor *bp,
                     struct branch_operator *bo, void **oresult,
                     size_t *osize)
{
    struct bo_groupby *bg = (struct bo_groupby *)bo->gdata;
    struct branch_op_result_entry *bore;
    struct branch_groupby_entry_disk *bged;
    struct branch_groupby_disk *bgd;
    void *nbor;
    int len = sizeof(*bore) + sizeof(*bgd);
    int err = 0, i = 0, j;

    /* Step 1: self handling to calculate the region length */
    if (!bg->bgb.nr)
        return 0;
    len += bg->bgb.nr * sizeof(*bged);
    BGB_HT_LEN(bg, len, i);

    if (i != bg->bgb.nr) {
        hvfs_err(xnet, "Groupby entry NR mismatch: %d vs %d(iter)\n",
                 bg->bgb.nr, i);
        return -EFAULT;
    }

    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = len - sizeof(*bore);

    /* construct branch_groupby_disk and copy it */
    bgd = (void *)bore->data;
    bgd->type = BRANCH_DISK_GB;
    bgd->nr = bg->bgb.nr;
    for (j = 0; j < BGB_MAX_OP; j++)
        bgd->ops[j] = bg->bgb.ops[j];

    bged = bgd->bged;
    BGB_HT_SAVE(bg, bged);
    
    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    /* Step 2: push the flush request to my children */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }
    
    return err;
}

void __groupby_update(struct bo_groupby *bg, struct branch_line_disk *bld)
{
    char *tag, *group = NULL;
    struct branch_groupby_entry *bge = NULL;
    long value = 0;
    int isnew = 0, i;

    /* Step 1: process the branch line to regexec the tag name and get the
     * value */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    sscanf(tag, "%a[_a-zA-Z].%ld", &group, &value);

retest:
    if (BGB_HT_TEST(group, bg, bge)) {
        /* this means the group does exist; bge has been installed */
    } else {
        /* this means the group doesn't exist */
        bge = xzalloc(sizeof(*bge));
        if (!bge) {
            hvfs_err(xnet, "xzalloc() BGE failed, ignore this line\n");
            goto out;
        }
        INIT_HLIST_NODE(&bge->hlist);
        bge->group = group;
        isnew = 1;
    }

    /* ok, we update the BGE */
    for (i = 0; i < BGB_MAX_OP; i++) {
        switch (bg->bgb.ops[i]) {
        case BGB_NONE:
            break;
        case BGB_SUM:
            bge->values[i] += value;
            break;
        case BGB_AVG:
            bge->values[i] += value;
            bge->lnrs[i]++;
            break;
        case BGB_MAX:
            if (bge->values[i] < value || !bge->lnrs[i])
                bge->values[i] = value;
            bge->lnrs[i]++;
            break;
        case BGB_MIN:
            if (bge->values[i] > value || !bge->lnrs[i])
                bge->values[i] = value;
            bge->lnrs[i]++;
            break;
        case BGB_COUNT:
            bge->lnrs[i]++;
            break;
        default:
            hvfs_err(xnet, "Invalid groupby OP %d\n", bg->bgb.ops[i]);
        }
    }

    if (isnew) {
        if (BGB_HT_ADD(bge, bg)) {
            /* already exists? */
            xfree(bge);
            goto retest;
        }
    }

    return;
out:
    xfree(group);
}

int bo_groupby_input(struct branch_processor *bp,
                     struct branch_operator *bo,
                     struct branch_line_disk *bld,
                     u64 site, u64 ack, int *errstate)
{
    struct bo_groupby *bg;
    char *tag;
    int err = 0, sample = 0, left_stop = 0;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush groupby operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("groupby", bld, site);

    bg = (struct bo_groupby *)bo->gdata;

    /* check if the tag match the rule */
    tag = alloca(bld->tag_len + 1);
    memcpy(tag, bld->data + bld->name_len, bld->tag_len);
    tag[bld->tag_len] = '\0';
    err = regexec(&bg->preg, tag, 0, NULL, 0);
    if (!err) {
        /* matched, just mark the sample value */
        sample = 1;
    }

    if (sample && bg->lor == BGB_ALL) {
        __groupby_update(bg, bld);
    }
    /* push the branch line to other operatorers */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
            left_stop = 1;
        } else if (sample) {
            if (bg->lor == BGB_LEFT)
                __groupby_update(bg, bld);
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        } else if (sample) {
            if (bg->lor == BGB_RIGHT)
                __groupby_update(bg, bld);
            if (bg->lor == BGB_MATCH && !left_stop)
                __groupby_update(bg, bld);
        }
    } else if (left_stop) {
        *errstate = BO_STOP;
    }

out:
    return err;
}

/* groupby_output() dump the current groupby operator's value to the
 * branch_line_disk structure.
 */
int bo_groupby_output(struct branch_processor *bp,
                      struct branch_operator *bo,
                      struct branch_line_disk *bld,
                      struct branch_line_disk **obld,
                      int *len, int *errstate)
{
    /* Note that, we pack the whole groupby region to one branch line, user
     * who want to parse the groupby region should extract the info from it */
    struct branch_line_disk *nbld, *__tmp;
    struct bo_groupby *bg = (struct bo_groupby *)bo->gdata;
    struct branch_groupby_disk *bgd;
    struct branch_groupby_entry_disk *bged;
    int err = 0, nlen = sizeof(*bgd), i = 0;

    /* calculate the data length */
    nlen += bg->bgb.nr * sizeof(*bged);
    BGB_HT_LEN(bg, nlen, i);
    if (i != bg->bgb.nr) {
        hvfs_err(xnet, "groupby's internal state mismatch: "
                 "NR %d vs %d(cal)\n",
                 bg->bgb.nr, i);
        return -EFAULT;
    }

    nbld = xzalloc(sizeof(*nbld) + nlen);
    if (!nbld) {
        hvfs_err(xnet, "xzalloc() branch_line_disk failed\n");
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    nbld->bl.id = bo->id;
    nbld->bl.data = nbld->data;
    nbld->bl.data_len = nlen;

    /* setup the values */
    bgd = (void *)nbld->data;
    bgd->type = BRANCH_DISK_GB;
    bgd->nr = bg->bgb.nr;
    for (i = 0; i < BGB_MAX_OP; i++) {
        bgd->ops[i] = bg->bgb.ops[i];
    }

    bged = bgd->bged;
    BGB_HT_SAVE(bg, bged);

    if (!(*len))
        *obld = NULL;
    __tmp = xrealloc(*obld, *len + sizeof(*nbld) + nlen);
    if (!__tmp) {
        hvfs_err(xnet, "xrealloc() BLD failed\n");
        xfree(nbld);
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    memcpy((void *)__tmp + *len, nbld, sizeof(*nbld) + nlen);
    *len += sizeof(*nbld) + nlen;
    *obld = __tmp;
    xfree(nbld);

    /* push the request to my children */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

struct bdb *bp_find_bdb(struct branch_processor *bp,
                        char *dbname, char *prefix)
{
    struct branch_operator *pos;
    struct bo_indexer *bi;

    list_for_each_entry(pos, &bp->oplist, list) {
        if (strcmp(pos->name, "indexer") == 0) {
            bi = (struct bo_indexer *)(pos->gdata);

            if (bi->flag == BIDX_BDB) {
                if ((strcmp(bi->bi.bdb.dbname, dbname) == 0) &&
                    (strcmp(bi->bi.bdb.prefix, prefix) == 0)) {
                    return bi->bi.bdb.__bdb;
                }
            }
        }
    }

    return NULL;
}

/* Return Value: 0: failed; 1: passed
 */
int bp_find_bdb_check(struct branch_processor *bp,
                      char *dbname, char *prefix, 
                      struct basic_expr *be)
{
    struct atomic_expr *ae;
    struct branch_operator *pos;
    struct bo_indexer *bi;

    list_for_each_entry(pos, &bp->oplist, list) {
        if (strcmp(pos->name, "indexer") == 0) {
            bi = (struct bo_indexer *)(pos->gdata);
            
            if (bi->flag == BIDX_BDB) {
                if ((strcmp(bi->bi.bdb.dbname, dbname) == 0) &&
                    (strcmp(bi->bi.bdb.prefix, prefix) == 0)) {
                    /* check if the DB exists */
                    char *m;
                    
                    list_for_each_entry(ae, &be->exprs, list) {
                        m = strstr(bi->bi.bdb.activedbs, ae->attr);
                        if (!m || (m && m[strlen(ae->attr)] != ';') ||
                            *m != *ae->attr) {
                            hvfs_err(xnet, "Subdatabase %s in DB(%s-%s) "
                                     "does not exist\n",
                                     ae->attr, dbname, prefix);
                            return 0;
                        }
                    }
                }
            }
        }
    }

    return 1;
}

/* indexer_open() to load in the metadata from indexer rules
 *
 * API: (string in branch_op->data)
 * 1. type: [plain|bdb]
 * 2. schema: <dbname:prefix>
 *
 * for OP:indexer, we use TAG as the attached info, DATA as key=value paires.
 */
int bo_indexer_open(struct branch_processor *bp,
                    struct branch_operator *bo,
                    struct branch_op_result *bor,
                    struct branch_op *op)
{
    struct bo_indexer *bi;
    char *regex = "type:([^;]*);+schema:([^;]*):([^;]*)";
    char dup[op->len + 1];
    int err = 0, i;

    /* Step 1: parse the arguments from branch op */
    if (!op || !op->data)
        return -EINVAL;

    bi = xzalloc(sizeof(*bi));
    if (!bi) {
        hvfs_err(xnet, "xzalloc() bo_indexer failed\n");
        return -ENOMEM;
    }

    /* load in the bor value */
    if (bor) {
        struct branch_op_result_entry *bore = bor->bore;
        union branch_indexer_disk *bid;

        for (i = 0; i < bor->nr; i++) {
            if (bo->id == bore->id) {
                ASSERT(bore->len >= sizeof(*bid), xnet);
                bid = (union branch_indexer_disk *)(bore->data);
                
                switch (bid->s.flag) {
                case BIDX_PLAIN:
                {
                    struct branch_indexer_plain_disk *bipd = 
                        (void *)bore->data;
                    
                    bi->bi.nr = bipd->nr;
                    bi->flag = BIDX_PLAIN;
                    hvfs_warning(xnet, "Load in NR %ld lines for PLAIN\n", 
                                 bi->bi.nr);
                    break;
                }
                case BIDX_BDB:
                {
                    struct branch_indexer_bdb_disk *bibd = 
                        (void *)bore->data;
                    char dbname[bibd->dbname_len + 1],
                        prefix[bibd->prefix_len + 1], *p, *q, *end;
                    
                    bi->bi.nr = bibd->nr;
                    bi->flag = BIDX_BDB;
                    memcpy(dbname, bibd->data, bibd->dbname_len);
                    dbname[bibd->dbname_len] = '\0';
                    memcpy(prefix, bibd->data + bibd->dbname_len,
                           bibd->prefix_len);
                    prefix[bibd->prefix_len] = '\0';
                    bi->bi.bdb.dbname = strdup(dbname);
                    bi->bi.bdb.prefix = strdup(prefix);
                    bi->bi.bdb.activedbs = strdup("db_base;");
                    hvfs_warning(xnet, "Load in NR %ld lines for BerkeleyDB: "
                                 "DB'%s' PREFIX'%s' {",
                                 bi->bi.nr, dbname, prefix);
                    /* dump the active DBs, there must be a tailing ';'! */
                    p = bibd->data + bibd->dbname_len + bibd->prefix_len;
                    end = p + bibd->dbs_len;
                    while (p < end) {
                        q = p;
                        while (*q != ';') {
                            q++;
                            if (q >= end) {
                                break;
                            }
                        }
                        if (*q == ';') {
                            *q = '\0';
                            hvfs_plain(xnet, "%s ", p);
                            {
                                int olen = 0, len = strlen(p);
                                char *m;
                                
                                if (bi->bi.bdb.activedbs) {
                                    /* find the needle */
                                    m = strstr(bi->bi.bdb.activedbs, p);
                                    if (m && m[len] == ';') {
                                        /* ok, bypass this entry */
                                        goto bypass;
                                    }
                                    olen = strlen(bi->bi.bdb.activedbs);
                                }
                                m = xrealloc(bi->bi.bdb.activedbs, 
                                             olen + len + 2);
                                if (m) {
                                    memcpy(m + olen, p, len);
                                    m[olen + len] = ';';
                                    m[olen + len + 1] = '\0';
                                    bi->bi.bdb.activedbs = m;
                                } else {
                                    hvfs_err(xnet, 
                                             "xrealloc() database item "
                                             "failed\n");
                                }
                            }
                        } else if (q >= end) {
                            hvfs_plain(xnet, " [CROSS BORDER]\n");
                            break;
                        } else {
                            hvfs_plain(xnet, " [ABORT]\n");
                            break;
                        }
                    bypass:
                        p = q + 1;
                    }
                    hvfs_plain(xnet, "}\n");
                    break;
                }
                default:
                    hvfs_err(xnet, "Invalid saved branch indexer type X(%x), "
                             "reject load in\n",
                             bid->s.type);
                    return -EINVAL;
                }
                break;
            }
            bore = (void *)bore + sizeof(*bore) + bore->len;
        }
    }

    memcpy(dup, op->data, op->len);
    dup[op->len] = '\0';

    /* parse the regex strings */
    {
        regex_t preg;
        regmatch_t *pmatch;
        char errbuf[op->len + 1];
        int i, len;

        pmatch = xzalloc(4 * sizeof(regmatch_t));
        if (!pmatch) {
            hvfs_err(xnet, "malloc regmatch_t failed\n");
            err = -ENOMEM;
            goto out_free;
        }
        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "regcomp failed w/ %d\n", err);
            goto out_free2;
        }
        err = regexec(&preg, dup, 4, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, op->len);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_clean;
        }

        for (i = 1; i < 4; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, dup + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the type */
                hvfs_err(xnet, "type=%s\n", errbuf);
                if (strcmp(errbuf, "plain") == 0) {
                    bi->flag = BIDX_PLAIN;
                    xlock_init(&bi->bi.plain.lock);
                } else if (strcmp(errbuf, "bdb") == 0) {
                    bi->flag = BIDX_BDB;
                }
                break;
            case 2:
            {
                /* this is the dbname */
                hvfs_err(xnet, "schema=DB:%s;", errbuf);
                if (bi->flag == BIDX_BDB) {
                    bi->bi.bdb.dbname = strdup(errbuf);
                }
                break;
            }
            case 3:
                /* this is the table */
                hvfs_plain(xnet, "PREFIX:%s\n", errbuf);
                if (bi->flag == BIDX_BDB) {
                    bi->bi.bdb.prefix = strdup(errbuf);
                }
                break;
            default:
                continue;
            }
        }
        if (bi->flag == BIDX_BDB) {
            if (!bi->bi.bdb.activedbs)
                bi->bi.bdb.activedbs = strdup("db_base;");
            bi->bi.bdb.__bdb = bdb_open(hmo.site_id, 
                                        bp->be->branch_name,
                                        bi->bi.bdb.dbname, 
                                        bi->bi.bdb.prefix);
            if (!bi->bi.bdb.__bdb) {
                hvfs_err(xnet, "Open BDB '%s-%s' failed, "
                         "reject load in\n", bi->bi.bdb.dbname, 
                         bi->bi.bdb.prefix);
                err = -EINVAL;
                goto out_clean;
            }
        }
    out_clean:
        regfree(&preg);
    out_free2:
        xfree(pmatch);
        if (err)
            goto out_free;
    }

    /* set the bs to gdata */
    bo->gdata = bi;
    return 0;

out_free:
    xfree(bi);

    return err;
}

int bo_indexer_close(struct branch_operator *bo)
{
    struct bo_indexer *bi = bo->gdata;

    /* Note that, we assume the buffer has already been flushed */
    if (bi->flag == BIDX_PLAIN) {
        xlock_destroy(&bi->bi.plain.lock);
        xfree(bi->bi.plain.buffer);
    } else if (bi->flag == BIDX_BDB) {
        /* FIXME: we should clean the BDB resources */
        xfree(bi->bi.bdb.dbname);
        xfree(bi->bi.bdb.prefix);
        xfree(bi->bi.bdb.activedbs);
        bdb_close(bi->bi.bdb.__bdb);
#ifdef USE_BDB
        xfree(bi->bi.bdb.__bdb);
#endif
    }
    xfree(bi);

    return 0;
}

/* Generate the BOR region entry to flush. Note that we will realloc the
 * bp->bor region.
 */
int bo_indexer_plain_md_flush(struct branch_processor *bp,
                              struct branch_operator *bo, void **oresult,
                              size_t *osize)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    struct branch_op_result_entry *bore;
    struct branch_indexer_plain_disk *bipd;
    void *nbor;
    int len = sizeof(*bore) + sizeof(union branch_indexer_disk);

    /* Step 1: self handling */
    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = len - sizeof(*bore);

    bipd = (void *)bore->data;
    bipd->type = BRANCH_DISK_INDEXER;
    bipd->flag = BIDX_PLAIN;
    bipd->nr = bi->bi.nr;

    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    return 0;
}

int bo_indexer_plain_flush(struct branch_processor *bp,
                           struct branch_operator *bo, void **oresult,
                           size_t *osize)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    struct branch_indexer_plain *bip = &bi->bi.plain;
    struct hstat hs;
    struct mdu mdu;
    u64 buuid, bsalt;
    off_t offset;
    int err = 0;
    char fname[256];

    if (!bip->size)
        return 0;

    /* in bp mode, we are sure that we are NOT in MDSL, Thus, we should pay a
     * little patient for api calls */
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = hvfs_stat_eh(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "Root branch does not exist, w/ %d\n",
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

    /* find the output file now */
    sprintf(fname, ".%s.indexer.p%d", bp->be->branch_name, bo->id);
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.puuid = buuid;
    hs.psalt = bsalt;
    hs.name = fname;
    err = hvfs_stat_eh(buuid, bsalt, 0, &hs);
    if (err == -ENOENT) {
        /* create the file now */
        hs.uuid = 0;
        err = hvfs_create_eh(buuid, bsalt, &hs, 0, NULL);
        if (err) {
            hvfs_err(xnet, "do internal file create (SDT) on branch '%s'"
                     " failed w/ %d\n",
                     fname, err);
            goto out;
        }
    } else if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                 " failed w/ %d\n",
                 fname, err);
        goto out;
    }
    mdu = hs.mdu;

    /* proxy file in append write mode */
    hs.mc.c.offset = -1;
    offset = bip->offset;
    err = hvfs_fwrite_eh(&hs, 0, SCD_PROXY, bip->buffer, offset, 
                         &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "flush filter buffer to %s failed w/ %d\n",
                 fname, err);
        goto out;
    }

    /* well, update the file metadata now */
    {
        struct mdu_update mu;

        memset(&mu, 0, sizeof(mu));
        mu.valid = MU_COLUMN | MU_FLAG_ADD | MU_SIZE;
        mu.flags = HVFS_MDU_IF_PROXY;
        mu.column_no = 1;
        mu.size = offset + mdu.size;
        hs.mc.cno = 0;          /* write to zero column */
        hs.mc.c.len = mu.size;

        hs.name = NULL;
        /* access SDT, using the old hs.hash value */
        err = hvfs_update_eh(buuid, bsalt, &hs, &mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     fname, err);
            goto out;
        }
    }

    /* then, it is ok to clean and reset the buffer now */
    xlock_lock(&bip->lock);
    if (bip->offset == offset)
        bip->offset = 0;
    else {
        memmove(bip->buffer, bip->buffer + offset, bip->offset - offset);
        bip->offset -= offset;
    }
    xlock_unlock(&bip->lock);

    /* Step 2: push the flush request to other operatores */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }

out:
    return err;
}

int bo_indexer_bdb_flush(struct branch_processor *bp,
                         struct branch_operator *bo, void **oresult,
                         size_t *osize)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    struct branch_op_result_entry *bore;
    struct branch_indexer_bdb_disk *bibd;
    void *nbor;
    int len = sizeof(*bore) + sizeof(union branch_indexer_disk), 
        err = 0, dbname_len, prefix_len;

    /* Step 1: self handling */
    len += strlen(bi->bi.bdb.dbname);
    len += strlen(bi->bi.bdb.prefix);
    len += strlen(bi->bi.bdb.activedbs);

    bore = xzalloc(len);
    if (!bore) {
        hvfs_err(xnet, "xzalloc() bore failed\n");
        return -ENOMEM;
    }
    bore->id = bo->id;
    bore->len = len - sizeof(*bore);

    bibd = (void *)bore->data;
    bibd->type = BRANCH_DISK_INDEXER;
    bibd->flag = BIDX_BDB;
    bibd->nr = bi->bi.nr;
    bibd->dbname_len = dbname_len = strlen(bi->bi.bdb.dbname);
    bibd->prefix_len = prefix_len = strlen(bi->bi.bdb.prefix);
    bibd->dbs_len = strlen(bi->bi.bdb.activedbs);
    memcpy(bibd->data, bi->bi.bdb.dbname, dbname_len);
    memcpy(bibd->data + dbname_len,
           bi->bi.bdb.prefix, prefix_len);
    memcpy(bibd->data + dbname_len + prefix_len,
           bi->bi.bdb.activedbs, bibd->dbs_len);

    nbor = xrealloc(bp->bor, bp->bor_len + len);
    if (!nbor) {
        hvfs_err(xnet, "xrealloc() bor region failed\n");
        xfree(bore);
        return -ENOMEM;
    }

    memcpy(nbor + bp->bor_len, bore, len);
    bp->bor = nbor;
    bp->bor_len += len;
    ((struct branch_op_result *)bp->bor)->nr++;

    xfree(bore);

    /* Step 2: push the flush request to my children */
    {
        int errstate = BO_FLUSH;

        if (bo->left) {
            err = bo->left->input(bp, bo->left, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's left branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->left->id, err);
                }
            }
        }
        errstate = BO_FLUSH;
        if (bo->right) {
            err = bo->right->input(bp, bo->right, NULL, -1UL, 0, &errstate);
            if (errstate == BO_STOP) {
                /* ignore any errors */
                if (err) {
                    hvfs_err(xnet, "flush on BO %d's right branch %d "
                             "failed w/ %d\n",
                             bo->id, bo->right->id, err);
                }
            }
        }
    }

    return err;
}

int bo_indexer_flush(struct branch_processor *bp,
                     struct branch_operator *bo, void **oresult,
                     size_t *osize)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;

    switch (bi->flag) {
    case BIDX_PLAIN:
        bo_indexer_plain_md_flush(bp, bo, oresult, osize);
        return bo_indexer_plain_flush(bp, bo, oresult, osize);
        break;
    case BIDX_BDB:
        return bo_indexer_bdb_flush(bp, bo, oresult, osize);
        break;
    default:
        hvfs_err(xnet, "Invalid indexer type X(%x)\n", bi->flag);
    }

    return -EINVAL;
}

int bo_indexer_plain_input(struct branch_processor *bp,
                           struct branch_operator *bo,
                           struct branch_line_disk *bld,
                           u64 site, u64 ack, int *errstate)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    struct branch_indexer_plain *bip = &bi->bi.plain;
    int err = 0, len;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush filter buffer of operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("indexer", bld, site);
    xlock_lock(&bip->lock);
    /* save the input data to the buffer */
    len = bld->bl.data_len + bld->tag_len + 8 + 3; /* 8B for site id, 2B '\t'
                                                    * and 1B '\n' */
retry:
    if (bip->offset + len > bip->size) {
        /* need to realloc the buffer now */
        void *p = xrealloc(bip->buffer,
                           max(len, bip->size + BI_PLAIN_CHUNK));
        if (!p) {
            hvfs_err(xnet, "realloc buffer space to %d failed\n",
                     bip->size + BI_PLAIN_CHUNK);
            *errstate = BO_STOP;
            xlock_unlock(&bip->lock);
            return -ENOMEM;
        }
        bip->size += BI_PLAIN_CHUNK;
        bip->buffer = p;
        goto retry;
    }
    sprintf(bip->buffer + bip->offset, "%08lx\t", bld->bl.sites[0]);
    bip->offset += 9;
    memcpy(bip->buffer + bip->offset, bld->data + bld->name_len,
           bld->tag_len);
    bip->offset += bld->tag_len;
    *(char *)(bip->buffer + bip->offset) = '\t';
    bip->offset += 1;
    memcpy(bip->buffer + bip->offset, bld->bl.data,
           bld->bl.data_len);
    bip->offset += bld->bl.data_len;
    *(char *)(bip->buffer + bip->offset) = '\n';
    bip->offset += 1;
    xlock_unlock(&bip->lock);
    /* increase the # of handled lines */
    bi->bi.nr++;

    /* Step 2: push the branch line to other operatores */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }

out:
    return err;
}

int bo_indexer_bdb_input(struct branch_processor *bp,
                         struct branch_operator *bo,
                         struct branch_line_disk *bld,
                         u64 site, u64 ack, int *errstate)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    int err = 0;

    /* check if it is a flush operation */
    if (*errstate == BO_FLUSH) {
        if (bo->flush)
            err = bo->flush(bp, bo, NULL, NULL);
        else
            err = -EINVAL;

        if (err) {
            hvfs_err(xnet, "flush filter buffer of operator %s "
                     "failed w/ %d\n", bo->name, err);
            *errstate = BO_STOP;
            return -EHSTOP;
        }
        return err;
    } else if (*errstate == BO_STOP) {
        return -EHSTOP;
    }

    /* sanity check */
    if (!bp || !bld) {
        *errstate = BO_STOP;
        return -EINVAL;
    }

    /* deal with data now */
    __bp_bld_dump("indexer", bld, site);

    /* Parse the data line to extract sub-table name. User should follow the
     * low-level BDB rules as following:
     *
     * TAG: [+-]puuid:filename:uuid:hash.SUFFIX
     * KVS: type=png;tag:color=rgb;tag:location=china;@ctime=12345;
     *
     */
    {
        char *regex = "(^|[ \t;,]+)([^=;,]*)[ \t]*=[ \t]*([^=;,]*)[,;]*";
        regex_t preg;
        regmatch_t pmatch[4];
        char kvs[bld->bl.data_len + 1], *p, *end, errbuf[100];
        struct base base;
        int len;

        end = kvs + bld->bl.data_len;
        memcpy(kvs, bld->data + bld->name_len + bld->tag_len, 
               bld->bl.data_len);
        kvs[bld->bl.data_len] = '\0';

        err = regcomp(&preg, regex, REG_EXTENDED);
        if (err) {
            hvfs_err(xnet, "Invalid regex strings\n");
            goto bypass;
        }

        /* iterate on the databases */
        p = kvs;
        do {
            memset(pmatch, 0, 4 * sizeof(regmatch_t));
            err = regexec(&preg, p, 4, pmatch, 0);
            if (err == REG_NOMATCH) {
                goto free_reg;
            } else if (err) {
                regerror(err, &preg, errbuf, 100);
                hvfs_err(xnet, "regexec failed w/ %s\n", errbuf);
                goto free_reg;
            }

            len = pmatch[2].rm_eo - pmatch[2].rm_so;
            memcpy(errbuf, "db_", 3);
            memcpy(errbuf + 3, p + pmatch[2].rm_so, len);
            errbuf[len + 3] = '\0';
            hvfs_err(xnet, "Got DB '%s'\n", errbuf);
            {
                int olen = 0;
                char *m;
                
                len += 3;
                if (bi->bi.bdb.activedbs) {
                    /* find the needle */
                    m = strstr(bi->bi.bdb.activedbs, errbuf);
                    if (m && m[len] == ';') {
                        /* ok, bypass this entry */
                        goto do_prepare;
                    }
                    olen = strlen(bi->bi.bdb.activedbs);
                }
                m = xrealloc(bi->bi.bdb.activedbs, 
                             olen + len + 2);
                if (m) {
                    memcpy(m + olen, errbuf, len);
                    m[olen + len] = ';';
                    m[olen + len + 1] = '\0';
                    bi->bi.bdb.activedbs = m;
                } else {
                    hvfs_err(xnet, "xrealloc() database item failed\n");
                }
            }
        do_prepare:
            /* prepare the sub database */
            if (errbuf[3] == '@')
                err = bdb_db_prepare(bi->bi.bdb.__bdb, errbuf, 
                                     BDB_INTEGER_ULONG);
            else
                err = bdb_db_prepare(bi->bi.bdb.__bdb, errbuf, 0);
            if (err) {
                hvfs_err(xnet, "bdb_db_prepare() failed w/ %d\n", err);
            }
            p += pmatch[3].rm_eo + 1;
        } while (p < end);
    free_reg:
        regfree(&preg);
    bypass:
        /* then, we push current line to low level BDB handlers to insert it
         * into database */
        {
            char tag[bld->tag_len + 1];

            memcpy(tag, bld->data + bld->name_len, bld->tag_len);
            tag[bld->tag_len] = '\0';
            p = tag + bld->tag_len;
            /* ignore the .ID suffix */
            do {
                if  (*p != '.') {
                    if (*p == ':')
                        break;
                    p--;
                } else {
                    *p = '\0';
                    break;
                }
            } while (p > tag);
            /* what operation should we do?
             * + => put
             * - => del
             */
            switch (tag[0]) {
            case '-':
                base.tag = tag + 1;
                base.kvs = kvs;
                err = bdb_db_del(bi->bi.bdb.__bdb, &base);
                if (err) {
                    hvfs_err(xnet, "delete line from BDB failed w/ %d\n", err);
                }
                break;
            case '+':
                base.tag = tag + 1;
                base.kvs = kvs;
                err = bdb_db_put(bi->bi.bdb.__bdb, &base);
                if (err) {
                    hvfs_err(xnet, "push line to BDB failed w/ %d\n", err);
                }
                break;
            default:
                base.tag = tag;
                base.kvs = kvs;
                err = bdb_db_put(bi->bi.bdb.__bdb, &base);
                if (err) {
                    hvfs_err(xnet, "push line to BDB failed w/ %d\n", err);
                }
            }
            /* increase the # of handled lines */
            bi->bi.nr++;
        }
    }

    /* Step 2: push the branch line to other operatores */
    if (bo->left) {
        err = bo->left->input(bp, bo->left, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's left operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->left->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's left operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->left->name, site, site, 
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }
    if (bo->right) {
        err = bo->right->input(bp, bo->right, bld, site, ack, errstate);
        if ((*errstate) == BO_STOP) {
            if (err) {
                hvfs_err(xnet, "BO %d's right operator '%s' failed w/ %d "
                         "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                         bo->id, bo->right->name, err, site, site,
                         bld->bl.id, ack);
                goto out;
            } else {
                hvfs_err(xnet, "BO %d's right operator '%s' swallow this branch "
                         "line (Psite %lx from %lx id %ld, "
                         "last_ack %ld)\n",
                         bo->id, bo->right->name, site, site,
                         bld->bl.id, ack);
                /* reset errstate to ZERO */
                *errstate = 0;
            }
        }
    }

out:
    return err;
}

int bo_indexer_input(struct branch_processor *bp,
                     struct branch_operator *bo,
                     struct branch_line_disk *bld,
                     u64 site, u64 ack, int *errstate)
{
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;

    switch (bi->flag) {
    case BIDX_PLAIN:
        return bo_indexer_plain_input(bp, bo, bld, site, ack, errstate);
        break;
    case BIDX_BDB:
        return bo_indexer_bdb_input(bp, bo, bld, site, ack, errstate);
        break;
    default:
        hvfs_err(xnet, "Invalid indexer type X(%x)\n", bi->flag);
    }

    return -EINVAL;
}

/* indexer_output() dump current # of handled lines to the branch_line_disk
 * structure.
 */
int bo_indexer_output(struct branch_processor *bp,
                      struct branch_operator *bo,
                      struct branch_line_disk *bld,
                      struct branch_line_disk **obld,
                      int *len, int *errstate)
{
    /* Note that, we pack the number to one branch line, user who want to
     * parse the number should extract from branch line
     */
    struct branch_line_disk *nbld, *__tmp;
    struct bo_indexer *bi = (struct bo_indexer *)bo->gdata;
    union branch_indexer_disk *bid;
    int err = 0, nlen = sizeof(*bid);

    if (bi->flag == BIDX_BDB) {
        if (bi->bi.bdb.activedbs)
            nlen += strlen(bi->bi.bdb.activedbs);
    }
    nbld = xzalloc(sizeof(*nbld) + nlen);
    if (!nbld) {
        hvfs_err(xnet, "xzalloc() branch_line_disk failed\n");
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    nbld->bl.id = bo->id;
    nbld->bl.data = nbld->data;
    nbld->bl.data_len = nlen;

    /* setup the values */
    bid = (void *)nbld->data;
    bid->s.type = BRANCH_DISK_INDEXER;
    bid->s.flag = bi->flag;
    bid->s.nr = bi->bi.nr;
    if (bi->flag == BIDX_BDB) {
        /* setup BDB fields */
        bid->bibd.dbname_len = strlen(bi->bi.bdb.dbname);
        bid->bibd.prefix_len = strlen(bi->bi.bdb.prefix);
        if (bi->bi.bdb.activedbs) {
            bid->bibd.dbs_len = strlen(bi->bi.bdb.activedbs);
            memcpy(bid->bibd.data, bi->bi.bdb.activedbs, bid->bibd.dbs_len);
        }
    }

    if (!(*len))
        *obld = NULL;
    __tmp = xrealloc(*obld, *len + sizeof(*nbld) + nlen);
    if (!__tmp) {
        hvfs_err(xnet, "xrealloc() BLD failed\n");
        xfree(nbld);
        *errstate = BO_STOP;
        return -ENOMEM;
    }
    memcpy((void *)__tmp + *len, nbld, sizeof(*nbld) + nlen);
    *len += sizeof(*nbld) + nlen;
    *obld = __tmp;
    xfree(nbld);

    /* push the request to my children */
    if (bo->left && bo->left->output) {
        err = bo->left->output(bp, bo->left, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's left branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->left->id, err);
            }
        }
    }
    *errstate = 0;
    if (bo->right && bo->right->output) {
        err = bo->right->output(bp, bo->right, bld, obld, len, errstate);
        if (*errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "output on BO %d's right branch %d "
                         "failed w/ %d\n",
                         bo->id, bo->right->id, err);
            }
        }
    }

    return err;
}

struct branch_processor *bp_alloc(void)
{
    struct branch_processor *bp;

    bp = xzalloc(sizeof(*bp));
    if (!bp) {
        hvfs_err(xnet, "alloc branch processor failed\n");
        return NULL;
    }

    INIT_LIST_HEAD(&bp->oplist);
    atomic_set(&bp->bonr, 0);
    bp->bpto = BP_DEFAULT_BTO;
    bp->memlimit = BP_DEFAULT_MEMLIMIT;

    /* init the root operator */
    bo_init(bp, &bp->bo_root, NULL, NULL, "root", NULL, NULL);

    return bp;
}

/* This is not the critical code path, thus, we can be slow 8-)
 */
int __bo_install_cb(struct branch_operator *bo, char *name)
{
    if (strcmp(name, "root") == 0) {
        bo->flush = bo_root_flush;
        bo->input = bo_root_input;
        bo->output = bo_root_output;
    } else if (strcmp(name, "filter") == 0) {
        bo->open = bo_filter_open;
        bo->close = bo_filter_close;
        bo->input = bo_filter_input;
        bo->flush = bo_filter_flush;
    } else if (strcmp(name, "sum") == 0) {
        bo->open = bo_sum_open;
        bo->close = bo_sum_close;
        bo->input = bo_sum_input;
        bo->output = bo_sum_output;
        bo->flush = bo_sum_flush;
    } else if (strcmp(name, "max") == 0) {
        bo->open = bo_max_open;
        bo->close = bo_mm_close;
        bo->input = bo_mm_input;
        bo->output = bo_mm_output;
        bo->flush = bo_mm_flush;
    } else if (strcmp(name, "min") == 0) {
        bo->open = bo_min_open;
        bo->close = bo_mm_close;
        bo->input = bo_mm_input;
        bo->output = bo_mm_output;
        bo->flush = bo_mm_flush;
    } else if (strcmp(name, "knn") == 0) {
        bo->open = bo_knn_open;
        bo->close = bo_knn_close;
        bo->input = bo_knn_input;
        bo->output = bo_knn_output;
        bo->flush = bo_knn_flush;
    } else if (strcmp(name, "groupby") == 0) {
        bo->open = bo_groupby_open;
        bo->close = bo_groupby_close;
        bo->input = bo_groupby_input;
        bo->output = bo_groupby_output;
        bo->flush = bo_groupby_flush;
    } else if (strcmp(name, "rank") == 0) {
    } else if (strcmp(name, "indexer") == 0) {
        bo->open = bo_indexer_open;
        bo->close = bo_indexer_close;
        bo->input = bo_indexer_input;
        bo->output = bo_indexer_output;
        bo->flush = bo_indexer_flush;
    } else if (strcmp(name, "count") == 0) {
        bo->open = bo_count_open;
        bo->close = bo_sum_close;
        bo->input = bo_sum_input;
        bo->output = bo_sum_output;
        bo->flush = bo_sum_flush;
    } else if (strcmp(name, "avg") == 0) {
        bo->open = bo_avg_open;
        bo->close = bo_sum_close;
        bo->input = bo_sum_input;
        bo->output = bo_sum_output;
        bo->flush = bo_sum_flush;
    } else if (strcmp(name, "codec") == 0) {
    } else {
        hvfs_err(xnet, "Operator %s is not support yet.\n",
                 name);
        return -ENOSYS;
    }

    return 0;
}

void bp_destroy(struct branch_processor *bp)
{
    bo_destroy(&bp->bo_root);

    xfree(bp);
}

struct branch_processor *bp_alloc_init(struct branch_entry *be,
                                       struct branch_op_result *bor)
{
    struct branch_processor *bp;
    struct branch_operator *bo, *nbo[be->bh->ops.nr];
    int i, j, err = 0, inited = 0;

    bp = bp_alloc();
    if (!bp) {
        hvfs_err(xnet, "alloc branch processor failed\n");
        return NULL;
    }
    /* for bo_init() using, we should set the bp->be pointer */
    bp->be = be;

    /* construct the operator list */
    for (i = 0; i < be->bh->ops.nr; i++) {
        nbo[i] = NULL;
        bo = bo_alloc();
        if (!bo) {
            hvfs_err(xnet, "bo_alloc() '%s'->op %d failed\n",
                     be->branch_name, be->bh->ops.ops[i].op);
            continue;
        }
        bo->id = be->bh->ops.ops[i].id;
        bo->rid = be->bh->ops.ops[i].rid;
        bo->lor = be->bh->ops.ops[i].lor;

        switch(be->bh->ops.ops[i].op) {
        case BRANCH_OP_FILTER:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "filter", NULL, NULL);
            break;
        case BRANCH_OP_SUM:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "sum", NULL, NULL);
            break;
        case BRANCH_OP_MAX:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "max", NULL, NULL);
            break;
        case BRANCH_OP_MIN:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "min", NULL, NULL);
            break;
        case BRANCH_OP_KNN:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "knn", NULL, NULL);
            break;
        case BRANCH_OP_GROUPBY:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "groupby", NULL, NULL);
            break;
        case BRANCH_OP_RANK:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "rank", NULL, NULL);
            break;
        case BRANCH_OP_INDEXER:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "indexer", NULL, NULL);
            break;
        case BRANCH_OP_COUNT:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "count", NULL, NULL);
            break;
        case BRANCH_OP_AVG:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "avg", NULL, NULL);
            break;
        case BRANCH_OP_CODEC:
            err = bo_init(bp, bo, bor, &be->bh->ops.ops[i], 
                          "udf_codec", NULL, NULL);
            break;
        default:
            hvfs_err(xnet, "Invalid operator %d\n",
                     be->bh->ops.ops[i].op);
            bo_free(bo);
            continue;
        }

        if (err) {
            hvfs_err(xnet, "bo_init() for op %d failed w/ %d, ignore it\n",
                     bo->id, err);
            bo_free(bo);
            continue;
        }

        /* add this operator to the bp oplist */
        xlock_lock(&bp->lock);
        list_add_tail(&bo->list, &bp->oplist);
        atomic_inc(&bp->bonr);
        xlock_unlock(&bp->lock);
        nbo[i] = bo;
        inited++;
    }

    /* setup the operators' tree */
    for (i = 0; i < inited; i++) {
        if (!nbo[i])
            continue;
        if (!nbo[i]->rid) {
            if (!nbo[i]->lor) {
                /* insert to root's left branch */
                if (bp->bo_root.left) {
                    hvfs_err(xnet, "Root's left branch conflict "
                             "(N:%d,O:%d)\n",
                             nbo[i]->id, bp->bo_root.left->id);
                    bo_free(nbo[i]);
                } else {
                    bp->bo_root.left = nbo[i];
                }
            } else {
                /* insert to root's right branch */
                if (bp->bo_root.right) {
                    hvfs_err(xnet, "Root's right branch conflict "
                             "(N:%d,O:%d)\n",
                             nbo[i]->id, bp->bo_root.right->id);
                    bo_free(nbo[i]);
                } else {
                    bp->bo_root.right = nbo[i];
                }
            }
        } else {
            /* find the root operator */
            int found = 0;
            
            for (j = 0; j < inited; j++) {
                if (nbo[j]->id == nbo[i]->rid) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                if (!nbo[i]->lor) {
                    /* insert to left branch */
                    if (nbo[j]->left) {
                        hvfs_err(xnet, "BO %d left branch conflict"
                                 " (N:%d,O:%d)\n",
                                 nbo[j]->id, 
                                 nbo[i]->id, nbo[j]->left->id);
                        bo_free(nbo[i]);
                    } else {
                        nbo[j]->left = nbo[i];
                    }
                } else {
                    /* insert to right branch */
                    if (nbo[j]->right) {
                        hvfs_err(xnet, "BO %d right branch conflict"
                                 " (N:%d,O:%d)\n",
                                 nbo[j]->id,
                                 nbo[i]->id, nbo[j]->right->id);
                        bo_free(nbo[i]);
                    } else {
                        nbo[j]->right = nbo[i];
                    }
                }
            } else {
                hvfs_err(xnet, "Root id(%d) for BO %d doesn't exist\n",
                         nbo[i]->rid, nbo[i]->id);
                bo_free(nbo[i]);
            }
        }
    }

    return bp;
}

int __bp_handle_push_console(struct xnet_msg *msg, 
                             struct branch_line_disk *bld)
{
    u64 site;
    int err = 0;

    if (bld->bl.position == BL_PRIMARY) {
        site = msg->tx.ssite_id;
    } else if (bld->bl.position == BL_REPLICA) {
        site = bld->bl.sites[0];
    } else {
        hvfs_err(xnet, "Invalid branch line postion %d\n",
                 bld->bl.position);
        return -EINVAL;
    }

    hvfs_info(xnet, "BL pushed from %lx Psite %lx id %ld last_ack %ld\n",
              msg->tx.ssite_id, site, bld->bl.id, msg->tx.arg1);
    
    return err;
}

int bp_handle_push(struct branch_processor *bp, struct xnet_msg *msg,
                   struct branch_line_disk *bld)
{
    u64 site, ack;
    int errstate = 0, err = 0;
    
    if (!bp)
        return __bp_handle_push_console(msg, bld);

    ++bp->blnr;
    if (BP_DO_FLUSH(bp->blnr)) {
        errstate = BO_FLUSH;
        err = bp->bo_root.input(bp, &bp->bo_root, NULL, -1UL, 0, &errstate);
        if (errstate == BO_STOP) {
            /* ignore any errors */
            if (err) {
                hvfs_err(xnet, "normal flush on root branch "
                         "failed w/ %d\n", err);
            }
        }
        errstate = 0;
    }

    /* ABI:
     * tx.arg1: last_ack
     */

    /* setup the bld structure */
    bld->bl.data = bld->data + bld->name_len + bld->tag_len;
    ack = msg->tx.arg1;
    if (bld->bl.position == BL_PRIMARY) {
        site = msg->tx.ssite_id;
    } else if (bld->bl.position == BL_REPLICA) {
        site = bld->bl.sites[0];
    } else {
        hvfs_err(xnet, "Invalid branch line postion %d\n",
                 bld->bl.position);
        return -EINVAL;
    }

    /* calling the processor framework and begin processing */

    /* Step 1: push the branch line to root operator */
    err = bp->bo_root.input(bp, &bp->bo_root, bld, site, ack,
                            &errstate);
    BE_UPDATE_TS(bp->be, time(NULL));
    if (errstate == BO_STOP) {
        if (err) {
            hvfs_err(xnet, "root operator failed w/ %d "
                     "(Psite %lx from %lx id %ld, last_ack %ld)\n",
                     err, site, msg->tx.ssite_id, bld->bl.id, ack);
        } else {
            hvfs_err(xnet, "root operator swallow this branch "
                     "line (Psite %lx from %lx id %ld, "
                     "last_ack %ld)\n",
                     site, msg->tx.ssite_id, bld->bl.id, ack);
        }
        goto out;
    }

out:
    return err;
}

int bp_handle_bulk_push(struct branch_processor *bp, struct xnet_msg *msg,
                        struct branch_line_push_header *blph)
{
    struct branch_line_disk *bld;
    int len = 0, i;
    int err = 0;

    bld = (struct branch_line_disk *)((void *)blph + sizeof(*blph) + 
                                      blph->name_len);
    if (!bp) {
        for (i = 0; i < blph->nr; i++) {
            bld = (struct branch_line_disk *)((void *)bld + len);
            /* setup the bld structure */
            len = bld->name_len + bld->tag_len;
            bld->bl.data = bld->data + len;
            len += bld->bl.data_len;
            
            err = __bp_handle_push_console(msg, bld);
        }
        return err;
    }

    for (i = 0; i < blph->nr; i++) {
        bld = (struct branch_line_disk *)((void *)bld + len);
        len = sizeof(*bld) + bld->name_len + 
            bld->tag_len + bld->bl.data_len;

        err = bp_handle_push(bp, msg, bld);
        if (err == -EADJUST) {
            /* if it is a adjust notice, we should break right now */
            break;
        } else if (err) {
            char name[blph->name_len + 1];

            memcpy(name, (void *)blph + sizeof(*blph), blph->name_len);
            name[blph->name_len] = '\0';
            hvfs_err(xnet, "Handle bulk B %s BL idx @%d failed w/ %d\n",
                     name, i, err);
        }
        /* adjust the last ack id */
        msg->tx.arg1 = bld->bl.id;
    }

    return err;
}

u64 bp_get_ack(struct branch_processor *bp, u64 site)
{
    return bac_lookup(site, &bp->bo_root.bac);
}
