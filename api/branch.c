/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-22 00:24:51 macan>
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

struct branch_mgr
{
    struct regular_hash *bht;
    int hsize;
    atomic_t asize;
};

struct branch_entry
{
    struct hlist_node hlist;
    struct branch_header *bh;
    char *branch_name;
    time_t update;
    atomic_t ref;
};

struct branch_mgr bmgr;

static inline
u32 __branch_hash(char *str, u32 len)
{
    return JSHash(str, len) % bmgr.hsize;
}

int branch_init(int hsize)
{
    int err = 0, i;

    /* regular hash init */
    hsize = (hsize == 0) ? BRANCH_HT_DEFAULT_SIZE : hsize;
    bmgr.bht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!bmgr.bht) {
        hvfs_err(xnet, "BRANCH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&bmgr.bht[i].h);
        xlock_init(&bmgr.bht[i].lock);
    }
    bmgr.hsize = hsize;
    atomic_set(&bmgr.asize, 0);
out:
    return err;
}

void branch_destroy(void)
{
    if (bmgr.bht)
        xfree(bmgr.bht);
}

int __branch_insert(char *branch_name, struct branch_header *bh)
{
    struct regular_hash *rh;
    struct branch_entry *be, *tpos;
    struct hlist_node *pos;
    int i;

    i = __branch_hash(branch_name, strlen(branch_name));
    rh = bmgr.bht + i;

    be = xzalloc(sizeof(struct branch_entry));
    if (unlikely(!be))
        return -ENOMEM;

    INIT_HLIST_NODE(&be->hlist);
    atomic_set(&be->ref, 1);
    be->update = time(NULL);
    be->bh = bh;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (strlen(branch_name) == strlen(tpos->branch_name) &&
            memcmp(tpos->branch_name, branch_name, 
                   strlen(branch_name))) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&be->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i) {
        xfree(be);
        return -EEXIST;
    }
    atomic_inc(&bmgr.asize);
    
    return 0;
}

int __branch_remove(char *branch_name)
{
    int err = 0;

    return err;
}

int __branch_lookup(char *branch_name)
{
    int err = 0;

    return err;
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
                  char *tag, u8 level, struct branch_ops * ops)
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

    err = __hvfs_stat(hmi.root_uuid, hmi.root_salt, -1, &hs);
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
    err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
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
    err = __hvfs_create(buuid, bsalt, &hs, 0, NULL);
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

    offset = (void *)bh + sizeof(*bh) + 
        nr * sizeof(struct branch_op);
    for (i = 0; i < nr; i++) {
        bh->ops.ops[i] = ops->ops[i];
        memcpy(offset, ops->ops[i].data, ops->ops[i].len);
        offset += ops->ops[i].len;
    }

    /* calculate which itbid we should stored it in */
    hs.hash = hvfs_hash(hs.puuid, (u64)hs.name, strlen(hs.name),
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
    err = __hvfs_fwrite(&hs, 0, bh, sizeof(*bh) + 
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
        mu->valid = MU_COLUMN;
        mu->column_no = 1;
        hs.mc.cno = 0;

        hs.uuid = 0;
        hs.name = branch_name;
        err = __hvfs_update(hs.puuid, hs.psalt, &hs, mu);
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

/* branch_load()
 *
 * Load a branch metadata to current site. This operation is always called on
 * MDSs (and the targe MDSL). Based on the metadata, the MDSs can determine
 * the final location of the BRANCH (through itbid). While, MDSs can even do
 * the middle data pre-processing either (through branch_ops).
 *
 * Also note that, all the MDSs can NOT modify the branch metadata themselves.
 */
int branch_load(char *branch_name, char *tag, 
                struct branch_ops **ops)
{
    struct hstat hs;
    struct branch_header *bh;
    u64 buuid, bsalt;
    int err = 0;

    if (!branch_name)
        return -EINVAL;

    /* Step 1: find the root branch dir */
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = __hvfs_stat(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "Root branche does not exist, w/ %d\n",
                 err);
        goto out;
    }
    hs.hash = 0;
    err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                 "failed w/ %d\n", err);
        goto out;
    }

    /* Step 2: find the branch now */
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.puuid = buuid;
    hs.psalt = bsalt;
    hs.name = branch_name;
    err = __hvfs_stat(buuid, bsalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                 " failed w/ %d\n", branch_name, err);
        goto out;
    }

    /* Step 3: read in the branch data content */
    err = __hvfs_fread(&hs, 0, (void *)&bh, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "read the branch '%s' failed w/ %d\n",
                 branch_name, err);
        goto out;
    }
    /* fix the data pointer in branch_ops */
    if (bh->ops.nr) {
        void *offset = (void *)bh + sizeof(*bh) + bh->ops.nr *
            sizeof(struct branch_op);
        int i;
        for (i = 0; i < bh->ops.nr; i++) {
            bh->ops.ops[i].data = offset;
            offset += bh->ops.ops[i].len;
        }
    }
    
    /* Step 4: register the loaded-in branch to memory hash table */
    err = __branch_insert(branch_name, bh);
    if (err) {
        hvfs_err(xnet, "add branch to hash table failed w/ %d\n",
                 err);
        xfree(bh);
        goto out;
    }

out:
    return err;
}
