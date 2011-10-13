/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-11 07:19:00 macan>
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

#include "mds.h"
#include "xnet.h"
#include "branch.h"

#define FORMAT_STRING "type:bdb;schema:default_db:default"

/* this default trigger work following the rules bellow:
 *
 * TRIG on post-CREATE operation
 * Construct a file creation time string and send it to a selected BP site.
 */
int dt_main(u16 where, struct itb *itb, struct ite *ite,
            struct hvfs_index *hi, int status, void *arg)
{
    struct dir_trigger __attribute__((unused)) *dt = 
        (struct dir_trigger *)arg;
    struct branch_ops *bo;
    struct branch_entry *be;
    char branch_name[256];
    char tag[256], kvs[256], *p;
    int err = 0;

    if (status)
        goto out;
    if (where == DIR_TRIG_POST_CREATE) {
        memset(tag, 0, sizeof(tag));
        memset(kvs, 0, sizeof(kvs));
        p = tag;
        p += sprintf(p, "%lx:", itb->h.puuid);
        if (hi->flag & INDEX_BY_NAME) {
            memcpy(p, hi->name, hi->namelen);
            p += hi->namelen;
        }
        p += sprintf(p, ":%lx:%lx", hi->uuid, hi->hash);

        p = kvs;
        p += sprintf(p, "@ctime=%ld", ite->s.mdu.ctime);

        /* Step 1: try to load the branch 'default-puuid' */
        memset(branch_name, 0, sizeof(branch_name));
        sprintf(branch_name, "default-%lx", hi->puuid);
        be = branch_lookup_load(branch_name);
        if (PTR_ERR(be) == -ENOENT) {
            /* create it now */
            bo = alloca(sizeof(*bo) + sizeof(struct branch_op));
            if (!bo) {
                goto out;
            }
            bo->nr = 1;
            bo->ops[0].op = BRANCH_OP_INDEXER;
            bo->ops[0].len = strlen(FORMAT_STRING);
            bo->ops[0].id = 1;
            bo->ops[0].rid = 0;
            bo->ops[0].lor = 0;
            bo->ops[0].data = FORMAT_STRING;
            err = branch_create(hi->puuid, hi->uuid, branch_name, 
                                "default", 1, bo);
            if (err) {
                hvfs_err(xnet, "branch_create(%s) failed w/ %d\n",
                         branch_name, err);
                goto out;
            }
        } else if (IS_ERR(be)) {
            hvfs_err(xnet, "branch_load(%s) failed w/ %ld\n",
                     branch_name, PTR_ERR(be));
            goto out;
        } else {
            branch_put(be);
        }

        /* Step 2: publish the string to the branch */
        err = branch_publish(hi->puuid, hi->uuid, branch_name, tag, 1,
                             kvs, p - kvs);
        if (err) {
            hvfs_err(xnet, "branch_publish(%s) to B'%s' failed w/ %d\n",
                     tag, branch_name, err);
            goto out;
        }
    } else if (where == DIR_TRIG_POST_UNLINK) {
        memset(tag, 0, sizeof(tag));
        memset(kvs, 0, sizeof(kvs));
        p = tag;
        p += sprintf(p, "-%lx:", itb->h.puuid);
        if (hi->flag & INDEX_BY_NAME) {
            memcpy(p, hi->name, hi->namelen);
            p += hi->namelen;
        }
        p += sprintf(p, ":%lx:%lx", hi->uuid, hi->hash);

        p = kvs;
        p += sprintf(p, "@ctime=%ld", ite->s.mdu.ctime);

        /* Step 1: try to load the branch 'default-puuid' */
        memset(branch_name, 0, sizeof(branch_name));
        sprintf(branch_name, "default-%lx", hi->puuid);
        be = branch_lookup_load(branch_name);
        if (PTR_ERR(be) == -ENOENT) {
            /* create it now */
            bo = alloca(sizeof(*bo) + sizeof(struct branch_op));
            if (!bo) {
                goto out;
            }
            bo->nr = 1;
            bo->ops[0].op = BRANCH_OP_INDEXER;
            bo->ops[0].len = strlen(FORMAT_STRING);
            bo->ops[0].id = 1;
            bo->ops[0].rid = 0;
            bo->ops[0].lor = 0;
            bo->ops[0].data = FORMAT_STRING;
            err = branch_create(hi->puuid, hi->uuid, branch_name, 
                                "default", 1, bo);
            if (err) {
                hvfs_err(xnet, "branch_create(%s) failed w/ %d\n",
                         branch_name, err);
                goto out;
            }
        } else if (IS_ERR(be)) {
            hvfs_err(xnet, "branch_load(%s) failed w/ %ld\n",
                     branch_name, PTR_ERR(be));
            goto out;
        } else {
            branch_put(be);
        }

        /* Step 2: publish the string to the branch */
        err = branch_publish(hi->puuid, hi->uuid, branch_name, tag, 1,
                             kvs, p - kvs);
        if (err) {
            hvfs_err(xnet, "branch_publish(%s) to B'%s' failed w/ %d\n",
                     tag, branch_name, err);
            goto out;
        }
    }
    
out:
    return TRIG_CONTINUE;
}
