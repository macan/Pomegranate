/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-02-17 11:14:25 macan>
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

#define COUNT1_STRING "rule:create;lor:all"
#define COUNT2_STRING "rule:unlink;lor:all"
#define SUM1_STRING "rule:sum;lor:all"
#define SUM2_STRING "rule:unlink;lor:all"
#define MAX_STRING "rule:sum;lor:all"
#define MIN_STRING "rule:sum;lor:all"

/* this statis trigger work following the rules bellow:
 *
 * TRIG on post-CREATE operation
 * Construct a file name string and send it to a selected BP site.
 *
 * TRIG on post-UNLINK operation
 * Construct a file name string + file length(minus).
 *
 * TRIG on post-UPDATE operation
 * Construct a file name string + file length(positive).
 */
static
int __do_branch_create(struct hvfs_index *hi, char *branch_name)
{
    struct branch_ops *bo;
    int err = 0;

    /* create it now */
    bo = alloca(sizeof(*bo) + 6 * sizeof(struct branch_op));
    if (!bo) {
        return -ENOMEM;
    }
    bo->nr = 6;
    bo->ops[0].op = BRANCH_OP_COUNT;
    bo->ops[0].len = strlen(COUNT1_STRING);
    bo->ops[0].id = 1;
    bo->ops[0].rid = 0;
    bo->ops[0].lor = 0;
    bo->ops[0].data = COUNT1_STRING;
    
    bo->ops[1].op = BRANCH_OP_SUM;
    bo->ops[1].len = strlen(SUM1_STRING);
    bo->ops[1].id = 2;
    bo->ops[1].rid = 1;
    bo->ops[1].lor = 0;
    bo->ops[1].data = SUM1_STRING;
    
    bo->ops[2].op = BRANCH_OP_SUM;
    bo->ops[2].len = strlen(SUM2_STRING);
    bo->ops[2].id = 3;
    bo->ops[2].rid = 1;
    bo->ops[2].lor = 1;
    bo->ops[2].data = SUM2_STRING;
    
    bo->ops[3].op = BRANCH_OP_MAX;
    bo->ops[3].len = strlen(MAX_STRING);
    bo->ops[3].id = 4;
    bo->ops[3].rid = 2;
    bo->ops[3].lor = 0;
    bo->ops[3].data = MAX_STRING;
    
    bo->ops[4].op = BRANCH_OP_MIN;
    bo->ops[4].len = strlen(MIN_STRING);
    bo->ops[4].id = 5;
    bo->ops[4].rid = 2;
    bo->ops[4].lor = 1;
    bo->ops[4].data = MIN_STRING;
    
    bo->ops[5].op = BRANCH_OP_COUNT;
    bo->ops[5].len = strlen(COUNT2_STRING);
    bo->ops[5].id = 6;
    bo->ops[5].rid = 3;
    bo->ops[5].lor = 1;
    bo->ops[5].data = COUNT2_STRING;
    
    err = branch_create(hi->puuid, hi->uuid, branch_name, 
                        "statis", 1, bo);
    if (err) {
        hvfs_err(xnet, "branch_create(%s) failed w/ %d\n",
                 branch_name, err);
        goto out;
    }

out:
    return err;
}

int dt_main(u16 where, struct itb *itb, struct ite *ite,
            struct hvfs_index *hi, int status, void *arg)
{
    struct dir_trigger __attribute__((unused)) *dt = 
        (struct dir_trigger *)arg;
    struct branch_entry *be;
    char branch_name[256];
    char tag[256], data[256], *p;
    int err = 0, sampled = 0;

    if (status)
        goto out;
    if (where == DIR_TRIG_POST_CREATE) {
        memset(tag, 0, sizeof(tag));
        memset(data, 0, sizeof(data));
        p = tag;
        p += sprintf(p, "create.%ld", 0L);
        
        p = data;
        p += sprintf(p, "%lx:", itb->h.puuid);
        if (hi->flag & INDEX_BY_NAME) {
            memcpy(p, hi->name, hi->namelen);
            p += hi->namelen;
        }
        p += sprintf(p, ":%lx:%lx", hi->uuid, hi->hash);
        sampled = 1;
    } else if (where == DIR_TRIG_POST_UNLINK) {
        memset(tag, 0, sizeof(tag));
        memset(data, 0, sizeof(data));
        p = tag;
        p += sprintf(p, "unlink.%ld", ite->s.mdu.size);
        
        p = data;
        p += sprintf(p, "%lx:", itb->h.puuid);
        if (hi->flag & INDEX_BY_NAME) {
            memcpy(p, hi->name, hi->namelen);
            p += hi->namelen;
        }
        p += sprintf(p, ":%lx:%lx", hi->uuid, hi->hash);
        sampled = 1;
    } else if (where == DIR_TRIG_POST_UPDATE) {
        if (hi->flag & INDEX_MDU_UPDATE) {
            struct mdu_update *mu = hi->data;

            if (!mu)
                goto out;
            if (!(mu->valid & MU_SIZE))
                goto out;
            
            memset(tag, 0, sizeof(tag));
            memset(data, 0, sizeof(data));
            p = tag;
            p += sprintf(p, "sum.%ld", ite->s.mdu.size);
            
            p = data;
            p += sprintf(p, "%lx:", itb->h.puuid);
            if (hi->flag & INDEX_BY_NAME) {
                memcpy(p, hi->name, hi->namelen);
                p += hi->namelen;
            }
            p += sprintf(p, ":%lx:%lx", hi->uuid, hi->hash);
            sampled = 1;
        }
    }
    if (!sampled)
        goto out;

    /* Step 1: try to load the branch 'statis-puuid' */
    memset(branch_name, 0, sizeof(branch_name));
    sprintf(branch_name, "statis-%lx", hi->puuid);
    be = branch_lookup_load(branch_name);
    if (PTR_ERR(be) == -ENOENT) {
        err = __do_branch_create(hi, branch_name);
        if (err)
            goto out;
    } else if (IS_ERR(be)) {
        hvfs_err(xnet, "branch_load(%s) failed w/ %ld\n",
                 branch_name, PTR_ERR(be));
        goto out;
    } else {
        branch_put(be);
    }
    
    /* Step 2: publish the string to the branch */
    err = branch_publish(hi->puuid, hi->uuid, branch_name, tag, 1,
                         data, p - data);
    if (err) {
        hvfs_err(xnet, "branch_publish(%s) to B'%s' failed w/ %d\n",
                 tag, branch_name, err);
        goto out;
    }

out:
    return TRIG_CONTINUE;
}
