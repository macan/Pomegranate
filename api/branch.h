/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-27 23:56:27 macan>
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
#include "amc_api.h"

/* BRANCH is a async, non-cycle data flow system. 
 */

/* Define the BRANCH operations
 */
#define BRANCH_PUBLISH          0xf0000001 /* publish a new info to a
                                            * branch */
#define BRANCH_SUBSCRIBE        0xf0000002 /* subscribe a new branch */

/* The following is the branch service level:
 *
 * SAFE: means that we guarentee the published data safely transfered to
 * another N sites before return. (at most 16 sites!)
 *
 * FAST: means that we just return on coping the data to self's memory.
 */
#define BRANCH_LEVEL_MASK       0xf0
#define BRANCH_NR_MASK          0x0f
#define BRANCH_SAFE             0x10
#define BRANCH_FAST             0x20

struct branch_op
{
#define BRANCH_OP_FILTER        0x0001
#define BRANCH_OP_SUM           0x0002
#define BRANCH_OP_MAX           0x0003
#define BRANCH_OP_MIN           0x0004
#define BRANCH_OP_TOPN          0x0005
#define BRANCH_OP_GROUPBY       0x0006
#define BRANCH_OP_RANK          0x0007

#define BRANCH_OP_CODEC         0x0010
    u32 op;
    u32 len;
    void *data;
};

struct branch_ops
{
    int nr;
    struct branch_op ops[0];
};

struct branch_header
{
    /* who created this branch? */
    u64 puuid;
    u64 uuid;
    /* init tag attached w/ this branch */
    char tag[35];
    /* init level attached w/ this branch */
    u8 level;
    struct branch_ops ops;
};

typedef void *(*branch_callback_t)(void *);

/* APIs */
int branch_create(u64 puuid, u64 uuid, char *brach_name, char *tag,
                  u8 level, struct branch_ops *ops);
int branch_load(char *branch_name, char *tag);
int branch_publish(u64 puuid, u64 uuid, char *branch_name, char *tag,
                   u8 level, void *data, size_t data_len);
int branch_subscribe(u64 puuid, u64 uuid, char *branch_name, char *tag,
                     u8 level, branch_callback_t bc);
int branch_dispatch(void *arg);

/* APIs we nneed from api.c */
int __hvfs_stat(u64 puuid, u64 psalt, int column, struct hstat *);
int __hvfs_create(u64 puuid, u64 psalt, struct hstat *, u32 flag,
                  struct mdu_update *);
int __hvfs_update(u64 puuid, u64 psalt, struct hstat *,
                  struct mdu_update *);
int __hvfs_fwrite(struct hstat *hs, int column, void *data, 
                  size_t len, struct column *c);
int __hvfs_fread(struct hstat *hs, int column, void **data, 
                 struct column *c);
