/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-30 09:17:28 macan>
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

#ifndef __BRANCH_H__
#define __BRANCH_H__

#include "hvfs.h"
#include "mdsl_api.h"
#include "mds_api.h"
#include "amc_api.h"
#include "bp.h"

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
#define BRANCH_OP_KNN           0x0005
#define BRANCH_OP_GROUPBY       0x0006
#define BRANCH_OP_RANK          0x0007
#define BRANCH_OP_INDEXER       0x0008
#define BRANCH_OP_COUNT         0x0009
#define BRANCH_OP_AVG           0x000a

#define BRANCH_OP_CODEC         0x0100
    u32 op;
    u32 len;                    /* length of data */
    u32 id;                     /* unique id of this OP */
    u32 rid;                    /* root id of this OP */
    u32 lor;                    /* left(0) or right(1) */
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
    /* id of this branch */
    u64 id;
    /* init tag attached w/ this branch */
    char tag[35];
    /* init level attached w/ this branch */
    u8 level;
    struct branch_ops ops;
};

struct branch_line
{
    struct list_head list;
    u64 sites[16];              /* we support at most 16 replicas */
    time_t life;                /* when this bl comes in */
    time_t sent;                /* when did this bl be sent */
    u64 id;                     /* howto get a unique id? I think hmi.mi_tx is
                                 * a monotonous increasing value */
    char *tag;
    void *data;
    size_t data_len;

#define BL_NEW          0x00
#define BL_SENT         0x01
#define BL_ACKED        0x02
#define BL_STATE_MASK   0x0f
#define BL_CKPTED       0x80
    u8 state;

#define BL_PRIMARY      0x00
#define BL_REPLICA      0x01
    u8 position;
    u8 replica_nr;
#define BL_SELF_SITE(bl)    (bl)->sites[0]
};

struct branch_line_push_header
{
    int name_len;               /* length of branch name */
    int nr;                     /* # of branch line in this packet */
};

struct branch_line_ack_header
{
    u64 ack_id;
    int name_len;               /* length of branch name */
};

struct branch_adjust_entry
{
    u64 ack_id;                 /* which ack_id we want to adjust to */
    u64 lid;                    /* branch line id */
};

struct branch_line_disk
{
    /* branch line must be the first field */
    struct branch_line bl;
    int tag_len;
    int name_len;
    u8 data[0];
};

struct branch_entry
{
    struct hlist_node hlist;
    struct branch_header *bh;
    char *branch_name;
    time_t update;
    atomic_t dirty;
    atomic_t ref;
    xlock_t lock;
    struct branch_processor *bp;
    u64 last_ack;
    /* region for branch lines */
    struct list_head primary_lines;
    struct list_head replica_lines;
    off_t ckpt_foffset;         /* checkpoint file offset */
    int ckpt_nr;                /* # of ckpted BL */
#define BE_FREE         0x00
#define BE_SENDING      0x01    /* only one thread can sending */
    u32 state;                  /* state protected by lock */
};

#define BE_UPDATE_TS(be, time) do {                 \
        if (atomic_inc_return(&(be)->dirty) == 1) { \
            (be)->update = (time);                  \
        } else {                                    \
            atomic_dec(&(be)->dirty);               \
        }                                           \
    } while (0)

#define BE_ISDIRTY(be) ({                           \
            int __res = atomic_read(&(be)->dirty);  \
            __res;                                  \
})

#define BE_UNDIRTY(be) do {                     \
        atomic_dec(&(be)->dirty);               \
    } while (0)

typedef void *(*branch_callback_t)(void *);

/* APIs */
int branch_create(u64 puuid, u64 uuid, char *brach_name, char *tag,
                  u8 level, struct branch_ops *ops);
int branch_load(char *branch_name, char *tag, int mode);
int branch_publish(u64 puuid, u64 uuid, char *branch_name, char *tag,
                   u8 level, void *data, size_t data_len);
int branch_subscribe(u64 puuid, u64 uuid, char *branch_name, char *tag,
                     u8 level, branch_callback_t bc);
int branch_dispatch(void *arg);
int branch_dispatch_split(void *arg);

/* APIs we nneed from api.c */

typedef int (stat_local_t)(u64 puuid, u64 psalt, int column, struct hstat *);
typedef int (create_local_t)(u64 puuid, u64 psalt, struct hstat *, u32 flag,
                              struct mdu_update *);
typedef int (update_local_t)(u64 puuid, u64 psalt, struct hstat *,
                              struct mdu_update *);
typedef int (fread_local_t)(struct storage_index *, struct iovec**);
typedef int (fwrite_local_t)(struct storage_index *, void *,
                              u64 **);

extern stat_local_t __hvfs_stat_local;
extern create_local_t __hvfs_create_local;
extern update_local_t __hvfs_update_local;
extern fread_local_t __hvfs_fread_local, __mdsl_read_local;
extern fwrite_local_t __hvfs_fwrite_local, __mdsl_write_local;

struct branch_local_op
{
    stat_local_t *stat;
    create_local_t *create;
    update_local_t *update;
    fread_local_t *read;
    fwrite_local_t *write;
};
int branch_init(int hsize, int bto, u64 memlimit, struct branch_local_op *op);
void branch_destroy(void);

/* enhanced APIs we export based the version from api.c */
int hvfs_stat_eh(u64 puuid, u64 psalt, int column, struct hstat *);
int hvfs_create_eh(u64 puuid, u64 psalt, struct hstat *, u32 flag,
                   struct mdu_update *);
int hvfs_update_eh(u64 puuid, u64 psalt, struct hstat *,
                   struct mdu_update *);
int hvfs_fwrite_eh(struct hstat *hs, int column, u32 flag, 
                   void *data, size_t len, struct column *c);
ssize_t hvfs_fread_eh(struct hstat *hs, int column, void **data, 
                      struct column *c);

/* APIs from bp.c */
u64 bp_get_ack(struct branch_processor *bp, u64 site);
int bp_handle_bulk_push(struct branch_processor *bp, struct xnet_msg *msg,
                        struct branch_line_push_header *blph);

#endif
