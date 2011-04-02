/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-01 18:43:08 macan>
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

#ifndef __BP_H__
#define __BP_H__

#include "xnet.h"

struct branch_ack_cache_disk
{
    u64 site_id;
    u64 last_ack;
};

struct branch_ack_cache_entry
{
    struct hlist_node hlist;
    
    struct branch_ack_cache_disk bacd;
};

struct branch_ack_cache
{
    struct regular_hash *ht;
#define BAC_DEFAULT_SIZE        (4096)
    int hsize;
    atomic_t asize;
};

struct branch_processor;
struct branch_operator;
struct branch_op;
struct branch_op_result;
struct branch_line_disk;

typedef int (*open_t)(struct branch_operator *, 
                      struct branch_op_result *, 
                      struct branch_op *);
typedef int (*close_t)(struct branch_operator *);
typedef int (*flush_t)(struct branch_processor *,
                       struct branch_operator *, void **,
                       size_t *);
typedef int (*input_line_t)(struct branch_processor *,
                            struct branch_operator *,
                            struct branch_line_disk *,
                            u64, u64, int*);
typedef int (*output_line_t)(struct branch_processor *,
                             struct branch_operator *,
                             struct branch_line_disk *,
                             struct branch_line_disk **,
                             int *len, int *);
typedef int (*feed_tree_t)(struct branch_processor *,
                           struct branch_operator *,
                           struct branch_line_disk *,
                           u64, u64, int*);

/* the error state of branch operator
 */
#define BO_OK           0x00
#define BO_STOP         0x01
#define BO_FLUSH        0x02

struct branch_operator
{
    struct list_head list;      /* link to bp's op list */
    
    /* operator tree */
    struct branch_operator *left, *right;
    
    char *name;
    u32 id;
    u32 rid;
    u32 lor;
    
    /* ack cache */
    struct branch_ack_cache bac;
    /* data regin */
    void *code;                 /* pointer to foreign code */
    void *gdata;                /* pointer to global data */

    /* callback functions */
    open_t open;                /* called on open operation */
    close_t close;              /* called on close operation */
    flush_t flush;              /* called on flush operation */
    input_line_t input;         /* handle one input line */
    output_line_t output;       /* produce output line(s) */
    feed_tree_t tree;           /* feed the line to subtree, from left to
                                 * right */
};

struct branch_op_result_entry 
{
    u32 id;
    u32 len;                    /* at most 4GB */
    u8 data[0];
};

struct branch_op_result
{
    int nr;
    u32 reserved;
    struct branch_op_result_entry bore[0];
};

/* branch_log is used to write the log entry to log file or filter file
 */
struct branch_log_entry
{
    u64 ssite;
    time_t timestamp;
    char *tag;
    void *data;
    size_t data_len;
};

struct branch_log
{
    s64 value;
    int nr;
    struct branch_log_entry *ble;
};

struct branch_log_entry_disk
{
    u64 ssite;
    time_t timestamp;
    size_t data_len;
    u8 tag_len;
    u8 data[0];
};

struct branch_log_disk
{
    u8 type;
    int nr;
    s64 value;
    struct branch_log_entry_disk bled[0];
};

#define BRANCH_DISK_LOG         0x01
#define BRANCH_DISK_KNN         0x02
#define BRANCH_DISK_GB          0x03
#define BRANCH_DISK_INDEXER     0x04

/* branch_knn is used to manage the linked list of knn entry
 */
struct branch_knn_linear_entry
{
    struct list_head list;
    struct branch_log_entry ble;
    s64 value;
};

struct branch_knn_linear
{
    struct list_head ke;
    s64 center;
    s64 distance;
    int nr;
#define BKNN_POSITIVE   0x01
#define BKNN_MINUS      0x02
    u16 direction;
};

struct branch_knn_linear_entry_disk
{
    s64 value;
    struct branch_log_entry_disk bled;
};

/* NOTE that, each knn disk structure should put FLAG in the 16B offset
 * field! */
struct branch_knn_linear_disk
{
    u8 type;
    u8 direction;
    u16 flag;
    int nr;

    s64 center;
    s64 distance;
    struct branch_knn_linear_entry_disk bkled[0];
};

union branch_knn_disk
{
    u8 type;
    struct branch_knn_linear_disk bkld;
};

union branch_knn
{
    struct branch_knn_linear bkl;
};

#define BGB_MAX_OP      (4)
struct branch_groupby_entry_disk
{
    s64 values[BGB_MAX_OP];
    u64 lnrs[BGB_MAX_OP];
    int len;                    /* length of group name */
    char group[0];
};

struct branch_groupby_entry
{
    struct hlist_node hlist;
    char *group;                /* group name */
    s64 values[BGB_MAX_OP];
    u64 lnrs[BGB_MAX_OP];       /* for AVG operator */
};

struct branch_groupby_disk
{
    u8 type;
    u8 ops[BGB_MAX_OP];
    u32 nr;                     /* # of saved groups */
    struct branch_groupby_entry_disk bged[0];
};

struct branch_groupby
{
#define BGB_HASH_SIZE   (1024)
    struct regular_hash ht[BGB_HASH_SIZE]; /* a hash table for all groups */
    u32 nr;                                /* # of current groups */
#define BGB_NONE        0x00
#define BGB_SUM         0x01
#define BGB_AVG         0x02
#define BGB_MAX         0x03
#define BGB_MIN         0x04
#define BGB_COUNT       0x05
    u8 ops[BGB_MAX_OP];         /* left/right operator: you can only use the
                                 * following ops: SUM, AVG, MAX, MIN, COUNT
                                 */
};

#define BGB_HT_ADD(bge, bg) ({                              \
        u64 hash = __murmurhash64a((bge)->group,            \
                                   strlen((bge)->group),    \
                                   0xffeaddf0341f);         \
        int idx = hash % BGB_HASH_SIZE;                     \
        struct regular_hash *rh = &((bg)->bgb.ht[idx]);     \
        struct branch_groupby_entry *pos;                   \
        struct hlist_node *n;                               \
        int found = 0;                                      \
                                                            \
        xlock_lock(&rh->lock);                              \
        hlist_for_each_entry(pos, n, &rh->h, hlist) {       \
            if (strcmp(pos->group, (bge)->group) == 0) {    \
                /* already exist! */                        \
                found = 1;                                  \
                break;                                      \
            }                                               \
        }                                                   \
        xlock_unlock(&rh->lock);                            \
        if (!found) {                                       \
            hlist_add_head(&(bge)->hlist, &rh->h);          \
            (bg)->bgb.nr++;                                 \
        }                                                   \
        found;                                              \
    })

#define BGB_HT_TEST(group, bg, bge) ({                          \
            u64 hash = __murmurhash64a(group,                   \
                                       strlen(group),           \
                                       0xffeaddf0341f);         \
            int idx = hash % BGB_HASH_SIZE;                     \
            struct regular_hash *rh = &((bg)->bgb.ht[idx]);     \
            struct branch_groupby_entry *pos;                   \
            struct hlist_node *n;                               \
                                                                \
            (bge) = NULL;                                       \
            xlock_lock(&rh->lock);                              \
            hlist_for_each_entry(pos, n, &rh->h, hlist) {       \
                if (strcmp(pos->group, group) == 0) {           \
                    /* already exist! */                        \
                    (bge) = pos;                                \
                    break;                                      \
                }                                               \
            }                                                   \
            xlock_unlock(&rh->lock);                            \
            (bge);                                              \
        })
#define BGB_HT_CLEANUP(bg) do {                                         \
        struct branch_groupby_entry *tpos;                              \
        struct hlist_node *pos, *n;                                     \
        struct regular_hash *rh;                                        \
        int idx;                                                        \
                                                                        \
        for (idx = 0; idx < BGB_HASH_SIZE; idx++) {                     \
            rh = &((bg)->bgb.ht[idx]);                                  \
            xlock_lock(&rh->lock);                                      \
            hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {    \
                hlist_del(&tpos->hlist);                                \
                xfree(tpos->group);                                     \
                xfree(tpos);                                            \
            }                                                           \
            xlock_unlock(&rh->lock);                                    \
        }                                                               \
    } while (0)

#define BGB_HT_LEN(bg, len, nr) do {                                    \
        struct branch_groupby_entry *tpos;                              \
        struct hlist_node *pos, *n;                                     \
        struct regular_hash *rh;                                        \
        int idx;                                                        \
                                                                        \
        for (idx = 0; idx < BGB_HASH_SIZE; idx++) {                     \
            rh = &((bg)->bgb.ht[idx]);                                  \
            xlock_lock(&rh->lock);                                      \
            hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {    \
                (len) += strlen(tpos->group);                           \
                (nr)++;                                                 \
            }                                                           \
            xlock_unlock(&rh->lock);                                    \
        }                                                               \
    } while (0)

#define BGB_HT_SAVE(bg, bged) do {                                      \
        struct branch_groupby_entry *tpos;                              \
        struct hlist_node *pos, *n;                                     \
        struct regular_hash *rh;                                        \
        int idx, j, group_len;                                          \
                                                                        \
        for (idx = 0; idx < BGB_HASH_SIZE; idx++) {                     \
            rh = &((bg)->bgb.ht[idx]);                                  \
            xlock_lock(&rh->lock);                                      \
            hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {    \
                for (j = 0; j < BGB_MAX_OP; j++) {                      \
                    (bged)->values[j] = tpos->values[j];                \
                    (bged)->lnrs[j] = tpos->lnrs[j];                    \
                }                                                       \
                group_len = strlen(tpos->group);                        \
                (bged)->len = group_len;                                \
                memcpy((bged)->group, tpos->group, group_len);          \
                (bged) = (void *)(bged) + sizeof(*(bged)) + group_len;  \
            }                                                           \
            xlock_unlock(&rh->lock);                                    \
        }                                                               \
    } while (0)

struct branch_indexer_plain_disk
{
    u8 type;                    /* DISK_INDEXER */
    u32 flag;                   /* what is the type of indexer? */
    u64 nr;
};

struct branch_indexer_bdb_disk
{
    u8 type;                    /* DISK_INDEXER */
    u32 flag;                   /* what is the type of indexer? */
    u64 nr;
    u32 dbname_len, table_len;
    char data[0];
};

union branch_indexer_disk
{
    struct __self {
        u8 type;
        u32 flag;
        u64 nr;
    } s;
    struct branch_indexer_plain_disk bipd;
    struct branch_indexer_bdb_disk bibd;
};

struct branch_indexer_plain
{
    xlock_t lock;
#define BI_PLAIN_CHUNK          (4096)
    int size, offset;
    void *buffer;
};

struct branch_indexer_bdb
{
    char *dbname;
    char *table;
};

struct branch_indexer
{
    u64 nr;                     /* how many lines we handled? */
    union 
    {
        struct branch_indexer_plain plain;
        struct branch_indexer_bdb bdb;
    };
};

#define BP_DO_FLUSH(nr) ({                      \
    int __res = 0;                              \
    if (nr % BP_DEFAULT_FLUSH == 0)             \
        __res = 1;                              \
    __res;                                      \
})

struct branch_processor
{
    struct list_head oplist;    /* op list */
    void *bor;                  /* bor result buffer */
    atomic_t bonr;              /* # of branch operators */
    int bor_len;                /* region length of bor area */
    
    xlock_t lock;               /* protect bp update */
    
#define BP_DEFAULT_BTO          (30) /* 30 seconds */
    int bpto;
#define BP_DEFAULT_FLUSH        (30) /* for every 30 branch line, we issue a
                                      * flush command */
    int blnr;

    /* the following region is the branch processor memory table */
#define BP_DEFAULT_MEMLIMIT     (64 * 1024 * 1024)
    u64 memlimit;

    struct branch_entry *be;        /* pointer back to BE */
    struct branch_operator bo_root; /* the root operator */
};

/* bo_filter structure pointed by bo->gdata */
struct bo_filter
{
    /* accept_all:
     * -1: ignore this filter!
     *  1: accept all the input
     *  0: do regex
     */
    int accept_all;
#define BO_FILTER_CHUNK         (1024)
    int size, offset;

    regex_t preg;
    xlock_t lock;
    char *filename;
    /* internal buffer */
    void *buffer;
};

struct bo_sum
{
#define BS_LEFT         0
#define BS_RIGHT        1
#define BS_ALL          2
#define BS_MATCH        3
    int lor;
#define BS_COUNT        0x01
#define BS_SUM          0x02
#define BS_AVG          0x04
    u32 flag;

    regex_t preg;
    s64 value;
    u64 lnr;                    /* # of lines for AVG operator */
};

/* for max and min */
struct bo_mm
{
#define BMM_LEFT        0
#define BMM_RIGHT       1
#define BMM_ALL         2
#define BMM_MATCH       3
    u16 lor;
#define BMM_MAX         0
#define BMM_MIN         1
    u16 flag;

    regex_t preg;
    struct branch_log bl;
};

/* for knn */
struct bo_knn
{
#define BKNN_LEFT       0
#define BKNN_RIGHT      1
#define BKNN_ALL        2
#define BKNN_MATCH      3
    u16 lor;
#define BKNN_LINEAR     0x01
    u16 flag;

    regex_t preg;
    union branch_knn bkn;
};

/* for groupby */
struct bo_groupby
{
#define BGB_LEFT        0
#define BGB_RIGHT       1
#define BGB_ALL         2
#define BGB_MATCH       3
    u16 lor;

    regex_t preg;
    struct branch_groupby bgb;
};

/* for indexer */
struct bo_indexer
{
#define BIDX_PLAIN      0x01    /* plain file(unsorted) */
#define BIDX_BDB        0x02    /* BerkeleyDB */
    u16 flag;
    struct branch_indexer bi;
};

/* APIs */
int bp_handle_push(struct branch_processor *bp, struct xnet_msg *,
                   struct branch_line_disk *bld);
struct branch_processor *bp_alloc_init(struct branch_entry *,
                                       struct branch_op_result *);
int bac_load(struct branch_operator *, 
             struct branch_ack_cache_disk *, int);
int __bo_install_cb(struct branch_operator *bo, char *name);
void bp_destroy(struct branch_processor *bp);

#endif
