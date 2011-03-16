/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-16 11:19:34 macan>
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

    regex_t preg;
    u64 value;
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
