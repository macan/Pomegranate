/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-07 16:35:45 macan>
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

#ifndef __MDS_H__
#define __MDS_H__

#include "hvfs.h"
#include "prof.h"
#include "txg.h"
#include "tx.h"
#include "itb.h"
#include "cbht.h"
#include "mds_api.h"
#include "lib.h"

struct mds_conf 
{
    /* section for file name */
    char *profiling_file;
    char *conf_file;
    char *log_file;

    /* section for file fd */
    int pf_fd, cf_fd, lf_fd;

    /* intervals */
    int profiling_thread_interval;
    int txg_interval;

    /* conf */
#define HVFS_MDS_CHRECHK        0x01 /* recheck CH ring in fe dispatch */
    u64 option;
};

/*
 * Read(open) from the r2 manager. If reopen an opened one, r2 should initiate
 * the recover process to get the newest values from the MDSLs.
 */
struct hvfs_mds_info 
{
#define HMI_STATE_CLEAN         0x01
#define HMI_STATE_LASTOPEN      0x02
#define HMI_STATE_LASTMIG       0x03
#define HMI_STATE_LASTPAUSE     0x04
    u32 state;
    u64 gdt_salt;
    u64 gdt_uuid;
    u64 root_salt;
    u64 root_uuid;
    u64 group;
    atomic64_t mi_tx;           /* next tx # */
    atomic64_t mi_txg;          /* next txg # */
    atomic64_t mi_fuuid;        /* next file uuid */
    atomic64_t mi_duuid;        /* next dir uuid */
    atomic64_t mi_fnum;         /* total allocated file number */
    atomic64_t mi_dnum;         /* total allocated dir number */
};

struct hvfs_mds_object
{
    u64 site_id;                /* this site */
    struct xnet_context *xc;    /* the xnet context */

    struct mem_ops *mops;         /* memory management operations */
    struct eh cbht;               /* memory hash table */
    struct regular_hash *dh;      /* directory hash table */

#define CH_RING_NUM     2
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
    struct chring *chring[CH_RING_NUM];
    struct mds_prof profiling;
    struct mds_conf conf;
    struct hvfs_txg txg;
    struct hvfs_txc txc;
    struct itb_cache ic;
#define HMO_STATE_LAUNCH        0x00
#define HMO_STATE_RUNNING       0x01
#define HMO_STATE_PAUSE         0x02
#define HMO_STATE_RDONLY        0x03
    u64 state;
};

extern struct hvfs_mds_info hmi;
extern struct hvfs_mds_object hmo;
extern u32 hvfs_mds_tracing_flags;

/* APIs */
/* for dispatch.c */
void mds_client_dispatch(struct xnet_msg *msg);
void mds_mds_dispatch(struct xnet_msg *msg);
void mds_mdsl_dispatch(struct xnet_msg *msg);
void mds_ring_dispatch(struct xnet_msg *msg);
void mds_root_dispatch(struct xnet_msg *msg);

/* for cbht.c */
struct bucket *cbht_bucket_alloc(int);
int cbht_bucket_init(struct eh *, struct segment *);
void cbht_copy_dir(struct segment *, u64, u64, struct eh *);
int cbht_enlarge_dir(struct eh *);
int cbht_update_dir(struct eh *, struct bucket *);
int cbht_bucket_split(struct eh *, struct bucket *, u64, struct bucket **);
int mds_cbht_init(struct eh *, int);
void mds_cbht_destroy(struct eh *);
int mds_cbht_insert(struct eh *, struct itb *);
int mds_cbht_del(struct eh *, struct itb *);
struct bucket *mds_cbht_search_dir(u64);
int mds_cbht_search(struct hvfs_index *, struct hvfs_md_reply *, struct hvfs_txg *);

/* for itb.c */
struct itb *mds_read_itb(u64, u64, u64);
void ite_update(struct hvfs_index *, struct ite *);
struct itb *get_free_itb();
void itb_free(struct itb *);
struct itb *itb_cow(struct itb *);
struct itb *itb_dirty(struct itb *, struct hvfs_txg *);
int itb_search(struct hvfs_index *, struct itb *, void *, struct hvfs_txg *);
int itb_readdir(struct hvfs_index *, struct itb *, struct hvfs_md_reply *);
int itb_cache_init(struct itb_cache *, int);
int itb_cache_destroy(struct itb_cache *);

/* for txg.c: DRAFT */
void txg_add_itb(struct hvfs_txg *, struct itb *);

#endif
