/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-26 21:38:26 macan>
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
#include "dh.h"
#include "cbht.h"
#include "mds_api.h"
#include "lib.h"
#include "async.h"

/* FIXME: we should implement a ARC/DULO cache */
struct itb_cache 
{
    struct list_head lru;
    atomic_t csize;             /* current cache size */
    xlock_t lock;
};

struct mds_conf 
{
    /* section for dynamic configuration */
    char dcaddr[MDS_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
    char *profiling_file;
    char *conf_file;
    char *log_file;

    /* section for file fd */
    int pf_fd, cf_fd, lf_fd;

    /* # of threads */
    /* NOTE: # of profiling thread is always ONE */
    int commit_threads;         /* # of commit threads */
    int service_threads;        /* # of service threads, pass this value to
                                     lnet serve-in threads' pool
                                     initialization */
    int async_threads;          /* # of async threads */
    int spool_threads;          /* # of service threads */
    int max_async_unlink;       /* max # of async unlink in one unlink wave */

    /* misc configs */
    int txc_hash_size;          /* TXC hash table size */
    int txc_ftx;                /* TXC init free TXs */
    int cbht_bucket_depth;      /* CBHT bucket depth */
    int itb_cache;
    int async_unlink;           /* enable/disable async unlink */
    int ring_vid_max;           /* max # of vid in the ring(AUTO) */
    int itb_depth_default;      /* default value of itb depth */
    int async_update_N;         /* default # of processing request */
    s8 itbid_check;             /* should we do ITBID check? */
    u8 cbht_slow_down;          /* set to 1 to eliminate the eh->lock
                                 * conflicts */

    /* intervals */
    int profiling_thread_interval;
    int txg_interval;
    int unlink_interval;

    /* conf */
#define HVFS_MDS_CHRECHK        0x01 /* recheck CH ring in fe dispatch */
#define HVFS_MDS_ITB_RWLOCK     0x02 /* use pthread rwlock as index lock */
#define HVFS_MDS_ITB_MUTEX      0x04 /* use pthread mutex as index lock */
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
    u64 gdt_uuid;               /* special UUID for GDT */
    u64 root_salt;
    u64 root_uuid;
    u64 group;
    u64 uuid_base;              /* the base value of UUID allocation */
    atomic64_t mi_tx;           /* next tx # */
    atomic64_t mi_txg;          /* next txg # */
    atomic64_t mi_uuid;         /* next file and dir uuid */
    atomic64_t mi_fnum;         /* total allocated file number */
    atomic64_t mi_dnum;         /* total allocated dir number */
};

struct hvfs_mds_object
{
    u64 site_id;                /* this site */
    struct xnet_context *xc;    /* the xnet context */

    struct mem_ops *mops;         /* memory management operations */
    struct eh cbht;               /* memory hash table */
    struct dh dh;                 /* directory hash table */

#define CH_RING_NUM     2
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
    struct chring *chring[CH_RING_NUM];
    struct mds_prof prof;
    struct mds_conf conf;
#define TXG_NUM         2
#define TXG_OPEN        0
#define TXG_WB          1
    struct hvfs_txg *txg[TXG_NUM];
    struct hvfs_txc txc;
    struct itb_cache ic;
#define HMO_STATE_LAUNCH        0x00
#define HMO_STATE_RUNNING       0x01
#define HMO_STATE_PAUSE         0x02
#define HMO_STATE_RDONLY        0x03
    u64 state;

    struct list_head async_unlink;

    /* the following region is used for threads */
    time_t unlink_ts;

    sem_t timer_sem;            /* for timer thread wakeup */
    sem_t commit_sem;           /* for commit thread wakeup */
    sem_t unlink_sem;           /* for unlink thread wakeup */
    sem_t async_sem;            /* for async thread wakeup */
    
    pthread_t timer_thread;
    pthread_t *commit_thread;   /* array of commit threads */
    pthread_t *async_thread;    /* array of async threads */
    pthread_t unlink_thread;
    pthread_t *spool_thread;    /* array of service threads */

    u8 timer_thread_stop;       /* running flag for timer thread */
    u8 commit_thread_stop;      /* running flag for commit thread */
    u8 async_thread_stop;       /* running flag for async thread */
    u8 dconf_thread_stop;       /* running flag for dconf thread */
    u8 unlink_thread_stop;      /* running flag for unlink thread */
    u8 spool_thread_stop;       /* running flag for service thread */
};

extern struct hvfs_mds_info hmi;
extern struct hvfs_mds_object hmo;
extern u32 hvfs_mds_tracing_flags;

struct dconf_req
{
#define DCONF_ECHO_CONF         0
#define DCONF_SET_TXG_INTV      1
#define DCONF_SET_PROF_INTV     2
#define DCONF_SET_UNLINK_INTV   3
    u64 cmd;
    u64 arg0;
};

/* this is the mds forward request header, we should save the route list
 * here. */
struct mds_fwd
{
    int len;
    u64 route[0];
};

/* APIs */
/* for mds.c */
int mds_init(int bdepth);
void mds_destroy(void);
void mds_reset_itimer(void);

/* for fe.c */
int mds_fe_dispatch(struct xnet_msg *msg);

/* for dispatch.c */
int mds_client_dispatch(struct xnet_msg *msg);
int mds_mds_dispatch(struct xnet_msg *msg);
int mds_mdsl_dispatch(struct xnet_msg *msg);
int mds_ring_dispatch(struct xnet_msg *msg);
int mds_root_dispatch(struct xnet_msg *msg);

/* for cbht.c */
struct bucket *cbht_bucket_alloc(int);
int cbht_bucket_init(struct eh *, struct segment *);
void cbht_copy_dir(struct segment *, u64, u64, struct eh *);
int cbht_enlarge_dir(struct eh *, u32);
int cbht_update_dir(struct eh *, struct bucket *);
int cbht_bucket_split(struct eh *, struct bucket *, u64, u32);
int mds_cbht_init(struct eh *, int);
void mds_cbht_destroy(struct eh *);
int mds_cbht_insert(struct eh *, struct itb *);
int mds_cbht_del(struct eh *, struct itb *);
struct bucket *mds_cbht_search_dir(u64, u32 *);
int mds_cbht_search(struct hvfs_index *, struct hvfs_md_reply *, 
                    struct hvfs_txg *, struct hvfs_txg **);
void cbht_print_dir(struct eh *);
void mds_cbht_search_dump_itb(struct hvfs_index *);
int mds_cbht_insert_bbrlocked(struct eh *, struct itb *, 
                              struct bucket **, 
                              struct bucket_entry **,
                              struct itb **);

/* for itb.c */
struct itb *mds_read_itb(u64, u64, u64);
void ite_update(struct hvfs_index *, struct ite *);
struct itb *get_free_itb();
void itb_free(struct itb *);
struct itb *itb_dirty(struct itb *, struct hvfs_txg *, struct itb_lock *,
                      struct hvfs_txg **);
int itb_search(struct hvfs_index *, struct itb *, void *, struct hvfs_txg *,
               struct itb **, struct hvfs_txg **);
int itb_readdir(struct hvfs_index *, struct itb *, struct hvfs_md_reply *);
int itb_cache_init(struct itb_cache *, int);
int itb_cache_destroy(struct itb_cache *);
void itb_dump(struct itb *);
void async_unlink(time_t t);
int unlink_thread_init(void);
void unlink_thread_destroy(void);
void async_unlink_ite(struct itb *, int *);
void itb_del_ite(struct itb *, struct ite *, u64, u64);
int __itb_add_ite_blob(struct itb *, struct ite *);
static inline void itb_get(struct itb *i)
{
    atomic_inc(&i->h.ref);
}
static inline void itb_put(struct itb *i)
{
    if (atomic_dec_return(&i->h.ref) == 0)
        itb_free(i);
}

/* for tx.c */
struct hvfs_tx *mds_alloc_tx(u16, struct xnet_msg *);
void mds_free_tx(struct hvfs_tx *);
void mds_pre_free_tx(int);
void mds_get_tx(struct hvfs_tx *);
void mds_put_tx(struct hvfs_tx *);
int mds_init_txc(struct hvfs_txc *, int, int);
int mds_destroy_txc(struct hvfs_txc *);
int mds_txc_add(struct hvfs_txc *, struct hvfs_tx *);
struct hvfs_tx *mds_txc_search(struct hvfs_txc *, u64, u64);
int mds_txc_evict(struct hvfs_txc *, struct hvfs_tx *);
void mds_tx_done(struct hvfs_tx *);
void mds_tx_reply(struct hvfs_tx *);
void mds_tx_commit(struct hvfs_tx *);
int mds_init_tx(u64);
void mds_destroy_tx(void);
void mds_tx_chg2forget(struct hvfs_tx *);

/* for txg.c: DRAFT */
void txg_add_itb(struct hvfs_txg *, struct itb *);
int txg_switch(struct hvfs_mds_info *, struct hvfs_mds_object *);
static inline void txg_get(struct hvfs_txg *t)
{
    atomic64_inc(&t->tx_pending);
}

static inline void txg_put(struct hvfs_txg *t)
{
    atomic64_dec(&t->tx_pending);
    if ((t->state != TXG_STATE_OPEN) && (atomic64_read(&t->tx_pending) == 0)) {
        /* signal the waiter, if exists */
        mcond_signal(&t->cond);
    }
}
int txg_init(u64);
void txg_changer(time_t);
int commit_tp_init(void);
void commit_tp_destroy(void);

/* for prof.c */
void dump_profiling(time_t);

/* for conf.c */
int dconf_init(void);
void dconf_destroy(void);

/* for dh.c */
int mds_dh_init(struct dh *, int);
void mds_dh_destroy(struct dh *);
struct dhe *mds_dh_load(struct dh *, u64);
struct dhe *mds_dh_insert(struct dh *, struct hvfs_index *);
struct dhe *mds_dh_search(struct dh *, u64);
int mds_dh_remove(struct dh *, u64);
u64 mds_get_itbid(struct dhe *, u64);
int mds_dh_bitmap_update(struct dh *, u64, u64, u8);
void mds_dh_bitmap_dump(struct dh *, u64);

/* for c2m.c, client 2 mds APIs */
void mds_statfs(struct hvfs_tx *);
void mds_lookup(struct hvfs_tx *);
void mds_create(struct hvfs_tx *);
void mds_release(struct hvfs_tx *);
void mds_update(struct hvfs_tx *);
void mds_linkadd(struct hvfs_tx *);
void mds_unlink(struct hvfs_tx *);
void mds_symlink(struct hvfs_tx *);
void mds_lb(struct hvfs_tx *);
void mds_dump_itb(struct hvfs_tx *);

/* for m2m.c, mds 2 mds APIs */
void mds_ldh(struct xnet_msg *msg);
void mds_ausplit(struct xnet_msg *msg);
void mds_forward(struct xnet_msg *msg);

/* for async.c */
int async_tp_init(void);
void async_tp_destroy(void);
void async_update_checking(time_t);
void au_handle_split_sync(void);

/* please do not move the follow section */
/* SECTION BEGIN */
#include "itb.h"
/* SECTION END */

/* APIs */
/* for spool.c */
int spool_create(void);
void spool_destroy(void);
int spool_dispatch(struct xnet_msg *);

/* APIs */
/* __txg_busy_loop_detector()
 *
 * NOTE: I observe the busy loop situation in the test cast this day, but it
 * is very hard to reproduce it, so I put this loop detector() here in the
 * following test cases to catch it.
 */
#define BLD_COUNT       0
#define BLD_RESET       1
static inline 
void __txg_busy_loop_detector(struct hvfs_txg *t, int bld)
{
    static int i = 0;
    if (bld == BLD_COUNT) {
        i++;
    } else if (bld == BLD_RESET) {
        i = 0;
    }
    if (i == 100000000) {
        HVFS_VV("TXG %p %ld state %x\n", t, t->txg, t->state);
        HVFS_BUG();
    }
}

static inline
struct hvfs_txg *mds_get_open_txg(struct hvfs_mds_object *hmo)
{
    struct hvfs_txg *t;

retry:
    /* get the txg first */
    t = hmo->txg[TXG_OPEN];     /* atomic read */
    txg_get(t);
    /* checking the txg state */
    if (t->state != TXG_STATE_OPEN) {
        /* oh, txg switched, for correctness, retry myself */
        txg_put(t);
        __txg_busy_loop_detector(t, BLD_COUNT);
        goto retry;
    }

    __txg_busy_loop_detector(t, BLD_RESET);
    return t;
}

static inline
struct hvfs_txg *mds_get_wb_txg(struct hvfs_mds_object *hmo)
{
    return hmo->txg[TXG_WB];
}

#endif
