/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-02-21 19:07:28 macan>
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

#ifndef __MDSL_H__
#define __MDSL_H__

#include "hvfs.h"
#include "txg.h"
#include "mdsl_api.h"
#include "lprof.h"
#include "lib.h"
#include "ring.h"
#include "mdsl_config.h"
#include "profile.h"

#ifdef HVFS_TRACING
extern u32 hvfs_mdsl_tracing_flags;
#endif

#define HVFS_MDSL_HOME "/tmp/hvfs"

#define MDSL_STORAGE_DEFAULT_CHUNK              (4 * 1024 * 1024)
#define MDSL_STORAGE_ITB_DEFAULT_CHUNK          (64 * 1024 * 1024)
#define MDSL_STORAGE_DATA_DEFAULT_CHUNK         (64 * 1024 * 1024)

/* mmap window */
struct mmap_window 
{
    void *addr;
    loff_t offset;              /* the offset of this mmap file */
    loff_t file_offset;         /* the file offset */
    size_t len;
    u64 arg;
    u64 flag;
};

struct mmap_args                /* got from the md file */
{
    size_t win;                 /* window size of the mmap region */
    loff_t foffset;             /* foffset */
    u64 range_id;               /* range for select the range file */
    u64 range_begin;
#define MA_OFFICIAL             0x00
#define MA_GC                   0x01
    u32 flag;
};

/* append buffer */
struct append_buf
{
    void *addr;
    size_t len;
    size_t acclen;              /* accumulate length */
    u64 falloc_size;
    loff_t file_offset;         /* offset of the mapped file */
    loff_t offset;              /* the data offset within the buf */
    loff_t falloc_offset;       /* where to fallocate */
};

/* md disk structure */
struct range_
{
#define MDSL_RANGE_MASK         0x0f
#define MDSL_RANGE_PRIMARY      0x00
#define MDSL_RANGE_SECONDARY    0x01
#define MDSL_RANGE_THIRD        0x02
    u64 begin, end;             /* the range type is in the low bits of
                                 * begin */
    u64 range_id;
};
typedef struct range_ range_t;

#define MDSL_MDISK_RANGE        0x01
struct md_disk
{
    /* region for range */
    u32 winsize;                /* the window size of the each range file */
    u32 range_nr[3];            /* primary, secondary, third replicas */
    range_t *new_range;         /* region for new ranges comming in */
    range_t *ranges;            /* ranges loaded from disk file */
    u64 gc_offset;
    int new_size;
    int size;                   /* total size of the ranges from disk */
    u32 range_aid;              /* alloc id of range */

    /* region for itb/data file */
    u32 itb_master;
    u32 data_master;
};

#define DISK_SEC        (512)
#define DISK_SEC_ROUND_UP(x) (x = ((x + (DISK_SEC - 1)) & ~(DISK_SEC - 1)))
struct odirect
{
    int wfd, rfd;               /* wfd is for odirect write, rfd is for
                                 * buffered reading */
    void *addr;
    size_t len;
    loff_t file_offset;
    loff_t offset;
};

struct bmmap                    /* mmap of bitmap */
{
    void *addr;
    size_t len;
    loff_t file_offset;
    xlock_t lock;
};

union bmmap_disk
{
    struct __bmmap_disk
    {
        size_t size;
        int used;
        /* Note that, the low 10 bits are in region index */
#define BMMAP_DISK_NR_SHIFT     (10)
#define BMMAP_DISK_INDEX_MASK   ((1UL << BMMAP_DISK_NR_SHIFT) - 1)
        s64 sarray[0];          /* sorted array of bitmap slice id */
    } bd;
    u8 __array[4096];
};

struct proxy_args
{
    u64 uuid;                   /* uuid of this file */
    u64 cno;                    /* column number of this file */
};

struct proxy
{
    u64 foffset;                /* current file offset */
};

struct fdhash_entry
{
    struct hlist_node list;
    struct list_head lru;
    xlock_t lock;               /* write lock? */
    xcond_t cond;               /* cond var for FDE_LOCKED state */
    u64 uuid;
    u64 arg;
    atomic_t ref;
    int type;
    int fd;
#define FDE_FREE        0       /* just created */
#define FDE_OPEN        1       /* file opened */
#define FDE_MEMWIN      2       /* mem window access */
#define FDE_ABUF        3       /* append-buf access */
#define FDE_NORMAL      4       /* normal access */
#define FDE_ABUF_UNMAPPED       5 /* append-buf access w/o mapping  */
#define FDE_MDISK       6         /* md disk structure accessing */
#define FDE_ODIRECT     7         /* using the O_DIRECT to write */
#define FDE_BITMAP      8         /* bitmap of dir */
#define FDE_LOCKED      9       /* lock this md file */
    short state;
#define FDE_AUX_FREE    0
#define FDE_AUX_LOCKED  1
    short aux_state;            /* for lock */
    union 
    {
        struct md_disk mdisk;
        struct mmap_window mwin;
        struct append_buf abuf;
        struct odirect odirect;
        struct bmmap bmmap;
        struct proxy proxy;
    };
};

struct mdsl_storage_access
{
    struct iovec *iov;
    void *arg;
    loff_t offset;              /* file offset, if -1 we just acces @ current
                                 * location */
    int iov_nr;
};

extern struct mdsl_storage ms;

struct txg_compact_cache
{
    struct list_head free_list;   /* txg_open_entry free list */
    struct list_head active_list; /* txg entry just in memory */
    struct list_head wbed_list;   /* txg entry already to disk but waiting for
                                   * TXG_END */
    struct list_head tmp_list;  /* txg entry written to disk temp file */
    xlock_t free_lock;
    xlock_t active_lock;
    xlock_t wbed_lock;
    atomic_t size, used;
};

struct txg_open_entry_disk
{
    struct list_head list;
#define TXG_OPEN_ENTRY_DISK_BEGIN       0x01
#define TXG_OPEN_ENTRY_DISK_ITB         0x02
#define TXG_OPEN_ENTRY_DISK_DIR         0x04
#define TXG_OPEN_ENTRY_DISK_BITMAP      0x08
#define TXG_OPEN_ENTRY_DISK_CKPT        0x10
#define TXG_OPEN_ENTRY_DISK_END         0x20
#define TXG_OPEN_ENTRY_DISK_DIR_R       0x40
#define TXG_OPEN_ENTRY_DISK_RDIR        0x80
    u32 type;
    u32 len;
    u64 ssite;
    u64 txg;
};

struct directw_log
{
};

struct mdsl_storage
{
#define MDSL_STORAGE_FDHASH_SIZE        2048
    struct regular_hash *fdhash;
    struct list_head lru;
    xlock_t lru_lock;
    xlock_t txg_fd_lock;
    xlock_t tmp_fd_lock;
    /* global fds */
    int txg_fd, tmp_fd, tmp_txg_fd, log_fd, split_log_fd;
    atomic_t active;
    atomic_t peace;          /* peace counter count the MDSL slient seconds */
    atomic64_t memcache;
    xcond_t cond;               /* condition var for read controller */
};

struct mdsl_conf
{
    /* section for dynamic configuration */
    char dcaddr[MDSL_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
    char *mdsl_home;
    char *profiling_file;
    char *conf_file;
    char *log_file;

    /* section for file fd */
    FILE *pf_file, *cf_file, *lf_file;

    /* # of threads */
    /* NOTE: # of profiling thread is always ONE */
    int spool_threads;          /* # of service threads */
    int aio_threads;            /* # of io threads */

    /* misc configs */
    u64 memlimit;               /* memlimit of the TCC */
    u64 fdlimit;                /* fd limit of the mem cache */
    u64 mclimit;                /* memcache threshold */
    u64 pcct;                   /* pagecache cleanup threshold */
    int itb_falloc;             /* # of itb file chunk to pre-alloc */
    int ring_vid_max;           /* max # of vid in the ring(AUTO) */
    int tcc_size;               /* # of tcc cache size */
    int storage_fdhash_size;    /* # of storage fdhash size */
    int itb_file_chunk;         /* chunk size of the itb file */
    int data_file_chunk;        /* chunk size of the data file */
    int fd_cleanup_N;           /* # of fds to cleanup for each tick */
    int stacksize;              /* pthread stack size */
    int disk_low_load;          /* describe the disk low load threshold. This
                                 * value is very important for slow disk, you
                                 * should set this value lower if you find
                                 * that mdsl is slow. */
    int expection;              /* this value impact the AIO sync length
                                 * adjusting, larger value leads to larger
                                 * block! */
    int rread_max;              /* the concurrent random read max value */
    u32 aio_sync_len;           /* sync chunnk size for AIO */
    u32 aio_expect_bw;          /* user expected IO bandwidth per disk */
#define MDSL_PROF_NONE          0x00
#define MDSL_PROF_PLOT          0x01
#define MDSL_PROF_HUMAN         0x02
#define MDSL_PROF_R2            0x03
    u8 prof_plot;               /* do we dump profilings for gnuplot */

    /* intervals */
    int profiling_thread_interval;
    int gc_interval;            /* garbage collection interval */
    int hb_interval;            /* heart beat interval */

    /* conf */
#define HVFS_MDSL_WDROP         0x01 /* drop all the writes to this MDSL */
#define HVFS_MDSL_MEMLIMIT      0x02 /* limit the TCC memory usage */
#define HVFS_MDSL_RADICAL_DEL   0x04 /* radical delete the memory resource for
                                      * deleted directory */
    u64 option;
};

struct hvfs_mdsl_object
{
    u64 site_id;                /* this site */
    struct xnet_context *xc;

    struct txg_compact_cache tcc;
    struct mdsl_storage storage;
    struct directw_log dl;

#define CH_RING_NUM     3
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
#define CH_RING_BP      2
    struct chring *chring[CH_RING_NUM];
    struct mdsl_prof prof;
    struct mdsl_conf conf;
#define HMO_STATE_INIT          0x00
#define HMO_STATE_LAUNCH        0x01
#define HMO_STATE_RUNNING       0x02
#define HMO_STATE_PAUSE         0x03
#define HMO_STATE_RDONLY        0x04
#define HMO_STATE_OFFLINE       0x05
    u32 state;

#define HMO_AUX_STATE_RECOVERY  0x01
    u32 aux_state;

    u64 ring_site;
#define HMO_SESSION_BEGIN       0xff00000000000000
#define HMO_SESSION_END         0x00ff000000000000
#define HMO_SESSION_MASK        0xffff000000000000
    u64 session;                /* current session id */
    time_t tick;                /* tick of this MDSL */

    /* the following region is used for threads */
    sem_t timer_sem;            /* for timer thread wakeup */
    atomic64_t pending_ios;     /* pending IOs */
    
    pthread_t timer_thread;
    pthread_t *spool_thread;    /* array of service threads */
    pthread_t *aio_thread;      /* array of aio threads */

    /* mdsl profiling array */
    struct hvfs_profile hp;

    u32 timer_thread_stop:1;    /* running flag for timer thread */
    u32 spool_thread_stop:1;    /* running flag for service thread */
    u32 aio_thread_stop:1;      /* running flag for aio thread */

    /* callback functions */
    void (*cb_exit)(void *);
    void (*cb_hb)(void *);
    void (*cb_ring_update)(void *);
    void (*cb_addr_table_update)(void *);
};

extern struct hvfs_mdsl_info hmi;
extern struct hvfs_mdsl_object hmo;

/* APIs */
void mdsl_pre_init(void);
void mdsl_help(void);
int mdsl_verify(void);
int mdsl_init(void);
void mdsl_destroy(void);
u64 mdsl_select_ring(struct hvfs_mdsl_object *);
void mdsl_set_ring(u64);
int mdsl_ring_update(struct xnet_msg *);
int mdsl_addr_table_update(struct xnet_msg *);

/* spool.c */
int mdsl_spool_create(void);
void mdsl_spool_destroy(void);
int mdsl_spool_dispatch(struct xnet_msg *);
void mdsl_spool_redispatch(struct xnet_msg *, int);

int mdsl_tcc_init(void);
void mdsl_tcc_destroy(void);

/* dispatch.c */
int mdsl_dispatch(struct xnet_msg *);
/*
 * Return value: 1: pause the handling; 0: running
 */
extern atomic_t itb_loads;
static inline
int mdsl_dispatch_check(struct xnet_msg *msg)
{
    if (msg->tx.cmd == HVFS_MDS2MDSL_ITB) {
        if (atomic_inc_return(&itb_loads) >= hmo.conf.spool_threads) {
            atomic_dec(&itb_loads);
            return 1;
        }
    }

    return 0;
}

/* m2ml.c */
void mdsl_itb(struct xnet_msg *);
void mdsl_bitmap(struct xnet_msg *);
void mdsl_wbtxg(struct xnet_msg *);
void mdsl_wdata(struct xnet_msg *);
void mdsl_bitmap_commit(struct xnet_msg *);
void mdsl_bitmap_commit_v2(struct xnet_msg *);
void mdsl_analyse(struct xnet_msg *);

/* c2ml.c */
void mdsl_read(struct xnet_msg *);
void mdsl_write(struct xnet_msg *);
void mdsl_statfs(struct xnet_msg *);

/* prof.c */
void mdsl_dump_profiling(time_t, struct hvfs_profile *hp);

/* tcc.c */
int mdsl_tcc_init(void);
void mdsl_tcc_destroy(void);
struct txg_open_entry *get_txg_open_entry(struct txg_compact_cache *);
void put_txg_open_entry(struct txg_open_entry *);
struct txg_open_entry *toe_lookup(u64, u64);
struct txg_open_entry *toe_lookup_recent(u64);
void toe_put(struct txg_open_entry *);
int itb_append(struct itb *, struct itb_info *, u64, u64);
int toe_to_tmpfile(int, u64, u64, void *);
int toe_to_tmpfile_N(int, u64, u64, void *, int);
void toe_active(struct txg_open_entry *);
void toe_deactive(struct txg_open_entry *);
void toe_wait(struct txg_open_entry *, int);

/* storage.c */
#define MDSL_STORAGE_IO_PEAK    ((u64)(CPU_CORE) << 1)

#define MDSL_STORAGE_MD         0x0000
#define MDSL_STORAGE_ITB        0x0001
#define MDSL_STORAGE_RANGE      0x0002
#define MDSL_STORAGE_DATA       0x0003
#define MDSL_STORAGE_DIRECTW    0x0004
#define MDSL_STORAGE_ITB_ODIRECT        0x0005
#define MDSL_STORAGE_BITMAP     0x0006
#define MDSL_STORAGE_NORMAL     0x0007

#define MDSL_STORAGE_LOG        0x0100
#define MDSL_STORAGE_SPLIT_LOG  0x0200
#define MDSL_STORAGE_TXG        0x0300
#define MDSL_STORAGE_TMP_TXG    0x0400

#define MDSL_STORAGE_RANGE_SHIFT        20
#define MDSL_STORAGE_DEFAULT_RANGE_SIZE             \
    (1UL << (3 + MDSL_STORAGE_RANGE_SHIFT)) /* 8MB */
#define MDSL_STORAGE_idx2range(idx)     (idx >> MDSL_STORAGE_RANGE_SHIFT)
#define MDSL_STORAGE_RANGE_SLOTS        (1UL << MDSL_STORAGE_RANGE_SHIFT)

#define MDSL_FILE_BULK_LOAD             0x0000
#define MDSL_FILE_BULK_LOAD_DROP        0x000f

int mdsl_storage_init(void);
void mdsl_storage_destroy(void);
struct fdhash_entry *mdsl_storage_fd_lookup_create(u64, int, u64);
static inline
void mdsl_storage_fd_put(struct fdhash_entry *fde)
{
    atomic_dec(&fde->ref);
}
void mdsl_storage_pending_io(void);
int mdsl_storage_clean_dir(u64);
int mdsl_storage_evict_rangef(u64);
void mdsl_storage_fd_limit_check(time_t);
int mdsl_storage_fd_cleanup(struct fdhash_entry *fde);
int append_buf_create(struct fdhash_entry *, char *, int);
int append_buf_flush_trunc(struct fdhash_entry *, u64);
int mdsl_storage_fd_write(struct fdhash_entry *fde, 
                          struct mdsl_storage_access *msa);
int mdsl_storage_fd_read(struct fdhash_entry *fde, 
                         struct mdsl_storage_access *msa);
int mdsl_storage_dir_make_exist(char *path);
int __range_lookup(u64, u64, struct mmap_args *, u64 *);
int __range_write(u64, u64, struct mmap_args *, u64);
int __range_write_conditional(u64, u64, struct mmap_args *, u64);
int __mdisk_lookup(struct fdhash_entry *, int, u64, range_t **);
int __mdisk_add_range(struct fdhash_entry *, u64, u64, u64);
int mdsl_storage_toe_commit(struct txg_open_entry *, struct txg_end *);
int mdsl_storage_update_range(struct txg_open_entry *);
void mdsl_storage_fd_pagecache_cleanup(void);
int mdsl_storage_fd_lockup(struct fdhash_entry *);
int mdsl_storage_fd_unlock(struct fdhash_entry *);
u64 mdsl_storage_fd_max_offset(struct fdhash_entry *);
void mdsl_storage_fd_remove(struct fdhash_entry *);
int mdsl_storage_find_max_txg(u64, u64 *, int);
void mdsl_startup_normal(void);
void mdsl_exit_normal(void);
int mdsl_txg_integrated(void);

/* internal API of storage layer */
int mdsl_storage_fd_mdisk(struct fdhash_entry *fde, char *path);
int __mdisk_write(struct fdhash_entry *fde, struct mdsl_storage_access *msa);
int __mdisk_lookup_nolock(struct fdhash_entry *fde, int op, u64 arg, 
                          range_t **out);
int __mdisk_add_range_nolock(struct fdhash_entry *fde, u64 begin, u64 end, 
                             u64 range_id);
void __mdisk_range_sort(void *ranges, size_t size);
int append_buf_destroy_async(struct fdhash_entry *fde);

/* defines for buf flush */
#define ABUF_ASYNC      0x01
#define ABUF_UNMAP      0x02
#define ABUF_SYNC       0x04
#define ABUF_TRUNC      0x08
#define ABUF_XSYNC      0x10    /* XSYNC means use MS_ASYNC for msync() */

/* aio.c */
#define MDSL_AIO_SYNC           0x01
#define MDSL_AIO_SYNC_UNMAP     (ABUF_ASYNC | ABUF_UNMAP)
#define MDSL_AIO_SYNC_UNMAP_TRUNC       (ABUF_ASYNC | ABUF_UNMAP | \
                                         ABUF_TRUNC)
#define MDSL_AIO_SYNC_UNMAP_XSYNC       (ABUF_ASYNC | ABUF_UNMAP | \
                                         ABUF_XSYNC)
#define MDSL_AIO_ODIRECT        0x04
#define MDSL_AIO_READ           0x10
void aio_tune_bw(void);
int mdsl_aio_queue_empty(void);
u64 aio_sync_length(void);
int mdsl_aio_create(void);
void mdsl_aio_destroy(void);
int mdsl_aio_submit_request(void *addr, u64 len, u64, loff_t, int, int);
void mdsl_aio_start(void);

/* gc.c */
struct gc_data_stat
{
    u64 total, valid, hole, max;
};
#define GC_DATA_NONE    0x00
#define GC_DATA_STAT    0x01
#define GC_DATA         0x02
int mdsl_gc_md(u64);
int mdsl_gc_data_stat(u64 duuid, int column, struct gc_data_stat *gds);
int mdsl_gc_data_by_trunc(u64 duuid, int column);

/* ml2ml.c */
int mdsl_do_recovery(void);

#endif
