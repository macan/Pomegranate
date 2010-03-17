/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-17 12:33:42 macan>
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
    loff_t offset;                 /* the data offset with respect to window */
    size_t len;
};

/* append buffer */
struct append_buf
{
    void *addr;
    size_t len;
    loff_t file_offset;              /* offset of the mapped file */
    loff_t offset;                   /* the data offset within the buf */
};

struct fdhash_entry
{
    struct hlist_node list;
    xlock_t lock;
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
    int state;
    union 
    {
        struct mmap_window mwin;
        struct append_buf abuf;
    };
};

struct mdsl_storage_access
{
    struct iovec *iov;
    void *arg;
    int iov_nr;
};

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
    /* global fds */
    int txg_fd, tmp_txg_fd, log_fd, split_log_fd;
};

struct mdsl_conf
{
    /* section for dynamic configuration */
    char dcaddr[MDSL_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
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
    int ring_vid_max;           /* max # of vid in the ring(AUTO) */
    int tcc_size;               /* # of tcc cache size */
    int storage_fdhash_size;    /* # of storage fdhash size */
    int itb_file_chunk;         /* chunk size of the itb file */
    int data_file_chunk;        /* chunk size of the data file */
    u8 prof_plot;               /* do we dump profilings for gnuplot */

    /* intervals */
    int profiling_thread_interval;
    int gc_interval;

    /* conf */
#define HVFS_MDSL_WDROP         0x01 /* drop all the writes to this MDSL */
#define HVFS_MDSL_MEMLIMIT      0x02 /* limit the TCC memory usage */
    u64 option;
};

struct hvfs_mdsl_info
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
    u64 uuid_base;
    atomic64_t mi_tx;           /* next tx # */
    atomic64_t mi_txg;          /* next txg # */
    atomic64_t mi_uuid;         /* next file uuid */
    atomic64_t mi_fnum;         /* total allocated file # */
};

struct hvfs_mdsl_object
{
    u64 site_id;                /* this site */
    struct xnet_context *xc;

    struct txg_compact_cache tcc;
    struct mdsl_storage storage;
    struct directw_log dl;

#define CH_RING_NUM     2
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
    struct chring *chring[CH_RING_NUM];
    struct mdsl_prof prof;
    struct mdsl_conf conf;
#define HMO_STATE_LAUNCH        0x00
#define HMO_STATE_RUNNING       0x01
#define HMO_STATE_PAUSE         0x02
#define HMO_STATE_RDONLY        0x03
    u32 state;

    /* the following region is used for threads */
    sem_t timer_sem;            /* for timer thread wakeup */
    
    pthread_t timer_thread;
    pthread_t *spool_thread;    /* array of service threads */
    pthread_t *aio_thread;      /* array of aio threads */

    u8 timer_thread_stop;       /* running flag for timer thread */
    u8 spool_thread_stop;       /* running flag for service thread */
    u8 aio_thread_stop;         /* running flag for aio thread */
};

extern struct hvfs_mdsl_info hmi;
extern struct hvfs_mdsl_object hmo;

/* APIs */
void mdsl_pre_init(void);
void mdsl_help(void);
int mdsl_verify(void);
int mdsl_init(void);
void mdsl_destroy(void);

/* spool.c */
int mdsl_spool_create(void);
void mdsl_spool_destroy(void);
int mdsl_spool_dispatch(struct xnet_msg *);

int mdsl_tcc_init(void);
void mdsl_tcc_destroy(void);

/* dispatch.c */
int mdsl_dispatch(struct xnet_msg *);

/* m2ml.c */
void mdsl_itb(struct xnet_msg *);
void mdsl_bitmap(struct xnet_msg *);
void mdsl_wbtxg(struct xnet_msg *);
void mdsl_wdata(struct xnet_msg *);

/* prof.c */
void mdsl_dump_profiling(time_t);

/* tcc.c */
int mdsl_tcc_init(void);
void mdsl_tcc_destroy(void);
struct txg_open_entry *get_txg_open_entry(struct txg_compact_cache *);
void put_txg_open_entry(struct txg_open_entry *);
struct txg_open_entry *toe_lookup(u64, u64);
int itb_append(struct itb *, struct itb_info *, u64, u64);
int toe_to_tmpfile(int, u64, u64, void *);

/* storage.c */
#define MDSL_STORAGE_MD         0x0000
#define MDSL_STORAGE_ITB        0x0001
#define MDSL_STORAGE_RANGE      0x0002
#define MDSL_STORAGE_DATA       0x0003
#define MDSL_STORAGE_DIRECTW    0x0004

#define MDSL_STORAGE_LOG        0x0100
#define MDSL_STORAGE_SPLIT_LOG  0x0200
#define MDSL_STORAGE_TXG        0x0300
#define MDSL_STORAGE_TMP_TXG    0x0400

int mdsl_storage_init(void);
void mdsl_storage_destroy(void);
struct fdhash_entry *mdsl_storage_fd_lookup_create(u64, int, u64);
static inline
void mdsl_storage_fd_put(struct fdhash_entry *fde)
{
    atomic_dec(&fde->ref);
}
int append_buf_create(struct fdhash_entry *, char *, int);
int mdsl_storage_fd_write(struct fdhash_entry *fde, 
                          struct mdsl_storage_access *msa);
/* defines for buf flush */
#define ABUF_ASYNC      0x01
#define ABUF_UNMAP      0x02
#define ABUF_SYNC       0x04

/* aio.c */
#define MDSL_AIO_SYNC           0x01
#define MDSL_AIO_SYNC_UNMAP     0x03
int mdsl_aio_create(void);
void mdsl_aio_destroy(void);
int mdsl_aio_submit_request(void *addr, u64 len, u64, int flag);
void mdsl_aio_start(void);

#endif
