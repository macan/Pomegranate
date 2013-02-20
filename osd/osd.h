/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2013-02-19 14:32:16 macan>
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

#ifndef __OSD_H__
#define __OSD_H__

#include "hvfs.h"
#include "obj.h"
#include "xnet.h"
#include "lprof.h"
#include "root.h"
#include "osd_config.h"

#ifdef HVFS_TRACING
extern u32 hvfs_osd_tracing_flags;
#endif

#define HVFS_OSD_HOME "/tmp/hvfs"

#define OSD_DEFAULT_PREFIX_LEN          4

struct log_manager
{
    atomic_t addnr;
    atomic_t delnr;
    struct list_head add;
    struct list_head del;
    xlock_t add_lock;
    xlock_t del_lock;
};

struct scan_manager
{
    struct list_head head;
    xlock_t lock;
};

struct round_robin_algo
{
    int cur;                    /* current position */
};

union selector_algo
{
    struct round_robin_algo rra;
};

struct store_array_manager
{
    char **store_array;         /* copied from hoo.conf.osd_storages_array */
    int array_size;             /* copied from
                                 * hoo.conf.osd_storages_array_size */
    union selector_algo sa;     /* selector algorithms */
};

struct osd_storage
{
    xlock_t objlog_fd_lock;        /* obj log file's lock */
    int objlog_fd;                 /* obj log file FD */
    struct store_array_manager am; /* storage array manager */
    struct log_manager lm;         /* obj add/del in current session */
    struct scan_manager sm;
};

struct obj_gather
{
    int asize, psize;
    struct objid_dev *ids;
};

struct obj_gather_all
{
    int cur;                    /* current dev */
    struct obj_gather add, rmv;
};

/* oga_manager manage a OGA array for all the active blocks
 */
struct oga_manager
{
    struct obj_gather_all *oga;
    xlock_t lock;
    xlock_t changed_lock;
    /* hash table for fast lookup */
#define HVFS_OSD_OM_HSIZE       10240
    struct regular_hash *ht;
    struct list_head changed;
    struct list_head changed_saving;
    int hsize;
#define OM_REPORT_ALL           0x00 /* init report all, then reset to DIFF */
#define OM_REPORT_BEGIN_SCAN    0x01
#define OM_REPORT_END_SCAN      0x02
#define OM_REPORT_DIFF          0x03
    u8 report_type;
#define OM_REPORT_PAUSE         0x00
#define OM_REPORT_ACTIVE        0x01
    u8 should_send;
};

struct om_entry
{
    struct hlist_node hlist;
    struct objid id;
    int dev;                    /* which device this obj exists */
};

struct om_changed_entry
{
    struct list_head list;
    struct objid id;
#define OM_UPDATE       0
#define OM_DELETE       1
    int upd_or_del;
};

struct osd_conf
{
    /* section for dynamic configuration */
    char dcaddr[OSD_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
    char *osd_home;
    char *profiling_file;
    char *conf_file;
    char *log_file;             /* log file(HOME/log) for osd add/del */

    /* section for storage directories */
    char *storages;             /* use ',;' */
    char **osd_storages_array;  /* parsed osd storages */

    /* section for file id */
    FILE *pf_file, *cf_file, *lf_file;

    /* # of threads */
    /* NOTE: # of profiling thread is always ONE */
    int spool_threads;          /* # of service threads */
    int aio_threads;            /* # of io threads */

    /* misc configs */
    int stacksize;

#define OSD_PROF_NONE           0x00
#define OSD_PROF_PLOT           0x01
#define OSD_PROF_HUMAN          0x02
#define OSD_PROF_R2             0x03
    u8 prof_plot;               /* do we dump profilings for gnuplot */
    u8 osd_storages_array_size;

    /* intervals */
    int profiling_thread_interval;
    int hb_interval;
    int diff_rep_interval;
    int full_rep_interval;

    /* conf */
#define HVFS_OSD_WDROP          0x01 /* drop all the writes to this OSD */
    u64 option;
};

struct hvfs_osd_object
{
    u64 site_id;                /* this site */
    struct xnet_context *xc;

    struct osd_storage storage;
    struct osd_prof prof;
    struct osd_conf conf;
#define HOO_STATE_INIT          0x00
#define HOO_STATE_LAUNCH        0x01
#define HOO_STATE_RUNNING       0x02
#define HOO_STATE_PAUSE         0x03
#define HOO_STATE_RDONLY        0x04
#define HOO_STATE_OFFLINE       0x05
    u32 state;

#define HMO_AUX_STATE_RECOVERY  0x01
    u32 aux_state;

    u64 ring_site;
    time_t tick;                /* tick of this OSD */

    /* the following region is used for threads */
    sem_t timer_sem;            /* for timer thread wakeup */
    sem_t reporter_sem;         /* for reporter thread wakeup */
    atomic64_t pending_ios;     /* pending IOs */

    pthread_t timer_thread;
    pthread_t *spool_thread;    /* array of service threads */
    pthread_t *aio_thread;      /* array of aio threads */
    pthread_t reporter_thread;

    /* osd profiling array */
    struct hvfs_profile hp;

    /* section for obj info */
    struct oga_manager om;

    u32 timer_thread_stop:1;    /* running flag for timer thread */
    u32 spool_thread_stop:1;    /* running flag for service thread */
    u32 aio_thread_stop:1;      /* running flag for aio thread */
    u32 reporter_thread_stop:1; /* running flag for reporter thread */

    /* callback funcitons */
    void (*cb_exit)(void *);
    void (*cb_hb)(void *);
    void (*cb_addr_table_update)(void *);
};

extern struct hvfs_osd_info hoi;
extern struct hvfs_osd_object hoo;
extern atomic_t obj_reads;

#define LOG_BEGIN_MAGIC         0x32fce973
#define LOG_END_MAGIC           0x23cf9c7f
#define LOG_ENTRY_MAGIC         0x7913c94f
struct log_entry
{
    u32 magic;
    u32 session;
    union 
    {
        struct
        {
            struct objid id;
            u64 site_id:63;
            u64 add_or_del:1;   /* there is no read/write log entry! */
        } _entry;
        struct 
        {
            u32 addnr;
            u32 delnr;
        } _end;
    };
    u64 ts;                     /* time stamp */
};

/* APIs */
int osd_config(void);
void osd_help(void);

void osd_pre_init(void);
int osd_init(void);
int osd_verify(void);

void osd_reset_itimer(void);

void osd_destroy(void);
u64 osd_select_ring(struct hvfs_osd_object *);
void osd_set_ring(u64);
int osd_addr_table_update(struct xnet_msg *);
void osd_reporter_schedule();
int osd_do_report();
void __do_obj_diff_report();

/* prof.c */
void osd_dump_profiling(time_t t, struct hvfs_profile *hp);

/* storage.c */
struct osd_storage_file_header
{
    u64 uuid;
    u32 bid;
    u32 len;
    u32 crc;
    u32 version:20;
    u32 consistency:4;
    u32 fh_ver:8;
    unsigned char digest[16];   /* MD5 digest */
};

typedef struct osd_storage_file_header OSD_FH;
#define OSD_FH_SIZE     (sizeof(OSD_FH))

int osd_storage_dir_make_exist(char *path);
int osd_storage_init(void);
void osd_storage_destroy(void);
void osd_startup_normal(void);
void osd_exit_normal(void);
#define HVFS_OSD_WRITE_TRUNC    0x01
int osd_storage_write(struct objid *obj, void *data, u32 offset, int length, int *dev);
int osd_storage_read(struct objid *obj, void **data, u32 offset, int length);
int osd_storage_read_strict(struct objid *obj, void **data, u32 offset, int length, int version);
int osd_storage_sync(struct objid *obj, u32 offset, u32 length);
int osd_storage_trunc(struct objid *obj, off_t length, int *dev);
void osd_get_obj_path(struct objid oid, char *store, char *path);
int osd_storage_statfs(struct statfs *s);
struct obj_gather_all *osd_storage_process_report();
int osd_om_state_change(u8 target_state, u8 target_send);
int __om_update_entry(struct objid id, int dev);
int osd_storage_getlen(struct objid *obj);

/* spool.c */
int osd_spool_dispatch(struct xnet_msg *);
void osd_spool_redispatch(struct xnet_msg *, int);

/* the follwing are marker types */
#define OSD_MRK_PAUSE           0x01
#define OSD_MRK_RDONLY          0x02
#define OSD_MRK_OFFLINE         0x03
#define OSD_CLR_PAUSE           0xf1
#define OSD_CLR_RDONLY          0xf2
#define OSD_CLR_OFFLINE         0xf3
int osd_set_marker(u32 type);
int osd_clr_marker(u32 type);

int osd_spool_create(void);
void osd_spool_destroy(void);

/* dispatch.c */
int osd_dispatch(struct xnet_msg *);

/* x2o.c */
int osd_write(struct xnet_msg *);
int osd_sweep(struct xnet_msg *);
int osd_read(struct xnet_msg *);
int osd_sync(struct xnet_msg *);
int osd_statfs(struct xnet_msg *);

#endif
