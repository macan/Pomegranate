/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-20 19:51:13 macan>
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

#ifndef __ROOT_H__
#define __ROOT_H__

#include "hvfs.h"
#include "prof.h"
#include "lib.h"
#include "rprof.h"
#include "mgr.h"
#include "xnet.h"

struct root_conf
{
    /* section for dynamic configuration */
    char dcaddr[ROOT_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
    char *root_home;
    char *profiling_file;
    char *conf_file;
    char *log_file;
#define HVFS_ROOT_HOME          "/tmp/hvfs"
#define HVFS_ROOT_STORE         "root_store"
#define HVFS_BITMAP_STORE       "bitmap_store"
#define HVFS_SITE_STORE         "site_store"
#define HVFS_ADDR_STORE         "addr_store"
    char *root_store;
    char *bitmap_store;
    char *site_store;
    char *addr_store;

    /* section for file fd */
    FILE *pf_file, *cf_file, *lf_file;
    int root_store_fd, bitmap_store_fd;
    int site_store_fd, addr_store_fd;

    /* # of threads */
    /* Note: # of profiling thread is always ONE */
    int service_threads;        /* # of service threads, pass this value to
                                     lnet */

    /* misc configs */
    u32 site_mgr_htsize;        /* site mgr hash table size */
    u32 ring_mgr_htsize;        /* ring mgr hash table size */
    u32 root_mgr_htsize;        /* root mgr hash table size */
    u32 addr_mgr_htsize;        /* addr mgr hash table size */
    u32 ring_push_interval;     /* interval to push the CHRing to
                                 * subscribers */
    u32 hb_interval;            /* interval to check the site entry
                                 * heartbeat */
    u32 sync_interval;          /* interval to do self sync */

    u32 ring_vid_max;

    u8 prof_plot;

    /* conf */
#define HVFS_ROOT_MEMONLY       0x01 /* memory only service */
    u64 option;
};

struct hvfs_root_object
{
#define HRO_STATE_INIT          0x00
#define HRO_STATE_LAUNCH        0x01
#define HRO_STATE_RUNNING       0x02
#define HRO_STATE_PAUSE         0x03
#define HRO_STATE_RDONLY        0x04
    u32 state;                  /* this site id */
    u64 site_id;
    struct xnet_context *xc;

    /* list for HVFS filesystem instances */
    struct list_head hfs;
    /* list for low-level filesystem instances */
    struct list_head llfs;

    /* Register pool of client, mds, mdsl and Other ROOT servers. 
     *
     * Note that: now we just support ONE root server, next step we can
     * support BFT root service. */
    struct site_mgr site;

    /* ring manager */
#define CH_RING_NUM     2
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
    struct ring_mgr ring;

    /* root service manager */
    struct root_mgr root;

    /* address service manager */
    struct addr_mgr addr;

    struct root_conf conf;
    struct root_prof prof;

    sem_t timer_sem;

    /* the following region is used for threads */
    pthread_t *spool_thread;    /* array of service threads */
    pthread_t timer_thread;

    u8 spool_thread_stop;       /* running flag for service thread */
    u8 timer_thread_stop;       /* running flag for timer thread */
};

extern struct hvfs_root_object hro;

#ifdef HVFS_TRACING
extern u32 hvfs_root_tracing_flags;
#endif

/* API Region */
void root_pre_init(void);
int root_verify(void);
int root_config(void);
int root_init(void);
void root_destroy(void);

int root_spool_create(void);
void root_spool_destroy(void);
int root_spool_dispatch(struct xnet_msg *msg);

int root_dispatch(struct xnet_msg *msg);

int root_do_reg(struct xnet_msg *);
int root_do_unreg(struct xnet_msg *);
int root_do_update(struct xnet_msg *);

#endif
