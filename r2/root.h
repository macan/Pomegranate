/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-07 17:10:47 macan>
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

struct root_conf
{
    /* section for dynamic configuration */
    char dcaddr[ROOT_DCONF_MAX_NAME_LEN];
    int dcfd, dcepfd;
    pthread_t dcpt;

    /* section for file name */
    char *profiling_file;
    char *conf_file;
    char *log_file;

    /* section for file fd */
    FILE *pf_file, *cf_file, *lf_file;

    /* # of threads */
    /* Note: # of profiling thread is always ONE */
    int service_threads;        /* # of service threads, pass this value to
                                     lnet */

    /* misc configs */
    u32 site_mgr_htsize;        /* site mgr hash table size */
    u32 ring_mgr_htsize;        /* ring mgr hash table size */
    u32 root_mgr_htsize;        /* root mgr hash table size */
    u32 ring_push_interval;     /* interval to push the CHRing to
                                 * subscribers */

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
    u32 state;
    u64 site_id;

    /* list for HVFS filesystem instances */
    struct list_head hfs;
    /* list for low-level filesystem instances */
    struct list_head llfs;

    /* register pool of clients */
    struct site_mgr client;
    
    /* register pool of mds */
    struct site_mgr mds;
    
    /* register pool of mdsl */
    struct site_mgr mdsl;
    
    /* Other ROOT servers. 
     *
     * Note that: now we just support ONE root server, next step we can
     * support BFT root service. */
    struct site_mgr site;

    /* ring manager */
    struct ring_mgr ring;

    /* root service manager */
    struct root_mgr root;

    struct root_conf conf;

    /* the following region is used for threads */
    pthread_t *spool_thread;    /* array of service threads */

    u8 spool_thread_stop;       /* running flag for service thread */
};

extern struct hvfs_root_object hro;

#ifdef HVFS_TRACING
extern u32 hvfs_root_tracing_flags;
#endif

/* API Region */
int root_init(void);
void root_destroy(void);

#endif
