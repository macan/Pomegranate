/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 16:15:16 macan>
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
    struct extendible_hash *cbht; /* memory hash table */
    struct regular_hash *dh;      /* directory hash table */

#define CH_RING_NUM     2
#define CH_RING_MDS     0
#define CH_RING_MDSL    1
    struct consistent_hash *chring[CH_RING_NUM];
    struct mds_prof profiling;
    struct mds_conf conf;
    struct mds_txg txg;
    struct hvfs_txc txc;
#define HMO_STATE_LAUNCH        0x00
#define HMO_STATE_RUNNING       0x01
#define HMO_STATE_PAUSE         0x02
#define HMO_STATE_RDONLY        0x03
    u64 state;
};

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
};

extern struct hvfs_mds_info hmi;
extern struct hvfs_mds_object hmo;

#include "prof.h"

#endif
