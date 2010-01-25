/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-25 21:01:27 macan>
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

#ifndef __HVFS_H__
#define __HVFS_H__

#ifdef __KERNEL__
#include "hvfs_k.h"
#else  /* !__KERNEL__ */
#include "hvfs_u.h"
#endif

#include "tracing.h"
#include "memory.h"
#include "xlock.h"
#include "hvfs_common.h"
#include "hvfs_const.h"
#include "xhash.h"
#include "site.h"
#include "xprof.h"

/* This section for HVFS cmds & reqs */
/* Client to MDS */
#define HVFS_CLT2MDS_BASE       0x8000000000000000
#define HVFS_CLT2MDS_STATFS     0x8001000000000000
#define HVFS_CLT2MDS_LOOKUP     0x8002000000000000
#define HVFS_CLT2MDS_CREATE     0x8004000000000000
#define HVFS_CLT2MDS_RELEASE    0x8008000000000000
#define HVFS_CLT2MDS_UPDATE     0x8010000000000000
#define HVFS_CLT2MDS_LINKADD    0x8020000000000000
#define HVFS_CLT2MDS_UNLINK     0x8040000000000000
#define HVFS_CLT2MDS_SYMLINK    0x8080000000000000
#define HVFS_CLT2MDS_LB         0x8100000000000000 /* load bitmap */
/* NOTE: there is no *_LD in client, because we can use lookup instead */
#define HVFS_CLT2MDS_NODHLOOKUP (                                       \
        (HVFS_CLT2MDS_STATFS | HVFS_CLT2MDS_RELEASE) &                  \
        ~HVFS_CLT2MDS_BASE)
#define HVFS_CLT2MDS_NOCACHE (                              \
        (HVFS_CLT2MDS_LOOKUP | HVFS_CLT2MDS_NODHLOOKUP |    \
         HVFS_CLT2MDS_LB) &                                 \
        ~HVFS_CLT2MDS_BASE)

/* MDS to MDS */
#define HVFS_MDS2MDS_FWREQ      0x0000000080000000 /* forward req */
#define HVFS_MDS2MDS_SPITB      0x0000000080000001 /* split itb */
#define HVFS_MDS2MDS_AUPDATE    0x0000000080000002 /* async update */
#define HVFS_MDS2MDS_REDODELTA  0x0000000080000003 /* redo delta */
#define HVFS_MDS2MDS_LB         0x0000000080000004 /* load bitmap */
#define HVFS_MDS2MDS_LD         0x0000000080000005 /* load directory hash
                                                    * info */
/* MDSL to MDS */
/* RING/ROOT to MDS */

/* MDS to MDSL */
#define HVFS_MDS2MDSL_ITB       0x0000000080010000
#define HVFS_MDS2MDSL_BITMAP    0x0000000080020000
#define HVFS_MDS2MDSL_WBTXG     0x0000000080030000
#define HVFS_MDS2MDSL_WDATA     0x0000000080040000

/* Client to MDSL */
#define HVFS_CLT2MDSL_READ      0x0000000080050000
#define HVFS_CLT2MDSL_WRITE     0x0000000080060000
#define HVFS_CLT2MDSL_SYNC      0x0000000080070000
#define HVFS_CLT2MDSL_BGSEARCH  0x0000000080080000

/* APIs */
#define HASH_SEL_EH     0x00
#define HASH_SEL_CBHT   0x01
#define HASH_SEL_RING   0x02
#define HASH_SEL_DH     0x03
#define HASH_SEL_GDT    0x04
#define HASH_SEL_VSITE  0x05
u64 hvfs_hash(u64 key1, u64 key2, u64 key2len, u32 sel);

#define __cbht __attribute__((__section__(".cbht.text")))

#endif
