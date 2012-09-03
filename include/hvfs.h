/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-09 13:11:46 macan>
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
#include "hvfs_addr.h"
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
#define HVFS_CLT2MDS_LB_PROXY   (HVFS_MDS2MDS_LB)  /* proxy for MDS2MDS request */
#define HVFS_CLT2MDS_LD         0x8200000000000000 /* Note that, this is just
                                                    * a shadow ldh usage in
                                                    * client, you should not
                                                    * rely on this
                                                    * interface */
#define HVFS_CLT2MDS_LIST       0x8400000000000000 /* for readdir use */
#define HVFS_CLT2MDS_COMMIT     0x8800000000000000 /* trigger a memory
                                                    * snapshot */
#define HVFS_CLT2MDS_ACQUIRE    0x9000000000000000 /* acquire the locks/lease */

#define HVFS_CLT2MDS_DITB       0x8000000100000000 /* dump itb */
#define HVFS_CLT2MDS_DEBUG      (HVFS_CLT2MDS_DITB)
/* NOTE: there is no *_LD in client, because we can use lookup instead */
/* Note2: RELEASE should pass DH LOOKUP */
#define HVFS_CLT2MDS_NODHLOOKUP (                                       \
        (HVFS_CLT2MDS_STATFS |                                          \
         HVFS_CLT2MDS_LIST | HVFS_CLT2MDS_COMMIT) &                     \
        ~HVFS_CLT2MDS_BASE)
#define HVFS_CLT2MDS_NOCACHE (                              \
        (HVFS_CLT2MDS_LOOKUP | HVFS_CLT2MDS_NODHLOOKUP |    \
         HVFS_CLT2MDS_LB | HVFS_CLT2MDS_DEBUG |             \
         HVFS_CLT2MDS_LD | HVFS_CLT2MDS_RELEASE) &          \
        ~HVFS_CLT2MDS_BASE)
#define HVFS_CLT2MDS_RDONLY     (HVFS_CLT2MDS_NOCACHE)

/* MDS to MDS */
#define HVFS_MDS2MDS_FWREQ      0x0000000080000000 /* forward req */
#define HVFS_MDS2MDS_SPITB      0x0000000080000001 /* split itb */
#define HVFS_MDS2MDS_AUPDATE    0x0000000080000002 /* async update */
#define HVFS_MDS2MDS_REDODELTA  0x0000000080000003 /* redo delta */
#define HVFS_MDS2MDS_LB         0x0000000080000004 /* load bitmap */
#define HVFS_MDS2MDS_LD         (HVFS_CLT2MDS_LD)  /* load directory hash
                                                    * info */
#define HVFS_MDS2MDS_AUBITMAP   0x0000000080000006 /* async bitmap flip */
#define HVFS_MDS2MDS_AUBITMAP_R 0x0000000080000007 /* async bitmap flip confirm */
#define HVFS_MDS2MDS_AUDIRDELTA 0x0000000080000008 /* async dir delta update */
#define HVFS_MDS2MDS_AUDIRDELTA_R 0x0000000080000009 /* async dir delta update
                                                      * confirm */
#define HVFS_MDS2MDS_GB         0x000000008000000a /* gossip bitmap */
#define HVFS_MDS2MDS_GF         0x000000008000000b /* gossip ft info */
#define HVFS_MDS2MDS_GR         0x000000008000000c /* gossip rdir */
#define HVFS_MDS2MDS_BRANCH     0x000000008000000f /* branch commands */
#define HVFS_MDS_HA             0x0000000080000010 /* ha request */
#define HVFS_MDS_RECOVERY       0x0000000080000020 /* recovery analyse
                                                    * request */
/* begin recovery subregion: arg0 */
/* end recovery subregion */

/* MDSL to MDS */
/* RING/ROOT to MDS */
#define HVFS_R22MDS_COMMIT      0x0000000020000001 /* trigger a snapshot */
#define HVFS_R22MDS_PAUSE       0x0000000020000002 /* pause client/amc request
                                                    * handling */
#define HVFS_R22MDS_RESUME      0x0000000020000003 /* resume request
                                                    * handling */
#define HVFS_R22MDS_RUPDATE     0x0000000020000004 /* ring update */

/* AMC to MDS */
#define HVFS_AMC2MDS_REQ        0x0000000040000001 /* normal request */
#define HVFS_AMC2MDS_EXT        0x0000000040000002 /* extend request */

/* MDS to MDSL */
#define HVFS_MDS2MDSL_ITB       0x0000000080010000
#define HVFS_MDS2MDSL_BITMAP    0x0000000080020000
#define HVFS_MDS2MDSL_WBTXG     0x0000000080030000
/* subregion for arg0 */
#define HVFS_WBTXG_BEGIN        0x0001
#define HVFS_WBTXG_ITB          0x0002
#define HVFS_WBTXG_BITMAP_DELTA 0x0004
#define HVFS_WBTXG_DIR_DELTA    0x0008
#define HVFS_WBTXG_R_DIR_DELTA  0x0010
#define HVFS_WBTXG_CKPT         0x0020
#define HVFS_WBTXG_END          0x0040
#define HVFS_WBTXG_RDIR         0x0080
/* end subregion for arg0 */
#define HVFS_MDS2MDSL_WDATA     0x0000000080040000
#define HVFS_MDS2MDSL_BTCOMMIT  0x0000000080100000
#define HVFS_MDS2MDSL_ANALYSE   0x0000000080200000
/* subregion for arg0 */
#define HVFS_ANA_MAX_TXG        0x0001 /* find the max txg */
#define HVFS_ANA_UPDATE_LIST    0x0002 /* find the ddb and bdb (not) need
                                        * update */
/* end subregion for arg0 */

/* Client to MDSL */
#define HVFS_CLT2MDSL_READ      0x0000000080050000
#define HVFS_CLT2MDSL_WRITE     0x0000000080060000
#define HVFS_CLT2MDSL_SYNC      0x0000000080070000
#define HVFS_CLT2MDSL_BGSEARCH  0x0000000080080000
#define HVFS_CLT2MDSL_STATFS    0x0000000080090000

/* * to ROOT/RING */
#define HVFS_R2_REG             0x0000000040000001
#define HVFS_R2_UNREG           0x0000000040000002
#define HVFS_R2_UPDATE          0x0000000040000003
#define HVFS_R2_MKFS            0x0000000040000004
#define HVFS_R2_HB              0x0000000040000008 /* heart beat */
#define HVFS_R2_LGDT            0x0000000040000010 /* load gdt dh */
#define HVFS_R2_LBGDT           0x0000000040000011 /* load gdt bitmap */
#define HVFS_R2_ONLINE          0x0000000040000012 /* online a site */
#define HVFS_R2_OFFLINE         0x0000000040000014 /* offline a site */
#define HVFS_R2_FTREPORT        0x0000000040000018 /* ft report */
#define HVFS_R2_ADDSITE         0x0000000040000020 /* add site */
#define HVFS_R2_RMVSITE         0x0000000040000021 /* remove site */
#define HVFS_R2_SHUTDOWN        0x0000000040000022 /* shutdown site */
#define HVFS_R2_PROFILE         0x0000000040000023 /* gather profile */
#define HVFS_R2_INFO            0x0000000040000024 /* get info */
#define HVFS_R2_OREP            0x0000000040000025 /* object report */

/* ROOT/RING to * */
#define HVFS_FR2_RU             0x0000000041000000 /* ring updates to all
                                                    * sites */
#define HVFS_FR2_AU             0x0000000042000000 /* address table updates to
                                                    * all sites */

/* * to OSD */
#define HVFS_OSD_READ           0x0000000010000001 /* object read */
#define HVFS_OSD_WRITE          0x0000000010000002 /* object write */
#define HVFS_OSD_SYNC           0x0000000010000003 /* object sync */
#define HVFS_OSD_STATFS         0x0000000010000004 /* stat whole server */
#define HVFS_OSD_QUERY          0x0000000010000005 /* query on specific object */

/* APIs */
#define HASH_SEL_EH     0x00
#define HASH_SEL_CBHT   0x01
#define HASH_SEL_RING   0x02
#define HASH_SEL_DH     0x03
#define HASH_SEL_GDT    0x04
#define HASH_SEL_VSITE  0x05
#define HASH_SEL_KVS    0x06

#include "hash.c"

#define __cbht __attribute__((__section__(".cbht.text")))
#define __xnet __attribute__((__section__(".xnet.text")))
#define __mdsdisp __attribute__((__section__(".mds.dispatch.text")))
#define __UNUSED__ __attribute__((unused))

struct itbitmap
{
    struct list_head list;
    struct list_head lru;
    u64 offset:56;
#define BITMAP_END      0x80    /* means there is no slice after this slice */
    u64 flag:8;
    u64 ts;
#define XTABLE_BITMAP_SIZE      (128 * 1024 * 8) /* default is 128K storage */
#define XTABLE_BITMAP_BYTES     (128 * 1024)
#define XTABLE_BITMAP_SHIFT     (17)
    u8 array[XTABLE_BITMAP_BYTES];
};

#define BITMAP_ROUNDUP(x) (((x + 1) + XTABLE_BITMAP_SIZE - 1) & \
                           ~(XTABLE_BITMAP_SIZE - 1))
#define BITMAP_ROUNDDOWN(x) ((x) & (~((XTABLE_BITMAP_SIZE) - 1)))

#define PAGE_ROUNDUP(x, p) ((((size_t) (x)) + (p) - 1) & ~((p) - 1))
/* this struct is just for c2m.c, shadow of itbitmap header */
struct ibmap
{
    struct list_head list;
    struct list_head lru;
    u64 offset:56;
    u64 flag:8;
    u64 ts;
};

#endif
