/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-04 16:54:48 macan>
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

#ifndef __ITE_H__
#define __ITE_H__

#include "hvfs_const.h"
#include "mds_api.h"

/* FIXME: there should be many different ITE definations */

struct sdt_md                   /* 340B */
{
    union 
    {
        struct mdu mdu;         /* 84B */
        struct link_source ls;
    };
    char name[HVFS_MAX_NAME_LEN]; /* 256B */
};

struct gdt_md
{
    union 
    {
        struct mdu mdu;
        struct link_source ls;
    };
    u64 puuid;
};

#define HVFS_MDU_SIZE   (sizeof(struct mdu) + sizeof(u64)) /* include GDT.puuid */

/* ITB index table entry */
struct ite 
{
    /* section for indexing: 20B */
    u64 hash;
    u64 uuid;                   /* for dir: highest bit is 1 */

#define ITE_ACTIVE      0x00000000
#define ITE_UNLINKED    0x00000001
#define ITE_SNAPSHOT    0x00000002
#define ITE_SHADOW      0x00000003

#define ITE_STATE_MASK  0x00000007 /* 0-7 states */

#define ITE_FLAG_NORMAL 0x80000000 /* mdu */
#define ITE_FLAG_LS     0x40000000 /* link source */
#define ITE_FLAG_GDT    0x20000000
#define ITE_FLAG_SDT    0x10000000
    u32 flag;

    /* section for special metadata: 340B */
    union 
    {
        struct sdt_md s;
        struct gdt_md g;
    };

    /* section for columns: 144B */
    struct column column[6];    /* 144B */

    /* section for padding to 512B: 8B */
    char padding[8];
};
#define ITE_IS_DIR(ite) ((ite)->uuid & 0x8000000000000000)
#define ITE_IS_FILE(ite) (!((ite)->uuid & 0x8000000000000000))

/*
 * match a ITE entry
 */
#define ITE_MATCH_HIT   0
#define ITE_MATCH_MISS  1
int ite_match(struct ite *ite, struct hvfs_index *hi);

#endif
