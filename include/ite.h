/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-27 12:43:13 macan>
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

/* FIXME: there should be many different ITE definations */

struct column                   /* 24B */
{
    u64 stored_itbid;           /* for computing the location of dfile */
    u64 len;
    u64 offset;
};

struct sdt_md                   /* 340B */
{
    char name[HVFS_MAX_NAME_LEN]; /* 256B */
    union 
    {
        struct mdu mdu;         /* 84B */
        struct link_source ls;
    };
};

struct gdt_md
{
    u64 puuid;
    union 
    {
        struct mdu mdu;
        struct link_source ls;
    };
};

/* ITB index table entry */
struct ite 
{
    /* section for indexing: 20B */
    u64 hash;
    u64 uuid;

    u32 flag;

    /* section for special metadata: 340B */
    union 
    {
        struct sdt_md s;
        struct gdt_md g;
    };

    /* section for columns: 144B */
    struct column[6];           /* 144B */

    /* section for padding to 512B: 8B */
    char padding[8];
};

#endif
