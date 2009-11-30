/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 11:04:00 macan>
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

#ifndef __MDS_API_H__
#define __MDS_API_H__

/* the general index structure between HVFS client and MDS */
struct hvfs_index
{
    int len;                    /* the data length */

#define INDEX_BY_NAME           0x00000001 /* search by name */
#define INDEX_BY_UUID_F         0x00000002 /* search by fuuid */
#define INDEX_BY_UUID_D         0x00000003 /* search by duuid */
#define INDEX_BY_ITB            0x00000004 /* for READDIR, start address in
                                            * .hash and current depth of ITB
                                            * is in the low bits of .itb */

#define INDEX_LOOKUP            0x00000010 /* LOOKUP */
#define INDEX_INTENT_OPEN       0x00000020 /* open with ITE.ct++ */

#define INDEX_LINK_ADD          0x00000100 /* lookup & nlink++, TXC */

#define INDEX_CREATE            0x00001000 /* create, TXC */
#define INDEX_CREATE_LINK       0x00002000 /* hard link, TXC */
#define INDEX_CREATE_DIR        0x00004000 /* create new dir in SDT */
#define INDEX_CREATE_COPY       0x00008000 /* use the MDU to create */
#define INDEX_CREATE_FORCE      0x00010000 /* forced create */

#define INDEX_MDU_UPDATE        0x00100000 /* setattr, TXC */
#define INDEX_UNLINK            0x00200000 /* unlink, TXC */
#define INDEX_SYMLINK           0x00400000 /* symlink, TXC */

#define INDEX_ITB_LOAD          0x10000000 /* load ITB */
    u32 flag;
    u64 uuid;                   /* self uuid */
    u64 hash;                   /* hash value of the name, or manual set */
    u64 itbid;                  /* uuid computed by client, or true uuid by MDS */
    u64 puuid;                  /* parent uuid */
    void *data;                 /* MDS use: pointer to args */
    char name[0];
};

/* the general reply structure between HVFS client and MDS */
struct hvfs_md_reply
{
    int err;
    int len;                    /* the data length */

#define MD_REPLY_WITH_BITMAP    0x01 /* bitmap info in data area */
#define MD_REPLY_HARD_LINK      0x02 /*  */
#define MD_REPLY_DIR_SDT        0x04
#define MD_REPLY_READDIR        0x08

#define MD_REPLY_WITH_HI        0x10
#define MD_REPLY_WITH_MDU       0x20
#define MD_REPLY_WIHT_LS        0x40
#define MD_REPLY_WITH_DATA      0x80
    u64 flag;
    void *data;                 /* how to alloc data region more faster? */
};

/* Layout of the data region: low->high, selected by flags
 *
 * struct hvfs_index hi;
 * struct mdu mdu;
 * struct link_source ls;
 * char data[*];
 */

#endif
