/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-22 21:57:30 macan>
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
    u16 namelen;                /* the name length */
    union
    {
#define INDEX_COLUMN_ALL        0xffff
        u16 column;             /* which data column do you want */

#define KV_OP_SCAN              0x00
#define KV_OP_SCAN_CNT          0x01
#define KV_OP_GREP              0x02
#define KV_OP_GREP_CNT          0x03
        u16 op;                 /* option for scaner */
        /* we use the flags in ite.h struct kv.flags:
         *
         * HVFS_KV_NORMAL, HVFS_KV_STR
         */
#define HVFS_KV_MASK            (0xf000)
#define HVFS_KV_MAX_COLUMN      (0x1000 - 1)
        u16 kvflag;
    };

#define INDEX_BY_NAME           0x00000001 /* search by name */
#define INDEX_BY_UUID           0x00000002 /* search by uuid */
#define INDEX_BY_ITB            0x00000004 /* for READDIR, start address in
                                            * .hash and current depth of ITB
                                            * is in the low bits of .itb */

#define INDEX_LOOKUP            0x00000010 /* LOOKUP */
#define INDEX_INTENT_OPEN       0x00000020 /* open with ITE.ct++ */
#define INDEX_COLUMN            0x00000040 /* lookup the column info */
#define INDEX_INTENT_UNLINK     0x00000080 /* lookup for unlink */
#define INDEX_INTENT_CREATE     0x00000100

#define INDEX_LINK_ADD          0x00000800 /* lookup & nlink++, TXC */

#define INDEX_CREATE            0x00001000 /* create, TXC */
#define INDEX_CREATE_LINK       0x00002000 /* hard link, TXC */
#define INDEX_CREATE_DIR        0x00004000 /* create new dir in SDT */
#define INDEX_CREATE_COPY       0x00008000 /* use the MDU to create */
#define INDEX_CREATE_FORCE      0x00010000 /* forced create */
#define INDEX_CREATE_GDT        0x00020000 /* create the gdt entry */

#define INDEX_CREATE_LARGE      0x00800000 /* create large file */
#define INDEX_CREATE_SMALL      0x00040000 /* create small file */
#define INDEX_CREATE_KV         0x00080000 /* create kv file */

#define INDEX_MDU_UPDATE        0x00100000 /* setattr, TXC */
#define INDEX_UNLINK            0x00200000 /* unlink, TXC */
#define INDEX_SYMLINK           0x00400000 /* symlink, TXC */

#define INDEX_ITE_ACTIVE        0x01000000 /* active ITE */
#define INDEX_ITE_SHADOW        0x02000000 /* shadow/unlinked ITE */

#define INDEX_ITB_LOAD          0x10000000 /* load ITB */
#define INDEX_BIT_FLIP          0x80000000 /* need flip the bit of itbid @
                                            * client side*/
#define INDEX_KV                0x40000000 /* K/V mode access */
#define INDEX_DTRIG             0x20000000 /* toggle the trigger mode */
    u32 flag;
    u64 uuid;                   /* self uuid */
    u64 hash;                   /* hash value of the name, or manual set */
    u64 itbid;              /* uuid computed by client, or true uuid by MDS */
    u64 puuid;                  /* parent uuid */
    union
    {
        u64 ssalt;              /* self salt, used within HMR reply */
        u64 psalt;              /* parent salt, used in CLIENT requst */
    };
    union
    {
        void *data;                 /* MDS use: pointer to args */
        u64 dlen;                   /* in transfer data payload */
    };
    char name[0];
};

/* the general reply structure between HVFS client and MDS */
struct hvfs_md_reply
{
    short mdu_no;               /* # of MDUs */
    short ls_no;                /* # of LSs */
    short bitmap_no;            /* # of BITMAPs */
    short dc_no;                /* # of data columns */
    int err;
    int len;                    /* the data length */

#define MD_REPLY_DIR            0x01 /* result is a directory, either SDT or
                                      * GDT */
#define MD_REPLY_READDIR        0x02 /* piggyback the ITB depth in h8 of flag */

    /* please do NOT change the following defines, they should be consistent
     * with the defines in lib.h */
#define MD_REPLY_WITH_HI        0x10
#define MD_REPLY_WITH_MDU       0x20
#define MD_REPLY_WITH_LS        0x40
#define MD_REPLY_WITH_BITMAP    0x80   /* bitmap info in data area */
#define MD_REPLY_WITH_DC        0x1000 /* w/ data column info */

    /* this region is not exist in lib.h */
#define MD_REPLY_WITH_BFLIP     0x0100
#define MD_REPLY_WITH_KV        0x0200

    u32 flag;
    void *data;                 /* how to alloc data region more faster? */
    /* Layout of data region
     *
     * |---HI---|---MDU---/---LS---|---BITMAP---|---DC---|
     * |---dentry array---|
     */
    /*
     * Layout of the data region: low->high, selected by flags
     *
     * struct hvfs_index hi;
     * struct mdu mdu; + u64; (HVFS_MDU_SIZE)
     * struct link_source ls;
     * struct itbitmap + 128KB;
     * struct column
     */
};

struct dentry_info
{
    u64 uuid;                   /* dentry uuid */
    u16 mode;
    u16 namelen;
    u32 __padding;
    char name[0];               /* the dentry name */
};

/*
 * used for setattr and create
 *
 * Layout of mdu_update:
 *
 * |---mdu_update---|---symname---| or
 * |---mdu_update---|--llfs_ref--|---mu_column---|
 */
struct mdu_update 
{
    /* flags for valid */
#define MU_MODE         (1 << 0)
#define MU_UID          (1 << 1)
#define MU_GID          (1 << 2)
#define MU_FLAG_ADD     (1 << 3)
#define MU_ATIME        (1 << 4)
#define MU_MTIME        (1 << 5)
#define MU_CTIME        (1 << 6)
#define MU_VERSION      (1 << 7)
#define MU_SIZE         (1 << 8) /* for truncate? */
#define MU_FLAG_CLR     (1 << 9)
#define MU_COLUMN       (1 << 10) /* update column infomation? */
#define MU_NLINK        (1 << 11)
#define MU_SYMNAME      (1 << 12) /* symbol name */
#define MU_LLFS         (1 << 13) /* llfs_ref */

#define MU_NLINK_DELTA  (1 << 14) /* delta update to nlink, almost same as
                                   * linkadd operation */

    u64 atime;
    u64 mtime;
    u64 ctime;
    u64 size;                   /* for truncate? */

    u32 valid;

    u32 uid;
    u32 gid;

    u32 flags;

    u32 version;
    s32 nlink;
    u16 mode;
    u16 column_no;              /* # of columns */
    u16 namelen;                /* name length of symbol name */
};

struct column                   /* 24B */
{
    u64 stored_itbid;           /* for computing the location of dfile */
    u64 len;
    u64 offset;
};

struct mu_column
{
    u64 cno;
    struct column c;
};

/* APIs */

/* NOTE: how to alloc a hmr very fast? */
static inline
struct hvfs_md_reply *get_hmr(void)
{
    return xzalloc(sizeof(struct hvfs_md_reply));
}

#endif
