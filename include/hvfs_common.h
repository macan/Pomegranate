/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-02-12 10:01:01 macan>
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

#ifndef __HVFS_COMMON_H__
#define __HVFS_COMMON_H__

/* the LLFS referal */
struct llfs_ref 
{
    /* FIXME: how to construct the fsid? */
    u64 fsid;                   /* the id of the file system */
    u64 rfino;                  /* referenced file ino */
#ifdef HVFS_SELF_LLFS_SUPPORT
    /* the following two is only for HVFS */
    u64 hash;
    u64 puuid;
#endif
};

/* the HVFS metadata unit */
struct mdu 
{
    /* NOTE THAT: this mdu.flags share the id space with kv.flags and
     * ls.flags, we have pre-allocate the forth 4bits to kv flags!! */
    /* section for general info: 32B */
#define HVFS_MDU_IF_DIRSYNC     0x00000010 /* dissync */
#define HVFS_MDU_IF_IMMUTABLE   0x00000020 /* immutable file */
#define HVFS_MDU_IF_APPEND      0x00000040 /* append only */
#define HVFS_MDU_IF_SYNC        0x00000080 /* sync update */
#define HVFS_MDU_IF_NOATIME     0x00000100 /* no atime */
#define HVFS_MDU_IF_PROXY       0x00000200 /* proxy read/write */
#define HVFS_MDU_IF_LZO         0x00000400 /* data w/ lzo compressed */

#define HVFS_MDU_IF_DA          0x80000000 /* delay allocation */

#define HVFS_MDU_IF_NORMAL      0x08000000 /* normal file */
#define HVFS_MDU_IF_LARGE       0x04000000 /* large file */
#define HVFS_MDU_IF_SMALL       0x02000000 /* small file */
#define HVFS_MDU_IF_SYMLINK     0x01000000 /* symlink file */

#define HVFS_MDU_IF_LINKT       0x00800000 /* hard link target */
#define HVFS_MDU_IF_KV          0x00400000 /* kv file */

#define HVFS_MDU_IF_TRIG        0x00200000 /* trigger support based on
                                            * directory, the default trigger
                                            * column for HVFS files are
                                            * HVFS_TRIG_COLUMN. */
    u32 flags;

    u32 uid;
    u32 gid;
    u16 mode;                   /* the same as VFS */
    u16 nlink;
    u64 size;
    u32 dev;
    u32 version;

    /* section for time: 32B */
    u64 atime;                  /* access time */
    u64 ctime;                  /* change time */
    u64 mtime;                  /* modify time */
    u64 dtime;                  /* delete time */
    
    /* section for advance function: 20B */
    union 
    {
        struct llfs_ref lr;
        char symname[16];
    };
};

/* the HVFS link_source */
struct link_source
{
    u32 flags;                  /* the same as mdu flags */

    u32 uid;
    u32 gid;
    u16 mode;
    u16 nlink;                  /* nlink should be exactly the same postion as
                                 * in struct mdu! */
    
    /* u64 size + u64 (dev+version) */
    u64 s_puuid;
    u64 s_psalt;
    u64 s_uuid;
    u64 s_hash;
    /* the next u64 is ready to FAIL! becaust in LEASE operations, we write to
     * mdu.dtime field w/o any checking */
    u64 dtime;
};

#endif
