/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-30 19:24:27 macan>
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

#ifndef __MDSL_API_H__
#define __MDSL_API_H__

struct si_core 
{
    u64 uuid;                   /* the dir UUID */
    /* for read_itb: itbid
     * for read_bitmap: self UUID
     * for read/write: itbid
     */
    u64 arg0;
};

/* storage index for mds */
struct si_mds 
{
    u64 offset;                 /* for read_bitmap: the bitmap offset */
    u32 len;                    /* the data length */
};

/* storage index for client */
struct si_client 
{
    u64 hash;                   /* entry hash value */
    u64 offset;                 /* the data offset of this op */
    u32 olen;                   /* the data length of this op */
    u32 column;                 /* the column where the data reside */
    u32 len;                    /* the total data length */
    u16 namelen;                /* the name length */
#define SIC_INDEX_BY_NAME       0x00
#define SIC_INDEX_BY_UUID       0x01
    u16 flag;                   /* which index method used */
};

typedef struct si_client si_data_t;

/* search colump operations */
struct scop 
{
    u32 column;
    u16 len;                    /* key length, max key length: 64KB */
    u16 op;
    char key[0];
};

/* storage index for search */
struct si_search 
{
    u16 num;                    /* number of op[] */
    u16 op;
    int len;                    /* the total length of ops[] */
    struct scop ops[0];
};

struct storage_index 
{
    struct si_core sic;
    union 
    {
        struct __si_client 
        {
            struct si_client sc;
            char *name;
            char *data;
        } c;
        struct __si_mds
        {
            struct si_mds sm;
            char *data;
        } m;
        struct si_search s;
    };
};

struct storage_index_tx
{
    struct si_core sic;
    union 
    {
        struct __si_client
        {
            struct si_client sc;
            char name[0];
            char data[0];
        } c;
        struct __si_mds
        {
            struct si_mds sm;
            char data[0];
        } m;
        struct si_search s;
    };
};

/* the result of the MDSL execution */
struct storage_result_core
{
    int err;
    int len;                    /* the total data length */
#define SR_BGSEARCH     0x01
#define SR_READ         0x02
#define SR_WRITE        0x03
#define SR_ITB          0x04
#define SR_BITMAP       0x05
#define SR_PRECOMMIT    0x06
#define SR_WRITED       0x07    /* write data */
    u64 flag;
};

struct storage_result 
{
    struct storage_result_core src;
    void *data;
};

#endif
