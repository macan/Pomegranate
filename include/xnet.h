/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-27 17:04:33 macan>
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

#ifndef __XNET_H__
#define __XNET_H__

struct xnet_context
{
    /* FIXME */
    u8 type;
    int pt_num;
    int service_port;
};

struct xnet_msg_tx 
{
    u8 version;                 /* the protocol version */
#define XNET_MSG_NOP    0
#define XNET_MSG_REQ    1
#define XNET_MSG_RPY    2
#define XNET_MSG_CMD    3
    u8 type;                           /* msg type */
#define XNET_NEED_REPLY         0x0001 /* otherwise, no reply data */
#define XNET_NEED_TX            0x0002 /* otherwise, no commit msg */
#define XNET_NEED_DATA_FREE     0x0004 /* data in iov should be free */
#define XNET_NEED_ACK           0x0008 /* otherwise, no ack msg */
#define XNET_BARRIER            0x0010 /* schedule can through it */
#define XNET_BCAST              0x0020 /* broadcast msg */
#define XNET_REDUCE             0x0040 /* reduce msg */
    u16 flag;                          /* msg flags */
    int err;
    u64 ssite_id;               /* source site */
    u64 dsite_id;               /* target site */
    u64 cmd;                    /* please refer to the cmd list of
                                 * REQ/RPY/CMD */
    u64 arg0;
    u64 len;                    /* total data len */
};

struct xnet_msg
{
    struct xnet_msg_tx tx;      /* header of msg */
#define XNET_MSG_OPEN           0
#define XNET_MSG_FREEZE         1
#define XNET_MSG_SENT           2
#define XNET_MSG_ACKED          3
#define XNET_MSG_COMMITED       4
#define XNET_RX                 5
#define XNET_PAIRED             6
    u8 state;
#define XNET_MSG_NORMAL         0x01 /* normal allocation */
#define XNET_MSG_CACHE          0x02 /* allocation based on cache */
    u8 alloc_flag;
    u8 iov_alen;                /* alloc length */
    u8 iov_ulen;                /* used number */
    struct iovec *iov;
#define xm_data iov[0].iov_base

    struct xnet_context *xc;
    struct xnet_msg *pair;
    struct list_head list;
    u64 reqno;
    void *private;
};

/* APIs */
struct xnet_msg *xnet_alloc_msg(u8 alloc_flag);
void xnet_free_msg(struct xnet_msg *);

/* ERR convention:
 *
 * the xnet_* should return the errno with the same convention of kernel,
 * which means that the return value should be minus number!
 */
int xnet_send(struct xnet_context *xc, struct xnet_msg *m);

#endif
