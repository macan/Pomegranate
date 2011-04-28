/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-28 13:53:30 macan>
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

struct xnet_msg_tx 
{
    u8 version:4;               /* the protocol version: but we only use the
                                 * low 4 bits :) */
    u8 magic:4;                 /* per-instance magic to detect corrupt
                                 * messages */
#define XNET_MSG_NOP    0
#define XNET_MSG_REQ    1
#define XNET_MSG_RPY    2
#define XNET_MSG_CMD    3
#define XNET_MSG_HELLO  4
#define XNET_MSG_HELLO_ACK 5
    u8 type;                           /* msg type */
#define XNET_NEED_REPLY         0x0001 /* otherwise, no reply data */
#define XNET_NEED_TX            0x0002 /* otherwise, no commit msg */
#define XNET_NEED_DATA_FREE     0x0004 /* data in iov should be free */
#define XNET_NEED_ACK           0x0008 /* otherwise, no ack msg */
#define XNET_BARRIER            0x0010 /* schedule can through it */
#define XNET_BCAST              0x0020 /* broadcast msg */
#define XNET_REDUCE             0x0040 /* reduce msg */
#define XNET_DATA_PREPARED      0x0080 /* data in iov is the receiving
                                        * region */

#define XNET_NEED_RESEND        0x0100 /* otherwise, return on send err */
#define XNET_FWD                0x0200 /* forwarded msg */

#define XNET_PTRESTORE          0x8000 /* temp flag for xnet-simple pointer
                                        * restore */
    u16 flag;                          /* msg flags */
    int err;
    u64 ssite_id;               /* source site */
    u64 dsite_id;               /* target site */
    u64 cmd;                    /* please refer to the cmd list of
                                 * REQ/RPY/CMD */
    u64 arg0;
    u64 arg1;
    u32 reqno;
    u32 len;                    /* total data len */
    u64 handle;                 /* this is the pointer to the request */
    u64 reserved;
};

struct xnet_msg
{
    struct xnet_msg_tx tx;      /* header of msg */
#define XNET_MSG_OPEN           0
#define XNET_MSG_FREEZE         1
#define XNET_MSG_SENT           2
#define XNET_MSG_ACKED          3
#define XNET_MSG_COMMITED       4
#define XNET_MSG_RX             5
#define XNET_MSG_PAIRED         6
    u8 state;
#define XNET_MSG_NORMAL         0x01 /* normal allocation */
#define XNET_MSG_CACHE          0x02 /* allocation based on cache */
    u8 alloc_flag;

    u8 riov_alen;
    u8 riov_ulen;
    u32 siov_alen;              /* alloc length */
    u32 siov_ulen;              /* used number */

    struct iovec *siov;
    struct iovec *riov;
#define xm_datacheck riov
#define xm_data riov[0].iov_base

    struct xnet_context *xc;
    struct xnet_msg *pair;
    struct list_head list;
    void *private;

    atomic_t ref;
#ifdef USE_XNET_SIMPLE
    sem_t event;
    time_t ts;
#endif
};

struct xnet_type_ops
{
    void *(*buf_alloc)(size_t size, int alloc_flag);
    void (*buf_free)(void *buf, int alloc_flag);
    int (*recv_handler)(struct xnet_msg *msg); /* first dispatcher */
    int (*dispatcher)(struct xnet_msg *msg);   /* secondary dispatcher */
};

struct xnet_context
{
    /* FIXME */
    u8 type;
    int pt_num;
    int service_port;
    struct xnet_type_ops ops;
    u64 site_id;                /* local site id */
#ifdef USE_XNET_SIMPLE
    sem_t wait;
    struct list_head list;
    struct list_head resend_q;
    xlock_t resend_lock;
#endif
};

struct xnet_group_entry
{
    u64 site_id;
#define XNET_GROUP_RECVED       0x00001
    u64 flags;
};

struct xnet_group
{
#define XNET_GROUP_ALLOC_UNIT   64
    int asize, psize;           /* actual size, physical size */
    struct xnet_group_entry sites[0];
};

/* APIs */
/* Note: this branch only concern xnet_simple, thus we add more arguments to
 * it!
 */
#ifdef USE_XNET_SIMPLE
struct xnet_context *xnet_register_type(u8, u16, u64, struct xnet_type_ops *);
struct xnet_context *xnet_register_lw(u8, u16, u64, struct xnet_type_ops *);
int xnet_resend(struct xnet_context *xc, struct xnet_msg *m);
int xnet_resend_remove(struct xnet_msg *msg);
struct xnet_conf 
{
    int resend_timeout;
    int send_timeout;
    int siov_nr;
    u32 magic:4;                /* magic we should use */
    u32 enable_resend:1;
    u32 pause:1;
};
#else
struct xnet_context *xnet_register_type(u8, struct xnet_type_ops *);
static inline
void xnet_resend_remove(struct xnet_msg *msg)
{
}
#endif
int xnet_unregister_type(struct xnet_context *);

struct xnet_msg *xnet_alloc_msg(u8 alloc_flag);
void xnet_free_msg(struct xnet_msg *);
void xnet_raw_free_msg(struct xnet_msg *);

int xnet_msg_add_sdata(struct xnet_msg *, void *, u32);
int xnet_msg_add_rdata(struct xnet_msg *, void *, u32);
void xnet_msg_free_sdata(struct xnet_msg *);
void xnet_msg_free_rdata(struct xnet_msg *);

/* ERR convention:
 *
 * the xnet_* should return the errno with the same convention of kernel,
 * which means that the return value should be minus number!
 */
int xnet_send(struct xnet_context *xc, struct xnet_msg *m);

#define xnet_msg_set_site(m, id) ((m)->tx.dsite_id = id)

void xnet_set_magic(u8 magic);

static inline 
void xnet_msg_fill_cmd(struct xnet_msg *m, u64 cmd, u64 arg0, u64 arg1) 
{
    m->tx.arg0 = arg0;
    m->tx.arg1 = arg1;
    m->tx.cmd = cmd;
}

static inline
void xnet_msg_fill_tx(struct xnet_msg *m, u8 type, u16 flag, u64 ssite, 
                      u64 dsite)
{
    m->tx.type = type;
    m->tx.flag = flag;
    m->tx.ssite_id = ssite;
    m->tx.dsite_id = dsite;
}

#define xnet_clear_auto_free(m) do {            \
        (m)->tx.flag &= (~XNET_NEED_DATA_FREE); \
    } while (0)

#define xnet_set_auto_free(m) do {              \
        (m)->tx.flag |= (XNET_NEED_DATA_FREE);  \
    } while (0)

static inline
void xnet_msg_set_err(struct xnet_msg *msg, int err)
{
    msg->tx.err = err;
}

static inline
void xnet_msg_fill_reqno(struct xnet_msg *msg, u64 reqno)
{
    msg->tx.reqno = reqno;
}

TRACING_FLAG_DEF(xnet);
void xnet_reset_tracing_flags(u64);

extern void *mds_gwg;           /* simulate global wait group */
int xnet_wait_group_add(void *, struct xnet_msg *);
int xnet_wait_group_del(void *, struct xnet_msg *);

int xnet_isend(struct xnet_context *xc, struct xnet_msg *m);

#ifdef USE_XNET_SIMPLE
int st_init(void);
void st_destroy(void);
void st_list(char *type);
int xnet_update_ipaddr(u64, int, char *ipaddr[], short port[]);
int hst_to_xsst(void *, int);
u64 hst_find_free(u64);
void xnet_wait_any(struct xnet_context *xc);
void st_print(void);
#else
/* To eliminate warnings */
int hst_to_xsst(void *, int);
u64 hst_find_free(u64);
void st_print(void);
#endif

/* XNET Group management */
static inline
int xnet_group_add(struct xnet_group **xg, u64 site_id)
{
    int err = 0, i;

    if (!xg)
        return -EINVAL;
    if (!(*xg))
        goto alloc;
    
    /* Note that, we do NOT check any argument */
retry:
    if ((*xg)->asize < (*xg)->psize) {
        /* check if this site is already in the group */
        for (i = 0; i < (*xg)->asize; i++) {
            if ((*xg)->sites[i].site_id == site_id) {
                return err;
            }
        }
        (*xg)->sites[(*xg)->asize].site_id = site_id;
        (*xg)->sites[(*xg)->asize].flags = 0;
        (*xg)->asize += 1;
    } else {
        /* try to realloc more entries */
        struct xnet_group *__xg;
        
    alloc:
        __xg = xrealloc((*xg), sizeof(struct xnet_group) + 
                        ((*xg == NULL) ? XNET_GROUP_ALLOC_UNIT : 
                         ((*xg)->psize + XNET_GROUP_ALLOC_UNIT)) * 
                         sizeof(struct xnet_group_entry));
        if (__xg == NULL) {
            err = -ENOMEM;
            goto out;
        }
        if (!(*xg)) {
            memset(__xg, 0, sizeof(struct xnet_group) + 
                   XNET_GROUP_ALLOC_UNIT * sizeof(struct xnet_group_entry));
            __xg->psize = XNET_GROUP_ALLOC_UNIT;
        } else {
            memset(&__xg->sites[__xg->psize], 0, 
                   sizeof(struct xnet_group_entry) * XNET_GROUP_ALLOC_UNIT);
            __xg->psize += XNET_GROUP_ALLOC_UNIT;
        }
        *xg = __xg;
        goto retry;
    }
out:
    return err;
}

/* Profiling Section */
extern struct xnet_prof g_xnet_prof;
extern struct xnet_conf g_xnet_conf;

/* This section for XNET reply msg */
#define XNET_RPY_ACK            0x01
#define XNET_RPY_COMMIT         0x02
#define XNET_RPY_DATA           0x03

#define XNET_RPY_DATA_ITB       0x04 /* should change to RPY_DATA */
#define xnet_rpy_cmd_fallback(msg) do {         \
        if (msg->tx.cmd == XNET_RPY_DATA_ITB)   \
            msg->tx.cmd = XNET_RPY_DATA;        \
    } while (0)

#endif
