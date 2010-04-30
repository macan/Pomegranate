/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-04-30 18:46:12 macan>
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

#include "hvfs.h"
#include "xnet.h"
#include "mds.h"
#include "ring.h"
#include "lib.h"

#ifdef UNIT_TEST
#define TYPE_MDS        0
#define TYPE_CLIENT     1
#define TYPE_MDSL       2
#define TYPE_RING       3

#define OP_CREATE       0
#define OP_LOOKUP       1
#define OP_UNLINK       2
#define OP_CREATE_DIR   3
#define OP_WDATA        4
#define OP_RDATA        5
#define OP_ALL          100
#define OP_DATA_ALL     200

u64 __attribute__((unused)) split_retry = 0;
u64 __attribute__((unused)) create_failed = 0;
u64 __attribute__((unused)) lookup_failed = 0;
u64 __attribute__((unused)) unlink_failed = 0;

char *ipaddr[] = {
    "10.10.111.9",              /* mds */
    "10.10.111.9",              /* client */
    "10.10.111.9",              /* mdsl */
    "10.10.111.9",              /* ring */
};

short port[4][4] = {
    {8210, 8211, 8212, 8213,},  /* mds */
    {8412, 8413, 8414, 8415,},  /* client */
    {8810, 8811, 8812, 8813,},  /* mdsl */
    {8710, 8711, 8712, 8713,},  /* ring */
};

#define HVFS_TYPE(type, idx) ({                 \
            u64 __sid = -1UL;                   \
            switch (type){                      \
            case TYPE_MDS:                      \
                __sid = HVFS_MDS(idx);          \
                break;                          \
            case TYPE_CLIENT:                   \
                __sid = HVFS_CLIENT(idx);       \
                break;                          \
            case TYPE_MDSL:                     \
                __sid = HVFS_MDSL(idx);         \
                break;                          \
            case TYPE_RING:                     \
                __sid = HVFS_RING(idx);         \
                break;                          \
            default:;                           \
            }                                   \
            __sid;                              \
        })

static inline
u64 HVFS_TYPE_SEL(int type, int id)
{
    u64 site_id = -1UL;

    switch (type) {
    case TYPE_MDS:
        site_id = HVFS_MDS(id);
        break;
    case TYPE_CLIENT:
        site_id = HVFS_CLIENT(id);
        break;
    case TYPE_MDSL:
        site_id = HVFS_MDSL(id);
    case TYPE_RING:
        site_id = HVFS_RING(id);
    default:;
    }

    return site_id;
}

int msg_wait()
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

static inline
u64 SELECT_SITE(u64 itbid, u64 psalt, int type)
{
    struct chp *p;

    p = ring_get_point(itbid, psalt, hmo.chring[type]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return 0;
    }
    return p->site_id;
}

static inline
int SET_ITBID(struct hvfs_index *hi)
{
    struct dhe *e;

    e = mds_dh_search(&hmo.dh, hi->puuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        return PTR_ERR(e);
    }
    hi->itbid = mds_get_itbid(e, hi->hash);

    return 0;
}

int get_send_msg_create(int nid, u64 puuid, u64 itbid,
                        struct mdu_update *imu, void *data)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct mdu_update *mu;
    u64 dsite;
    int err = 0, recreate = 0;

    /* construct the hvfs_index */
    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d", 
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name) + 
        (imu ? sizeof(struct mdu_update) : 0);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);
    
    hi->flag = INDEX_CREATE | INDEX_BY_NAME;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    if (imu) {
        mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) +
                                   strlen(name));
        memcpy(mu, imu, sizeof(struct mdu_update));
        /* The following line is very IMPORTANT! */
        hi->dlen = sizeof(struct mdu_update);
    }

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_CREATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under spliting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        split_retry++;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        create_failed++;
        goto out_msg;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid CREATE reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out_msg;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS. IMPOSSIBLE code path! */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            struct hvfs_index *rhi;
            int no = 0;

            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(xnet, "extract HI failed, not found.\n");
            }
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
    }

    /* finally, we wait for the commit respond */
    if (msg->tx.flag & XNET_NEED_TX) {
    rewait:
        err = sem_wait(&msg->event);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }
    }
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
    return err;
out:
    xfree(hi);
    return err;
}

int get_send_msg_create_dir(int nid, u64 puuid, u64 itbid,
                            struct mdu_update *imu, void *data)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct mdu_update *mu;
    u64 dsite;
    int err = 0, recreate = 0;

    /* construct the hvfs_index */
    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d", 
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name) + 
        (imu ? sizeof(struct mdu_update) : 0);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);
    
    hi->flag = INDEX_CREATE | INDEX_BY_NAME | INDEX_CREATE_DIR;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    if (imu) {
        mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) +
                                   strlen(name));
        memcpy(mu, imu, sizeof(struct mdu_update));
        /* The following line is very IMPORTANT! */
        hi->dlen = sizeof(struct mdu_update);
    }

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_CREATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under spliting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        split_retry++;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        create_failed++;
        goto out_msg;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid CREATE reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out_msg;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS. IMPOSSIBLE code path! */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            struct hvfs_index *rhi;
            int no = 0;

            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(xnet, "extract HI failed, not found.\n");
            }
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
    }

    /* finally, we wait for the commit respond */
    if (msg->tx.flag & XNET_NEED_TX) {
    rewait:
        err = sem_wait(&msg->event);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }
    }
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
    return err;
out:
    xfree(hi);
    return err;
}

/* send_msg_dump()
 */
int __send_msg_dump(struct xnet_msg *msg)
{
    int err;
    
    msg->tx.cmd = HVFS_CLT2MDS_DITB;
    msg->tx.flag &= ~XNET_NEED_REPLY;
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() DITB request failed\n");
        goto out;
    }
out:
    return err;
}

int get_send_msg_lookup(int nid, u64 puuid, u64 itbid)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    int err = 0;

    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d",
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->column = 3;             /* magic here:) */
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);

    hi->flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LOOKUP, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        lookup_failed++;
        __send_msg_dump(msg);
        hvfs_err(mds, "DUMP criminal hash 0x%lx\n", hi->hash);
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid LOOKUP reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n", 
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            struct hvfs_index *rhi;
            int no = 0;

            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(xnet, "extract HI failed, not found.\n");
            }
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
        if (hmr->flag & MD_REPLY_WITH_DC) {
            struct column *c;
            int no = 0;
            
            c = hmr_extract(hmr, EXTRACT_DC, &no);
            if (!c) {
                hvfs_err(xnet, "extract DC failed, not found.\n");
            }
        }
    }
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int get_send_msg_unlink(int nid, u64 puuid, u64 itbid)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    int err = 0;

    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d",
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);

    hi->flag = INDEX_UNLINK | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_UNLINK, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        unlink_failed++;
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid UNLINK reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n", 
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            struct hvfs_index *rhi;
            int no = 0;

            rhi = hmr_extract(hmr, EXTRACT_HI, &no);
            if (!rhi) {
                hvfs_err(xnet, "extract HI failed, not found.\n");
            }
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
    }
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
    if (msg->tx.flag & XNET_NEED_TX) {
    rewait:
        err = sem_wait(&msg->event);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }
    }
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

void __data_read(struct hvfs_index *hi, struct column *c)
{
    u8 *data;
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    int err = 0, i;

    hvfs_err(xnet, "Read column itbid %ld len %ld offset %ld\n",
             c->stored_itbid, c->len, c->offset);

    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err= -ENOMEM;
        goto out_free;
    }

    si->sic.uuid = hi->puuid;
    si->sic.arg0 = c->stored_itbid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = 0;
    si->scd.cr[0].stored_itbid = hi->itbid;
    si->scd.cr[0].file_offset = c->offset;
    si->scd.cr[0].req_offset = 0;
    si->scd.cr[0].req_len = c->len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(c->stored_itbid, hi->psalt, CH_RING_MDSL);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_READ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, si, sizeof(*si) +
                       sizeof(struct column_req));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    /* recv the reply, parse the data now */
    ASSERT(msg->pair->tx.len == c->len, xnet);
    if (msg->pair->xm_datacheck) {
        data = msg->pair->xm_data;
    } else {
        hvfs_err(xnet, "recv data read reply ERROR %d\n",
                 msg->pair->tx.err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    }

    /* check the data now */
    for (i = 0; i < c->len; i++) {
        if (data[i] != (u8)(hi->uuid & 0xff)) {
            hvfs_err(xnet, "Data verify error!\n");
            break;
        }
    }
    
out_msg:
    xnet_free_msg(msg);
out_free:
    xfree(si);

    return;
}

int get_send_msg_rdata(int nid, u64 puuid, u64 itbid)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    int err = 0;

    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d",
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->column = 0;             /* magic here:) */
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);

    hi->flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_COLUMN;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LOOKUP, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        lookup_failed++;
        __send_msg_dump(msg);
        hvfs_err(mds, "DUMP criminal hash 0x%lx\n", hi->hash);
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid LOOKUP reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n", 
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            goto pass;
        }
        
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
        if (hmr->flag & MD_REPLY_WITH_DC) {
            struct column *c;
            
            c = hmr_extract(hmr, EXTRACT_DC, &no);
            if (!c) {
                hvfs_err(xnet, "extract DC failed, not found.\n");
                goto pass;
            }

            /* now, it is ok to write the data region to the MDSL */
            __data_read(rhi, c);
        }
    }
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
pass:
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

void __data_write(struct hvfs_index *hi, struct column *c)
{
    u8 data[1024];
    struct storage_index *si;
    struct xnet_msg *msg;
    struct mdu_update *mu;
    struct mu_column *mc;
    u64 dsite;
    u64 location;
    int len = lib_random(1023) + 1;
    int err = 0, i;

    hvfs_err(xnet, "Read uuid %ld column itbid %ld len %ld offset %ld "
             "target len %d\n",
             hi->uuid, c->stored_itbid, c->len, c->offset, len);
    
    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    for (i = 0; i < len; i++) {
        data[i] = (u8)(hi->uuid & 0xff);
    }
    
    si->sic.uuid = hi->puuid;
    si->sic.arg0 = hi->itbid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = 0;
    si->scd.cr[0].stored_itbid = hi->itbid;
    si->scd.cr[0].req_len = len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDSL);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_WRITE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, si, sizeof(*si) + 
                       sizeof(struct column_req));
    xnet_msg_add_sdata(msg, data, len);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    /* recv the reply, parse the offset now */
    if (msg->pair->xm_datacheck) {
        location = *((u64 *)msg->pair->xm_data);
    } else {
        hvfs_err(xnet, "recv data write reply ERROR!\n");
        goto out_free;
    }

    xnet_free_msg(msg);
    /* ok, we should update the MDU in MDS! */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
    if (!mu) {
        hvfs_err(xnet, "xzalloc() mdu update failed\n");
        goto out_msg;
    }
    mc = (void *)mu + sizeof(*mu);

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);

    hi->flag = INDEX_MDU_UPDATE | INDEX_BY_UUID;
    hi->dlen = sizeof(*mu) + sizeof(struct mu_column);
    hi->namelen = 0;
    mu->size = len;
    mu->column_no = 1;
    mu->valid = MU_COLUMN | MU_SIZE;
    mc->cno = 0;
    mc->c.stored_itbid = hi->itbid;
    mc->c.len = len;
    mc->c.offset = location;
    
    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_UPDATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hi, sizeof(*hi));
    xnet_msg_add_sdata(msg, mu, sizeof(*mu) +
                       sizeof(struct mu_column));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg2;
    }

out_msg2:
    xfree(mu);
out_msg:
    xnet_free_msg(msg);
out_free:
    xfree(si);
    return;
}

int get_send_msg_wdata(int nid, u64 puuid, u64 itbid)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    int err = 0;

    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "client-xnet-test-%ld-%ld-%d",
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->column = 0;             /* magic here:) */
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS);

    hi->flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_COLUMN;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LOOKUP, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        lookup_failed++;
        __send_msg_dump(msg);
        hvfs_err(mds, "DUMP criminal hash 0x%lx\n", hi->hash);
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid LOOKUP reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS */
        hvfs_err(xnet, "MDS Site %lx reply w/ %d\n", 
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            goto pass;
        }
        
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
        if (hmr->flag & MD_REPLY_WITH_DC) {
            struct column *c;
            
            c = hmr_extract(hmr, EXTRACT_DC, &no);
            if (!c) {
                hvfs_err(xnet, "extract DC failed, not found.\n");
                goto pass;
            }

            /* now, it is ok to write the data region to the MDSL */
            __data_write(rhi, c);
        }
    }
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
pass:
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int msg_send(int entry, int op, int base)
{
    lib_timer_def();
    u8 data[HVFS_MDU_SIZE];
    int i, err = 0;

    switch (op) {
    case OP_CREATE:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_create(i + base, hmi.root_uuid, hmo.site_id, 
                                      NULL, (void *)data);
            if (err) {
                hvfs_err(xnet, "create 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "Create Latency: ");
        break;
    case OP_LOOKUP:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_lookup(i + base, hmi.root_uuid, hmo.site_id);
            if (err) {
                hvfs_err(xnet, "lookup 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "Lookup Latency: ");
        break;
    case OP_UNLINK:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_unlink(i + base, hmi.root_uuid, hmo.site_id);
            if (err) {
                hvfs_err(xnet, "unlink 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "Unlink Latency: ");
        break;
    case OP_CREATE_DIR:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_create_dir(i + base, hmi.root_uuid, hmo.site_id, 
                                          NULL, (void *)data);
            if (err) {
                hvfs_err(xnet, "create 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "Create DIR Latency: ");
        break;
    case OP_WDATA:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_wdata(i + base, hmi.root_uuid, hmo.site_id);
            if (err) {
                hvfs_err(xnet, "wdata 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "WDATA Latency: ");
        break;
    case OP_RDATA:
        lib_timer_B();
        for (i = 0; i < entry; i++) {
            err = get_send_msg_rdata(i + base, hmi.root_uuid, hmo.site_id);
            if (err) {
                hvfs_err(xnet, "rdata 'client-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "RDATA Latency: ");
        break;
    default:;
    }

    return err;
}

struct msg_send_args
{
    int tid, thread;
    int entry, op;
    pthread_barrier_t *pb;
};

pthread_barrier_t barrier;

void *__msg_send(void *arg)
{
    struct msg_send_args *msa = (struct msg_send_args *)arg;
    lib_timer_def();

    pthread_barrier_wait(msa->pb);
    if (msa->tid == 0)
        lib_timer_B();
    if (msa->op == OP_ALL) {
        msg_send(msa->entry, OP_CREATE, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Create Aggr Lt: ");
            lib_timer_B();
        }
        msg_send(msa->entry, OP_LOOKUP, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Lookup Aggr Lt: ");
            lib_timer_B();
        }
        msg_send(msa->entry, OP_UNLINK, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Unlink Aggr Lt: ");
        }
    } else if (msa->op == OP_DATA_ALL) {
        msg_send(msa->entry, OP_CREATE, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Create Aggr Lt: ");
            lib_timer_B();
        }
        msg_send(msa->entry, OP_LOOKUP, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Lookup Aggr Lt: ");
            lib_timer_B();
        }
        msg_send(msa->entry, OP_WDATA, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "WDATA  Aggr Lt: ");
        }
        msg_send(msa->entry, OP_RDATA, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "RDATA  Aggr Lt: ");
        }
        msg_send(msa->entry, OP_UNLINK, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Unlink Aggr Lt: ");
        }
    } else {
        msg_send(msa->entry, msa->op, msa->tid * msa->entry);
        pthread_barrier_wait(msa->pb);
        if (msa->tid == 0) {
            lib_timer_E();
            lib_timer_O(msa->entry * msa->thread, "Aggr Latency: ");
        }
    }

    pthread_exit(0);
}

int msg_send_mt(int entry, int op, int thread)
{
    pthread_t pt[thread];
    struct msg_send_args msa[thread];
    int i, err = 0;

    entry /= thread;

    for (i = 0; i < thread; i++) {
        msa[i].tid = i;
        msa[i].thread = thread;
        msa[i].entry = entry;
        msa[i].op = op;
        msa[i].pb = &barrier;
        err = pthread_create(&pt[i], NULL, __msg_send, &msa[i]);
        if (err)
            goto out;
    }

    for (i = 0; i < thread; i++) {
        pthread_join(pt[i], NULL);
    }
out:
    return err;
}

int get_send_msg_create_gdt(int dsite, struct hvfs_index *oi, void *data)
{
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct gdt_md *mdu;
    int err = 0, recreate = 0, nr = 0;

    /* construct the hvfs_index */
    dpayload = sizeof(struct hvfs_index) + HVFS_MDU_SIZE;
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    memcpy(hi, oi, sizeof(*hi));
    hi->puuid = hmi.gdt_uuid;
    hi->psalt = hmi.gdt_salt;
    /* itbid should be lookup and calculated by the caller! */
    hi->itbid = oi->itbid;
    hi->namelen = 0;
    hi->flag = INDEX_CREATE | INDEX_CREATE_COPY | INDEX_BY_UUID |
        INDEX_CREATE_GDT;

    memcpy((void *)hi + sizeof(struct hvfs_index),
           data, HVFS_MDU_SIZE);
    /* The following line is very IMPORTANT! */
    hi->dlen = HVFS_MDU_SIZE;
    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_CREATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(xnet, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under spliting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        split_retry++;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %ld w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        create_failed++;
        goto out_msg;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid CREATE reply from site %ld.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out_msg;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS. IMPOSSIBLE code path! */
        hvfs_err(xnet, "MDS Site %ld reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
    }
    /* ok, we got the correct respond, insert it to the DH */
    hi = hmr_extract(hmr, EXTRACT_HI, &nr);
    if (!hi) {
        hvfs_err(xnet, "Invalid reply w/o hvfs_index as expected.\n");
        goto skip;
    }
    mdu = hmr_extract(hmr, EXTRACT_MDU, &nr);
    if (!mdu) {
        hvfs_err(xnet, "Invalid reply w/o MDU as expacted.\n");
        goto skip;
    }
    hvfs_err(xnet, "Got suuid 0x%lx ssalt %lx puuid %lx psalt %lx.\n", 
               hi->uuid, mdu->salt, mdu->puuid, mdu->psalt);
    /* we should export the self salt to the caller */
    oi->ssalt = mdu->salt;
    
    /* finally, we wait for the commit respond */
skip:
    if (msg->tx.flag & XNET_NEED_TX) {
    rewait:
        err = sem_wait(&msg->event);
        if (err < 0) {
            if (errno == EINTR)
                goto rewait;
            else
                hvfs_err(xnet, "sem_wait() failed %d\n", errno);
        }
    }
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
    return err;
out:
    xfree(hi);
    return err;
}

int lookup_root()
{
    struct xnet_msg *msg;
    struct hvfs_index hi;
    struct hvfs_md_reply *hmr;
    struct dhe *gdte;
    u64 dsite;
    int err = 0;

    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(xnet, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out;
    }

    memset(&hi, 0, sizeof(hi));
    hi.puuid = hmi.gdt_uuid;
    hi.psalt = hmi.gdt_salt;
    hi.uuid = hmi.root_uuid;
    hi.hash = hvfs_hash_gdt(hi.uuid, hmi.gdt_salt);
    hi.itbid = mds_get_itbid(gdte, hi.hash);
    hi.flag = INDEX_LOOKUP | INDEX_BY_UUID;

    dsite = SELECT_SITE(hi.itbid, hi.psalt, CH_RING_MDS);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LOOKUP, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &hi, sizeof(hi));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_free;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err) {
        hvfs_err(mds, "lookup root failed w/ %d\n",
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_free;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid LOOKUP reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out_free;
    }
    /* ok, get the root mdu */
    {
        struct gdt_md *m;
        int no = 0;

        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
        }
        hmi.root_salt = m->salt;
        hvfs_info(xnet, "Change root salt to %lx\n", hmi.root_salt);
    }
    xnet_set_auto_free(msg->pair);
out_free:
    xnet_free_msg(msg);
out:
    return err;
}

int create_root()
{
    char data[HVFS_MDU_SIZE];
    struct hvfs_index hi;
    struct dhe *gdte;
    struct mdu *mdu = (struct mdu *)data;
    struct chp *p;
    u64 *i = (u64 *)(data + sizeof(struct mdu));
    int err = 0;

    gdte = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
    if (IS_ERR(gdte)) {
        /* fatal error */
        hvfs_err(xnet, "This is a fatal error, we can not find the GDT DHE.\n");
        err = PTR_ERR(gdte);
        goto out;
    }

    memset(&hi, 0, sizeof(hi));
    hi.uuid = hmi.root_uuid;
    hi.hash = hvfs_hash(hi.uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);
    hi.itbid = mds_get_itbid(gdte, hi.hash);

    /* find the GDT service MDS */
    p = ring_get_point(hi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto out;
    }

    /* ok, step 1, we lookup the root entry, if failed we will create a new
     * root entry */
    if (lookup_root() == 0) {
        hvfs_info(xnet, "Lookup root entry successfully.\n");
        return 0;
    }

    memset(data, 0, HVFS_MDU_SIZE);
    mdu->mode = 0xff;
    mdu->nlink = 2;
    mdu->flags = HVFS_MDU_IF_NORMAL;
    
    *i = hmi.root_uuid;         /* the root is myself */
    *(i + 1) = hmi.root_salt;
    *(i + 2) = hmi.root_salt;

    err = get_send_msg_create_gdt(p->site_id, &hi, data);
    if (err) {
        hvfs_err(xnet, "create root GDT entry failed w/ %d\n", err);
    }

    /* update the root salt now */
    hmi.root_salt = hi.ssalt;
    hvfs_info(xnet, "Change root salt to %lx\n", hmi.root_salt);
    
out:
    return err;
}

int dh_insert(u64 uuid, u64 puuid, u64 ssalt)
{
    struct hvfs_index hi;
    struct dhe *e;
    int err = 0;

    memset(&hi, 0, sizeof(hi));
    hi.uuid = uuid;
    hi.puuid = puuid;
    hi.ssalt = ssalt;

    e = mds_dh_insert(&hmo.dh, &hi);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_debug(xnet, "Insert dir:%lx in DH w/  %p\n", uuid, e);
out:
    return err;
}

int dh_search(u64 uuid)
{
    struct dhe *e;
    int err = 0;

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    hvfs_debug(xnet, "Search dir:%lx in DH hit %p\n", uuid, e);
out:
    return err;
}

int dh_remove(u64 uuid)
{
    return mds_dh_remove(&hmo.dh, uuid);
}

int bitmap_insert(u64 uuid, u64 offset)
{
    struct dhe *e;
    struct itbitmap *b;
    int err = 0, i;

    b = xzalloc(sizeof(*b));
    if (!b) {
        hvfs_err(xnet, "xzalloc() struct itbitmap failed\n");
        err = -ENOMEM;
        goto out;
    }
    INIT_LIST_HEAD(&b->list);
    b->offset = (offset / XTABLE_BITMAP_SIZE) * XTABLE_BITMAP_SIZE;
    b->flag = BITMAP_END;
    /* set all bits to 1, within the previous 8 ITBs */
    for (i = 0; i < ((1 << hmo.conf.itb_depth_default) / 8); i++) {
        b->array[i] = 0xff;
    }

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out_free;
    }
    err = __mds_bitmap_insert(e, b);
    if (err) {
        hvfs_err(xnet, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }

out:
    return err;
out_free:
    xfree(b);
    return err;
}

/* ring_add() add one site to the CH ring
 */
int ring_add(struct chring **r, u64 site)
{
    struct chp *p;
    char buf[256];
    int vid_max, i, err;

    vid_max = hmo.conf.ring_vid_max ? hmo.conf.ring_vid_max : HVFS_RING_VID_MAX;

    if (!*r) {
        *r = ring_alloc(vid_max << 1, 0);
        if (!*r) {
            hvfs_err(xnet, "ring_alloc() failed.\n");
            return -ENOMEM;
        }
    }

    p = (struct chp *)xzalloc(vid_max * sizeof(struct chp));
    if (!p) {
        hvfs_err(xnet, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < vid_max; i++) {
        snprintf(buf, 256, "%ld.%d", site, i);
        (p + i)->point = hvfs_hash(site, (u64)buf, strlen(buf), HASH_SEL_VSITE);
        (p + i)->vid = i;
        (p + i)->type = CHP_AUTO;
        (p + i)->site_id = site;
        err = ring_add_point(p + i, *r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = NULL,
    };
    int err = 0;
    int self, sport, i, j, thread;
    long entry;
    int op;
    char *value;
    char profiling_fname[256];

    hvfs_info(xnet, "op:   0/1/2/3/4/5/100/200   => "
              "create/lookup/unlink/create_dir/wdata/rdata/all/data_all\n");
    value = getenv("entry");
    if (value) {
        entry = atoi(value);
    } else {
        entry = 1024;
    }
    value = getenv("op");
    if (value) {
        op = atoi(value);
    } else {
        op = OP_LOOKUP;
    }
    value = getenv("thread");
    if (value) {
        thread = atoi(value);
    } else {
        thread = 1;
    }

    pthread_barrier_init(&barrier, NULL, thread);

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is client:%d.\n", self);
    }

    st_init();
    lib_init();
    mds_pre_init();
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.prof_plot = 1;
    mds_init(10);
    
//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);

    /* setup the profiling file */
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "./CP-BACK-client.%d", self);
    hmo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hmo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s failed %d\n", 
                 profiling_fname, errno);
        return EINVAL;
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            xnet_update_ipaddr(HVFS_TYPE(i, j), 1, &ipaddr[i], 
                               (short *)(&port[i][j]));
        }
    }

    sport = port[TYPE_CLIENT][self];
    self = HVFS_CLIENT(self);

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;
    hmi.gdt_salt = 0;
    hvfs_info(xnet, "Select GDT salt to %lx\n", hmi.gdt_salt);
    hmi.root_uuid = 1;
    hmi.root_salt = 0xdfeadb0;
    hvfs_info(xnet, "Select root salt to %lx\n", hmi.root_salt);

    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(1));
    ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(0));
    ring_add(&hmo.chring[CH_RING_MDSL], HVFS_MDSL(1));

    ring_dump(hmo.chring[CH_RING_MDS]);
    ring_dump(hmo.chring[CH_RING_MDSL]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);

    err = mds_verify();
    if (err) {
        hvfs_err(xnet, "Verify MDS configration failed!\n");
        goto out;
    }

//    SET_TRACING_FLAG(mds, HVFS_DEBUG | HVFS_VERBOSE);

    create_root();
    msg_send_mt(entry, op, thread);
    
    hvfs_info(xnet, "Split_retry %ld, FAILED:[create,lookup,unlink] "
              "%ld %ld %ld\n",
              split_retry, create_failed, lookup_failed, unlink_failed);

    pthread_barrier_destroy(&barrier);
    xnet_unregister_type(hmo.xc);
    mds_destroy();
out:
    return err;
}
#endif
