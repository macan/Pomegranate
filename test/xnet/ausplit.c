/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-06 15:33:29 macan>
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
#define OP_ALL          100

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
    snprintf(name, HVFS_MAX_NAME_LEN, "ausplit-xnet-test-%ld-%ld-%d", 
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

    hvfs_debug(xnet, "MDS dpayload %ld (namelen %d, dlen %ld)\n", 
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
    snprintf(name, HVFS_MAX_NAME_LEN, "ausplit-xnet-test-%ld-%ld-%d",
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

    hvfs_debug(xnet, "MDS dpayload %ld (namelen %d, dlen %ld)\n", 
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
    snprintf(name, HVFS_MAX_NAME_LEN, "ausplit-xnet-test-%ld-%ld-%d",
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

    hvfs_debug(xnet, "MDS dpayload %ld (namelen %d, dlen %ld)\n", 
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
                hvfs_err(xnet, "create 'ausplit-xnet-test-%ld-%ld-%d' failed\n",
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
                hvfs_err(xnet, "lookup 'ausplit-xnet-test-%ld-%ld-%d' failed\n",
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
                hvfs_err(xnet, "unlink 'ausplit-xnet-test-%ld-%ld-%d' failed\n",
                         hmi.root_uuid, hmo.site_id, i + base);
            }
        }
        lib_timer_E();
        lib_timer_O(entry, "Unlink Latency: ");
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
    } else {
        msg_send(msa->entry, OP_CREATE, msa->tid * msa->entry);
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

void *ausplit_buf_alloc(size_t size, int aflag)
{
    if (unlikely(aflag == HVFS_MDS2MDS_SPITB)) {
        /* alloc the whole ITB */
        return xzalloc(sizeof(struct itb) + sizeof(struct ite) * ITB_SIZE);
    } else {
        return xzalloc(size);
    }
}

int main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = ausplit_buf_alloc,
        .buf_free = NULL,
        .recv_handler = mds_spool_dispatch,
        .dispatcher = mds_fe_dispatch,
    };
    int err = 0;
    int type = 0;
    int self, sport, i, j, thread;
    long entry;
    int op, memonly;
    char *value;
    char profiling_fname[256];

    hvfs_info(xnet, "type: 0/1/2/3 => mds/client/mdsl/ring\n");
    hvfs_info(xnet, "op:   0/1/2   => create/lookup/unlink\n");
    value = getenv("type");
    if (value) {
        type = atoi(value);
    }
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
    value = getenv("memonly");
    if (value) {
        memonly = atoi(value);
    } else
        memonly = 1;

    pthread_barrier_init(&barrier, NULL, thread);

    if (argc < 2) {
        hvfs_err(xnet, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(xnet, "Self type+ID is %s:%d.\n",
                  (type == TYPE_MDS ? "mds" : 
                   (type == TYPE_CLIENT ? "client" : 
                    (type == TYPE_MDSL ? "mdsl" : "ring"))),
                  self);
    }

    st_init();
    lib_init();
    mds_init(10);
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.itbid_check = 1;
    hmo.conf.prof_plot = 1;
    if (memonly)
        hmo.conf.option |= HVFS_MDS_MEMONLY;

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);

    /* setup the profiling file */
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "./CP-BACK-ausplit.%s.%d",
            (type == TYPE_MDS ? "mds" : 
             (type == TYPE_CLIENT ? "client" : 
              (type == TYPE_MDSL ? "mdsl" : 
               "ring"))), self);
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

    sport = port[type][self];

    switch (type) {
    case TYPE_MDS:
        self = HVFS_MDS(self);
        break;
    case TYPE_CLIENT:
        self = HVFS_CLIENT(self);
        break;
    case TYPE_MDSL:
        self = HVFS_MDSL(self);
        break;
    case TYPE_RING:
        self = HVFS_RING(self);
        break;
    default:;
    }

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;
    hmi.gdt_salt = 0;
    hvfs_info(xnet, "Select GDT salt to  %lx\n", hmi.gdt_salt);
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
    dh_insert(hmi.root_uuid, hmi.root_uuid, hmi.root_salt);
    bitmap_insert(1, 0);

//    SET_TRACING_FLAG(mds, HVFS_DEBUG | HVFS_VERBOSE);

    switch (type) {
    case TYPE_MDS:
        msg_wait();
        break;
    case TYPE_CLIENT:
        msg_send_mt(entry, op, thread);
        break;
    default:;
    }
    
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
