/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-04 17:44:15 macan>
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
u64 split_retry = 0;
u64 create_failed = 0;
u64 lookup_failed = 0;
u64 unlink_failed = 0;

char *ipaddr1[] = {
    "127.0.0.1",
};

char *ipaddr2[] = {
    "127.0.0.1",
};

short port1[] = {
    8412,
};

short port2[] = {
    8210,
};

void hmr_print(struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct mdu *m;
    struct link_source *ls;
    void *p = hmr->data;

    hvfs_info(xnet, "hmr-> err %d, mdu_no %d, len %d, flag 0x%x.\n",
              hmr->err, hmr->mdu_no, hmr->len, hmr->flag);
    if (!p)
        return;
    hi = (struct hvfs_index *)p;
    hvfs_info(xnet, "hmr-> HI: namelen %d, flag 0x%x, uuid %ld, hash %ld, itbid %ld, "
              "puuid %ld, psalt %ld\n", hi->namelen, hi->flag, hi->uuid, hi->hash,
              hi->itbid, hi->puuid, hi->psalt);
    p += sizeof(struct hvfs_index);
    if (hmr->flag & MD_REPLY_WITH_MDU) {
        m = (struct mdu *)p;
        hvfs_info(xnet, "hmr->MDU: size %ld, dev %ld, mode 0x%x, nlink %d, uid %d, "
                  "gid %d, flags 0x%x, atime %lx, ctime %lx, mtime %lx, dtime %lx, "
                  "version %d\n", m->size, m->dev, m->mode, m->nlink, m->uid,
                  m->gid, m->flags, m->atime, m->ctime, m->mtime, m->dtime,
                  m->version);
        p += sizeof(struct mdu);
    }
    if (hmr->flag & MD_REPLY_WITH_LS) {
        ls = (struct link_source *)p;
        hvfs_info(xnet, "hmr-> LS: hash %ld, puuid %ld, uuid %ld\n",
                  ls->s_hash, ls->s_puuid, ls->s_uuid);
        p += sizeof(struct link_source);
    }
    if (hmr->flag & MD_REPLY_WITH_BITMAP) {
        hvfs_info(xnet, "hmr-> BM: ...\n");
    }
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

/* get_send_msg_create()
 */
int get_send_msg_create(int dsite, int nid, u64 puuid, u64 itbid, u64 flag, 
                        struct mdu_update* imu)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct mdu_update *mu;
    int err = 0, recreate = 0;

    /* construct the hvfs_index */
    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "mds-xnet-test-%ld-%ld-%d", 
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name) + 
        (imu ? sizeof(struct mdu_update) : 0);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = flag;
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
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
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

/* get_send_msg_unlink()
 */
int get_send_msg_unlink(int dsite, int nid, u64 puuid, u64 itbid, u64 flag)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    int err = 0;

    /* construct the hvfs_index */
    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "mds-xnet-test-%ld-%ld-%d", 
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed \n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = flag;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
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
        goto out_msg;
    }
    /* this means we hvae got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %ld w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        unlink_failed++;
        goto out_msg;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid UNLINK reply from site %ld.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
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
    /* ok, we got the correct respond, dump it */
//    hmr_print(hmr);
    /* FIXME: wait for the commit respond */
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

/**
 *@dsite: dest site
 *@nid: name id
 */
int get_send_msg_lookup(int dsite, int nid, u64 puuid, u64 itbid, u64 flag)
{
    char name[HVFS_MAX_NAME_LEN];
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    int err = 0;
    
    memset(name, 0, sizeof(name));
    snprintf(name, HVFS_MAX_NAME_LEN, "mds-xnet-test-%ld-%ld-%d", 
             puuid, itbid, nid);
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = flag;
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

    hvfs_debug(xnet, "MSG dpayload %d (namelen %d, dlen %ld)\n", 
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
        hvfs_err(xnet, "LOOKUP failed @ MDS site %ld w/ %d\n",
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
        hvfs_err(xnet, "Invalid LOOKUP reply from site %ld.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS */
        hvfs_err(xnet, "MDS Site %ld reply w/ %d\n", 
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

int msg_send(int dsite, int loop)
{
    lib_timer_def();
    int i, err;
    u64 puuid = 0;
    
    /* create many ites */
    lib_timer_start(&begin);
    for (i = 0; i < loop; i++) {
        err = get_send_msg_create(dsite, i, puuid, 0, 
                                  INDEX_CREATE, NULL);
        if (err) {
            hvfs_err(xnet, "create 'mds-xnet-test-%ld-%ld-%d' failed\n",
                     puuid, 0UL, i);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo_plus(&begin, &end, loop, "CREATE Latency: ");

    hvfs_info(xnet, "Create %d ITE(s) done.\n", loop);
    
    /* do lookup */
    lib_timer_start(&begin);
    for (i = 0; i < loop; i++) {
        err = get_send_msg_lookup(dsite, i, puuid, 0,
                                  INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE);
        if (err) {
            hvfs_err(xnet, "lookup 'mds-xnet-test-%ld-%ld-%d' failed\n",
                     puuid, 0UL, i);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo_plus(&begin, &end, loop, "LOOKUP Latency: ");

    hvfs_info(xnet, "Lookup %d ITE(s) done.\n", loop);

    /* then delete them */
    lib_timer_start(&begin);
    for (i = 0; i < loop; i++) {
        err = get_send_msg_unlink(dsite, i, puuid, 0,
                                  INDEX_UNLINK | INDEX_BY_NAME | 
                                  INDEX_ITE_ACTIVE);
        if (err) {
            hvfs_err(xnet, "unlink 'mds-xnet-test-%ld-%ld-%d' failed\n",
                     puuid, 0UL, i);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo_plus(&begin, &end, loop, "UNLINK Latency: ");
    
    hvfs_info(xnet, "Unlink %d ITE(s) done.\n", loop);
    hvfs_info(xnet, "Split_retry %ld, FAILED:[create,lookup,unlink] "
              "%ld %ld %ld\n",
              split_retry, create_failed, lookup_failed, unlink_failed);

    return 0;
}

int msg_wait(int dsite)
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

int dh_insert(u64 uuid, u64 puuid, u64 psalt)
{
    struct hvfs_index hi;
    struct dhe *e;
    int err = 0;

    memset(&hi, 0, sizeof(hi));
    hi.uuid = uuid;
    hi.puuid = puuid;
    hi.ssalt = psalt;

    e = mds_dh_insert(&hmo.dh, &hi);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_info(xnet, "Insert dir:%8ld in DH w/  %p\n", uuid, e);
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
    hvfs_info(xnet, "Search dir:%8ld in DH hit %p\n", uuid, e);
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
        .recv_handler = mds_fe_dispatch,
    };
    int err = 0;
    int dsite, self, entry = 0;
    short port;
    char *value;

    value = getenv("entry");
    if (value) {
        entry = atoi(value);
    }
    if (!entry)
        entry = 100;
    
    if (argc == 2) {
        /* Server Mode */
        port = 8210;
        dsite = HVFS_CLIENT(0);
        self = HVFS_MDS(0);
    } else {
        /* Client Mode */
        port = 8412;
        dsite = HVFS_MDS(0);
        self = HVFS_CLIENT(0);
    }
    
    hvfs_info(xnet, "Full Path MDS w/ XNET Simple UNIT TESTing Mode(%s)...\n",
              (HVFS_IS_MDS(self) ? "Server" : "Client"));

    st_init();
    lib_init();
    mds_pre_init();
    mds_init(10);                /* max capacity is 2^11 */
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.itbid_check = 1;

    hmo.xc = xnet_register_type(0, port, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }
    hmo.site_id = self;
    hmi.gdt_salt = lib_random(0xfffffff);
    hvfs_info(xnet, "Select GDT salt to %ld\n", hmi.gdt_salt);

    xnet_update_ipaddr(HVFS_CLIENT(0), 1, ipaddr1, port1);
    xnet_update_ipaddr(HVFS_MDS(0), 1, ipaddr2, port2);

//    SET_TRACING_FLAG(xnet, HVFS_DEBUG);
//    SET_TRACING_FLAG(mds, HVFS_DEBUG);
//    SET_TRACING_FLAG(lib, HVFS_DEBUG);

    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_dump(hmo.chring[CH_RING_MDS]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);

    if (HVFS_IS_CLIENT(self))
        msg_send(dsite, entry);
    else
        msg_wait(dsite);

    xnet_unregister_type(hmo.xc);
    dh_remove(hmi.gdt_uuid);
    st_destroy();
    mds_destroy();

    return 0;
out:
    dh_remove(hmi.gdt_uuid);
    st_destroy();
    mds_destroy();

    return err;
}
#endif
