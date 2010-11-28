/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-28 18:47:07 macan>
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
#include "root.h"
#include "amc_api.h"
#include <getopt.h>

/* global variables */
atomic64_t split_retry = {.counter = 0,};
atomic64_t create_failed = {.counter = 0,};
atomic64_t lookup_failed = {.counter = 0,};
atomic64_t unlink_failed = {.counter = 0,};

/* Note that the AMC client just wrapper the mds core functions to act as a
 * standalone program. The API exported by this file can be called by the
 * python program.
 */
#define HVFS_R2_DEFAULT_PORT    8710
#define HVFS_AMC_DEFAULT_PORT   9001
#define HVFS_CLT_DEFAULT_PORT   8412

static inline char *__toupper(char *str)
{
    if (strcmp(str, "client") == 0)
        return "Client";
    else if (strcmp(str, "amc") == 0)
        return "AMC";
    
    return "Unknown";
}

int __hvfs_list(u64 duuid, int op, struct list_result *lr);

static
int __UNUSED__ msg_wait()
{
    while (1) {
        xnet_wait_any(hmo.xc);
    }
    return 0;
}

static inline
u64 SELECT_SITE(u64 itbid, u64 psalt, int type, u32 *vid)
{
    struct chp *p;

    p = ring_get_point(itbid, psalt, hmo.chring[type]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        return -1UL;
    }
    *vid = p->vid;
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
    mds_dh_put(e);

    return 0;
}

static
void __UNUSED__ hmr_print(struct hvfs_md_reply *hmr)
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
    if (oi->flag & INDEX_CREATE_KV) {
        hi->flag |= INDEX_CREATE_KV;
    }

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
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %ld w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
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
    hvfs_info(xnet, "Got suuid 0x%lx ssalt %lx puuid %lx psalt %lx.\n", 
               hi->uuid, mdu->salt, mdu->puuid, mdu->psalt);
    /* we should export the self salt to the caller */
    oi->ssalt = mdu->salt;
    //hmr_print(hmr);
    
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
        hvfs_debug(xnet, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_debug(xnet, "Insert dir:%lx in DH w/  %p\n", uuid, e);
    mds_dh_put(e);
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
    mds_dh_put(e);
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
        mds_dh_put(e);
        hvfs_err(xnet, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }
    mds_dh_put(e);
    
out:
    return err;
out_free:
    xfree(b);
    return err;
}

int bitmap_insert2(u64 uuid, u64 offset, void *bitmap, int len)
{
    struct dhe *e;
    struct itbitmap *b;
    int err = 0;

    b = xzalloc(sizeof(*b));
    if (!b) {
        hvfs_err(xnet, "xzalloc() struct itbitmap failed\n");
        err = -ENOMEM;
        goto out;
    }
    INIT_LIST_HEAD(&b->list);
    b->offset = (offset / XTABLE_BITMAP_SIZE) * XTABLE_BITMAP_SIZE;
    b->flag = BITMAP_END;
    /* copy the bitmap */
    memcpy(b->array, bitmap, len);
    memset(b->array + len, 0, XTABLE_BITMAP_BYTES - len);

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out_free;
    }
    err = __mds_bitmap_insert(e, b);
    if (err) {
        mds_dh_put(e);
        hvfs_err(xnet, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }
    mds_dh_put(e);

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
        err = ring_add_point_nosort(p + i, *r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
}

struct chring *chring_tx_to_chring(struct chring_tx *ct)
{
    struct chring *ring;
    int err = 0, i;

    ring = ring_alloc(ct->nr, ct->group);
    if (IS_ERR(ring)) {
        hvfs_err(xnet, "ring_alloc failed w/ %ld\n",
                 PTR_ERR(ring));
        return ring;
    }

    /* ok, let's copy the array to chring */
    for (i = 0; i < ct->nr; i++) {
        err = ring_add_point_nosort(&ct->array[i], ring);
        if (err) {
            hvfs_err(xnet, "ring add point failed w/ %d\n", err);
            goto out;
        }
    }
    /* sort it */
    ring_resort_nolock(ring);

    /* calculate the checksum of the CH ring */
    lib_md5_print(ring->array, ring->alloc * sizeof(struct chp), "CHRING");

    return ring;
out:
    ring_free(ring);
    return ERR_PTR(err);
}

/* r2cli_do_reg()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_reg(u64 request_site, u64 root_site, u64 fsid, u32 gid)
{
    struct xnet_msg *msg;
    int err = 0;

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_REG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    /* send the reg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ERECOVER) {
        hvfs_err(xnet, "R2 notify a client recover process on site "
                 "%lx, do it.\n", request_site);
    } else if (msg->pair->tx.err == -EHWAIT) {
        hvfs_err(xnet, "R2 reply that another instance is still alive, "
                 "wait a moment and retry.\n");
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "Reg site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

    /* parse the register reply message */
    hvfs_info(xnet, "Begin parse the reg reply message\n");
    if (msg->pair->xm_datacheck) {
        void *data = msg->pair->xm_data;
        void *bitmap;
        union hvfs_x_info *hxi;
        struct chring_tx *ct;
        struct root_tx *rt;
        struct hvfs_site_tx *hst;

        /* parse hxi */
        err = bparse_hxi(data, &hxi);
        if (err < 0) {
            hvfs_err(xnet, "bparse_hxi failed w/ %d\n", err);
            goto out;
        }
        memcpy(&hmi, hxi, sizeof(hmi));
        data += err;
        /* parse ring */
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(xnet, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        hmo.chring[CH_RING_MDS] = chring_tx_to_chring(ct);
        if (!hmo.chring[CH_RING_MDS]) {
            hvfs_err(xnet, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        err = bparse_ring(data, &ct);
        if (err < 0) {
            hvfs_err(xnet, "bparse_ring failed w/ %d\n", err);
            goto out;
        }
        hmo.chring[CH_RING_MDSL] = chring_tx_to_chring(ct);
        if (!hmo.chring[CH_RING_MDSL]) {
            hvfs_err(xnet, "chring_tx 2 chring failed w/ %d\n", err);
            goto out;
        }
        data += err;
        /* parse root_tx */
        err = bparse_root(data, &rt);
        if (err < 0) {
            hvfs_err(xnet, "bparse root failed w/ %d\n", err);
            goto out;
        }
        data += err;
        hvfs_info(xnet, "fsid %ld gdt_uuid %ld gdt_salt %lx "
                  "root_uuid %ld root_salt %lx\n",
                  rt->fsid, rt->gdt_uuid, rt->gdt_salt, 
                  rt->root_uuid, rt->root_salt);
        if (rt->root_salt == -1UL) {
            hvfs_err(xnet, "root_salt is not valid, please mkfs first!\n");
            err = -EINVAL;
            goto out;
        }
        dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);

        /* parse bitmap */
        err = bparse_bitmap(data, &bitmap);
        if (err < 0) {
            hvfs_err(xnet, "bparse bitmap failed w/ %d\n", err);
            goto out;
        }
        data += err;
        bitmap_insert2(hmi.gdt_uuid, 0, bitmap, err - sizeof(u32));
        
        /* parse addr */
        err = bparse_addr(data, &hst);
        if (err < 0) {
            hvfs_err(xnet, "bparse addr failed w/ %d\n", err);
            goto out;
        }
        /* add the site table to the xnet */
        err = hst_to_xsst(hst, err - sizeof(u32));
        if (err) {
            hvfs_err(xnet, "hst to xsst failed w/ %d\n", err);
        }
    }
    
out:
    xnet_free_msg(msg);
out_nofree:

    return err;
}

/* r2cli_do_unreg()
 *
 * @gid: already right shift 2 bits
 */
int r2cli_do_unreg(u64 request_site, u64 root_site, u64 fsid, u32 gid)
{
    struct xnet_msg *msg;
    union hvfs_x_info *hxi;
    int err = 0;

    hxi = (union hvfs_x_info *)&hmi;

    /* alloc one msg and send it to the perr site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_nofree;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, root_site);
    xnet_msg_fill_cmd(msg, HVFS_R2_UNREG, request_site, fsid);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hxi, sizeof(*hxi));

    /* send te unreeg request to root_site w/ requested siteid = request_site */
    msg->tx.reserved = gid;

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err) {
        hvfs_err(xnet, "Unreg site %lx failed w/ %d\n", request_site,
                 msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }

out:
    xnet_free_msg(msg);
out_nofree:
    return err;
}

void amc_cb_exit(void *arg)
{
    int err = 0;

    err = r2cli_do_unreg(hmo.xc->site_id, HVFS_RING(0), hmo.fsid, 0);
    if (err) {
        hvfs_err(xnet, "unreg self %lx w/ r2 %x failed w/ %d\n",
                 hmo.xc->site_id, HVFS_RING(0), err);
        return;
    }
}

void amc_cb_ring_update(void *arg)
{
    struct chring_tx *ct;
    void *data = arg;
    int err = 0;

    hvfs_info(xnet, "Update the chrings ...\n");
    
    err = bparse_ring(data, &ct);
    if (err < 0) {
        hvfs_err(xnet, "bparse_ring failed w/ %d\n", err);
        goto out;
    }
    hmo.chring[CH_RING_MDS] = chring_tx_to_chring(ct);
    if (!hmo.chring[CH_RING_MDS]) {
        hvfs_err(xnet, "chring_tx 2 chring failed w/ %d\n", err);
        goto out;
    }
    data += err;
    err = bparse_ring(data, &ct);
    if (err < 0) {
        hvfs_err(xnet, "bparse_ring failed w/ %d\n", err);
        goto out;
    }
    hmo.chring[CH_RING_MDSL] = chring_tx_to_chring(ct);
    if (!hmo.chring[CH_RING_MDSL]) {
        hvfs_err(xnet, "chring_tx 2 chring failed w/ %d\n", err);
        goto out;
    }
out:
    return;
}

int hvfs_lookup_root(void)
{
    struct xnet_msg *msg;
    struct hvfs_index hi;
    struct hvfs_md_reply *hmr;
    struct dhe *gdte;
    u64 dsite;
    u32 vid;
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
    mds_dh_put(gdte);
    hi.flag = INDEX_LOOKUP | INDEX_BY_UUID;

    dsite = SELECT_SITE(hi.itbid, hi.psalt, CH_RING_MDS, &vid);

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
        hvfs_info(xnet, "root mdu mode %o nlink %d flags %x\n", 
                  m->mdu.mode, m->mdu.nlink, m->mdu.flags);
        dh_insert(hmi.root_uuid, hmi.root_uuid, hmi.root_salt);
    }
    xnet_set_auto_free(msg->pair);
out_free:
    xnet_free_msg(msg);
out:
    return err;
}

int hvfs_create_root(void)
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
    mds_dh_put(gdte);

    /* find the GDT service MDS */
    p = ring_get_point(hi.itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(xnet, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -ECHP;
        goto out;
    }

    /* ok, step 1, we lookup the root entry, if failed we will create a new
     * root entry */
relookup:
    if (hvfs_lookup_root() == 0) {
        hvfs_info(xnet, "Lookup root entry successfully.\n");
        return 0;
    }

    memset(data, 0, HVFS_MDU_SIZE);
    mdu->mode = 0040755;
    mdu->nlink = 2;
    mdu->flags = HVFS_MDU_IF_NORMAL | HVFS_MDU_IF_KV;
    
    *i = hmi.root_uuid;         /* the root is myself */
    *(i + 1) = hmi.root_salt;
    *(i + 2) = hmi.root_salt;

    err = get_send_msg_create_gdt(p->site_id, &hi, data);
    if (err) {
        hvfs_err(xnet, "create root GDT entry failed w/ %d\n", err);
        if (err == -EEXIST)
            goto relookup;
    }

    /* update the root salt now */
    hmi.root_salt = hi.ssalt;
    dh_insert(hmi.root_uuid, hmi.root_uuid, hmi.root_salt);
    hvfs_info(xnet, "Change root salt to %lx\n", hmi.root_salt);
    
out:
    return err;
}

int amc_dispatch(struct xnet_msg *msg)
{
    int err = 0;

    switch (msg->tx.cmd) {
    case HVFS_FR2_RU:
        err = mds_ring_update(msg);
        break;
    default:
        hvfs_err(xnet, "AMC core dispatcher handle INVALID "
                 "request <0x%lx %d>\n",
                 msg->tx.ssite_id, msg->tx.reqno);
        err = -EINVAL;
    }

    return err;

}

int __core_main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = amc_dispatch,
    };
    int err = 0;
    int self = -1, sport = -1;
    int thread = 1;
    int fsid = 1;               /* default to fsid 1 for kv store */
    char *r2_ip = NULL;
    char *type = NULL;
    short r2_port = HVFS_R2_DEFAULT_PORT;
    char *shortflags = "d:p:t:h?r:y:f:";
    struct option longflags[] = {
        {"id", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        {"thread", required_argument, 0, 't'},
        {"root", required_argument, 0, 'r'},
        {"type", required_argument, 0, 'y'},
        {"fsid", required_argument, 0, 'f'},
        {"help", no_argument, 0, '?'},
    };
    char profiling_fname[256];

    while (1) {
        int longindex = -1;
        int opt = getopt_long(argc, argv, shortflags, longflags, &longindex);
        if (opt == -1)
            break;
        switch (opt) {
        case 'd':
            self = atoi(optarg);
            break;
        case 'p':
            sport = atoi(optarg);
            break;
        case 't':
            thread = atoi(optarg);
            break;
        case 'r':
            r2_ip = strdup(optarg);
            break;
        case 'y':
            type = strdup(optarg);
            break;
        case 'f':
            fsid = atoi(optarg);
            break;
        case 'h':
        case '?':
            hvfs_info(xnet, "help menu:\n");
            hvfs_info(xnet, "    -d,--id      self CLT/AMC id.\n");
            hvfs_info(xnet, "    -p,--port    self CLT/AMC port.\n");
            hvfs_info(xnet, "    -t,--thread  thread number.\n");
            hvfs_info(xnet, "    -r,--root    root server.\n");
            hvfs_info(xnet, "    -y,--type    client type: client/amc.\n");
            hvfs_info(xnet, "    -h,--help    print this menu.\n");
            return 0;
            break;
        default:
            return EINVAL;
        }
    }

    /* ok, check the arguments */
    if (!type)
        type = "amc";
    
    if (strncmp("client", type, 6) == 0) {
        type = "client";
    } else if (strncmp("amc", type, 3) == 0) {
        type = "amc";
    } else
        return EINVAL;
    
    if (self == -1) {
        hvfs_err(xnet, "Please set the AMC id w/ '-d' option\n");
        return EINVAL;
    }

    if (sport == -1) {
        if (strncmp("client", type, 6) == 0) {
            sport = HVFS_CLT_DEFAULT_PORT;
        } else 
            sport = HVFS_AMC_DEFAULT_PORT;
    }
    
    if (!r2_ip) {
        hvfs_err(xnet, "Please set the r2 server ip w/ '-r' option\n");
        return EINVAL;
    }

    hvfs_info(xnet, "%s Self id %d port %d\n", __toupper(type), self, sport);

    /* it is ok to init the MDS core function now */
    st_init();
    lib_init();
    mds_pre_init();
    hmo.prof.xnet = &g_xnet_prof;
    hmo.conf.prof_plot = 1;
    mds_init(10);
    hmo.gossip_thread_stop = 1;
    if (hmo.conf.xnet_resend_to)
        g_xnet_conf.resend_timeout = hmo.conf.xnet_resend_to;

    /* setup the profiling file */
    memset(profiling_fname, 0, sizeof(profiling_fname));
    sprintf(profiling_fname, "./CP-BACK-%s.%d", type, self);
    hmo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hmo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s failed %d\n",
                 profiling_fname, errno);
        return EINVAL;
    }

    /* setup the address of root server */
    xnet_update_ipaddr(HVFS_RING(0), 1, &r2_ip, &r2_port);
    if (strcmp(type, "amc") == 0) {
        self = HVFS_AMC(self);
    } else if (strcmp(type, "client") == 0) {
        self = HVFS_CLIENT(self);
    } else {
        return EINVAL;
    }

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;
    hmo.fsid = fsid;
    
    hmo.cb_exit = amc_cb_exit;
    hmo.cb_ring_update = amc_cb_ring_update;
    err = r2cli_do_reg(self, HVFS_RING(0), fsid, 0);
    if (err) {
        hvfs_err(xnet, "ref self %x w/ r2 %x failed w/ %d\n",
                 self, HVFS_RING(0), err);
        goto out;
    }
    hvfs_info(xnet, "AMI gdt uuid %ld salt %lx root uuid %ld "
              "salt %lx for site %s %x\n",
              hmi.gdt_uuid, hmi.gdt_salt, hmi.root_uuid,
              hmi.root_salt, type, self);

    err = mds_verify();
    if (err) {
        hvfs_err(xnet, "Verify MDS configration failed!\n");
        goto out;
    }

    /* should we create root entry? no! */
    //SET_TRACING_FLAG(xnet, HVFS_DEBUG);

    /* FIXME: we should coming into a shell to send/recv requests and wait for
     * replies. */

out:
    return err;
}

void __core_exit(void)
{
    mds_destroy();
    xnet_unregister_type(hmo.xc);
}

/* hvfs_create_table() create a new table 'name' in the root directory, for
 * now we do not support hierarchical table namespace.
 */
int hvfs_create_table(char *name)
{
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct mdu_update *mu;
    u64 dsite;
    u32 vid;
    int err = 0, recreate = 0;

    /* Note that we just create the sdt entry, gdt entry is not need
     * actually */

    /* construct the hvfs_index */
    dpayload = sizeof(struct hvfs_index) + strlen(name) + 
        sizeof(struct mdu_update);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(hmi.root_uuid, (u64)name, strlen(name),
                         HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;

    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

    /* using INDEX_CREATE_KV to get the self salt value */
    hi->flag = INDEX_CREATE | INDEX_BY_NAME | INDEX_CREATE_DIR |
        INDEX_CREATE_KV;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) +
                               strlen(name));
    mu->valid = MU_FLAG_ADD;
    mu->flags = HVFS_MDU_IF_KV | HVFS_MDU_IF_NORMAL;
    hi->dlen = sizeof(struct mdu_update);

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

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }
    /* ok, we have got the reply, parse it to check the return statues */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
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
    /* ok, create the gdt entry now */
    {
        struct hvfs_index *rhi;
        struct dhe *e;
        struct gdt_md *m;
        struct chp *p;
        int no = 0;

        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            goto out_msg;
        }
        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "extract MDU failed, not found.\n");
            goto out_msg;
        }
        e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "This is a fatal error, we can not find the GDT DHE.\b");
            err = PTR_ERR(e);
            goto out_msg;
        }
        memset(hi, 0, sizeof(*hi));
        hi->uuid = rhi->uuid;
        hi->hash = hvfs_hash(hi->uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);
        hi->itbid = mds_get_itbid(e, hi->hash);
        mds_dh_put(e);
        hi->flag = INDEX_CREATE_KV;

        /* find the GDT service MDS */
        p = ring_get_point(hi->itbid, hmi.gdt_salt, hmo.chring[CH_RING_MDS]);
        if (IS_ERR(p)) {
            hvfs_err(xnet, "ring_get_point() failed w/ %ld\n",
                     PTR_ERR(p));
            err = -ECHP;
            goto out_msg;
        }
        m->mdu.mode = 0040755;
        m->mdu.nlink = 2;
        m->mdu.flags = HVFS_MDU_IF_NORMAL | HVFS_MDU_IF_KV;
        m->puuid = rhi->puuid;
        m->salt = m->mdu.dev;
        m->psalt = rhi->psalt;

        err = get_send_msg_create_gdt(p->site_id, hi, m);
        if (err) {
            hvfs_err(xnet, "create table GDT entry failed w/ %d\n",
                     err);
            goto out_msg;
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

int hvfs_find_table(char *name, u64 *uuid, u64 *salt)
{
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    u32 vid;
    int err = 0;

    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(hmi.root_uuid, (u64)name, strlen(name),
                         HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;

    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

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

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
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
        struct gdt_md *gmd;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
        }
        *uuid = rhi->uuid;
        gmd = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!gmd) {
            hvfs_err(xnet, "extract MDU failed, not found.\n");
        }
        *salt = gmd->mdu.dev;
        dh_insert(rhi->uuid, hmi.root_uuid, *salt);
        
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid, 
                                 MDS_BITMAP_SET);
            hvfs_debug(xnet, "update %ld bitmap %ld to 1.\n", 
                       rhi->puuid, rhi->itbid);
        }
    }
    /* ok, we got the correct respond, dump it */
    //hmr_print(hmr);
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int hvfs_drop_table(char *name)
{
    size_t dpayload;
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    u32 vid;
    int err = 0;

    /* check if this table is empty, if it is not empty, we reject the drop
     * operation */
    {
        struct list_result lr = {
            .arg = NULL,
            .cnt = 0,
        };
        u64 uuid, salt;
        
        err = hvfs_find_table(name, &uuid, &salt);
        if (err) {
            hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n",
                     err);
            goto out_exit;
        }
        err = __hvfs_list(uuid, LIST_OP_COUNT, &lr);
        if (err) {
            hvfs_err(xnet, "__hvfs_list() failed w/ %d\n", err);
            goto out_exit;
        }
        if (lr.cnt) {
            hvfs_err(xnet, "Table %s is not empty (%d entrie(s)), "
                     "reject drop\n", name, lr.cnt);
            err = -EINVAL;
            goto out_exit;
        }
    }

    /* normal drop table flow */
    dpayload = sizeof(struct hvfs_index) + strlen(name);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    hi->hash = hvfs_hash(hmi.root_uuid, (u64)name, strlen(name),
                         HASH_SEL_EH);
    hi->puuid = hmi.root_uuid;
    hi->psalt = hmi.root_salt;

    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

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
resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT){
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
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
    /* Then, we should release the gdt entry now */
    {
        struct xnet_msg *msg2;
        struct hvfs_index hi, *rhi;
        struct dhe *gdte;
        int no = 0;

        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            err = -EFAULT;
            goto out;
        }

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
        hi.namelen = 0;
        hi.uuid = rhi->uuid;
        hi.flag = INDEX_BY_UUID | INDEX_UNLINK | INDEX_ITE_ACTIVE;
        hi.hash = hvfs_hash(hi.uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);
        hi.itbid = mds_get_itbid(gdte, hi.hash);
        mds_dh_put(gdte);

        dsite = SELECT_SITE(hi.itbid, hi.psalt, CH_RING_MDS, &vid);
        
        msg2 = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg2) {
            hvfs_err(xnet, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto out;
        }
        xnet_msg_fill_tx(msg2, XNET_MSG_REQ, XNET_NEED_REPLY,
                         hmo.xc->site_id, dsite);
        xnet_msg_fill_cmd(msg2, HVFS_CLT2MDS_UNLINK, 0, 0);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg2, &msg2->tx, sizeof(msg2->tx));
#endif
        xnet_msg_add_sdata(msg2, &hi, sizeof(hi));

    gdt_resend:
        err = xnet_send(hmo.xc, msg2);
        if (err) {
            hvfs_err(xnet, "xnet_send() failed\n");
            goto gdt_out;
        }
        ASSERT(msg2->pair, xnet);
        if (msg2->pair->tx.err == -ESPLIT) {
            /* the ITB is under splitting, we need retry */
            xnet_set_auto_free(msg2->pair);
            xnet_free_msg(msg2->pair);
            msg2->pair = NULL;
            goto gdt_resend;
        } else if (msg2->pair->tx.err == -ERESTART ||
                   msg2->pair->tx.err == -EHWAIT) {
            xnet_set_auto_free(msg2->pair);
            xnet_free_msg(msg2->pair);
            msg2->pair = NULL;
            goto gdt_resend;
        } else if (msg2->pair->tx.err) {
            hvfs_err(xnet, "UNLINK failed @ MDS site %ld w/ %d\n",
                     msg2->pair->tx.ssite_id, msg2->pair->tx.err);
            err = msg2->pair->tx.err;
            goto gdt_out;
        }

    gdt_out:
        xnet_free_msg(msg2);
    }
    xnet_set_auto_free(msg->pair);
out:
    xnet_free_msg(msg);
out_exit:
    return err;
out_free:
    xfree(hi);
    return err;
}

int __hvfs_read(struct amc_index *ai, char **value, struct column *c)
{
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    u32 vid = 0;
    int err = 0;

    hvfs_debug(xnet, "Read column itbid %ld len %ld offset %ld\n",
               c->stored_itbid, c->len, c->offset);

    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return -ENOMEM;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    si->sic.uuid = ai->ptid;
    si->sic.arg0 = c->stored_itbid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = ai->column;
    si->scd.cr[0].stored_itbid = c->stored_itbid;
    si->scd.cr[0].file_offset = c->offset;
    si->scd.cr[0].req_offset = 0;
    si->scd.cr[0].req_len = c->len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(c->stored_itbid, ai->psalt, CH_RING_MDSL, &vid);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_READ, 0, 0);
    msg->tx.reserved = vid;
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
        *value = xmalloc(c->len + 1);
        if (!*value) {
            hvfs_err(xnet, "xmalloc value region failed.\n");
            err = -ENOMEM;
            goto out_msg;
        }
        memcpy(*value, msg->pair->xm_data, c->len);
        (*value)[c->len] = '\0';
    } else {
        hvfs_err(xnet, "recv data read reply ERROR %d\n",
                 msg->pair->tx.err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    }

out_msg:
    xnet_free_msg(msg);
out_free:
    xfree(si);

    return err;
}

int __hvfs_write(struct amc_index *ai, char *value, u32 len, 
                 struct column *col)
{
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    u64 location;
    u32 vid = 0;
    int err = 0;

    hvfs_debug(xnet, "TO write column %d target len %d itbid %ld\n",
               ai->column, len, ai->sid);
    
    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return -ENOMEM;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    si->sic.uuid = ai->ptid;
    si->sic.arg0 = ai->sid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = ai->column;
    si->scd.cr[0].stored_itbid = ai->sid;
    si->scd.cr[0].req_len = len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(ai->sid, ai->psalt, CH_RING_MDSL, &vid);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_WRITE, 0, 0);
    msg->tx.reserved = vid;
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, si, sizeof(*si) + 
                       sizeof(struct column_req));
    xnet_msg_add_sdata(msg, value, len);

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

    if (location == 0) {
        hvfs_warning(xnet, "puuid %lx uuid 0x%lx to %lx L @ %ld len %d\n",
                     ai->ptid, ai->tid, dsite, location, len);
    }

    col->stored_itbid = ai->sid;
    col->len = len;
    col->offset = location;

out_msg:
    xnet_free_msg(msg);

out_free:
    xfree(si);
    
    return err;
}

int __hvfs_indirect_write(struct amc_index *ai, char *key, char *value, 
                          struct column *col)
{
    struct mu_column *mc, nmc;
    int target_column = ai->column;
    int err = 0, i, nr, found = 0, indirect_len;

    hvfs_debug(xnet, "TO write column %d target len %ld itbid %ld\n",
               ai->column, strlen(value), ai->sid);

    /* Step 1: Get data content of the indirect column (sync read) */
    if (ai->op == INDEX_PUT || ai->op == INDEX_UPDATE)
        err = hvfs_get_indirect(ai, &mc);
    else if (ai->op == INDEX_SPUT || ai->op == INDEX_SUPDATE) {
        void *data = ai->data;
        size_t dlen = ai->dlen;

        ai->data = key;
        ai->dlen = strlen(key);
        err = hvfs_sget_indirect(ai, &mc);
        ai->data = data;
        ai->dlen = dlen;
    }

    if (err == -ENOENT) {
        /* ok, it is safe to use hvfs_put to create this column cell */
        err = 0;
    } else if (err < 0) {
        hvfs_err(xnet, "get indirect column failed w/ %d, "
                 "try to use '(s)update'?\n", err);
        goto out;
    } else {
        if (ai->op == INDEX_PUT)
            ai->op = INDEX_UPDATE;
        if (ai->op == INDEX_SPUT)
            ai->op = INDEX_SUPDATE;
    }
    
    if (!(err == 0 || err % sizeof(struct mu_column) == 0)) {
        HVFS_BUGON("Corrupted indirect column!");
    }
    indirect_len = err;

    /* Step 2: Write the new data column (sync write) */
    ai->column = target_column;
    err = __hvfs_write(ai, value, strlen(value), col);
    if (err) {
        hvfs_err(xnet, "write value to stroage column %d failed w/ %d %s\n",
                 ai->column, err, strerror(-err));
        goto out_free;
    }
    
    /* Step 3: Try to add or update new content */
    if (!indirect_len) {
        nmc.cno = target_column;
        nmc.c = *col;
    } else {
        nr = indirect_len / sizeof(struct mu_column);
        for (i = 0; i < nr; i++) {
            if ((mc + i)->cno == target_column) {
                (mc + i)->c = *col;
                found = 1;
                break;
            }
        }
        if (!found) {
            /* realloc the mc and put the new column at last */
            struct mu_column *p;

            p = xrealloc(mc, indirect_len + sizeof(struct mu_column));
            if (!p) {
                hvfs_err(xnet, "realloc indirect column failed\n");
                err = -ENOMEM;
                goto out_free;
            }
            mc = p;
            p = ((void *)p) + indirect_len;
            p->cno = target_column;
            p->c = *col;
        }
    }

    /* Step 4: Write the new indirect column (sync write) */
    if (found) {
        /* just write mc */
        ai->column = 0;
        err = __hvfs_write(ai, (char *)mc, indirect_len, col);
        if (err) {
            hvfs_err(xnet, "write indirect column failed w/ %d\n",
                     err);
            goto out_free;
        }
    } else {
        /* write mc if exist and the nmc */
        ai->column = 0;
        if (indirect_len) {
            /* write mc */
            err = __hvfs_write(ai, (char *)mc, indirect_len + 
                               sizeof(struct mu_column), col);
            if (err) {
                hvfs_err(xnet, "write indirect column failed w/ %d\n",
                         err);
                goto out_free;
            }
        } else {
            /* write nmc */
            err = __hvfs_write(ai, (char *)&nmc, sizeof(nmc), col);
            if (err) {
                hvfs_err(xnet, "write indirect column failed w/ %d\n",
                         err);
                goto out_free;
            }
        }
    }

    /* Step 5: Update indirect column info to 'col', already in it */
    hvfs_info(xnet, "indirect_len %d, col offset %ld len %ld\n", 
              indirect_len, col->offset, col->len);

out_free:
    ai->column = target_column;
    xfree(mc);

out:
    return err;
}

/*
 * Note that, the key must not be zero, otherwise it will trigger the MDS key
 * recomputing :(
 */
int hvfs_put(char *table, u64 key, char *value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    struct column col;
    u64 dsite;
    u32 vid;
    int err = 0, recreate = 0;

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_PUT;
    ai.column = column;
    ai.key = key;

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, key);
    mds_dh_put(e);

    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have to use the indirect column to save this column */
        err = __hvfs_indirect_write(&ai, (char *)&key, value, &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else if (column) {
        /* if it is not the 0th column, we write the value to MDSL */
        err = __hvfs_write(&ai, value, strlen(value), &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else {
        /* check the value length */
        if (strlen(value) > XTABLE_VALUE_SIZE) {
            hvfs_err(xnet, "Value is %d bytes long, using other columns "
                     "instead.\n", (int)strlen(value));
            err = -EINVAL;
            goto out;
        }
    }

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    if (column) {
        ai.dlen = sizeof(col);
        xnet_msg_add_sdata(msg, &col, sizeof(col));
    } else {
        ai.dlen = strlen(value);
        xnet_msg_add_sdata(msg, value, strlen(value));
    }

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        sched_yield();
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        sleep(1);
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_get_indirect(struct amc_index *iai, struct mu_column **mc)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct kv *kv;
    u64 dsite;
    u32 vid;
    int err = 0;

    /* construct the ai structure and send to the table server */
    memcpy(&ai, iai, sizeof(ai));
    ai.op = INDEX_GET;
    ai.column = -1;            /* this means to access the indirect column */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_debug(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                   msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
    *mc = xzalloc(msg->pair->tx.len - sizeof(u64));
    if (!*mc) {
        hvfs_err(xnet, "xmalloc() value failed\n");
        err = -ENOMEM;
        goto out_msg;
    }
    kv = msg->pair->xm_data + sizeof(u64);
    /* read in the data content */
    {
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;

        ai.column = 0;
        hvfs_warning(xnet, "Read in itbid %ld offset %ld len %ld\n",
                     c->stored_itbid, c->offset, c->len);
        err = __hvfs_read(&ai, (char **)mc, c);
        if (err) {
            hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                     "failed w/ %d\n",
                     c->stored_itbid, c->offset, c->len, err);
            goto out_msg;
        }
        err = c->len;
    }
    
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_get(char *table, u64 key, char **value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct kv *kv;
    struct dhe *e;
    u64 dsite;
    u32 vid;
    int err = 0;

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_GET;
    ai.column = column;
    ai.key = key;

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, key);
    mds_dh_put(e);

    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we should read in the indirect column and then read the real
         * column */
        ai.column = -1;
    }
    
    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
    *value = xzalloc(msg->pair->tx.len - sizeof(u64));
    if (!*value) {
        hvfs_err(xnet, "xmalloc() value failed\n");
        err = -ENOMEM;
        goto out_msg;
    }
    kv = msg->pair->xm_data + sizeof(u64);
    if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have read in the indirect column in kv */
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;
        struct mu_column *mc;
        int i, found = 0;

        if (!c->len)
            goto out_msg;
        ai.column = 0;
        err = __hvfs_read(&ai, (char **)&mc, c);
        if (err) {
            hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                     "failed w/ %d\n",
                     c->stored_itbid, c->offset, c->len, err);
            goto out_msg;
        }
        /* find in the mu_column array */
        for (i = 0; i < (c->len / sizeof(*mc)); i++) {
            if (column == (mc + i)->cno) {
                found = 1;
                break;
            }
        }
        /* read the real column now */
        if (found) {
            ai.column = column;
            err = __hvfs_read(&ai, value, &(mc + i)->c);
            if (err) {
                hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld"
                         " len %ld failed w/ %d\n",
                         (mc + i)->c.stored_itbid, 
                         (mc + i)->c.offset, 
                         (mc + i)->c.len, err);
                goto out_msg;
            }
        } else {
            hvfs_warning(xnet, "Column %d does not exist.\n",
                         column);
        }
    } else if (column) {
        /* if it is not the 0th column, we read the value from mdsl */
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;

        if (!c->len) {
            goto out_msg;
        }
        err = __hvfs_read(&ai, value, c);
        if (err) {
            hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                     "failed w/ %d\n",
                     c->stored_itbid, c->offset, c->len, err);
            goto out_msg;
        }
    } else {
        memcpy(*value, kv->value, kv->len);
    }
    
out_msg:
    xnet_free_msg(msg);

    return err;
out:
    return err;
}

int hvfs_del(char *table, u64 key, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    u64 dsite;
    u32 vid;
    int err = 0;

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_DEL;
    ai.column = column;
    ai.key = key;

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, key);
    mds_dh_put(e);

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid,
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_update(char *table, u64 key, char *value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    struct column col;
    u64 dsite;
    u32 vid;
    int err = 0;

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_UPDATE;
    ai.column = column;
    ai.key = key;

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, key);
    mds_dh_put(e);

    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have to use the indirect column to save this column */
        err = __hvfs_indirect_write(&ai, (char *)&key, value, &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else if (column) {
        /* if it is not the 0th column, we write the value to MDSL */
        err = __hvfs_write(&ai, value, strlen(value), &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else {
        /* check the value length */
        if (strlen(value) > XTABLE_VALUE_SIZE) {
            hvfs_err(xnet, "Value is %d bytes long, using other columns "
                     "instead.\n", (int)strlen(value));
            err = -EINVAL;
            goto out;
        }
    }

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    if (column) {
        ai.dlen = sizeof(col);
        xnet_msg_add_sdata(msg, &col, sizeof(col));
    } else {
        ai.dlen = strlen(value);
        xnet_msg_add_sdata(msg, value, strlen(value));
    }

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UPDATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid,
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_sput(char *table, char *key, char *value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    struct column col;
    u64 dsite;
    u32 vid;
    int err = 0, recreate = 0;

    if (strlen(key) == 0) {
        hvfs_err(xnet, "Invalid key: Zero-length key?\n");
        err = -EINVAL;
        goto out;
    }
    
    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_SPUT;
    ai.column = column;
    ai.key = hvfs_hash(0, (u64)key, strlen(key), HASH_SEL_KVS);
    ai.tid = strlen(key);

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    
    ai.sid = mds_get_itbid(e, ai.key);
    mds_dh_put(e);

    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have to use the indirect column to save this column */
        err = __hvfs_indirect_write(&ai, key, value, &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else if (column) {
        /* if it is not the 0th column, we write the value to MDSL */
        err = __hvfs_write(&ai, value, strlen(value), &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    }

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY, 
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    xnet_msg_add_sdata(msg, key, strlen(key));
    if (column) {
        ai.dlen = sizeof(col) + ai.tid;
        xnet_msg_add_sdata(msg, &col, sizeof(col));
    } else {
        /* ai.dlen saved the total length */
        ai.dlen = strlen(value) + ai.tid;
        xnet_msg_add_sdata(msg, value, strlen(value));
    }

    hvfs_debug(xnet, "key len %ld, key+value len %ld\n", ai.tid, ai.dlen);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        sched_yield();
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        sleep(1);
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_sget_indirect(struct amc_index *iai, struct mu_column **mc)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct kv *kv;
    u64 dsite;
    u32 vid;
    int err = 0;

    /* construct the ai structure and send to the table server */
    memcpy(&ai, iai, sizeof(ai));
    ai.op = INDEX_SGET;
    /* this means to access the indirect column */
    ai.column = -1;
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    /* add the key content */
    ai.dlen = ai.tid;
    xnet_msg_add_sdata(msg, ai.data, ai.tid);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_debug(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                   msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
    *mc = xzalloc(msg->pair->tx.len - sizeof(u64));
    if (!*mc) {
        hvfs_err(xnet, "xmalloc() value failed\n");
        err = -ENOMEM;
        goto out_msg;
    }
    kv = msg->pair->xm_data + sizeof(u64);
    /* read in the data content */
    {
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;

        ai.column = 0;
        hvfs_warning(xnet, "Read in itbid %ld offset %ld len %ld\n",
                     c->stored_itbid, c->offset, c->len);
        err = __hvfs_read(&ai, (char **)mc, c);
        if (err) {
            hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                     "failed w/ %d\n",
                     c->stored_itbid, c->offset, c->len, err);
            goto out_msg;
        }
        err = c->len;
    }
    
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_sget(char *table, char *key, char **value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct kv *kv;
    struct dhe *e;
    u64 dsite;
    u32 vid;
    int err = 0;

    if (strlen(key) == 0) {
        hvfs_err(xnet, "Invalid key: Zero-length key?\n");
        err = -EINVAL;
        goto out;
    }

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_SGET;
    ai.column = column;
    ai.key = hvfs_hash(0, (u64)key, strlen(key), HASH_SEL_KVS);
    ai.tid = strlen(key);

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, ai.key);
    mds_dh_put(e);

    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we should read in the indirect column and then read the real
         * column */
        ai.column = -1;
    }

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    /* add the key content */
    ai.dlen = ai.tid;
    xnet_msg_add_sdata(msg, key, ai.tid);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid, 
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
    *value = xzalloc(msg->pair->tx.len - sizeof(u64));
    if (!*value) {
        hvfs_err(xnet, "xmalloc() value failed\n");
        err = -ENOMEM;
        goto out_msg;
    }
    kv = msg->pair->xm_data + sizeof(u64);
    if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have read in the indirect column in kv */
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;
        struct mu_column *mc;
        int i, found = 0;

        if (!c->len)
            goto out_msg;
        ai.column = 0;
        err = __hvfs_read(&ai, (char **)&mc, c);
        if (err) {
            hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                     "failed w/ %d\n",
                     c->stored_itbid, c->offset, c->len, err);
            goto out_msg;
        }
        /* find in the mu_column array */
        for (i = 0; i < (c->len / sizeof(*mc)); i++) {
            if (column == (mc + i)->cno) {
                found = 1;
                break;
            }
        }
        /* read the real column now */
        if (found) {
            ai.column = column;
            err = __hvfs_read(&ai, value, &(mc + i)->c);
            if (err) {
                hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld"
                         " len %ld failed w/ %d\n",
                         (mc + i)->c.stored_itbid,
                         (mc + i)->c.offset,
                         (mc + i)->c.len, err);
                goto out_msg;
            }
        } else {
            hvfs_warning(xnet, "Column %d does not exist.\n",
                         column);
        }
    } else if (column) {
        struct column *c = (void *)kv + kv->len + KV_HEADER_LEN;

        if (strncmp(key, (const char *)kv->value, (size_t)kv->klen) == 0) {
            err = __hvfs_read(&ai, value, c);
            if (err) {
                hvfs_err(xnet, "__hvfs_read() itbid %ld offset %ld len %ld "
                         "failed w/ %d\n",
                         c->stored_itbid, c->offset, c->len, err);
                goto out_msg;
            } 
        } else {
            err = -ENOTEXIST;
        }
    } else {
        /* check if it is the correct key */
        if (strncmp(key, (const char *)kv->value, (size_t)kv->klen) == 0) {
            memcpy(*value, kv->value + kv->klen, kv->len - kv->klen);
        } else {
            err = -ENOTEXIST;
        }
    }
    
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_sdel(char *table, char *key, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    u64 dsite;
    u32 vid;
    int err = 0;

    if (strlen(key) == 0) {
        hvfs_err(xnet, "Invalid key: Zero-length key?\n");
        err = -EINVAL;
        goto out;
    }

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_SDEL;
    ai.column = column;
    ai.key = hvfs_hash(0, (u64)key, strlen(key), HASH_SEL_KVS);
    ai.tid = strlen(key);

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, ai.key);
    mds_dh_put(e);
    
    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    /* add the key content */
    ai.dlen = ai.tid;
    xnet_msg_add_sdata(msg, key, ai.tid);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid,
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

int hvfs_supdate(char *table, char *key, char *value, int column)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    struct dhe *e;
    struct column col;
    u64 dsite;
    u32 vid;
    int err = 0;

    if (strlen(key) == 0) {
        hvfs_err(xnet, "Invalid key: Zero-length key?\n");
        err = -EINVAL;
        goto out;
    }

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_SUPDATE;
    ai.column = column;
    ai.key = hvfs_hash(0, (u64)key, strlen(key), HASH_SEL_KVS);
    ai.tid = strlen(key);

    /* lookup the table name in the root directory to find the table
     * metadata */
    err = hvfs_find_table(table, &ai.ptid, &ai.psalt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }

    /* using the info of table to get the slice id */
    e = mds_dh_search(&hmo.dh, ai.ptid);
    if (IS_ERR(e)) {
        hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }

    ai.sid = mds_get_itbid(e, ai.key);
    mds_dh_put(e);
    
    if (unlikely(column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", column);
        err = -EINVAL;
        goto out;
    } else if (column > XTABLE_INDIRECT_COLUMN) {
        /* we have to use the indirect column to save this column */
        err = __hvfs_indirect_write(&ai, key, value, &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d "
                     "failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    } else if (column) {
        /* if it is not the 0th column, we write the value to MDSL */
        err = __hvfs_write(&ai, value, strlen(value), &col);
        if (err) {
            hvfs_err(xnet, "write value to storage column %d failed w/ %d %s\n",
                     column, err, strerror(-err));
            goto out;
        }
    }

    /* construct the ai structure and send to the table server */
    dsite = SELECT_SITE(ai.sid, ai.psalt, CH_RING_MDS, &vid);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));
    xnet_msg_add_sdata(msg, key, ai.tid);
    if (column) {
        ai.dlen = sizeof(col) + ai.tid;
        xnet_msg_add_sdata(msg, &col, sizeof(col));
    } else {
        ai.dlen = strlen(value) + ai.tid;
        xnet_msg_add_sdata(msg, value, strlen(value));
    }

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        /* the ITB is under splitting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UPDATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    xnet_set_auto_free(msg->pair);

    mds_dh_bitmap_update(&hmo.dh, ai.ptid,
                         *(u64 *)msg->pair->xm_data,
                         MDS_BITMAP_SET);
out_msg:
    xnet_free_msg(msg);
    return err;
out:
    return err;
}

/* hvfs_list() is used to list the tables in the root directory or entries in
 * the sub directory
 */
int __hvfs_list(u64 duuid, int op, struct list_result *lr)
{
    struct xnet_msg *msg;
    struct hvfs_index hi;
    u64 dsite, itbid = 0;
    u64 salt;
    u32 vid;
    int err = 0, retry_nr;

    /* Step 0: prepare the args */
    if (op == LIST_OP_COUNT) {
        if (!lr) {
            hvfs_err(xnet, "No list_result argument provided!\n");
            err = -EINVAL;
            goto out;
        }
        lr->cnt = 0;
    } else if (op == LIST_OP_GREP) {
        if (!lr) {
            hvfs_err(xnet, "No list_result argument provided!\n");
            err = -EINVAL;
            goto out;
        }
    } else if (op == LIST_OP_GREP_COUNT) {
        if (!lr) {
            hvfs_err(xnet, "No list_result argument provided!\n");
            err = -EINVAL;
            goto out;
        }
        lr->cnt = 0;
    }
    
    if (duuid == hmi.root_uuid) {
        salt = hmi.root_salt;
    } else {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, duuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() %lx failed w/ %ld\n",
                     duuid, PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        salt = e->salt;
        mds_dh_put(e);
    }
    
    /* Step 1: we should refresh the bitmap of root directory */
    mds_bitmap_refresh_all(duuid);

    /* Step 2: we send the INDEX_BY_ITB requests to each MDS in serial or
     * parallel mode */
    do {
        err = mds_bitmap_find_next(duuid, &itbid);
        if (err < 0) {
            hvfs_err(xnet, "mds_bitmap_find_next() failed @ %ld w/ %d\n ",
                     itbid, err);
            break;
        } else if (err > 0) {
            /* this means we can safely stop now */
            break;
        } else {
            /* ok, we can issure the request to the dest site now */
            hvfs_debug(xnet, "Issue request %ld to site ...\n",
                       itbid);
            /* Step 3: we print the results to the console */
            memset(&hi, 0, sizeof(hi));
            hi.op = op;
            hi.puuid = duuid;
            hi.psalt = salt;
            hi.hash = -1UL;
            hi.itbid = itbid;
            hi.flag = INDEX_BY_ITB | INDEX_KV;
            if (lr->arg)
                hi.namelen = strlen(lr->arg);

            dsite = SELECT_SITE(itbid, hi.psalt, CH_RING_MDS, &vid);
            msg = xnet_alloc_msg(XNET_MSG_NORMAL);
            if (!msg) {
                hvfs_err(xnet, "xnet_alloc_msg() failed\n");
                err = -ENOMEM;
                goto out;
            }
            xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                             hmo.xc->site_id, dsite);
            xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LIST, 0, 0);
#ifdef XNET_EAGER_WRITEV
            xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
            xnet_msg_add_sdata(msg, &hi, sizeof(hi));
            xnet_msg_add_sdata(msg, lr->arg, hi.namelen);

            retry_nr = 0;
        retry:
            err = xnet_send(hmo.xc, msg);
            if (err) {
                hvfs_err(xnet, "xnet_send() failed\n");
                xnet_free_msg(msg);
                goto out;
            }

            ASSERT(msg->pair, xnet);
            if (msg->pair->tx.err) {
                /* Note that, if the itbid is less than 8, then we ignore the
                 * ENOENT error */
                if (itbid < 8 && msg->pair->tx.err == -ENOENT) {
                    xnet_free_msg(msg);
                    itbid++;
                    continue;
                }
                if (msg->pair->tx.err == -EHWAIT) {
                    /* we should wait and retry a few times */
                    if (retry_nr < 60) {
                        retry_nr++;
                        sleep(1);
                        goto retry;
                    }
                }
                hvfs_err(mds, "list table %lx slice %ld failed w/ %d\n", 
                         duuid, itbid,
                         msg->pair->tx.err);
                err = msg->pair->tx.err;
                xnet_free_msg(msg);
                goto out;
            }
            if (msg->pair->xm_datacheck) {
                /* ok, dump the entries */
                char kbuf[128];
                char *p = (char *)(msg->pair->xm_data +
                                   sizeof(struct hvfs_md_reply));
                int idx = 0, namelen;

                while (idx < msg->pair->tx.len - 
                       sizeof(struct hvfs_md_reply)) {
                    namelen = *(u32 *)p;
                    p += sizeof(u32);
                    hvfs_debug(mds, "len %d idx %d total %ld\n", 
                               namelen, idx, 
                               msg->pair->tx.len - 
                               sizeof(struct hvfs_md_reply));
                    if (!namelen) {
                        break;
                    }
                    memcpy(kbuf, p, namelen);
                    kbuf[namelen] = '\0';
                    switch (op) {
                    case LIST_OP_SCAN:
                    case LIST_OP_GREP:
                        hvfs_plain(xnet, "%s\n", kbuf);
                        break;
                    case LIST_OP_COUNT:
                    case LIST_OP_GREP_COUNT:
                        lr->cnt++;
                        break;
                    default:;
                    }
                    idx += namelen + sizeof(u32);
                    p += namelen;
                }
            } else {
                hvfs_err(xnet, "Invalid LIST reply from site %lx.\n",
                         msg->pair->tx.ssite_id);
                err = -EFAULT;
                xnet_free_msg(msg);
                goto out;
            }
            xnet_free_msg(msg);
        }
        itbid += 1;
    } while (1);

    err = 0;
out:    
    return err;
}

int hvfs_list(char *table, int op, char *arg)
{
    struct list_result lr = {
        .arg = arg,
        .cnt = 0,
    };
    u64 uuid, salt;
    int err = 0;
    
    if (!table) {
        err = __hvfs_list(hmi.root_uuid, op, &lr);
        if (err) {
            goto out;
        }
    } else {
        err = hvfs_find_table(table, &uuid, &salt);
        if (err) {
            hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n",
                     err);
            goto out;
        }
        err = __hvfs_list(uuid, op, &lr);
        if (err) {
            goto out;
        }
    }
    switch (op) {
    case LIST_OP_SCAN:
    case LIST_OP_GREP:
        break;
    case LIST_OP_COUNT:
    case LIST_OP_GREP_COUNT:
        hvfs_info(xnet, "%d\n", lr.cnt);
        break;
    default:;
    }

out:
    return err;
}

int hvfs_commit(int id)
{
    struct xnet_msg *msg;
    struct amc_index ai;
    u64 site_id;
    int err = 0;

    memset(&ai, 0, sizeof(ai));
    ai.op = INDEX_COMMIT;

    /* check the arguments */
    if (id < 0) {
        hvfs_err(xnet, "Invalid MDS id %d\n", id);
        err = -EINVAL;
        goto out;
    }
    site_id = HVFS_MDS(id);
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, site_id);
    xnet_msg_fill_cmd(msg, HVFS_AMC2MDS_REQ, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &ai, sizeof(ai));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

int hvfs_get_cluster(char *type)
{
    if (strncmp(type, "mdsl", 4) == 0) {
        st_list("mdsl");
    } else if (strncmp(type, "mds", 3) == 0) {
        st_list("mds");
    } else {
        hvfs_err(xnet, "Type '%s' not supported yet.\n", type);
    }

    return 0;
}

char *hvfs_active_site(char *type)
{
    struct xnet_group *xg = NULL;
    u64 base;
    char *err = NULL, *p;
    int i;
    
    if (strncmp(type, "mdsl", 4) == 0) {
        base = HVFS_MDSL(0);
        hvfs_info(xnet, "Active MDSL Sites:\n");
        xg = cli_get_active_site(hmo.chring[CH_RING_MDSL]);
        if (!xg) {
            hvfs_err(xnet, "cli_get_active_site() failed\n");
            err = "Error: No memory.";
            goto out;
        }
    } else if (strncmp(type, "mds", 3) == 0) {
        base = HVFS_MDS(0);
        hvfs_info(xnet, "Active MDS Sites:\n");
        xg = cli_get_active_site(hmo.chring[CH_RING_MDS]);
        if (!xg) {
            hvfs_err(xnet, "cli_get_active_site() failed\n");
            err = "Error: No memory.";
            goto out;
        }
    }

    /* print the active sites */
    if (xg) {
        err = xzalloc(xg->asize * 64);
        if (!err) {
            hvfs_err(xnet, "xzalloc result string failed.\n");
            err = "Error: No memory.";
            goto out;
        }
        p = err;
        for (i = 0; i < xg->asize; i++) {
            p += snprintf(p, 63, "%ld ", xg->sites[i].site_id);
            hvfs_info(xnet, "Site %ld => %lx\n", xg->sites[i].site_id - base,
                      xg->sites[i].site_id);
        }
    }
    
    xfree(xg);
out:
    return err;
}

int hvfs_online(char *type, int id, char *ip)
{
    struct xnet_msg *msg;
    u64 site_id;
    int err = 0;

    if (strncmp(type, "mdsl", 4) == 0) {
        site_id = HVFS_MDSL(id);
    } else if (strncmp(type, "mds", 3) == 0) {
        site_id = HVFS_MDS(id);
    } else {
        hvfs_err(xnet, "Invalid site type '%s'\n", type);
        err = -EINVAL;
        goto out;
    }

    if (id < 0) {
        hvfs_err(xnet, "Invalid id %d\n", id);
        err = -EINVAL;
        goto out;
    }

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, HVFS_ROOT(0));
    /* arg1: ip address */
    xnet_msg_fill_cmd(msg, HVFS_R2_ONLINE, site_id, inet_addr(ip));
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:

    return err;
}

int hvfs_offline(char *type, int id)
{
    struct xnet_msg *msg;
    u64 site_id;
    int err = 0;

    if (strncmp(type, "mdsl", 4) == 0) {
        site_id = HVFS_MDSL(id);
    } else if (strncmp(type, "mds", 3) == 0) {
        site_id = HVFS_MDS(id);
    } else {
        hvfs_err(xnet, "Invalid site type '%s'\n", type);
        err = -EINVAL;
        goto out;
    }

    if (id < 0) {
        hvfs_err(xnet, "Invalid id %d\n", id);
        err = -EINVAL;
        goto out;
    }

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, HVFS_ROOT(0));
    xnet_msg_fill_cmd(msg, HVFS_R2_OFFLINE, site_id, 0); /* arg1: ip
                                                          * address */
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    
    return err;
}

int __hvfs_create(u64 puuid, u64 psalt, struct hstat *hs, 
                  u32 flag, struct mdu_update *imu)
{
    size_t dpayload = sizeof(struct hvfs_index);
    struct xnet_msg *msg;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    struct mdu_update *mu;
    struct gdt_md gm;
    u64 dsite;
    u32 vid;
    int err = 0;

    if (hs->uuid == 0) {
        dpayload += strlen(hs->name);
    }
    
    if (flag & INDEX_SYMLINK) {
        /* ignore the column argument */
        if (!imu || !imu->namelen) {
            hvfs_err(xnet, "Create symlink need the mdu_update "
                     "argument and non-zero symlink name\n");
            return -EINVAL;
        }
        dpayload += sizeof(struct mdu_update) +
            imu->namelen;
    } else if (flag & INDEX_CREATE_GDT) {
        /* just copy the mdu from hstat, ignore mdu_update */
        dpayload += HVFS_MDU_SIZE;
        gm.mdu = hs->mdu;
        gm.puuid = hs->puuid;
        gm.psalt = hs->psalt;
    } else if (flag & INDEX_CREATE_DIR) {
        /* want to create the dir SDT entry */
        if (imu) {
            dpayload += sizeof(struct mdu_update);
            if (imu->valid & MU_LLFS)
                dpayload += sizeof(struct llfs_ref);
            if (imu->valid & MU_COLUMN)
                dpayload += imu->column_no * sizeof(struct mu_column);
        }
    } else if (flag & INDEX_CREATE_LINK) {
        /* imu is actually a link_source struct */
        if (!imu) {
            hvfs_err(xnet, "do link w/o link_souce?\n");
            return -EINVAL;
        }
        dpayload += sizeof(struct link_source);
    } else {
        /* normal file create */
        if (imu) {
            dpayload += sizeof(struct mdu_update);
            if (imu->valid & MU_LLFS)
                dpayload += sizeof(struct llfs_ref);
            if (imu->valid & MU_COLUMN)
                dpayload += imu->column_no * sizeof(struct mu_column);
        }
    }

    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }

    if (flag & INDEX_SYMLINK) {
        hi->hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                             HASH_SEL_EH);
        hi->puuid = puuid;
        hi->psalt = psalt;
        hi->flag = INDEX_SYMLINK;
        if (imu) {
            mu = (struct mdu_update *)((void *)hi + sizeof(*hi) + 
                                       sizeof(hs->name));
            memcpy(mu, imu, sizeof(*mu));
            memcpy((void *)mu + sizeof(*mu), (void *)imu + sizeof(*imu),
                   mu->namelen);
            hi->dlen = sizeof(*mu) + mu->namelen;
        }
    } else if (flag & INDEX_CREATE_GDT) {
        hi->hash = hvfs_hash(hs->uuid, hmi.gdt_salt, 0, HASH_SEL_GDT);
        hi->uuid = hs->uuid;
        hi->puuid = hmi.gdt_uuid;
        hi->psalt = hmi.gdt_salt;
        hi->flag = INDEX_BY_UUID | INDEX_CREATE | INDEX_CREATE_COPY |
            INDEX_CREATE_GDT;
        memcpy((void *)hi + sizeof(*hi), &gm, HVFS_MDU_SIZE);
        hi->dlen = HVFS_MDU_SIZE;
    } else if (flag & INDEX_CREATE_DIR) {
        hi->hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                             HASH_SEL_EH);
        hi->puuid = puuid;
        hi->psalt = psalt;
        hi->flag = INDEX_CREATE | INDEX_CREATE_DIR;
        if (imu) {
            off_t offset = sizeof(*mu);
            
            mu = (struct mdu_update *)((void *)hi + sizeof(*hi) +
                                       sizeof(hs->name));
            memcpy(mu, imu, sizeof(*mu));
            if (imu->valid & MU_LLFS) {
                memcpy((void *)mu + offset, (void *)imu + offset,
                       sizeof(struct llfs_ref));
                offset += sizeof(struct llfs_ref);
            }
            if (imu->valid & MU_COLUMN) {
                memcpy((void *)mu + offset, (void *)imu + offset,
                       imu->column_no * sizeof(struct mu_column));
                offset += imu->column_no * sizeof(struct mu_column);
            }
            hi->dlen = offset;
        }
    } else if (flag & INDEX_CREATE_LINK) {
        hi->hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                             HASH_SEL_EH);
        hi->puuid = puuid;
        hi->psalt = psalt;
        hi->flag = INDEX_CREATE | INDEX_CREATE_LINK;
        if (imu) {
            /* ugly code, you can't learn anything correct from the typo :( */
            mu = (struct mdu_update *)((void *)hi + sizeof(*hi) +
                                       sizeof(hs->name));
            
            memcpy(mu, imu, sizeof(struct link_source));
            hi->dlen = sizeof(struct link_source);
        }
    } else {
        hi->hash = hvfs_hash(puuid, (u64)hs->name, strlen(hs->name),
                             HASH_SEL_EH);
        hi->puuid = puuid;
        hi->psalt = psalt;
        hi->flag = INDEX_CREATE;
        if (imu) {
            off_t offset = sizeof(*mu);
            
            mu = (struct mdu_update *)((void *)hi + sizeof(*hi) +
                                       sizeof(hs->name));
            memcpy(mu, imu, sizeof(*mu));
            if (imu->valid & MU_LLFS) {
                memcpy((void *)mu + offset, (void *)imu + offset,
                       sizeof(struct llfs_ref));
                offset += sizeof(struct llfs_ref);
            }
            if (imu->valid & MU_COLUMN) {
                memcpy((void *)mu + offset, (void *)imu + offset,
                       imu->column_no + sizeof(struct mu_column));
                offset += imu->column_no + sizeof(struct mu_column);
            }
            hi->dlen = offset;
        }
    }

    if (hs->uuid == 0) {
        hi->flag |= INDEX_BY_NAME;
        memcpy(hi->name, hs->name, strlen(hs->name));
        hi->namelen = strlen(hs->name);
    }

    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hmo.xc->site_id, dsite);
    if (hi->flag & INDEX_SYMLINK)
        xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_SYMLINK, 0, 0);
    else
        xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_CREATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }
    /* this means we have got the reply, parse it */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        atomic64_inc(&split_retry);
        sched_yield();
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "CREATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        atomic64_inc(&create_failed);
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid CREATE reply from site %lx.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, something wrong on the MDS */
        hvfs_err(xnet, "MDS site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        struct gdt_md *m;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            err = -EFAULT;
            goto out;
        }
        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "Invalid reply w/o MDU as expected.\n");
            err = -EFAULT;
            goto out;
        }
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid,
                                 MDS_BITMAP_SET);
        }
        /* setup the output values */
        if (hs) {
            memset(hs, 0, sizeof(*hs));
            hs->puuid = rhi->puuid;
            hs->psalt = rhi->psalt;
            hs->uuid = rhi->uuid;
            memcpy(&hs->mdu, m, sizeof(hs->mdu));
        }
    }
    
out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int __hvfs_update(u64 puuid, u64 psalt, struct hstat *hs,
                  struct mdu_update *imu)
{
    struct xnet_msg *msg;
    size_t dpayload;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    u32 vid;
    int err = 0;

    dpayload = sizeof(struct hvfs_index);
    if (!hs->uuid) {
        dpayload += strlen(hs->name);
    }
    if (imu) {
        dpayload += sizeof(struct mdu_update);
        if (imu->valid & MU_LLFS)
            dpayload += sizeof(struct llfs_ref);
        if (imu->valid & MU_COLUMN)
            dpayload += imu->column_no * sizeof(struct mu_column);
    } else {
        hvfs_err(xnet, "do update w/o mdu_update argument?\n");
        return -EINVAL;
    }
    hi = xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    if (!hs->uuid) {
        hi->flag = INDEX_BY_NAME;
        hi->namelen = strlen(hs->name);
        hi->hash = hvfs_hash(puuid, (u64)hs->name, hi->namelen, HASH_SEL_EH);
        memcpy(hi->name, hs->name, hi->namelen);
    } else {
        hi->flag = INDEX_BY_UUID;
        hi->uuid = hs->uuid;
        if (!hs->hash)
            hi->hash = hvfs_hash(hs->uuid, psalt, 0, HASH_SEL_GDT);
        else
            hi->hash = hs->hash;
    }
    hi->puuid = puuid;
    hi->psalt = psalt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

    if (imu) {
        off_t offset = sizeof(*hi) + hi->namelen;

        memcpy((void *)hi + offset, imu, sizeof(*imu));
        offset += sizeof(*imu);
        if (imu->valid & MU_LLFS) {
            memcpy((void *)hi + offset, (void *)imu + offset,
                   sizeof(struct llfs_ref));
            offset += sizeof(struct llfs_ref);
        }
        if (imu->valid & MU_COLUMN) {
            if (imu->column_no == 1) {
                /* you know, the column is saved in hstat */
                memcpy((void *)hi + offset, &hs->mc,
                       imu->column_no * sizeof(struct mu_column));
            } else {
                memcpy((void *)hi + offset, (void *)imu +
                       sizeof(struct mdu_update),
                       imu->column_no * sizeof(struct mu_column));
            }
        }
    }

    hi->flag |= INDEX_MDU_UPDATE;
    hi->dlen = dpayload - sizeof(*hi) - hi->namelen;

    /* alloc one msg and send it to the peer site */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }
    
    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY |
                     XNET_NEED_DATA_FREE,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_UPDATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    /* this means we have got he reply, parse it */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_free_msg(msg);
        msg->pair = NULL;
        sched_yield();
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_free_msg(msg);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UPDATE failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid UPDATE reply from site %lx\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, something wrong on the MDS */
        hvfs_err(xnet, "MDS site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        struct gdt_md *m;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            err = -EFAULT;
            goto out;
        }
        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "Invalid reply w/o MDU as expected.\n");
            err = -EFAULT;
            goto out;
        }
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid,
                                 MDS_BITMAP_SET);
        }
        /* setup the output values */
        if (hs) {
            memset(hs, 0, sizeof(*hs));
            hs->puuid = rhi->puuid;
            hs->psalt = rhi->psalt;
            hs->uuid = rhi->uuid;
            hs->hash = rhi->hash;
            memcpy(&hs->mdu, m, sizeof(hs->mdu));
        }
    }
    
out_msg:
    xnet_free_msg(msg);
out:
    return err;
out_free:
    xfree(hi);
    return err;
}

int __hvfs_unlink(u64 puuid, u64 psalt, struct hstat *hs)
{
    struct xnet_msg *msg;
    size_t dpayload;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    u32 vid;
    int err = 0;

    dpayload = sizeof(struct hvfs_index) + 
        (hs->uuid == 0 ? strlen(hs->name) : 0);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    if (!hs->uuid) {
        hi->flag = INDEX_BY_NAME;
        hi->namelen = strlen(hs->name);
        hi->hash = hvfs_hash(puuid, (u64)hs->name, hi->namelen, HASH_SEL_EH);
        memcpy(hi->name, hs->name, hi->namelen);
    } else {
        hi->flag = INDEX_BY_UUID;
        hi->uuid = hs->uuid;
        if (!hs->hash)
            hi->hash = hvfs_hash(hs->uuid, psalt, 0, HASH_SEL_GDT);
        else
            hi->hash = hs->hash;
    }
    hi->puuid = puuid;
    hi->psalt = psalt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

    hi->flag |= INDEX_UNLINK | INDEX_ITE_ACTIVE;

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
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out;
    }

    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_free_msg(msg);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_free_msg(msg);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "UNLINK failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        atomic64_inc(&unlink_failed);
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
        hvfs_err(xnet, "MDS site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        struct gdt_md *m;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
        }
        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "Invalid reply w/o MDU as expected.\n");
            err = -EFAULT;
            goto out;
        }
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid,
                                 MDS_BITMAP_SET);
        }
        /* setup the output values */
        if (hs) {
            memset(hs, 0, sizeof(*hs));
            hs->puuid = rhi->puuid;
            if (hmr->flag & MD_REPLY_DIR) {
                hs->ssalt = m->salt;
            } else
                hs->psalt = rhi->psalt;
            hs->uuid = rhi->uuid;
            hs->hash = rhi->hash;
            memcpy(&hs->mdu, m, sizeof(hs->mdu));
        }
    }

out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int __hvfs_stat(u64 puuid, u64 psalt, int column, struct hstat *hs)
{
    struct xnet_msg *msg;
    size_t dpayload;
    struct hvfs_index *hi;
    struct hvfs_md_reply *hmr;
    u64 dsite;
    u32 vid;
    int err = 0;

    dpayload = sizeof(struct hvfs_index) + 
        (hs->uuid == 0 ? strlen(hs->name) : 0);
    hi = (struct hvfs_index *)xzalloc(dpayload);
    if (!hi) {
        hvfs_err(xnet, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    if (!hs->uuid) {
        hi->flag = INDEX_BY_NAME;
        hi->namelen = strlen(hs->name);
        hi->hash = hvfs_hash(puuid, (u64)hs->name, hi->namelen, HASH_SEL_EH);
        memcpy(hi->name, hs->name, hi->namelen);
    } else {
        hi->flag = INDEX_BY_UUID;
        hi->uuid = hs->uuid;
        if (!hs->hash)
            hi->hash = hvfs_hash(hs->uuid, psalt, 0, HASH_SEL_GDT);
        else
            hi->hash = hs->hash;
    }
    hi->puuid = puuid;
    hi->psalt = psalt;
    /* calculate the itbid now */
    err = SET_ITBID(hi);
    if (err)
        goto out_free;
    dsite = SELECT_SITE(hi->itbid, hi->psalt, CH_RING_MDS, &vid);

    if (column < 0)
        hi->flag |= INDEX_LOOKUP | INDEX_ITE_ACTIVE;
    else {
        hi->column = column;
        hi->flag |= INDEX_LOOKUP | INDEX_ITE_ACTIVE | INDEX_COLUMN;
    }

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
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

resend:
    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() lookup to %lx failed w/ %d\n",
                 msg->tx.dsite_id, err);
        goto out;
    }

    /* this means we have got the reply, parse it */
    ASSERT(msg->pair, xnet);
    if (msg->pair->tx.err == -ESPLIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        sched_yield();
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART ||
               msg->pair->tx.err == -EHWAIT) {
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(xnet, "LOOKUP failed @ MDS site %lx w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        atomic64_inc(&lookup_failed);
        goto out;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(xnet, "Invalid LOOKUP reply from site %lx\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, something wrong on the MDS */
        hvfs_err(xnet, "MDS site %lx reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        err = hmr->err;
        goto out;
    } else if (hmr->len) {
        struct hvfs_index *rhi;
        struct column *c = NULL;
        struct gdt_md *m;
        int no = 0;

        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
        rhi = hmr_extract(hmr, EXTRACT_HI, &no);
        if (!rhi) {
            hvfs_err(xnet, "extract HI failed, not found.\n");
            err = -EFAULT;
            goto out;
        }
        m = hmr_extract(hmr, EXTRACT_MDU, &no);
        if (!m) {
            hvfs_err(xnet, "Invalid reply w/o MDU as expected.\n");
            err = -EFAULT;
            goto out;
        }
        if (hmr->flag & MD_REPLY_WITH_BFLIP) {
            mds_dh_bitmap_update(&hmo.dh, rhi->puuid, rhi->itbid,
                                 MDS_BITMAP_SET);
        }
        if (hmr->flag & MD_REPLY_WITH_DC) {
            c = hmr_extract(hmr, EXTRACT_DC, &no);
            if (!c) {
                hvfs_err(xnet, "extract DC failed, not found.\n");
            }
        }
        /* setup the output values */
        if (hs) {
            memset(hs, 0, sizeof(*hs));
            hs->puuid = rhi->puuid;
            if (hmr->flag & MD_REPLY_DIR) {
                hs->ssalt = m->salt;
            } else 
                hs->psalt = rhi->psalt;
            hs->uuid = rhi->uuid;
            hs->hash = rhi->hash;
            memcpy(&hs->mdu, m, sizeof(hs->mdu));
            if (c) {
                hs->mc.cno = column;
                hs->mc.c = *c;
            }
        }
    }

out:
    xnet_free_msg(msg);
    return err;
out_free:
    xfree(hi);
    return err;
}

int __hvfs_readdir(u64 duuid, u64 salt, char **buf)
{
    struct xnet_msg *msg;
    struct hvfs_index hi;
    u64 dsite, itbid = 0;
    off_t offset = 0;
    size_t len = 0;
    u32 vid;
    int err = 0, retry_nr;

    /* Step 1: we should refresh the bitmap of the directory */
    mds_bitmap_refresh_all(duuid);

    /* Step 2: we send the INDEX_BY_ITB requests to each MDS in serial or
     * parallel mode */
    do {
        err = mds_bitmap_find_next(duuid, &itbid);
        if (err < 0) {
            hvfs_err(xnet, "mds_bitmap_find_next() failed @ %ld w/ %d\n",
                     itbid, err);
            break;
        } else if (err > 0) {
            /* this means we can safely stop now */
            break;
        } else {
            /* ok, we can issue the request to the dest site now */
            hvfs_debug(xnet, "Issue request %ld to site ...\n",
                       itbid);
            /* Step 3: we print the results to the console */
            memset(&hi, 0, sizeof(hi));
            hi.puuid = duuid;
            hi.psalt = salt;
            hi.hash = -1UL;
            hi.itbid = itbid;
            hi.flag = INDEX_BY_ITB;

            dsite = SELECT_SITE(itbid, hi.psalt, CH_RING_MDS, &vid);
            msg = xnet_alloc_msg(XNET_MSG_NORMAL);
            if (!msg) {
                hvfs_err(xnet, "xnet_alloc_msg() failed\n");
                err = -ENOMEM;
                goto out;
            }
            xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                             hmo.xc->site_id, dsite);
            xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_LIST, 0, 0);
#ifdef XNET_EAGER_WRITEV
            xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
            xnet_msg_add_sdata(msg, &hi, sizeof(hi));

            retry_nr = 0;
        retry:
            err = xnet_send(hmo.xc, msg);
            if (err) {
                hvfs_err(xnet, "xnet_send() failed\n");
                xnet_free_msg(msg);
                goto out;
            }

            ASSERT(msg->pair, xnet);
            if (msg->pair->tx.err) {
                /* Note that, if the itbid is less than 8, then we ignore the
                 * ENOENT error */
                if (itbid < 8 && msg->pair->tx.err == -ENOENT) {
                    xnet_free_msg(msg);
                    itbid++;
                    continue;
                }
                if (msg->pair->tx.err == -EHWAIT) {
                    if (retry_nr < 60) {
                        retry_nr++;
                        sleep(1);
                        goto retry;
                    }
                }
                hvfs_err(mds, "list dir %lx slice %ld failed w/ %d\n",
                         duuid, itbid, msg->pair->tx.err);
                err = msg->pair->tx.err;
                xnet_free_msg(msg);
                goto out;
            }
            if (msg->pair->xm_datacheck) {
                /* ok, dump the entries */
                char kbuf[260];
                char *p = (char *)(msg->pair->xm_data +
                                   sizeof(struct hvfs_md_reply)),
                    *np = NULL;
                struct dentry_info *tdi;
                int idx = 0;

                /* alloc the buffer */
                if (msg->pair->tx.len - sizeof(struct hvfs_md_reply) == 0) {
                    xnet_free_msg(msg);
                    itbid++;
                    continue;
                } else {
                    hvfs_debug(xnet, "From ITB %ld, len %ld\n", 
                               itbid,
                               msg->pair->tx.len - 
                               sizeof(struct hvfs_md_reply));
                }
                
                *buf = xrealloc(*buf, len + (msg->pair->tx.len - 
                                             sizeof(struct hvfs_md_reply)) /
                                sizeof(struct dentry_info) * 300);
                if (!*buf) {
                    hvfs_err(mds, "xzalloc() result buffer failed\n");
                    err = -ENOMEM;
                    xnet_free_msg(msg);
                    goto out;
                }
                len += (msg->pair->tx.len - sizeof(struct hvfs_md_reply)) /
                    sizeof(struct dentry_info) * 300;
                np = *buf + offset;

                while (idx < msg->pair->tx.len - 
                       sizeof(struct hvfs_md_reply)) {
                    tdi = (struct dentry_info *)p;
                    p += sizeof(*tdi);
                    if (tdi->namelen) {
                        memcpy(kbuf, p, tdi->namelen);
                        kbuf[tdi->namelen] = '\0';
                    } else {
                        kbuf[0] = '?';
                        kbuf[1] = '\0';
                    }
                    p += tdi->namelen;
                    idx += tdi->namelen + sizeof(*tdi);
                    offset += sprintf(np, "%s %06o %20lx %s\n",
                                      S_ISDIR(tdi->mode) ? "d" : "-",
                                      tdi->mode, tdi->uuid, 
                                      kbuf);
                    np = *buf + offset;
                }
            } else {
                hvfs_err(xnet, "Invalid LIST reply from site %lx.\n",
                         msg->pair->tx.ssite_id);
                err = -EFAULT;
                xnet_free_msg(msg);
                goto out;
            }
            xnet_free_msg(msg);
        }
        itbid += 1;
    } while (1);

    err = 0;
out:
    return err;
}

int __hvfs_pack_result(struct hstat *hs, void **data)
{
    char *p, *n;
    
    p = xzalloc(1024);
    if (!p) {
        hvfs_err(xnet, "xzalloc() result string failed\n");
        return -ENOMEM;
    }
    n = p;
    p += snprintf(p, 1023, "%lx %lx %lx %x "
                  "%d %d %o %d %ld %ld %ld %ld %ld %ld "
                  "%d ",
                  hs->puuid, hs->psalt, hs->uuid, hs->mdu.flags,
                  hs->mdu.uid, hs->mdu.gid, hs->mdu.mode,
                  hs->mdu.nlink, hs->mdu.size, hs->mdu.dev,
                  hs->mdu.atime, hs->mdu.ctime, hs->mdu.mtime,
                  hs->mdu.dtime, hs->mdu.version);
    if (hs->mdu.flags & HVFS_MDU_IF_SYMLINK) {
        if (hs->mdu.size > 16) {
            /* the refer name is saved in column 0, client can just read
             * in the data content */
            p += snprintf(p, 16, "$REF_COLUMN$ ");
        } else {
            strncpy(p, hs->mdu.symname, 16);
            p += hs->mdu.size;
            p[0] = ' ';
            p++;
        }
    } else {
        p += snprintf(p, 128, "$%ld$%ld$ ", hs->mdu.lr.fsid,
                      hs->mdu.lr.rfino);
    }
    p += snprintf(p, 256, "[%ld %ld %ld %ld]\n",
                  hs->mc.cno, hs->mc.c.stored_itbid,
                  hs->mc.c.len, hs->mc.c.offset);

    *data = n;

    return 0;
}

int __hvfs_fill_root(struct hstat *hs)
{
    int err = 0;
    
    memset(hs, 0, sizeof(*hs));
    hs->uuid = hmi.root_uuid;
    err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 1, hs);
    if (err) {
        hvfs_err(xnet, "do internal ROOT stat (GDT) failed w/ %d\n",
                 err);
    }

    return err;
}

/* @path: the dir path to the last directory
 * @name: the file name
 *
 * Note, if name is NULL or "", it means that we want to stat the last
 * directory in path.
 */
int hvfs_stat(char *path, char *name, void **data)
{
    struct hstat hs = {0,};
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hvfs_debug(xnet, "token: %s\n", p);
        /* ok, we should do stat on this directory based on the puuid, psalt
         * we got */
        /* Step 1: find in the SDT, zero uuid means using name to lookup */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* lookup the file in the parent directory now */
    if (name && strlen(name) > 0) {
        /* eh, we have to lookup this file now. Otherwise, what we want to
         * lookup is the last directory, just return a result string now */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal file stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        if (S_ISDIR(hs.mdu.mode)) {
            hs.hash = 0;
            err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 1, &hs);
            if (err) {
                hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
        }
    } else {
        /* check if it the root directory */
        if (puuid == hmi.root_uuid) {
            /* stat root w/o any file name, it is ROOT we want to state */
            err = __hvfs_fill_root(&hs);
            if (err) {
                hvfs_err(xnet, "fill root entry failed w/ %d\n", err);
                goto out;
            }
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

    err = __hvfs_pack_result(&hs, data);
    if (err) {
        hvfs_err(xnet, "pack result failed for '%s' w/ %d\n",
                 name, err);
        goto out;
    }

out:    
    return err;
}

/* hvfs_create() create a file or directory named 'name' in the path 'path'
 */
int hvfs_create(char *path, char *name, void **data, u32 is_dir)
{
    struct hstat hs;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !name || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* create the file or dir in the parent directory now */
    if (strlen(name) == 0) {
        hvfs_err(xnet, "Create zero-length named file?\n");
        err = -EINVAL;
        goto out;
    }
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_create(puuid, psalt, &hs, 
                        (is_dir ? INDEX_CREATE_DIR : 0), NULL);
    if (err) {
        hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    if (is_dir) {
        /* create the gdt entry now */
        err = __hvfs_create(hmi.gdt_uuid, hmi.gdt_salt, &hs, 
                            INDEX_CREATE_GDT, NULL);
        if (err) {
            hvfs_err(xnet, "do internal create (GDT) on '%s' faild w/ %d\n",
                     name, err);
            goto out;
        }
    }
    hs.puuid = puuid;
    hs.psalt = psalt;

    err = __hvfs_pack_result(&hs, data);
    if (err) {
        hvfs_err(xnet, "pack result failed for '%s' w/ %d\n",
                 name, err);
        goto out;
    }
    
out:
    return err;
}

/* parse the 'key=value' token to a mdu_update struct 
 */
void __kv2mu(char *kv, struct mdu_update *mu)
{
    char *p, *n = kv, *s = NULL;
    time_t t = time(NULL);

#define NEXT_TOKEN ({                           \
        p = strtok_r(n, "=, ", &s);             \
        if (!p)                                 \
            break;                              \
        })

    do {
        p = strtok_r(n, "=, ", &s);
        if (!p) {
            /* end */
            break;
        }
        if (strncmp(p, "mode", 4) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_MODE;
            mu->mode = atoi(p);
        } else if (strncmp(p, "uid", 3) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_UID;
            mu->uid = atoi(p);
        } else if (strncmp(p, "gid", 3) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_GID;
            mu->gid = atoi(p);
        } else if (strncmp(p, "flag_add", 8) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_FLAG_ADD;
            mu->flags = atoi(p);
        } else if (strncmp(p, "flag_clr", 8) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_FLAG_CLR;
            mu->flags = atoi(p);
        } else if (strncmp(p, "atime", 5) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_ATIME;
            mu->atime = atol(p);
            if (!mu->atime || mu->atime > t)
                mu->atime = t;
        } else if (strncmp(p, "ctime", 5) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_CTIME;
            mu->ctime = atol(p);
            if (!mu->ctime || mu->ctime > t)
                mu->ctime = t;
        } else if (strncmp(p, "mtime", 5) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_MTIME;
            mu->mtime = atol(p);
            if (!mu->mtime || mu->mtime > t)
                mu->mtime = t;
        } else if (strncmp(p, "version", 7) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_VERSION;
            mu->version = atoi(p);
        } else if (strncmp(p, "size", 4) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_SIZE;
            mu->size = atol(p);
        } else if (strncmp(p, "nlink", 5) == 0) {
            NEXT_TOKEN;
            mu->valid |= MU_NLINK;
            mu->nlink = atoi(p);
        } else if (strncmp(p, "llfs:fsid", 9) == 0) {
            struct llfs_ref *lr = (void *)mu + sizeof(*mu);
            
            NEXT_TOKEN;
            mu->valid |= MU_LLFS;
            lr->fsid = atol(p);
        } else if (strncmp(p, "llfs:rfino", 10) == 0) {
            struct llfs_ref *lr = (void *)mu + sizeof(*mu);
            
            NEXT_TOKEN;
            mu->valid |= MU_LLFS;
            lr->rfino = atol(p);
        } else if (strncmp(p, "mu:cno", 6) == 0) {
            struct mu_column *mc = (void *)mu + sizeof(*mu) + 
                sizeof(struct llfs_ref);

            NEXT_TOKEN;
            mu->valid |= MU_COLUMN;
            mu->column_no = 1;
            mc->cno = atol(p);
        } else if (strncmp(p, "mu:c:sitb", 9) == 0) {
            struct mu_column *mc = (void *)mu + sizeof(*mu) + 
                sizeof(struct llfs_ref);

            NEXT_TOKEN;
            mu->valid |= MU_COLUMN;
            mu->column_no = 1;
            mc->c.stored_itbid = atol(p);
        } else if (strncmp(p, "mu:c:len", 8) == 0) {
            struct mu_column *mc = (void *)mu + sizeof(*mu) + 
                sizeof(struct llfs_ref);

            NEXT_TOKEN;
            mu->valid |= MU_COLUMN;
            mu->column_no = 1;
            mc->c.len = atol(p);
        } else if (strncmp(p, "mu:c:offset", 11) == 0) {
            struct mu_column *mc = (void *)mu + sizeof(*mu) + 
                sizeof(struct llfs_ref);

            NEXT_TOKEN;
            mu->valid |= MU_COLUMN;
            mu->column_no = 1;
            mc->c.offset = atol(p);
        }
    } while (!(n = NULL));
#undef NEXT_TOKEN
}

/* hvfs_update() update a file or directory named 'name'
 */
int hvfs_fupdate(char *path, char *name, void **data)
{
    struct hstat hs;
    struct mdu_update *mu = NULL;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;
    
    /* parse the mdu_update string now, note that we can't modify the string
     * passed in */
    p = (char *)(*data);
    if (!p) {
        hvfs_err(xnet, "you try to update what?\n");
        err = -EINVAL;
        goto out;
    }
    n = strdup(p);
    if (!n) {
        hvfs_err(xnet, "strdup argument failed, no memory\n");
        err = -ENOMEM;
        goto out;
    }

    /* alloc the mdu_update now */
    mu = xzalloc(sizeof(*mu) + sizeof(struct llfs_ref) +
                 sizeof(struct mu_column));
    if (!mu) {
        hvfs_err(xnet, "alloc mdu_update failed\n");
        err = -ENOMEM;
        goto out;
    }
    
    do {
        p = strtok_r(n, ",", &s);
        if (!p) {
            /* end */
            break;
        }
        __kv2mu(p, mu);
    } while (!(n = NULL));
    
    if (!mu->valid) {
        hvfs_warning(xnet, "Nothing to update, just return\n");
        goto out_free;
    }
    if (mu->valid & MU_COLUMN) {
        if (!(mu->valid & MU_LLFS)) {
            /* move mdu_update to the position of llfs */
            memcpy((void *)mu + sizeof(*mu),
                   (void *)mu + sizeof(*mu) + sizeof(struct llfs_ref),
                   sizeof(struct mu_column));
        }
    }
    
    /* finally, do update now */
    if (!name) {
        /* update the final directory by uuid */
        hs.name = NULL;
        hs.hash = 0;
        err = __hvfs_update(hmi.gdt_uuid, hmi.gdt_salt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out_free;
        }
    } else {
        /* update the final file by name */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_update(puuid, psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            goto out_free;
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

    err = __hvfs_pack_result(&hs, data);
    if (err) {
        hvfs_err(xnet, "pack result failed for '%s' w/ %d\n",
                 name, err);
        goto out;
    }

out_free:
    xfree(mu);
out:
    return err;
}

/* hvfs_fdel() delete a file or directory named 'name'
 */
int hvfs_fdel(char *path, char *name, void **data, u32 is_dir)
{
    struct hstat hs;
    char *p = NULL, *n = path, *s = NULL;
    u64 saved_puuid = hmi.root_uuid, saved_psalt = hmi.root_salt;
    u64 saved_hash = 0;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        saved_psalt = psalt;
        saved_puuid = puuid;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        saved_hash = hs.hash;
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        /* got current directory's salt in hs.ssalt */
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* finally, do delete now */
    if (!name) {
        /* what we want to delete is a directory, double check it */
        if (!S_ISDIR(hs.mdu.mode) || !is_dir) {
            hvfs_err(xnet, "It is a dir you want to delete, isn't it?\n");
            err = -EINVAL;
            goto out;
        }
        /* FIXME: check if it is a empty directory? Yup, but how? */
        hs.name = NULL;
        /* Step 1: delete the SDT entry by UUID */
        hs.uuid = puuid;
        hs.hash = saved_hash;
        err = __hvfs_unlink(saved_puuid, saved_psalt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
        /* Step 2: delete the GDT entry */
        hs.uuid = puuid;
        hs.hash = 0;
        err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '?%lx' failed w/ %d\n",
                     puuid, err);
            goto out;
        }
    } else {
        /* delete a normal file or dir, it is easy */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_unlink(puuid, psalt, &hs);
        if (err) {
            hvfs_err(xnet, "do internal delete on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        if (is_dir) {
            /* ok, delete the GDT entry */
            hs.hash = 0;
            err = __hvfs_unlink(hmi.gdt_uuid, hmi.gdt_salt, &hs);
            if (err) {
                hvfs_err(xnet, "do internal delete on '%s' failed w/ %d\n",
                         name, err);
                goto out;
            }
        }
    }

    hs.puuid = puuid;
    hs.psalt = psalt;

    err = __hvfs_pack_result(&hs, data);
    if (err) {
        hvfs_err(xnet, "pack result failed for '%s' w/ %d\n",
                 name, err);
        goto out;
    }

out:
    return err;
}

/* @path: the dir path to the last directory
 * @name, the file name (if exists, should be a directory either)
 */
int hvfs_readdir(char *path, char *name, void **data)
{
    struct hstat hs = {0,};
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        /* Step 1: find in the SDT */
        hs.name = p;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    if (name && strlen(name) > 0) {
        /* stat the last dir */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        psalt = hs.ssalt;
    }

    err = __hvfs_readdir(puuid, psalt, (char **)data);
    if (err) {
        hvfs_err(xnet, "do internal readdir on '%s' failed w/ %d\n",
                 (name ? name : p), err);
        goto out;
    }

out:
    return err;
}

int hvfs_fcommit(int id)
{
    struct xnet_msg *msg;
    struct hvfs_index hi;
    u64 site_id;
    int err = 0;

    memset(&hi, 0, sizeof(hi));

    /* check the arguments */
    if (id < 0) {
        hvfs_err(xnet, "Invalid MDS id %d\n", id);
        err = -EINVAL;
        goto out;
    }
    site_id = HVFS_MDS(id);
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, site_id);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_COMMIT, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &hi, sizeof(hi));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    ASSERT(msg->pair, xnet);
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
out:
    return err;
}

void hvfs_free(void *p)
{
    xfree(p);
}

int __hvfs_fread(struct hstat *hs, int column, void **data, struct column *c)
{
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    u32 vid = 0;
    int err = 0;

    hvfs_warning(xnet, "Read column itbid %ld len %ld offset %ld "
                 "puuid %lx psalt %lx\n",
                 c->stored_itbid, c->len, c->offset, hs->puuid, hs->psalt);

    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() storage index failed\n");
        return -ENOMEM;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    /* fill the parent (dir) uuid to sic.uuid */
    si->sic.uuid = hs->puuid;
    si->sic.arg0 = c->stored_itbid;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = column;
    si->scd.cr[0].stored_itbid = c->stored_itbid;
    si->scd.cr[0].file_offset = c->offset;
    si->scd.cr[0].req_offset = 0;
    si->scd.cr[0].req_len = c->len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(c->stored_itbid, hs->psalt, CH_RING_MDSL, &vid);

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_READ, 0, 0);
    msg->tx.reserved = vid;
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
        *data = xmalloc(c->len);
        if (!*data) {
            hvfs_err(xnet, "xmalloc value region failed.\n");
            err = -ENOMEM;
            goto out_msg;
        }
        memcpy(*data, msg->pair->xm_data, c->len);
    } else {
        hvfs_err(xnet, "recv data read reply ERROR %d\n",
                 msg->pair->tx.err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    }

out_msg:
    xnet_free_msg(msg);
out_free:
    xfree(si);

    return err;
}

/* Ugly! hs->hash saves the user provided stored_itbid!
 */
int __hvfs_fwrite(struct hstat *hs, int column, void *data, 
                  size_t len, struct column *c)
{
    struct storage_index *si;
    struct xnet_msg *msg;
    u64 dsite;
    u64 location;
    u32 vid = 0;
    int err = 0;

    hvfs_warning(xnet, "To write column %d target len %ld itbid %ld "
                 "puuid %lx psalt %lx\n",
                 column, len, hs->hash, hs->puuid, hs->psalt);

    si = xzalloc(sizeof(*si) + sizeof(struct column_req));
    if (!si) {
        hvfs_err(xnet, "xzalloc() stroage index failed\n");
        return -ENOMEM;
    }

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out_free;
    }

    si->sic.uuid = hs->puuid;
    /* hs->hash saved the itbid */
    si->sic.arg0 = hs->hash;
    si->scd.cnr = 1;
    si->scd.cr[0].cno = column;
    si->scd.cr[0].stored_itbid = hs->hash;
    si->scd.cr[0].req_len = len;

    /* select the MDSL site by itbid */
    dsite = SELECT_SITE(hs->hash, hs->psalt, CH_RING_MDSL, &vid);

    /* construct the request messagexo */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDSL_WRITE, 0, 0);
    msg->tx.reserved = vid;
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
        err = -EFAULT;
        goto out_msg;
    }

    if (location == 0) {
        hvfs_warning(xnet, "puuid %lx uuid %lx to %lx C %d L @ %ld len %ld\n",
                     hs->puuid, hs->uuid, dsite, column, location, len);
    }

    c->stored_itbid = hs->hash;
    c->len = len;
    c->offset = location;

out_msg:
    xnet_free_msg(msg);

out_free:
    xfree(si);

    return err;
}

int hvfs_fread(char *path, char *name, int column, void **data, u64 *len)
{
    struct hstat hs;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !name || !data || !strlen(name))
        return -EINVAL;

    /* FIXME: column check */
    if (column >= 6) {
        hvfs_err(xnet, "Pomegranate FS lib does not support indirect"
                 " column at this moment.\n");
        return -ENOSYS;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* stat the file now to get the file info */
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, column, &hs);
    if (err) {
        hvfs_err(xnet, "do file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    
    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }
    
    /* read in the data now */
    
    err = __hvfs_fread(&hs, column, data, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fread on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

    *len = hs.mc.c.len;

out:
    return err;
}

int hvfs_fwrite(char *path, char *name, int column, void *data, u64 len)
{
    struct hstat hs;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !name || !data | !strlen(name))
        return -EINVAL;

    /* FIXME: column check */
    if (column >= 6) {
        hvfs_err(xnet, "Pomegranate FS lib does not support indirect"
                 " column at this moment.\n");
        return -ENOSYS;
    }

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* stat the file now to get the file info */
    hs.name = name;
    hs.uuid = 0;
    err = __hvfs_stat(puuid, psalt, column, &hs);
    if (err == -ENOENT) {
        /* ok, we should create the file now */
        err = __hvfs_create(puuid, psalt, &hs, 0, NULL);
        if (err) {
            hvfs_err(xnet, "do internal create (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
    } else if (err) {
        hvfs_err(xnet, "do file stat (SDT) on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n", PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }

    /* write out the data now */
    err = __hvfs_fwrite(&hs, column, data, len, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fwrite on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }

    /* update the file attributes */
    {
        struct mdu_update *mu;
        struct mu_column *mc;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mc = (void *)mu + sizeof(*mu);
        mu->valid = MU_COLUMN | MU_SIZE;
        mu->size = len;
        mu->column_no = 1;
        mc->cno = column;
        mc->c = hs.mc.c;

        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_update(puuid, psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    }
    
out:
    return err;
}

void __hvfs_dt_set_type(u16 type, char *p)
{
    if (!p)
        return;

    switch (type) {
    case DIR_TRIG_NATIVE:
        strncpy(p, "NATV", 4);
        break;
    case DIR_TRIG_C:
        strncpy(p, "CCCC", 4);
        break;
    case DIR_TRIG_PYTHON:
        strncpy(p, "PYTH", 4);
        break;
    default:
        strncpy(p, "INVL", 4);
    }
}

void __hvfs_dt_set_where(u16 where, char *p)
{
    if (!p)
        return;

    memset(p, 0, 8);
    switch (where) {
    case DIR_TRIG_NONE:
        strncpy(p, "NONE", 4);
        p[4] = '\0';
        break;
    case DIR_TRIG_PRE_FORCE:
        strncpy(p, "FORCEA", 6);
        p[6] = '\0';
        break;
    case DIR_TRIG_POST_FORCE:
        strncpy(p, "FORCEB", 6);
        p[6] = '\0';
        break;
    case DIR_TRIG_PRE_CREATE:
        strncpy(p, "CREATEA", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_POST_CREATE:
        strncpy(p, "CREATEB", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_PRE_LOOKUP:
        strncpy(p, "LOOKUPA", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_POST_LOOKUP:
        strncpy(p, "LOOKUPB", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_PRE_UNLINK:
        strncpy(p, "UNLINKA", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_POST_UNLINK:
        strncpy(p, "UNLINKB", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_PRE_LINKADD:
        strncpy(p, "LINKADDA", 8);
        break;
    case DIR_TRIG_POST_LINKADD:
        strncpy(p, "LINKADDB", 8);
        break;
    case DIR_TRIG_PRE_UPDATE:
        strncpy(p, "UPDATEA", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_POST_UPDATE:
        strncpy(p, "UPDATEB", 7);
        p[7] = '\0';
        break;
    case DIR_TRIG_PRE_LIST:
        strncpy(p, "LISTA", 5);
        p[5] = '\0';
        break;
    case DIR_TRIG_POST_LIST:
        strncpy(p, "LISTB", 5);
        p[5] = '\0';
        break;
    default:
        strncpy(p, "NONE", 4);
        p[4] = '\0';
    }
}

/* hvfs_reg_dtrigger()
 *
 * Register a new DTRIG to the directory. We do not check any conflicts on
 * it. Priority is sorted yet.
 */
int hvfs_reg_dtrigger(char *path, char *name, u16 priority, u16 where, 
                      u32 type, void *data, size_t len)
{
    struct hstat hs = {0,};
    void *old_dtrig, *new_dtrig;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    size_t total_len;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, HVFS_TRIG_COLUMN, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* ok, check if this is a directory */
    if (name && strlen(name) > 0) {
        /* stat the last dir */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, HVFS_TRIG_COLUMN, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        psalt = hs.ssalt;
    } else {
        /* check if it is root directory */
        if (puuid == hmi.root_uuid) {
            err = __hvfs_fill_root(&hs);
            if (err) {
                hvfs_err(xnet, "fill root entry failed w/ %d\n", err);
                goto out;
            }
            hs.psalt = hmi.gdt_salt;
            hs.puuid = hmi.gdt_uuid;
            hs.hash = hvfs_hash(hmi.root_uuid, hs.psalt, 0, HASH_SEL_GDT);
        }
    }

    /* read in the dtrig content */
    err = __hvfs_fread(&hs, HVFS_TRIG_COLUMN, &old_dtrig, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fread on '%s' failed w/ %d\n",
                 name, err);
        goto out;
    }
    
    total_len = hs.mc.c.len + len + 20;
    new_dtrig = xmalloc(total_len);
    if (!new_dtrig) {
        hvfs_err(xnet, "xmalloc() new dtrig region failed\n");
        err = -ENOMEM;
        if (hs.mc.c.len)
            xfree(old_dtrig);
        goto out;
    }

    /* insert ourself to the old_dtrig buffer */
    if (hs.mc.c.len > 0) {
        void *p;
        int old_priority;
        off_t offset = 0, old_offset = 0;
        size_t tmp_len;

        p = new_dtrig;
        while (offset < total_len) {
            hvfs_debug(xnet, "ooffset %ld offset %ld\n", old_offset, offset);
            if (old_offset >= hs.mc.c.len)
                goto just_copy;
            old_priority = *(int *)(old_dtrig + old_offset + 12);
            tmp_len = *(int *)(old_dtrig + old_offset + 16);
            hvfs_debug(xnet, "opri %d pri %d len %ld\n",
                       old_priority, priority, tmp_len);
            if (old_priority < priority) {
            just_copy:
                p = new_dtrig + offset;
                /* type */
                __hvfs_dt_set_type(type, p);
                p += 4;
                /* where */
                __hvfs_dt_set_where(where, p);
                p += 8;
                /* priority */
                *(int *)p  = priority;
                p += 4;
                /* length */
                *(int *)p = len;
                p += 4;
                /* copy in the new dtrigger */
                memcpy(p, data, len);
                p += len;
                /* copy the remain old dtriggers */
                memcpy(p, old_dtrig + old_offset, (total_len - len - 20 - offset));
                break;
            } else {
                /* copy this entry to new dtrigger */
                memcpy(new_dtrig + offset, old_dtrig + old_offset,
                       tmp_len + 20);
                old_offset += tmp_len + 20;
            }
            offset += tmp_len + 20;
        }
        xfree(old_dtrig);
    } else {
        void *p = new_dtrig;

        /* type */
        __hvfs_dt_set_type(type, p);
        p += 4;
        /* where */
        __hvfs_dt_set_where(where, p);
        p += 8;
        /* priority */
        *(int *)p = priority;
        p += 4;
        /* length */
        *(int *)p = len;
        p += 4;
        /* copy in the new dtrigger */
        memcpy(p, data, len);
    }

    /* calculate which itbid we should stored it in */
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hmi.gdt_uuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n",
                     PTR_ERR(e));
            err = PTR_ERR(e);
            goto out;
        }
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }
    
    /* ok, we can update the directory trigger now */
    err = __hvfs_fwrite(&hs, HVFS_TRIG_COLUMN, new_dtrig, 
                        total_len, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fwrite on '%s' failed w/ %d\n",
                 name, err);
        xfree(new_dtrig);
        goto out;
    }
    xfree(new_dtrig);

    /* update the gdt column and file attributes */
    {
        struct mdu_update *mu;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mu->valid = MU_COLUMN | MU_FLAG_ADD;
        mu->flags = HVFS_MDU_IF_TRIG;
        mu->column_no = 1;
        hs.mc.cno = HVFS_TRIG_COLUMN;

        /* GDT update */
        hs.uuid = puuid;
        hs.hash = 0;
        err = __hvfs_update(hmi.gdt_uuid, hmi.gdt_salt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     name, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    }
    
out:
    return err;
}

/* hvfs_cat_dtrigger()
 *
 * Cat the dtrigger content to user
 */
int hvfs_cat_dtrigger(char *path, char *name, void **data)
{
    struct hstat hs = {0,};
    void *old_dtrig;
    char *p = NULL, *n = path, *s = NULL;
    u64 puuid = hmi.root_uuid, psalt = hmi.root_salt;
    int err = 0;

    if (!path || !data)
        return -EINVAL;

    /* parse the path and do __stat on each directory */
    do {
        p = strtok_r(n, "/", &s);
        if (!p) {
            /* end */
            break;
        }
        hs.name = p;
        hs.uuid = 0;
        /* Step 1: find in the SDT */
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do_internal dir stat (SDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        /* Step 2: find in the GDT */
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, HVFS_TRIG_COLUMN, &hs);
        if (err) {
            hvfs_err(xnet, "do internal dir stat (GDT) on '%s' failed w/ %d\n",
                     p, err);
            break;
        }
        psalt = hs.ssalt;
    } while (!(n = NULL));

    if (err)
        goto out;

    /* ok, check if this is a directory */
    if (name && strlen(name) > 0) {
        /* stat the last dir */
        hs.name = name;
        hs.uuid = 0;
        err = __hvfs_stat(puuid, psalt, -1, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (SDT) on '%s' failed w/ %d\n",
                     name, err);
            goto out;
        }
        puuid = hs.uuid;
        hs.hash = 0;
        err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, HVFS_TRIG_COLUMN, &hs);
        if (err) {
            hvfs_err(xnet, "do last dir stat (GDT) on '%s' failed w/ %d\n",
                     name ,err);
            goto out;
        }
        psalt = hs.ssalt;
    } else {
        /* check if it is root directory */
        if (puuid == hmi.root_uuid) {
            err = __hvfs_fill_root(&hs);
            if (err) {
                hvfs_err(xnet, "fill root entry failed w/ %d\n", err);
                goto out;
            }
            hs.psalt = hmi.gdt_salt;
            hs.puuid = hmi.gdt_uuid;
            hs.hash = hvfs_hash(hmi.root_uuid, hs.psalt, 0, HASH_SEL_GDT);
        }
    }

    /* read in the dtrig content */
    err = __hvfs_fread(&hs, HVFS_TRIG_COLUMN, &old_dtrig, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "do internal fread on '%s' failed w/ %d\n",
                 name ,err);
        goto out;
    }

    /* parse the dtrig content and echo the result */
    if (hs.mc.c.len > 0) {
        char *type, *where, b[64], *p = b;
        int priority, length;
        off_t offset = 0;
        int i;
        
        while (offset < hs.mc.c.len) {
            hvfs_debug(xnet, "offset %ld\n", offset);
            type = (char *)(old_dtrig + offset);
            where = (char *)(old_dtrig + offset + 4);
            priority = *(int *)(old_dtrig + offset + 12);
            length = *(int *)(old_dtrig + offset + 16);
            p = b;
            memset(p, 0, sizeof(b));
            memcpy(p, type, 4);
            *(p + 4) = ' ';
            p += 5;
            for (i = 0; i < 8; i++) {
                if (*(where + i) != '\0')
                    *(p + i) = *(where + i);
                else
                    *(p + i) = ' ';
            }
            p += 8;
            p += snprintf(p, 50, " %d %d\n", priority, length);
            hvfs_info(xnet, "%s", b);
            offset += length + 20;
        }
        xfree(old_dtrig);
    } else {
        hvfs_plain(xnet, "None\n");
    }
    
out:
    return err;
}

static
int __hvfs_statfs(struct statfs *s, u64 dsite)
{
    struct statfs *ns;
    struct xnet_msg *msg;
    int err = 0;

    /* alloc xnet msg */
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        return -ENOMEM;
    }

    /* construct the request message */
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_STATFS, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    /* this is a trick to pass the sanity checking in MDS */
    xnet_msg_add_sdata(msg, &err, sizeof(err));

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() failed\n");
        goto out_msg;
    }

    /* recv the reply, parse the statfs structure */
    if (msg->pair->xm_datacheck) {
        ns = (struct statfs *)msg->pair->xm_data;
    } else {
        hvfs_err(xnet, "recv statfs reply ERROR!\n");
        err = -EFAULT;
        goto out_msg;
    }

    s->f_blocks += ns->f_blocks;
    s->f_bfree += ns->f_bfree;
    s->f_bavail += ns->f_bavail;
    s->f_files += ns->f_files;
    s->f_ffree += ns->f_ffree;
    
out_msg:
    xnet_free_msg(msg);

    return err;
}

/* hvfs_statfs() stat the HMIs from all the MDSs.
 */
int hvfs_statfs(void **data)
{
    struct statfs s;
    struct xnet_group *xg = NULL;
    char *p = NULL;
    int err = 0, i;

    memset(&s, 0, sizeof(s));
    p = xzalloc(512);
    if (!p) {
        hvfs_err(xnet, "xzalloc() result buffer failed\n");
        return -ENOMEM;
    }
    
    xg = cli_get_active_site(hmo.chring[CH_RING_MDS]);
    if (!xg) {
        hvfs_err(xnet, "cli_get_active_site() failed\n");
        err = -ENOMEM;
        goto out;
    }

    for (i = 0; i < xg->asize; i++) {
        err = __hvfs_statfs(&s, xg->sites[i].site_id);
        if (err) {
            hvfs_err(xnet, "Statfs from %lx failed /w %d\n",
                     xg->sites[i].site_id, err);
        }
    }

    s.f_type = HVFS_SUPER_MAGIC;
    s.f_namelen = HVFS_MAX_NAME_LEN;
    
    /* construct the result buffer */
    snprintf(p, 512, "FS STAT:\n"
             "\tf_type\t\t0x%lx\n"
             "\tf_bsize\t\t%ld\n"
             "\tf_blocks\t%ld\n"
             "\tf_bfree\t\t%ld\n"
             "\tf_bavail\t%ld\n"
             "\tf_files\t\t%ld\n"
             "\tf_ffree\t\t%ld\n"
             "\tf_fsid\t\t????\n"
             "\tf_namelen\t%ld\n",
             s.f_type, s.f_bsize, s.f_blocks, s.f_bfree,
             s.f_bavail, s.f_files, s.f_ffree, 
             s.f_namelen);
    *data = p;

out:
    return err;
}
