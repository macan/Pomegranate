/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-08-11 04:08:22 macan>
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

/* Note that the AMC client just wrapper the mds core functions to act as a
 * standalone program. The API exported by this file can be called by the
 * python program.
 */
#define HVFS_R2_DEFAULT_PORT    8710
#define HVFS_AMC_DEFAULT_PORT   9001

int msg_wait()
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

    return 0;
}

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
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
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
        if (!hmo.chring[CH_RING_MDS]) {
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

    err = r2cli_do_unreg(hmo.xc->site_id, HVFS_RING(0), 1, 0);
    if (err) {
        hvfs_err(xnet, "unreg self %lx w/ r2 %x failed w/ %d\n",
                 hmo.xc->site_id, HVFS_RING(0), err);
        return;
    }
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

int __core_main(int argc, char *argv[])
{
    struct xnet_type_ops ops = {
        .buf_alloc = NULL,
        .buf_free = NULL,
        .recv_handler = NULL,
    };
    int err = 0;
    int self = -1, sport = -1;
    int thread = 1;
    char *r2_ip = NULL;
    short r2_port = HVFS_R2_DEFAULT_PORT;
    char *shortflags = "d:p:t:h?r:";
    struct option longflags[] = {
        {"id", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        {"thread", required_argument, 0, 't'},
        {"root", required_argument, 0, 'r'},
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
        case 'h':
        case '?':
            hvfs_info(xnet, "help menu:\n");
            hvfs_info(xnet, "    -d,--id      self AMC id.\n");
            hvfs_info(xnet, "    -p,--port    self AMC port.\n");
            hvfs_info(xnet, "    -t,--thread  thread number.\n");
            hvfs_info(xnet, "    -r,--root    root server.\n");
            hvfs_info(xnet, "    -h,--help    print this menu.\n");
            return 0;
            break;
        default:
            return EINVAL;
        }
    }

    /* ok, check the arguments */
    if (self == -1) {
        hvfs_err(xnet, "Please set the AMC id w/ '-d' option\n");
        return EINVAL;
    }

    if (sport == -1) {
        sport = HVFS_AMC_DEFAULT_PORT;
    }
    
    if (!r2_ip) {
        hvfs_err(xnet, "Please set the r2 server ip w/ '-r' option\n");
        return EINVAL;
    }

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
    sprintf(profiling_fname, "./CP-BACK-amc.%d", self);
    hmo.conf.pf_file = fopen(profiling_fname, "w+");
    if (!hmo.conf.pf_file) {
        hvfs_err(xnet, "fopen() profiling file %s failed %d\n",
                 profiling_fname, errno);
        return EINVAL;
    }

    /* setup the address of root server */
    xnet_update_ipaddr(HVFS_RING(0), 1, &r2_ip, &r2_port);
    self = HVFS_AMC(self);

    hmo.xc = xnet_register_type(0, sport, self, &ops);
    if (IS_ERR(hmo.xc)) {
        err = PTR_ERR(hmo.xc);
        goto out;
    }

    hmo.site_id = self;

    hmo.cb_exit = amc_cb_exit;
    err = r2cli_do_reg(self, HVFS_RING(0), 1, 0);
    if (err) {
        hvfs_err(xnet, "ref self %x w/ r2 %x failed w/ %d\n",
                 self, HVFS_RING(0), err);
        goto out;
    }
    hvfs_info(xnet, "AMI gdt uuid %ld salt %lx\n",
              hmi.gdt_uuid, hmi.gdt_salt);

    err = mds_verify();
    if (err) {
        hvfs_err(xnet, "Verify MDS configration failed!\n");
        goto out;
    }

    /* should we create root entry? no! */

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
    } else if (msg->pair->tx.err == -ERESTART) {
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
    } else if (msg->pair->tx.err == -ERESTART) {
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
    } else if (msg->pair->tx.err == -ERESTART) {
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
        } else if (msg2->pair->tx.err == -ERESTART) {
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
    return err;
out_free:
    xfree(hi);
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
    u64 dsite;
    u32 vid;
    int err = 0, recreate = 0;

    memset(&ai, 0, sizeof(ai));
    ai.flag = INDEX_PUT;
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
    ai.dlen = strlen(value);
    xnet_msg_add_sdata(msg, value, strlen(value));

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
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
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
    ai.flag = INDEX_GET;
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
    } else if (msg->pair->tx.err == -ERESTART) {
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
    memcpy(*value, kv->value, kv->len);
    
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
    ai.flag = INDEX_DEL;
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
    } else if (msg->pair->tx.err == -ERESTART) {
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
    u64 dsite;
    u32 vid;
    int err = 0;

    memset(&ai, 0, sizeof(ai));
    ai.flag = INDEX_UPDATE;
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
    ai.dlen = strlen(value);
    xnet_msg_add_sdata(msg, value, strlen(value));

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
    } else if (msg->pair->tx.err == -ERESTART) {
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
    int err = 0;

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
                hvfs_err(mds, "list root failed w/ %d\n",
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
                        hvfs_info(xnet, "%s\n", kbuf);
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
