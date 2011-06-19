/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-17 09:39:47 macan>
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
#include "root.h"
#include "xtable.h"

static inline
int __prepare_xnet_msg(struct xnet_msg *msg, struct xnet_msg **orpy)
{
    struct xnet_msg *rpy;
    
    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(root, "xnet_alloc_msg() reply failed.\n");
        return -ENOMEM;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hro.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    rpy->tx.handle = msg->tx.handle;

    *orpy = rpy;
    
    return 0;
}

static inline
void __root_send_rpy(struct xnet_msg *rpy, int err)
{
    if (err && err != -ERECOVER) {
        /* delete the data payload */
        rpy->tx.len = sizeof(rpy->tx);
#ifdef XNET_EAGER_WRITEV
        rpy->siov_ulen = 1;
#else
        rpy->siov_ulen = 0;
#endif
    }
    
    xnet_msg_set_err(rpy, err);
    if (xnet_send(hro.xc, rpy)) {
        hvfs_err(root, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);
}

static inline
int __pack_msg(struct xnet_msg *msg, void *data, int len)
{
    u32 *__len = xmalloc(sizeof(u32));

    if (!__len) {
        hvfs_err(root, "pack msg xmalloc failed\n");
        return -ENOMEM;
    }

    *__len = len;
    xnet_msg_add_sdata(msg, __len, sizeof(u32));
    xnet_msg_add_sdata(msg, data, len);

    return 0;
}

static inline
void __simply_send_reply(struct xnet_msg *msg, int err)
{
    struct xnet_msg *rpy = xnet_alloc_msg(XNET_MSG_CACHE);

    if (!rpy) {
        hvfs_err(root, "xnet_alloc_msg() failed\n");
        return;
    }
    xnet_msg_set_err(rpy, err);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hro.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hro.xc, rpy)) {
        hvfs_err(root, "xnet_isend() failed\n");
        /* do not retry myself, client is forced to retry */
    }
    xnet_free_msg(rpy);
}

/* root_do_reg()
 *
 * do register the site_id in arg0. If the site state is INIT, we should read
 * in the hxi info and return it. If the site state is NORMAL, we should alert
 * the caller that there is already a running server/client with the same
 * site_id. If the site state is SHUTDOWN, we should do state change in atomic
 * fashion. If the site state is TRANSIENT, we should just wait a moment for
 * the state change. If the site state is ERROR, we should do a recover process.
 *
 * Return ABI: | hxi info(fixed size) | ring info(MDS/MDSL) | root info | gdt
 * bitmap | site_table |
 */
int root_do_reg(struct xnet_msg *msg)
{
    struct site_entry *se;
    struct xnet_msg *rpy;
    struct root_entry *root;
    struct ring_entry *ring;
    struct addr_entry *addr;
    struct root_tx *root_tx;
    void *addr_data = NULL, *ring_data = NULL, *ring_data2 = NULL,
        *ring_data3 = NULL;
    u32 gid;
    u64 fsid;
    int addr_len, ring_len, ring_len2, ring_len3;
    int err = 0, saved_err = 0;

    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare rpy xnet_msg failed w/ %d\n", err);
        goto out;
    }

    /* ABI:
     * @tx.arg0: site_id or -1UL to random selected a site_id
     * @tx.arg1: fsid
     * @tx.reserved: gid
     */
    err = site_mgr_lookup_create(&hro.site, msg->tx.arg0, &se);
    if (err > 0) {
        /* it is a new create site entry, set the fsid now */
        se->fsid = msg->tx.arg1;
        se->gid = msg->tx.reserved & 0xffffffff;
        err = root_read_hxi(se->site_id, se->fsid, &se->hxi);
        if (err == -ENOTEXIST) {
            err = root_create_hxi(se);
            if (err) {
                hvfs_err(root, "create hxi %ld %lx failed w/ %d\n",
                         se->fsid, se->site_id, err);
                goto send_rpy;
            }
            /* write the hxi to disk now */
            err = root_write_hxi(se);
            if (err) {
                hvfs_err(root, "write hxi %ld %lx failed w/ %d\n",
                         se->fsid, se->site_id, err);
                goto send_rpy;
            }
        } else if (err) {
            hvfs_err(root, "read %ld %lx hxi failed w/ %d\n",
                     se->fsid, se->site_id, err);
            goto send_rpy;
        }
        hvfs_err(root, "Create site entry %lx\n", msg->tx.arg0);
    } else if (err < 0) {
        hvfs_err(root, "lookup create site entry %lx failed w/ %d\n",
                 msg->tx.arg0, err);
        goto send_rpy;
    }
    
    /* now, we get a entry, either new created or an existed one, we should
     * act on the diffierent state */
    err = root_compact_hxi(msg->tx.arg0, msg->tx.arg1, msg->tx.reserved,
                           &se->hxi);
    if (err == -ERECOVER) {
        saved_err = err;
        err = 0;
    }
    if (err) {
        hvfs_err(root, "compact %lx hxi failed w/ %d\n", msg->tx.arg0,
                 err);
        goto send_rpy;
    }
    
    /* pack the hxi in the rpy message */
    xlock_lock(&se->lock);
    if (se->state == SE_STATE_NORMAL) {
        err = __pack_msg(rpy, &se->hxi, sizeof(se->hxi));
        if (err) {
            hvfs_err(root, "pack hxi failed w/ %d\n", err);
            xlock_unlock(&se->lock);
            goto send_rpy;
        }
    } else {
        hvfs_err(root, "site entry %lx in state %x\n", se->site_id,
                 se->state);
        err = -EFAULT;
        xlock_unlock(&se->lock);
        goto send_rpy;
    }
    xlock_unlock(&se->lock);

    /* pack the ring info */
    /* Step 1: pack the MDS ring of the group */
    gid = msg->tx.reserved << 2;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup() gid %d failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send_rpy;
    }

    err = ring_mgr_compact_one(&hro.ring, gid,
                               &ring_data, &ring_len);
    if (err) {
        hvfs_err(root, "ring_mgr_compact_one() failed w/ %d\n",
                 err);
        ring_mgr_put(ring);
        goto send_rpy;
    }
    err = __pack_msg(rpy, ring_data, ring_len);
    if (err) {
        hvfs_err(root, "pack ring %d failed w/ %d\n",
                 gid, err);
        goto send_rpy;
    }
    ring_mgr_put(ring);
    /* Step 2: pack the MDSL ring of the group */
    gid = msg->tx.reserved << 2 | CH_RING_MDSL;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup() gid %d failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send_rpy;
    }

    err = ring_mgr_compact_one(&hro.ring, gid,
                               &ring_data2, &ring_len2);
    if (err) {
        hvfs_err(root, "ring_mgr_compact_one() failed w/ %d\n",
                 err);
        ring_mgr_put(ring);
        goto send_rpy;
    }
    err = __pack_msg(rpy, ring_data2, ring_len2);
    if (err) {
        hvfs_err(root, "pack ring %d failed w/ %d\n",
                 gid, err);
        goto send_rpy;
    }
    ring_mgr_put(ring);
    
    /* Step 3: pack the BP ring of the group */
    gid = msg->tx.reserved << 2 | CH_RING_BP;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup() gid %d failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send_rpy;
    }

    err = ring_mgr_compact_one(&hro.ring, gid,
                               &ring_data3, &ring_len3);
    if (err) {
        hvfs_err(root, "ring_mgr_compact_one() failed w/ %d\n",
                 err);
        ring_mgr_put(ring);
        goto send_rpy;
    }
    err = __pack_msg(rpy, ring_data3, ring_len3);
    if (err) {
        hvfs_err(root, "pack ring %d failed w/ %d\n",
                 gid, err);
        goto send_rpy;
    }
    ring_mgr_put(ring);

    /* pack the root info, just for verify the hxi info */
    root = root_mgr_lookup(&hro.root, msg->tx.arg1);
    if (IS_ERR(root)) {
        hvfs_err(root, "root_mgr_lookup() failed w/ %ld\n",
                 PTR_ERR(root));
        err = PTR_ERR(root);
        goto send_rpy;
    }
    /* set communication magic to arg0 */
    rpy->tx.arg0 = root->magic;

    root_tx = (void *)root + sizeof(root->hlist);
    err = __pack_msg(rpy, root_tx, sizeof(*root_tx));
    if (err) {
        hvfs_err(root, "pack root tx failed w/ %d\n", err);
        goto send_rpy;
    }
        
    /* pack the gdt bitmap */
    err = __pack_msg(rpy, root->gdt_bitmap, root->gdt_flen);
    if (err) {
        hvfs_err(root, "pack root %ld gdt bitmap failed w/ %d\n",
                 msg->tx.arg1, err);
        goto send_rpy;
    }
    
    /* pack the global site table */
    fsid = msg->tx.arg1;
relookup_addr:
    addr = addr_mgr_lookup(&hro.addr, fsid);
    if (IS_ERR(addr)) {
        hvfs_err(root, "lookup addr for fsid %ld failed w/ %ld\n",
                 fsid, PTR_ERR(addr));
        /* we just fallback to the address table of fsid 0 */
        if (msg->tx.arg1) {
            fsid = 0;
            goto relookup_addr;
        }
        err = PTR_ERR(addr);
        goto send_rpy;
    }
    err = addr_mgr_compact(addr, &addr_data, &addr_len);
    if (err) {
        hvfs_err(root, "compact the site table for %lx failed w/ %d\n",
                 msg->tx.arg0, err);
        goto send_rpy;
    }
    err = __pack_msg(rpy, addr_data, addr_len);
    
    if (err) {
        /* if we got the ERECOVER error, we should send the data region to the
         * requester either. */
        if (err == -ERECOVER) {
            hvfs_err(root, "One recover process will rise from %lx\n",
                     msg->tx.arg0);
        }
    }
send_rpy:
    if (!err)
        __root_send_rpy(rpy, saved_err);
    else
        __root_send_rpy(rpy, err);
    /* free the allocated resources */
    xfree(ring_data);
    xfree(ring_data2);
    xfree(ring_data3);
    xfree(addr_data);
    
out:
    xnet_free_msg(msg);

    return err;
}

/* root_do_unreg() do unregister the site.
 *
 * We just change the site entry's state to SE_STATE_SHUTDOWN and write the
 * hxi to the storage and flush the gdt bitmap to disk. Before flushing we
 * first update the in-memory hxi w/ the request.
 */
int root_do_unreg(struct xnet_msg *msg)
{
    union hvfs_x_info *hxi;
    struct site_entry *se;
    struct root_entry *re;
    struct xnet_msg *rpy;
    int err = 0;

    /* prepare the reply message */
    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare reply msg faild w/ %d\n", err);
        goto out_free;
    }

    /* sanity checking */
    if (msg->tx.len < sizeof(*hxi)) {
        hvfs_err(root, "Invalid unregister request from %lx w/ len %d\n",
                 msg->tx.ssite_id, msg->tx.len);
        err = -EINVAL;
        goto out;
    }

    /* ABI:
     * @tx.arg0: site_id
     * @tx.arg1: fsid
     * @tx.reserved: gid
     */

    if (msg->tx.arg0 != msg->tx.ssite_id) {
        hvfs_err(root, "Unreg other site %lx from site %lx\n",
                 msg->tx.arg0, msg->tx.ssite_id);
        err = -EINVAL;
#if 0
        goto out;
#endif
    }

    if (msg->xm_datacheck) {
        hxi = msg->xm_data;
    } else {
        hvfs_err(root, "Internal error, data lossing...\n");
        err = -EFAULT;
        goto out;
    }

    /* update the hxi to the site entry */
    se = site_mgr_lookup(&hro.site, msg->tx.arg0);
    if (IS_ERR(se)) {
        hvfs_err(root, "site mgr lookup %lx failed w/ %ld\n",
                 msg->tx.arg0, PTR_ERR(se));
        err = PTR_ERR(se);
        goto out;
    }

    xlock_lock(&se->lock);
    if (se->fsid != msg->tx.arg1 ||
        se->gid != msg->tx.reserved) {
        hvfs_err(root, "fsid mismatch %ld vs %ld or gid mismatch "
                 "%d vs %ld on site %lx\n",
                 se->fsid, msg->tx.arg1, se->gid, msg->tx.reserved,
                 msg->tx.arg0);
        err = -EINVAL;
        goto out_unlock;
    }
    switch (se->state) {
    case SE_STATE_INIT:
    case SE_STATE_TRANSIENT:
    case SE_STATE_ERROR:
        hvfs_err(root, "site entry %lx in state %x, check whether "
                 "we can update it.\n", msg->tx.arg0,
                 se->state);
        se->hb_lost = 0;
        /* fall-through */
    case SE_STATE_NORMAL:
        /* ok, we just change the state to shutdown */
        memcpy(&se->hxi, hxi, sizeof(*hxi));
        se->state = SE_STATE_SHUTDOWN;
        break;
    case SE_STATE_SHUTDOWN:
        hvfs_err(root, "the site %lx is already shutdown.",
                 se->site_id);
        break;
    default:
        hvfs_err(root, "site entry %lx in wrong state %x\n",
                 se->site_id, se->state);
    }
out_unlock:    
    xlock_unlock(&se->lock);
    if (err)
        goto out;

    /* ok, then we should init a flush operation now */
    re = root_mgr_lookup(&hro.root, se->fsid);
    if (IS_ERR(re)) {
        hvfs_err(root, "root mgr lookup fsid %ld failed w/ %ld\n",
                 se->fsid, PTR_ERR(re));
        err = PTR_ERR(re);
        goto out;
    }
#if 1
    /* update the root entry */
    if (HVFS_IS_CLIENT(msg->tx.ssite_id))
        re->root_salt = ((struct hvfs_client_info *)hxi)->root_salt;
    else {
        /* updateh the hxi info */
        se->hxi.hmi.root_salt = re->root_salt;
    }
#endif
    /* write the hxi */
    err = root_write_hxi(se);
    if (err) {
        hvfs_err(root, "Flush site %lx hxi to storage failed w/ %d.\n", 
                 se->site_id, err);
        goto out;
    }
    err = root_write_re(re);
    if (err) {
        hvfs_err(root, "Flush fs root %ld to storage failed w/ %d.\n",
                 re->fsid, err);
        goto out;
    }
    
out:
    __root_send_rpy(rpy, err);
out_free:
    xnet_free_msg(msg);
    
    return err;
}

int root_do_update(struct xnet_msg *msg)
{
    union hvfs_x_info *hxi;
    struct site_entry *se;
    struct xnet_msg *rpy;
    int err = 0;

    /* ABI:
     * @tx.arg0: site_id
     * @tx.arg1: fsid
     * @tx.reserved: gid
     */

    /* prepare the reply message */
    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare reply msg failed w/ %d\n", err);
        goto out_free;
    }
    
    /* sanity checking */
    if (msg->tx.len < sizeof(*hxi)) {
        hvfs_err(root, "Invalid update request from %lx w/ len %d\n",
                 msg->tx.ssite_id, msg->tx.len);
        err = -EINVAL;
        goto out;
    }

    if (msg->tx.arg0 != msg->tx.ssite_id) {
        hvfs_err(root, "Update site %lx from site %lx\n",
                 msg->tx.arg0, msg->tx.ssite_id);
        err = -EINVAL;
#if 0
        goto out;
#endif
    }

    if (msg->xm_datacheck) {
        hxi = msg->xm_data;
    } else {
        hvfs_err(root, "Internal error, data lossing...\n");
        err = -EFAULT;
        goto out;
    }

    /* update the hxi to the site entry */
    se = site_mgr_lookup(&hro.site, msg->tx.arg0);
    if (IS_ERR(se)) {
        hvfs_err(root, "site mgr lookup %lx failed w/ %ld\n",
                 msg->tx.arg0, PTR_ERR(se));
        err = PTR_ERR(se);
        goto out;
    }

    xlock_lock(&se->lock);
    if (se->fsid != msg->tx.arg1 ||
        se->gid != msg->tx.reserved) {
        hvfs_err(root, "fsid mismatch %ld vs %ld or gid mismatch "
                 "%d vs %ld on site %lx\n",
                 se->fsid, msg->tx.arg1, se->gid, msg->tx.reserved,
                 msg->tx.arg0);
        err = -EINVAL;
        goto out_unlock;
    }

    switch (se->state) {
    case SE_STATE_INIT:
    case SE_STATE_TRANSIENT:
    case SE_STATE_ERROR:
        hvfs_err(root, "site entry %lx in state %x, check whether "
                 "we can update it.\n", msg->tx.arg0,
                 se->state);
        se->hb_lost = 0;
        /* fall-through */
    case SE_STATE_NORMAL:
        /* ok, we just change the state to normal */
        memcpy(&se->hxi, hxi, sizeof(*hxi));
        se->state = SE_STATE_NORMAL;
        break;
    case SE_STATE_SHUTDOWN:
        hvfs_err(root, "the site %lx is already shutdown.",
                 se->site_id);
        break;
    default:
        hvfs_err(root, "site_entry %lx in wrong state %x\n",
                 se->site_id, se->state);
    }
out_unlock:
    xlock_unlock(&se->lock);
    if (err)
        goto out;

    /* ok, then we should init a flush operation now */
    err = root_write_hxi(se);
    if (err) {
        hvfs_err(root, "Flush site %lx hxi to storage failed w/ %d.\n",
                 se->site_id, err);
    }

out:    
    __root_send_rpy(rpy, err);
out_free:
    xnet_free_msg(msg);
    
    return err;
}

int root_do_mkfs(struct xnet_msg *msg)
{
    struct root_entry *re;
    struct ring_entry *ring;
    struct xnet_msg *rpy;
    u64 gid;
    int err = 0;

    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare rpy xnet_msg failed w/ %d\n", err);
        goto out;
    }

    /* ABI:
     * @tx.arg0: site_id (not user actually)
     * @tx.arg1: fsid
     * @tx.reserved: gid
     */
    /* Step 1: find the ch ring group */
    gid = msg->tx.reserved << 2 | CH_RING_MDS;
    ring = ring_mgr_lookup(&hro.ring, gid);
    if (IS_ERR(ring)) {
        hvfs_err(root, "ring_mgr_lookup gid %ld failed w/ %ld\n",
                 gid, PTR_ERR(ring));
        err = PTR_ERR(ring);
        goto send_rpy;
    }
    
    err = root_mgr_lookup_create2(&hro.root, msg->tx.arg1, &re);
    if (err < 0) {
        hvfs_err(root, "root mgr lookup create %ld failed w/ %d\n",
                 msg->tx.arg1, err);
        goto send_rpy;
    } else if (err > 0) {
        /* setup the bitmap region */
        err = root_bitmap_default(re);
        if (err) {
            hvfs_err(root, "create fsid %ld default root bitmap "
                     "failed w/ %d\n", re->fsid, err);
            goto send_rpy;
        }

    create_it:
        hvfs_err(root, "We just create fsid %ld\n", msg->tx.arg1);

        /* we should create the root dir entry in the gdt w/ the selected
         * ring */
        err = root_mkfs(re, ring, (u32)msg->tx.reserved);
        if (err) {
            hvfs_err(root, "root_mkfs %ld failed w/ %d\n",
                     re->fsid, err);
            goto send_rpy;
        } else {
            /* pack the root_tx in the reply message */
            struct root_tx *rt;

            rt = xmalloc(sizeof(*rt));
            if (!rt) {
                hvfs_err(root, "xmalloc root_tx failed\n");
                err = -ENOMEM;
                goto send_rpy;
            }
            rt->fsid = re->fsid;
            rt->gdt_uuid = re->gdt_uuid;
            rt->gdt_salt = re->gdt_salt;
            rt->root_uuid = re->root_uuid;
            rt->root_salt = re->root_salt;

            __pack_msg(rpy, rt, sizeof(*rt));
            xnet_set_auto_free(rpy);
        }
        /* write the new entry to disk now */
        err = root_write_re(re);
        if (err) {
            hvfs_err(root, "write root entry %ld to disk failed w/ %d\n",
                     re->fsid, err);
        }
    } else {
        if (re->root_salt == -1UL) {
            goto create_it;
        }
        hvfs_info(root, "fsid %ld already exist\n", msg->tx.arg1);
        err = -EEXIST;
    }
    
send_rpy:
    ring_mgr_put(ring);
    __root_send_rpy(rpy, err);
    
out:
    xnet_free_msg(msg);
    
    return err;
}

/* root_do_hb() handling the heartbeat from the r2 client
 *
 * The timeout checker always increase the site_entry->lost_hb, on receiving
 * the client's hb, we just update the site_entry->lost_hb to ZERO.
 */
int root_do_hb(struct xnet_msg *msg)
{
    union hvfs_x_info *hxi;
    struct site_entry *se;
    int err = 0, contain_hxi = 0;

    /* sanity checking */
    if (msg->tx.len >= sizeof(*hxi)) {
        contain_hxi = 1;
    }

    /* ABI:
     * tx.arg0: site_id
     * tx.arg1: fsid
     * xm_data: hxi
     */
    if (msg->tx.arg0 != msg->tx.ssite_id) {
        hvfs_warning(root, "Warning: site_id mismatch %lx vs %lx\n",
                     msg->tx.ssite_id, msg->tx.arg0);
    }
    
    se = site_mgr_lookup(&hro.site, msg->tx.arg0);
    if (IS_ERR(se)) {
        hvfs_err(root, "site mgr lookup %lx failed w/ %ld\n",
                 msg->tx.ssite_id, PTR_ERR(se));
        err = PTR_ERR(se);
        goto out;
    }
    /* clear the lost_hb */
    se->hb_lost = 0;
    /* check whether we can change the state */
    xlock_lock(&se->lock);
    if (se->state != SE_STATE_SHUTDOWN &&
        se->state != SE_STATE_INIT) {
        se->state = SE_STATE_NORMAL;
    }
    xlock_unlock(&se->lock);

    /* update the hxi info */
    if (contain_hxi) {
        if (msg->xm_datacheck) {
            hxi = msg->xm_data;
        } else {
            hvfs_err(root, "Internal error, data lossing ...\n");
            err = -EFAULT;
            goto out;
        }
        /* update the hxi to the site entry */
        xlock_lock(&se->lock);
        if (se->fsid != msg->tx.arg1 ||
            se->gid != msg->tx.reserved) {
            hvfs_err(root, "fsid mismatch %ld vs %ld or gid mismatch "
                     "%d vs %ld on site %lx\n",
                     se->fsid, msg->tx.arg1, se->gid, msg->tx.reserved,
                     msg->tx.arg0);
            err = -EINVAL;
            goto out_unlock;
        }
        switch (se->state) {
        case SE_STATE_INIT:
        case SE_STATE_TRANSIENT:
        case SE_STATE_ERROR:
            hvfs_err(root, "site entry %lx in state %x, check whether "
                     "we can update it.\n", msg->tx.arg0,
                     se->state);
            se->hb_lost = 0;
            /* fall-through */
        case SE_STATE_NORMAL:
            memcpy(&se->hxi, hxi, sizeof(*hxi));
            break;
        case SE_STATE_SHUTDOWN:
            hvfs_err(root, "the site %lx is already shutdown.\n",
                     se->site_id);
            break;
        default:
            hvfs_err(root, "site entry %lx in wrong state %x\n",
                     se->site_id, se->state);
        }
    out_unlock:
        xlock_unlock(&se->lock);
    }

out:
    xnet_free_msg(msg);

    return err;
}

/* root_do_bitmap() interact with MDS server
 *
 * DO NOT follow pack protocol!
 */
int root_do_bitmap(struct xnet_msg *msg)
{
    struct site_entry *se;
    struct root_entry *re;
    int err = 0;

    /* sanity checking */
    if (msg->tx.len != 0) {
        hvfs_err(root, "Invalid AUBITMAP request %d received from %lx\n",
                 msg->tx.reqno, msg->tx.ssite_id);
        err = -EINVAL;
        goto out;
    }

    /* Step 1: we find the target bitmap, and flip the bit(in tx.arg1) */
    /* get the fsid from the site entry */
    se = site_mgr_lookup(&hro.site, msg->tx.ssite_id);
    if (IS_ERR(se)) {
        hvfs_err(root, "site mgr lookup %lx failed w/ %ld\n",
                 msg->tx.ssite_id, PTR_ERR(se));        

        err = PTR_ERR(se);
        goto out;
    }
    
    /* find the root entry to get bitmap */
    re = root_mgr_lookup(&hro.root, se->fsid);
    if (IS_ERR(re)) {
        hvfs_err(root, "root mgr lookup %ld failed w/ %ld\n",
                 se->fsid, PTR_ERR(re));
        err = PTR_ERR(re);
        goto out;
    }

    /* check gdt uuid now */
    if (re->gdt_uuid != msg->tx.arg0) {
        hvfs_err(root, "Update uuid %ld to r2 server on fsid %ld?\n",
                 msg->tx.arg0, se->fsid);
        err = -EINVAL;
        goto out;
    }

    /* FIXME!!!: should we enlarge the gdt bitmap? */
    hvfs_warning(root, "Update uuid %ld offset %ld on fsid %ld\n",
                 msg->tx.arg0, msg->tx.arg1, se->fsid);
    /* flip the bit now */
    if ((msg->tx.arg1 >> 3) >= re->gdt_flen) {
        void *nb = root_bitmap_enlarge(re->gdt_bitmap, re->gdt_flen);

        if (!nb) {
            hvfs_err(root, "Enlarge bitmap region from %ld failed\n",
                     re->gdt_flen);
            err = -ENOMEM;
            goto out;
        }
        re->gdt_bitmap = nb;
        re->gdt_flen = BITMAP_ROUNDUP(re->gdt_flen + XTABLE_BITMAP_BYTES);
    }
    __set_bit(msg->tx.arg1, (unsigned long *)re->gdt_bitmap);
    
    /* Step 2: we reply the caller w/ AUBITMAP_R */
    {
        struct xnet_msg *rpy;

        rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!rpy) {
            hvfs_err(root, "xnet_alloc_msg() failed.\n");
            err = -ENOMEM;
            goto out;
        }
        xnet_msg_fill_tx(rpy, XNET_MSG_REQ, 0,
                         hro.site_id, msg->tx.ssite_id);
        xnet_msg_fill_cmd(rpy, HVFS_MDS2MDS_AUBITMAP_R, msg->tx.arg0,
                          msg->tx.arg1);
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
        err = xnet_send(hro.xc, rpy);
        if (err) {
            hvfs_err(root, "xnet_send() failed w/ %d\n", err);
        }
        xnet_free_msg(rpy);
    }
out:
    xnet_free_msg(msg);
    
    return err;
}

/* root_do_lgdt() try to load and construct the gdt entry
 *
 * following the HMR protocol
 */
int root_do_lgdt(struct xnet_msg *msg)
{
    struct hvfs_md_reply *hmr;
    struct hvfs_index *hi;
    struct root_entry *re;
    struct xnet_msg *rpy;
    int err = 0;

    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare reply msg failed w/ %d\n", err);
        goto out_exit;
    }
    
    /* ABI:
     * tx.arg0: site_id
     * tx.arg1: fsid
     */
    hmr = get_hmr();
    if (!hmr) {
        hvfs_err(root, "get_hmr() failed\n");
        /* do not retry myself */
        goto out;
    }
    hmr->flag |= MD_REPLY_WITH_HI;

    hi = xzalloc(sizeof(*hi));
    if (!hi) {
        hvfs_err(root, "xzalloc() hmr data region failed\n");
        xfree(hmr);
        goto out;
    }
    
    /* lookup the root entry to get the gdt entry */
    re = root_mgr_lookup(&hro.root, msg->tx.arg1);
    if (IS_ERR(re)) {
        hvfs_err(root, "root mgr lookup %ld failed w/ %ld\n",
                 msg->tx.arg1, PTR_ERR(re));
        err = PTR_ERR(re);
        goto send_rpy;
    }

    hi->puuid = re->gdt_uuid;
    hi->psalt = re->gdt_salt;
    hi->uuid = re->gdt_uuid;
    hi->ssalt = re->gdt_salt;

    /* send the reply now */
send_rpy:
    if (err) {
        /* send the err rpy */
        xnet_msg_set_err(rpy, err);
        xfree(hmr);
        xfree(hi);
    } else {
        /* send the correct rpy */
        xnet_msg_add_sdata(rpy, hmr, sizeof(hmr));
        xnet_msg_add_sdata(rpy, hi, sizeof(*hi));
    }
    err = xnet_send(hro.xc, rpy);
    if (err) {
        hvfs_err(root, "xnet_send() failed w/ %s.\n", 
                 strerror(-err));
    }
        
out:
    xnet_free_msg(rpy);
out_exit:
    xnet_free_msg(msg);

    return err;
}

/* root_do_lbgdt() try to load and construct the gdt bitmap
 *
 * following the itbitmap protocol
 */
int root_do_lbgdt(struct xnet_msg *msg)
{
    struct ibmap ibmap;
    struct root_entry *re;
    struct xnet_msg *rpy;
    u64 offset;
    int err = 0;

    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        hvfs_err(root, "prepare reply msg failed w/ %d\n", err);
        goto out_exit;
    }

    /* ABI:
     * tx.arg0: site_id
     * tx.arg1: fsid
     * tx.reserved: offset
     */

    /* Step 1: find the root entry and get the gdt bitmap pointer */
    re = root_mgr_lookup(&hro.root, msg->tx.arg1);
    if (IS_ERR(re)) {
        hvfs_err(root, "root mgr lookup %ld failed w/ %ld\n",
                 msg->tx.arg1, PTR_ERR(re));
        err = PTR_ERR(re);
        goto out;
    }

    /* Step 2: round down the offset */
    offset = mds_bitmap_cut(msg->tx.reserved, re->gdt_flen << 3);
    offset = BITMAP_ROUNDDOWN(offset);
    /* transform the bit offset to byte offset */
    
    /* Step 3: construct the itbitmap and reply to the source site */
    ibmap.offset = offset;
    offset >>= 3;
    ibmap.flag = ((re->gdt_flen - offset > XTABLE_BITMAP_BYTES) ?
                  0 : BITMAP_END);
    ibmap.ts = time(NULL);

    xnet_msg_add_sdata(rpy, &ibmap, sizeof(ibmap));
    xnet_msg_add_sdata(rpy, (void *)re->gdt_bitmap + offset, 
                       XTABLE_BITMAP_BYTES);
    err = xnet_send(hro.xc, rpy);
    if (err) {
        hvfs_err(root, "xnet_send() failed w/ %s.\n",
                 strerror(-err));
    }

out:
    xnet_free_msg(rpy);
out_exit:
    xnet_free_msg(msg);

    return err;
}

/* root_do_prof() merge the per-MDS stats together
 */
int root_do_prof(struct xnet_msg *msg)
{
    int err = 0;

    /* ABI:
     * xm_data: transfer plot entry
     */

    hvfs_info(root, "Notify: You can use test/result/aggr.sh to aggregate"
              " the results now!");
    xnet_free_msg(msg);

    return err;
}

int root_do_online(struct xnet_msg *msg)
{
    struct ring_entry *re;
    int type;
    int err = 0;

    /* ABI:
     * tx.arg0: site_id
     * tx.arg1: NONE
     */

    /* first, we should update the address table and bcast it to all the
     * active sites */
    /* FIXME: */

    /* second, we update the hash ring and bcast it */
    if (HVFS_IS_MDS(msg->tx.arg0)) {
        type = CH_RING_MDS;
    } else if (HVFS_IS_MDSL(msg->tx.arg0)) {
        type = CH_RING_MDSL;
    } else if (HVFS_IS_BP(msg->tx.arg0)) {
        type = CH_RING_BP;
    } else {
        hvfs_err(root, "Invalid site (type): %ld\n", msg->tx.arg0);
        err = -EINVAL;
        goto out;
    }
    
    re = ring_mgr_lookup(&hro.ring, type);
    if (IS_ERR(re)) {
        hvfs_err(root, "lookup ring %d failed\n", CH_RING_MDS);
        goto out;
    }
    
    err = cli_dynamic_add_site(re, msg->tx.arg0);
    if (err) {
        ring_mgr_put(re);
        hvfs_err(root, "cli_dynamic_add_site() failed w/ %d\n", err);
        goto out;
    }

    ring_mgr_put(re);

out:
    /* FIXME: send a reply? */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

int root_do_offline(struct xnet_msg *msg)
{
    struct ring_entry *re;
    int type;
    int err = 0;

    /* ABI:
     * tx.arg0: site_id
     * tx.arg1: force or not (0)
     */

    if (HVFS_IS_MDS(msg->tx.arg0)) {
        type = CH_RING_MDS;
    } else if (HVFS_IS_MDSL(msg->tx.arg0)) {
        type = CH_RING_MDSL;
    } else if (HVFS_IS_BP(msg->tx.arg0)) {
        type = CH_RING_BP;
    } else {
        hvfs_err(root, "Invalid site (type): %ld\n", msg->tx.arg0);
        err = -EINVAL;
        goto out;
    }

    re = ring_mgr_lookup(&hro.ring, type);
    if (IS_ERR(re)) {
        hvfs_err(root, "lookup ring %d failed\n", CH_RING_MDS);
        goto out;
    }
    
    err = cli_dynamic_del_site(re, msg->tx.arg0, msg->tx.arg1);
    if (err) {
        ring_mgr_put(re);
        hvfs_err(root, "ring_find_site() failed w/ %d\n", err);
        goto out;
    }

    ring_mgr_put(re);
    
out:
    /* FIXME: send a reply? */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

int root_do_ftreport(struct xnet_msg *msg)
{
    /* If a site_A report site_B is FAILED, we should check if it is realy
     * down by scan the site_mgr. If site_B is really failed, we mask it out
     * of our cluster. Otherwise, we just ignore the report and return a OK
     * update to site_A! */
    int err = 0;

    return err;
}

/* This function is NOT thread-safe! FIXME
 */
int root_do_addsite(struct xnet_msg *msg)
{
    struct sockaddr_in sin;
    int err = 0;

    /* ABI:
     * tx.arg0: ip address | service port (already converted to network order)
     * tx.arg1: site_id to add or site type
     * tx.reserved: fsid
     */

    sin.sin_family = AF_INET;
    sin.sin_port = msg->tx.arg0 & 0xffffffff;
    sin.sin_addr.s_addr = msg->tx.arg0 >> 32;

    /* For security reasons, we should only allow authorized sites to add
     * sites */
    err = cli_do_addsite(&sin, msg->tx.reserved, msg->tx.arg1);
    if (err) {
        hvfs_err(root, "cli_do_addsite(%ld, %ld) failed w/ %d\n",
                 msg->tx.reserved, msg->tx.arg1, err);
    }

    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}


int root_do_rmvsite(struct xnet_msg *msg)
{
    struct sockaddr_in sin;
    int err = 0;
    
    /* ABI:
     * tx.arg0: ip address | service port (already converted to network order)
     * tx.arg1: site_id to remove
     * tx.reserved: fsid
     */

    sin.sin_family = AF_INET;
    sin.sin_port = msg->tx.arg0 & 0xffffffff;
    sin.sin_addr.s_addr = msg->tx.arg0 >> 32;

    /* For security reasons, we should only allow authorized sites to remove
     * sites */
    err = cli_do_rmvsite(&sin, msg->tx.reserved, msg->tx.arg1);
    if (err) {
        hvfs_err(root, "cli_do_rmvsite(%ld, %ld) failed w/ %d\n",
                 msg->tx.reserved, msg->tx.arg1, err);
    }

    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

/* shutdown() only acts on a error state site_entry and flush the info to disk
 */
int root_do_shutdown(struct xnet_msg *msg)
{
    struct site_entry *se;
    int err = 0;
    
    /* ABI:
     * tx.arg0: site_id to shutdown
     */

    /* find the site entry */
    se = site_mgr_lookup(&hro.site, msg->tx.arg0);
    if (IS_ERR(se)) {
        hvfs_err(root, "site mgr lookup %lx failed w/ %ld\n",
                 msg->tx.arg0, PTR_ERR(se));
        err = PTR_ERR(se);
        goto out;
    }

    xlock_lock(&se->lock);
    /* do not check fsid and gid! */
    switch (se->state) {
    case SE_STATE_INIT:
    case SE_STATE_TRANSIENT:
    case SE_STATE_NORMAL:
    case SE_STATE_SHUTDOWN:
        hvfs_err(root, "site entry %lx is not in ERROR state(%x), "
                 "reject this shutdown request!\n",
                 se->site_id, se->state);
        err = -EINVAL;
        break;
    case SE_STATE_ERROR:
        se->state = SE_STATE_SHUTDOWN;
        break;
    default:
        hvfs_err(root, "site entry %lx in wrong state %x\n",
                 se->site_id, se->state);
        err = -EFAULT;
    }
    xlock_unlock(&se->lock);
    if (err)
        goto out;

    /* ok, then we should issue a flush operation now */
    err = root_write_hxi(se);
    if (err) {
        hvfs_err(root, "Flush site %lx hxi to storage failed w/ %d.\n",
                 se->site_id, err);
        goto out;
    }
    
out:
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

/* do_profile() handles the profile response from MDS and MDSL
 */
int root_do_profile(struct xnet_msg *msg)
{
    struct hvfs_profile *hp;
    int err = 0;

    if (msg->tx.len < sizeof(*hp) ||
        !msg->xm_datacheck) {
        hvfs_err(root, "Invalid profile request from site %lx\n",
                 msg->tx.ssite_id);
        err = -EINVAL;
        goto out;
    }
    hp = msg->xm_data;
    
    /* extract the profile */
    if (HVFS_IS_MDS(msg->tx.ssite_id)) {
        err = root_profile_update_mds(hp, msg);
    } else if (HVFS_IS_MDSL(msg->tx.ssite_id)) {
        err = root_profile_update_mdsl(hp, msg);
    } else if (HVFS_IS_BP(msg->tx.ssite_id)) {
        err = root_profile_update_bp(hp, msg);
    } else if (HVFS_IS_CLIENT(msg->tx.ssite_id)) {
        err = root_profile_update_client(hp, msg);
    } else {
        hvfs_err(root, "Invalid source site(%lx), type is ??\n",
                 msg->tx.ssite_id);
        err = -EINVAL;
    }
    if (err) {
        hvfs_err(root, "Profile request(%lx) handling failed w/ %d\n",
                 msg->tx.ssite_id, err);
    }
    
out:
    xnet_free_msg(msg);

    return err;
}

