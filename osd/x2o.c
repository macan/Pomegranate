/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-05 10:36:52 macan>
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

#include "osd.h"
#include "lib.h"

static inline
int __prepare_xnet_msg(struct xnet_msg *msg, struct xnet_msg **orpy)
{
    struct xnet_msg *rpy;
    
    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(osd, "xnet_alloc_msg() reply failed.\n");
        *orpy = NULL;
        return -ENOMEM;
    }
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hoo.site_id, msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    rpy->tx.handle = msg->tx.handle;

    *orpy = rpy;
    
    return 0;
}

static inline
void __osd_send_rpy(struct xnet_msg *rpy, int err)
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
    if (xnet_send(hoo.xc, rpy)) {
        hvfs_err(osd, "xnet_send() failed.\n");
    }
    xnet_free_msg(rpy);
}

static inline
int __pack_msg(struct xnet_msg *msg, void *data, int len)
{
    u32 *__len = xmalloc(sizeof(u32));

    if (!__len) {
        hvfs_err(osd, "pack msg xmalloc failed\n");
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
        hvfs_err(osd, "xnet_alloc_msg() failed\n");
        return;
    }
    xnet_msg_set_err(rpy, err);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hoo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hoo.xc, rpy)) {
        hvfs_err(osd, "xnet_isend() failed\n");
        /* do not retry myself, client is forced to retry */
    }
    xnet_free_msg(rpy);
}

/* osd_write() write a obj content to this OSD server
 *
 * ABI:
 *
 * tx.arg0 -> length(32b) + start_offset(32b)
 * tx.arg1 -> 
 * xm_data -> objid | [obj content]
 */
int osd_write(struct xnet_msg *msg)
{
    struct objid *obj;
    u32 length, offset;
    int err = 0;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD WRITE request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    offset = msg->tx.arg0 & 0xffffffff;
    length = (msg->tx.arg0 >> 32) & 0xffffffff;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD write request w/ NULL data payload\n");
        err = -EINVAL;
        goto out;
    }
    if (length > msg->tx.len - sizeof(*obj)) {
        hvfs_err(osd, "OSD write request w/ NOT enough data payload\n");
        err = -EINVAL;
        goto out;
    }

    err = osd_storage_write(obj, msg->xm_data + sizeof(*obj), offset, length);
    if (err) {
        hvfs_err(osd, "write to OSD storage device failed w/ %d\n", err);
        goto out;
    }
    
out:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

/* osd_sweep() sweep a obj region on this OSD server (ZERO the region)
 *
 * ABI:
 *
 * tx.arg0 -> length(32b) + start_offset(32b)
 * tx.arg1 ->
 * xm_data -> objid
 */
int osd_sweep(struct xnet_msg *msg)
{
    struct objid *obj;
    u32 length, offset;
    void *data;
    int err = 0;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD SWEEP request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    offset = msg->tx.arg0 & 0xffffffff;
    length = (msg->tx.arg0 >> 32) & 0xffffffff;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD sweep request w/ NULL data payload\n");
        err = -EINVAL;
        goto out;
    }
    /* alloc zero region */
    data = xzalloc(length);
    if (!data) {
        hvfs_err(osd, "Alloc %d bytes zero memory region failed\n", length);
        err = -ENOMEM;
        goto out;
    }

    err = osd_storage_write(obj, data, offset, length);
    if (err) {
        hvfs_err(osd, "write to OSD storage device failed w/ %d\n", err);
        goto out_free;
    }
out_free:
    xfree(data);
out:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);
    
    return err;
}

/* osd_read() read a obj region from this OSD server
 *
 * ABI:
 *
 * tx.arg0 -> length(32b) + start_offset(32b)
 * tx.arg1 ->
 * xm_data -> objid
 */
int osd_read(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    struct objid *obj;
    u32 length, offset;
    void *data = NULL;
    int err = 0;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD READ request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out_err;
    }

    offset = msg->tx.arg0 & 0xffffffff;
    length = (msg->tx.arg0 >> 32) & 0xffffffff;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD read request w/ NULL data payload\n");
        err = -EINVAL;
        goto out_err;
    }
    /* alloc a free region */
    data = xzalloc(length);
    if (!data) {
        hvfs_err(osd, "Alloc %d bytes zero memory region failed\n", length);
        err = -ENOMEM;
        goto out_err;
    }

    err = osd_storage_read(obj, data, offset, length);
    if (err) {
        hvfs_err(osd, "read from OSD storage device failed w/ %d\n", err);
        goto out_err;
    }

    /* send the read region back */
    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        goto out_err;
    }
    err = __pack_msg(rpy, data, length);
    __osd_send_rpy(rpy, err);

out_free:
    xfree(data);
    xnet_free_msg(msg);

    return err;
out_err:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    goto out_free;
}

/* osd_sync() sync a obj on this OSD server
 *
 * ABI:
 *
 * tx.arg0 -> length(32b) + start_offset(32b)
 * tx.arg1 ->
 * xm_data -> objid
 */
int osd_sync(struct xnet_msg *msg)
{
    struct objid *obj;
    u32 length, offset;
    int err = 0;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD SYNC request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    offset = msg->tx.arg0 & 0xffffffff;
    length = (msg->tx.arg0 >> 32) & 0xffffffff;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD sync request w/ NULL data payload\n");
        err = -EINVAL;
        goto out;
    }

    err = osd_storage_sync(obj, offset, length);
    if (err) {
        hvfs_err(osd, "sync to OSD storage device failed w/ %d\n", err);
        goto out;
    }
    
out:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

/* osd_statfs() traverous the storage tree to gather info
 */
int osd_statfs(struct xnet_msg *msg)
{
    struct statfs *s = (struct statfs *)xzalloc(sizeof(struct statfs));
    struct xnet_msg *rpy;
    int err = 0;

    if (!s) {
        hvfs_err(osd, "xzalloc() statfs failed\n");
        err = -ENOMEM;
        goto out_err;
    }

    err = osd_storage_statfs(s);
    if (err) {
        hvfs_err(osd, "statfs to OSD storage device failed w/ %d\n", err);
        goto out_err;
    }

    /* send the statfs result back */
    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        goto out_err;
    }
    xnet_msg_add_sdata(rpy, s, sizeof(*s));
    __osd_send_rpy(rpy, err);
    
out_free:
    xfree(s);
    xnet_free_msg(msg);

    return err;
out_err:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    goto out_free;
}
