/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2013-02-19 16:17:40 macan>
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

/* osd_write() write a obj content to this OSD server, each write incr the
 * version number.
 *
 * ABI:
 *
 * tx.arg0 -> length(32b) + start_offset(32b)
 * tx.arg1 -> flags
 * xm_data -> objid | [obj content]
 */
int osd_write(struct xnet_msg *msg)
{
    struct objid *obj;
    u32 length, offset;
    int err = 0, dev;

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
    if (msg->tx.arg1 & HVFS_OSD_WRITE_TRUNC) {
        err = osd_storage_trunc(obj, offset + length, &dev);
        if (err) {
            if (err != -ENOENT) {
                hvfs_err(osd, "trunc the obj %lx.%x file to %d bytes failed "
                         "w/ %d\n", obj->uuid, obj->bid, offset + length, err);
                goto out;
            }
        }
    }

    err = osd_storage_write(obj, msg->xm_data + sizeof(*obj), offset, 
                            length, &dev);
    if (err) {
        hvfs_err(osd, "write to OSD storage device failed w/ %d\n", err);
        goto out;
    }

    /* update the obj info to OGA manager */
    err = __om_update_entry(*obj, dev);
    if (err) {
        hvfs_err(osd, "update OM entry for obj %lx.%x 2changed list failed "
                 "w/ %d, ignore it\n", obj->uuid, obj->bid, err);
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
    u32 offset;
    int length;
    void *data = NULL;
    int err = 0, dev;

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
    if (length < 0) {
        /* sweep to the end of the file */
        length = osd_storage_getlen(obj) - OSD_FH_SIZE;
        if (length < 0) {
            hvfs_err(osd, "get obj %lx.%x len failed w/ %d\n",
                     obj->uuid, obj->bid, length);
            err = length;
            goto out;
        }
    }
    
    /* alloc zero region */
    data = xzalloc(length);
    if (!data) {
        hvfs_err(osd, "Alloc %d bytes zero memory region failed\n", length);
        err = -ENOMEM;
        goto out;
    }
    
    err = osd_storage_write(obj, data, offset, length, &dev);
    if (err) {
        hvfs_err(osd, "write to OSD storage device failed w/ %d\n", err);
        goto out_free;
    }

    /* update the obj info to OGA manager */
    err = __om_update_entry(*obj, dev);
    if (err) {
        hvfs_err(osd, "update OM entry for obj %lx.%x 2changed list failed "
                 "w/ %d, ignore it\n", obj->uuid, obj->bid, err);
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
 * tx.arg1 -> version (signed 32b: -1 means ignore version)
 * xm_data -> objid
 */
int osd_read(struct xnet_msg *msg)
{
    struct xnet_msg *rpy;
    struct objid *obj;
    u32 offset;
    int length, version;
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
    version = (int)msg->tx.arg1;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD read request w/ NULL data payload\n");
        err = -EINVAL;
        goto out_err;
    }

    /* alloc a free region */
    if (length > 0) {
        data = xzalloc(length);
        if (!data) {
            hvfs_err(osd, "Alloc %d bytes zero memory region failed\n", length);
            err = -ENOMEM;
            goto out_err;
        }
    }

    if (version != -1) {
        err = osd_storage_read_strict(obj, &data, offset, length, version);
    } else {
        err = osd_storage_read(obj, &data, offset, length);
    }
    if (err < 0) {
        hvfs_err(osd, "read from OSD storage device failed w/ %d\n", err);
        goto out_err;
    }
    /* set length to read data length */
    length = err;

    /* send the read region back */
    err = __prepare_xnet_msg(msg, &rpy);
    if (err) {
        goto out_err;
    }
    if (length > 0)
        xnet_msg_add_sdata(rpy, data, length);
    /* set data region length to arg0! */
    rpy->tx.arg0 = length;
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

/* osd_trunc() truncate an obj on this OSD server
 *
 * ABI:
 *
 * tx.arg0 -> length
 * xm_data -> objid
 */
int osd_trunc(struct xnet_msg *msg)
{
    struct objid *obj;
    off_t length;
    int err = 0, dev;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD TRUNC request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    length = msg->tx.arg0;
    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD trunc request w/ NULL data payload\n");
        err = -EINVAL;
        goto out;
    }

    err = osd_storage_trunc(obj, length, &dev);
    if (err) {
        hvfs_err(osd, "truncate to OSD storage device failed w/ %d\n", err);
        goto out;
    }
    
    /* update the obj info to OGA manager */
    err = __om_update_entry(*obj, dev);
    if (err) {
        hvfs_err(osd, "update OM entry for obj %lx.%x 2changed list failed "
                 "w/ %d, ignore it\n", obj->uuid, obj->bid, err);
    }

out:
    /* send a reply msg */
    __simply_send_reply(msg, err);
    xnet_free_msg(msg);

    return err;
}

/* osd_del() del a obj from this OSD server
 *
 * ABI:
 *
 * tx.arg0 ->
 * tx.arg1 ->
 * xm_data -> objid
 */
int osd_del(struct xnet_msg *msg)
{
    struct objid *obj;
    int err = 0;

    if (unlikely(msg->tx.len < sizeof(*obj))) {
        hvfs_err(osd, "Invalid OSD DEL request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto out;
    }

    obj = (struct objid *)msg->xm_data;
    if (!obj) {
        hvfs_err(osd, "Invalid OSD DEL request w/ NULL data payload\n");
        err = -EINVAL;
        goto out;
    }

    err = osd_storage_del(obj);
    if (err) {
        hvfs_err(osd, "DEL from OSD storage device failed w/ %d\n", err);
        goto out;
    }
    
    /* update the obj info to OGA manager */
    err = __om_del_entry(*obj);
    if (err) {
        hvfs_err(osd, "delete OM entry for obj %lx.%x failed "
                 "w/ %d, ignore it\n", obj->uuid, obj->bid, err);
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
