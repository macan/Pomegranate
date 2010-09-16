/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-16 21:23:49 macan>
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
#include "mds.h"
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "amc_api.h"

static inline
void xtable_send_reply(struct xnet_msg *msg, struct iovec *iov, 
                       int iovnr, int err)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!rpy) {
        hvfs_err(mds, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    if (err) {
        xnet_msg_set_err(rpy, err);
    } else {
        int i;
        
        for (i = 0; i < iovnr; i++) {
            xnet_msg_add_sdata(rpy, iov[i].iov_base, iov[i].iov_len);
        }
    }

    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, XNET_NEED_DATA_FREE, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_DATA, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    err = xnet_send(hmo.xc, rpy);
    if (err) {
        hvfs_err(mds, "xnet_send() failed w/ %d '%s'\n",
                 err, strerror(-err));
    }

    xnet_free_msg(rpy);
}

int xtable_put(struct amc_index *ai, struct iovec **iov, int *nr)
{
    struct hvfs_index *hi;
    struct hvfs_md_reply hmr;
    struct hvfs_txg *txg;
    int err = 0;

    hi = xzalloc(sizeof(struct hvfs_index));
    if (!hi) {
        hvfs_err(mds, "xzalloc() hvfs_index failed.\n");
        return -ENOMEM;
    }

    memset(&hmr, 0, sizeof(hmr));

    hi->flag = INDEX_CREATE | INDEX_KV;
    if (ai->column != 0) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->column = ai->column;
    }
    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, &hmr, txg, &txg);
    txg_put(txg);

    /* then, parse the hmr to value */
    if (err) {
        hvfs_debug(mds, "mds_cbht_search() for KV put K:%lx failed w/ %d\n",
                   hi->hash, err);
        goto out;
    }
    
    /* Note that, in a real kv store, we do NOT need to return the value on
     * put operation, instead, we return the real itbid. */
    *nr = 1;
    *iov = xzalloc(sizeof(struct iovec));
    if (!*iov) {
        hvfs_err(mds, "xzalloc iovec failed\n");
        err = -ENOMEM;
        goto out;
    }
    (*iov)->iov_base = xmalloc(sizeof(u64));
    if (!(*iov)->iov_base) {
        hvfs_err(mds, "xzalloc itbid failed\n");
        err = -ENOMEM;
        xfree(*iov);
        *iov = NULL;
        goto out;
    }
    (*iov)->iov_len = sizeof(u64);
    *(u64 *)(*iov)->iov_base = hi->itbid;
    
out:
    xfree(hmr.data);
    xfree(hi);
    
    return err;
}

int xtable_get(struct amc_index *ai, struct iovec **iov, int *nr)
{
    struct hvfs_index *hi;
    struct hvfs_md_reply hmr;
    struct hvfs_txg *txg;
    int err = 0;

    hi = xzalloc(sizeof(struct hvfs_index));
    if (!hi) {
        hvfs_err(mds, "xzalloc() hvfs_index failed.\n");
        err = -ENOMEM;
        goto out;
    }

    memset(&hmr, 0, sizeof(hmr));

    hi->flag = INDEX_LOOKUP | INDEX_KV;
    if (ai->column != 0) {
        /* the 0th column default to attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->column = ai->column;
    }
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;

    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, &hmr, txg, &txg);
    txg_put(txg);

    /* then, parse the hmr to value */
    if (err) {
        hvfs_debug(mds, "mds_cbht_search() for KV get K:%lx failed w/ %d\n",
                   hi->hash, err);
        goto out;
    }

    *nr = 2;
    *iov = xzalloc(sizeof(struct iovec) * 2);
    if (!*iov) {
        hvfs_err(mds, "xzalloc iovec failed\n");
        xfree(hmr.data);
        err = -ENOMEM;
        goto out;
    }
    (*iov)->iov_base = xmalloc(sizeof(u64));
    if (!(*iov)->iov_base) {
        hvfs_err(mds, "xzalloc itbid failed\n");
        err = -ENOMEM;
        xfree(*iov);
        *iov = NULL;
        goto out;
    }
    (*iov)->iov_len = sizeof(u64);
    *(u64 *)(*iov)->iov_base = hi->itbid;

    (*iov + 1)->iov_base = hmr.data;
    (*iov + 1)->iov_len = hmr.len;

out:
    xfree(hi);
    return err;
}

int xtable_del(struct amc_index *ai, struct iovec **iov, int *nr)
{
    struct hvfs_index *hi;
    struct hvfs_md_reply hmr;
    struct hvfs_txg *txg;
    int err = 0;

    hi = xzalloc(sizeof(struct hvfs_index));
    if (!hi) {
        hvfs_err(mds, "xzalloc() hvfs_index failed.\n");
        err = -ENOMEM;
        goto out;
    }

    memset(&hmr, 0, sizeof(hmr));

    hi->flag = INDEX_UNLINK | INDEX_KV;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;

    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, &hmr, txg, &txg);
    txg_put(txg);

    /* then, parse the hmr and return the result */
    if (err) {
        hvfs_debug(mds, "mds_cbht_search() for KV del K:%lx failed w/ %d\n",
                   hi->hash, err);
        goto out;
    }

    *nr = 1;
    *iov = xzalloc(sizeof(struct iovec));
    if (!*iov) {
        hvfs_err(mds, "xzalloc iovec failed\n");
        err = -ENOMEM;
        goto out;
    }
    (*iov)->iov_base = xmalloc(sizeof(u64));
    if (!(*iov)->iov_base) {
        hvfs_err(mds, "xzalloc itbid failed\n");
        err = -ENOMEM;
        xfree(*iov);
        *iov = NULL;
        goto out;
    }
    (*iov)->iov_len = sizeof(u64);
    *(u64 *)(*iov)->iov_base = hi->itbid;

out:
    xfree(hmr.data);
    xfree(hi);

    return err;
}

int xtable_update(struct amc_index *ai, struct iovec **iov, int *nr)
{
    struct hvfs_index *hi;
    struct hvfs_md_reply hmr;
    struct hvfs_txg *txg;
    int err = 0;

    hi = xzalloc(sizeof(struct hvfs_index));
    if (!hi) {
        hvfs_err(mds, "xzalloc() hvfs_index failed.\n");
        err = -ENOMEM;
        goto out;
    }

    memset(&hmr, 0, sizeof(hmr));

    hi->flag = INDEX_MDU_UPDATE | INDEX_KV;
    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, &hmr, txg, &txg);
    txg_put(txg);

    if (err) {
        hvfs_debug(mds, "mds_cbht_search() for KV update K:%lx failed w/ %d\n",
                   hi->hash, err);
        goto out;
    }

    *nr = 1;
    *iov = xzalloc(sizeof(struct iovec));
    if (!*iov) {
        hvfs_err(mds, "xzalloc iovec failed\n");
        err = -ENOMEM;
        goto out;
    }
    (*iov)->iov_base = xmalloc(sizeof(u64));
    if (!(*iov)->iov_base) {
        hvfs_err(mds, "xzalloc itbid failed\n");
        err = -ENOMEM;
        xfree(*iov);
        *iov = NULL;
        goto out;
    }
    (*iov)->iov_len = sizeof(u64);
    *(u64 *)(*iov)->iov_base = hi->itbid;

out:
    xfree(hmr.data);
    xfree(hi);

    return err;
}

int xtable_cupdate(struct amc_index *ai, struct iovec **iov, int *nr)
{
    return xtable_update(ai, iov, nr);
}

int xtable_commit(struct amc_index *ai, struct iovec **iov, int *nr)
{
    txg_change_immediately();
    *nr = 0;

    return 0;
}

/* xtable_handle_req() handle the incomming AMC request
 */
void xtable_handle_req(struct xnet_msg *msg)
{
    struct amc_index *ai;
    struct iovec *iov = NULL;
    int err = 0, nr = 0;
    
    /* sanity checking */
    if (msg->tx.len < sizeof(*ai)) {
        hvfs_err(mds, "Invalid AMC request %d received\n",
                 msg->tx.reqno);
        err = -EINVAL;
        goto send_rpy;
    }

    if (msg->xm_datacheck)
        ai = msg->xm_data;
    else {
        hvfs_err(mds, "Internal error, data lossing ...\n");
        err = -EFAULT;
        goto send_rpy;
    }

    if (ai->dlen) {
        ASSERT(ai->dlen == msg->tx.len - sizeof(*ai), mds);
        ai->data = msg->xm_data + sizeof(*ai);
    } else
        ai->data = NULL;

    if (ai->flag & INDEX_PUT) {
        err = xtable_put(ai, &iov, &nr);
    } else if (ai->flag & INDEX_GET) {
        err = xtable_get(ai, &iov, &nr);
    } else if (ai->flag & INDEX_DEL) {
        err = xtable_del(ai, &iov, &nr);
    } else if (ai->flag & INDEX_UPDATE) {
        err = xtable_update(ai, &iov, &nr);
    } else if (ai->flag & INDEX_CUPDATE) {
        err = xtable_cupdate(ai, &iov, &nr);
    } else if (ai->flag & INDEX_COMMIT) {
        err = xtable_commit(ai, &iov, &nr);
    } else {
        err = -EINVAL;
    }

send_rpy:
    xtable_send_reply(msg, iov, nr, err);

    /* free the resources */
    xfree(iov);

    xnet_free_msg(msg);
}
