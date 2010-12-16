/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-16 01:34:30 macan>
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

static inline
int __xtable_adjust_itbid(struct hvfs_index *hi,
                          struct xnet_msg *msg)
{
    struct dhe *e;
    struct chp *p;
    u64 itbid;
    int err = 0;

    e = mds_dh_search(&hmo.dh, hi->puuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        goto out;
    }
    itbid = mds_get_itbid(e, hi->hash);
    if (itbid != hi->itbid || hmo.conf.option & HVFS_MDS_CHRECHK) {
        p = ring_get_point(itbid, hi->psalt, hmo.chring[CH_RING_MDS]);
        if (unlikely(IS_ERR(p))) {
            hvfs_err(mds, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
            err = -ECHP;
            mds_dh_put(e);
            goto out;
        }
        if (hmo.site_id != p->site_id) {
            /* reply -ERESTART to retry */
            err = -ERESTART;
            if (itbid == hi->itbid) {
                err = -ERINGCHG;
            }
            mds_dh_put(e);
            /* doing the forward now */
            hi->flag |= INDEX_BIT_FLIP;
            hi->itbid = itbid;
            err = mds_do_forward(msg, p->site_id);
            if (!err)
                err = -EFWD;
            goto out;
        }
        hi->itbid = itbid;
    }
    mds_dh_put(e);
out:
    return err;
}

int xtable_put(struct amc_index *ai, struct iovec **iov, int *nr,
               struct xnet_msg *msg)
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
    if (ai->column > HVFS_KV_MAX_COLUMN) {
        hvfs_err(xnet, "Column is %d, which exceeds the maximum column.\n", 
                 ai->column);
        err = -EINVAL;
        goto out_hi;
    } else if (ai->column > XTABLE_INDIRECT_COLUMN) {
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = HVFS_KV_NORMAL; /* column is ZERO */
    } else if (ai->column != 0) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = ai->column;
        hi->kvflag |= HVFS_KV_NORMAL;
    }
    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out_hi;
    }

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
out_hi:
    xfree(hi);
    
    return err;
}

int xtable_get(struct amc_index *ai, struct iovec **iov, int *nr,
               struct xnet_msg *msg)
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

    hi->flag = INDEX_LOOKUP | INDEX_KV;
    /* the 0th column default to attached to the ITE */
    if (ai->column > HVFS_KV_MAX_COLUMN) {
        hvfs_err(mds, "Column number %d is too large.\n",
                 ai->column);
        err = -EINVAL;
        goto out;
    } else if (ai->column != 0) {
        if (unlikely(ai->column == -1)) {
            hi->flag |= INDEX_COLUMN;
            hi->kvflag = 0;
        } else {
            hi->flag |= INDEX_COLUMN;
            hi->kvflag = ai->column;
        }
    }
    hi->kvflag |= HVFS_KV_NORMAL;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out;
    }

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
        xfree(hmr.data);
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

int xtable_del(struct amc_index *ai, struct iovec **iov, int *nr,
               struct xnet_msg *msg)
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

    hi->flag = INDEX_UNLINK | INDEX_KV;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out;
    }

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

int xtable_update(struct amc_index *ai, struct iovec **iov, int *nr,
                  struct xnet_msg *msg)
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

    hi->flag = INDEX_MDU_UPDATE | INDEX_KV;
    if (unlikely(ai->column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(mds, "Column number %d is too large.\n", ai->column);
        err = -EINVAL;
        goto out_hi;
    } else if (ai->column > XTABLE_INDIRECT_COLUMN) {
        hi->flag |= INDEX_COLUMN;
        /* column is ZERO */
        hi->kvflag = HVFS_KV_NORMAL;
    } else if (ai->column != 0) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = ai->column;
        hi->kvflag |= HVFS_KV_NORMAL;
    }
    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out_hi;
    }

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
out_hi:
    xfree(hi);

    return err;
}

int xtable_cupdate(struct amc_index *ai, struct iovec **iov, int *nr,
                   struct xnet_msg *msg)
{
    return xtable_update(ai, iov, nr, msg);
}

int xtable_commit(struct amc_index *ai, struct iovec **iov, int *nr,
                  struct xnet_msg *msg)
{
    txg_change_immediately();
    *nr = 0;

    return 0;
}

int xtable_sput(struct amc_index *ai, struct iovec **iov, int *nr,
                struct xnet_msg *msg)
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

    /* MDS does NOT set the uuid internally, we can use it */
    hi->flag = INDEX_CREATE | INDEX_KV;

    /* Note that in KVS mode, we do support column access, max column is
     * 2^12 - 1 */
    if (unlikely(ai->column > HVFS_KV_MAX_COLUMN)) {
        hvfs_err(mds, "Column number %d is too large.\n", ai->column);
        err = -EINVAL;
        goto out_hi;
    } else if (ai->column > XTABLE_INDIRECT_COLUMN) {
        hi->flag |= INDEX_COLUMN;
        /* column is ZERO */
    } else if (ai->column) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = ai->column;
    }
    
    /* Set the string kv flag and the length to hi->uuid! */
    hi->kvflag |= HVFS_KV_STR;
    hi->uuid = ai->tid;

    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out_hi;
    }

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
out_hi:
    xfree(hi);
    
    return err;
}

int xtable_sget(struct amc_index *ai, struct iovec **iov, int *nr,
                struct xnet_msg *msg)
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

    hi->flag = INDEX_LOOKUP | INDEX_KV;
    /* Note that in KVS mode, we do support column access, max column is 2^12
     * - 1 */
    if (ai->column > HVFS_KV_MAX_COLUMN) {
        hvfs_err(mds, "Column number %d is too large.\n", ai->column);
        err = -EINVAL;
        goto out;
    } else if (ai->column == -1) {
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = 0;
    } else if (ai->column) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = ai->column;
    }
    
    /* Set the string kv flag and the length to hi->uuid! */
    hi->kvflag |= HVFS_KV_STR;
    hi->uuid = ai->tid;

    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out;
    }

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
        xfree(hmr.data);
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

int xtable_sdel(struct amc_index *ai, struct iovec **iov, int *nr,
                struct xnet_msg *msg)
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

    hi->flag = INDEX_UNLINK | INDEX_KV;
    /* Set the string kv flag and the length to hi->uuid! */
    hi->kvflag = HVFS_KV_STR;
    hi->uuid = ai->tid;

    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out;
    }

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

int xtable_supdate(struct amc_index *ai, struct iovec **iov, int *nr,
                   struct xnet_msg *msg)
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

    hi->flag = INDEX_MDU_UPDATE | INDEX_KV;

    /* Note that in KVS mode, we do support column access, max column is
     * 2^12 - 1 */
    if (ai->column > HVFS_KV_MAX_COLUMN) {
        hvfs_err(mds, "Column number %d is too large.\n", ai->column);
        err = -EINVAL;
        goto out_hi;
    } else if (ai->column > XTABLE_INDIRECT_COLUMN) {
        hi->flag |= INDEX_COLUMN;
        /* column is ZERO */
    } else if (ai->column) {
        /* the 0th column default attached to the ITE */
        hi->flag |= INDEX_COLUMN;
        hi->kvflag = ai->column;
    }

    /* Set the string kv flag and the length to hi->uuid! */
    hi->kvflag |= HVFS_KV_STR;
    hi->uuid = ai->tid;

    hi->namelen = ai->dlen;
    hi->hash = ai->key;
    hi->itbid = ai->sid;
    hi->puuid = ai->ptid;
    hi->psalt = ai->psalt;
    hi->data = ai->data;

    /* last second checking */
    err = __xtable_adjust_itbid(hi, msg);
    if (err) {
        if (err != -EFWD)
            hvfs_err(xnet, "adjust itbid %ld failed w/ %d\n", 
                     hi->itbid, err);
        goto out_hi;
    }

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
out_hi:
    xfree(hi);

    return err;
}

int xtable_scupdate(struct amc_index *ai, struct iovec **iov, int *nr,
                    struct xnet_msg *msg)
{
    return xtable_supdate(ai, iov, nr, msg);
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

    switch (ai->op) {
    case INDEX_PUT:
        err = xtable_put(ai, &iov, &nr, msg);
        break;
    case INDEX_SPUT:
        err = xtable_sput(ai, &iov, &nr, msg);
        break;
    case INDEX_GET:
        err = xtable_get(ai, &iov, &nr, msg);
        break;
    case INDEX_SGET:
        err = xtable_sget(ai, &iov, &nr, msg);
        break;
    case INDEX_DEL:
        err = xtable_del(ai, &iov, &nr, msg);
        break;
    case INDEX_SDEL:
        err = xtable_sdel(ai, &iov, &nr, msg);
        break;
    case INDEX_UPDATE:
        err = xtable_update(ai, &iov, &nr, msg);
        break;
    case INDEX_SUPDATE:
        err = xtable_supdate(ai, &iov, &nr, msg);
        break;
    case INDEX_CUPDATE:
        err = xtable_cupdate(ai, &iov, &nr, msg);
        break;
    case INDEX_SCUPDATE:
        err = xtable_scupdate(ai, &iov, &nr, msg);
        break;
    case INDEX_COMMIT:
        err = xtable_commit(ai, &iov, &nr, msg);
        break;
    default:
        err = -EINVAL;
    }

send_rpy:
    if (err != -EFWD)
        xtable_send_reply(msg, iov, nr, err);

    /* free the resources */
    xfree(iov);

    xnet_free_msg(msg);
}
