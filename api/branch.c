/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-27 23:42:27 macan>
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
#include "branch.h"

#define BRANCH_HT_DEFAULT_SIZE          (1024)

struct branch_mgr
{
    struct regular_hash *bht;
    int hsize;
    atomic_t asize;
#define BRANCH_MGR_DEFAULT_BTO          (600) /* ten minutes */
    int bto;                    /* branch entry timeout value */
    /* the following region is the branch memory table */
#define BRANCH_MGR_DEFAULT_MEMLIMIT     (64 * 1024 * 1024)
    u64 memlimit;
};

struct branch_entry
{
    struct hlist_node hlist;
    struct branch_header *bh;
    char *branch_name;
    time_t update;
    atomic_t ref;
    xlock_t lock;
    /* region for branch lines */
    struct list_head primary_lines;
    struct list_head replica_lines;
    off_t ckpt_foffset;         /* checkpoint file offset */
    int ckpt_nr;                /* # of ckpted BL */
#define BE_FREE         0x00
#define BE_SENDING      0x01    /* only one thread can sending */
    u32 state;                  /* state protected by lock */
};

struct branch_line
{
    struct list_head list;
    u64 sites[16];              /* we support at most 16 replicas */
    time_t life;                /* when this bl comes in */
    u64 id;                     /* howto get a unique id? I think hmi.mi_tx is
                                 * a monotonous increasing value */
    char *tag;
    void *data;
    size_t data_len;

#define BL_NEW          0x00
#define BL_SENT         0x01
#define BL_ACKED        0x02
#define BL_STATE_MASK   0x0f
#define BL_CKPTED       0x80
    u8 state;

#define BL_PRIMARY      0x00
#define BL_REPLICA      0x01
    u8 position;
    u8 replica_nr;
#define BL_SELF_SITE(bl)    (bl)->sites[0]
};

static inline
u64 BRANCH_GET_ID(void)
{
    return atomic64_inc_return(&hmi.mi_bid);
}

static inline
int BL_IS_CKPTED(struct branch_line *bl)
{
    return (bl->state & BL_CKPTED);
}

#define BL_SET_CKPTED(bl) do {                  \
        (bl)->state |= BL_CKPTED;               \
    } while (0)

struct branch_line_disk
{
    /* branch line must be the first field */
    struct branch_line bl;
    int tag_len;
    int name_len;
    u8 data[0];
};

struct branch_line_push_header
{
    int name_len;               /* length of branch name */
    int nr;                     /* # of branch line in this packet */
};

struct branch_line_ack_header
{
    int name_len;               /* length of branch name */
};

struct branch_mgr bmgr;

static inline
u32 __branch_hash(char *str, u32 len)
{
    return JSHash(str, len) % bmgr.hsize;
}


static 
void __branch_err_reply(struct xnet_msg *msg, int err)
{
    struct xnet_msg *rpy;

    rpy = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!rpy) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        /* do not retry myself */
        return;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(rpy, &rpy->tx, sizeof(rpy->tx));
#endif
    xnet_msg_set_err(rpy, err);
    xnet_msg_fill_tx(rpy, XNET_MSG_RPY, 0, hmo.site_id,
                     msg->tx.ssite_id);
    xnet_msg_fill_reqno(rpy, msg->tx.reqno);
    xnet_msg_fill_cmd(rpy, XNET_RPY_ACK, 0, 0);
    /* match the original request at the source site */
    rpy->tx.handle = msg->tx.handle;

    if (xnet_send(hmo.xc, rpy)) {
        hvfs_err(xnet, "xnet_send() failed\n");
        /* do not retry my self */
    }
    xnet_free_msg(rpy);
}

int branch_init(int hsize, int bto, u64 memlimit)
{
    int err = 0, i;

    /* regular hash init */
    hsize = (hsize == 0) ? BRANCH_HT_DEFAULT_SIZE : hsize;
    bmgr.bht = xzalloc(hsize * sizeof(struct regular_hash));
    if (!bmgr.bht) {
        hvfs_err(xnet, "BRANCH hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < hsize; i++) {
        INIT_HLIST_HEAD(&bmgr.bht[i].h);
        xlock_init(&bmgr.bht[i].lock);
    }
    bmgr.hsize = hsize;

    atomic_set(&bmgr.asize, 0);
    if (bto)
        bmgr.bto = bto;
    else
        bmgr.bto = BRANCH_MGR_DEFAULT_BTO;
    if (memlimit)
        bmgr.memlimit = memlimit;
    else
        bmgr.memlimit = BRANCH_MGR_DEFAULT_MEMLIMIT;
    
out:
    return err;
}

void branch_destroy(void)
{
    if (bmgr.bht)
        xfree(bmgr.bht);
}

int __branch_insert(char *branch_name, struct branch_header *bh)
{
    struct regular_hash *rh;
    struct branch_entry *be, *tpos;
    struct hlist_node *pos;
    int i;

    i = __branch_hash(branch_name, strlen(branch_name));
    rh = bmgr.bht + i;

    be = xzalloc(sizeof(struct branch_entry));
    if (unlikely(!be))
        return -ENOMEM;

    INIT_HLIST_NODE(&be->hlist);
    INIT_LIST_HEAD(&be->primary_lines);
    INIT_LIST_HEAD(&be->replica_lines);
    atomic_set(&be->ref, 0);
    xlock_init(&be->lock);
    be->branch_name = strdup(branch_name);
    be->update = time(NULL);
    be->bh = bh;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (strlen(branch_name) == strlen(tpos->branch_name) &&
            memcmp(tpos->branch_name, branch_name, 
                   strlen(branch_name))) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&be->hlist, &rh->h);
    xlock_unlock(&rh->lock);

    if (i) {
        xfree(be);
        return -EEXIST;
    }
    atomic_inc(&bmgr.asize);
    
    return 0;
}

int __branch_remove(char *branch_name)
{
    struct regular_hash *rh;
    struct branch_entry *tpos;
    struct hlist_node *pos, *n;
    int i;

    /* wait for the last reference */
    i = __branch_hash(branch_name, strlen(branch_name));
    rh = bmgr.bht + i;

retry:
    xlock_lock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (strlen(branch_name) == strlen(tpos->branch_name) &&
            memcmp(tpos->branch_name, branch_name,
                   strlen(branch_name))) {
            if (atomic_read(&tpos->ref) > 1) {
                xlock_unlock(&rh->lock);
                /* not in the hot path, we can sleep longer */
                xsleep(1000);
                goto retry;
            }
            hlist_del(&tpos->hlist);
            xfree(tpos);
            atomic_dec(&bmgr.asize);
            break;
        }
    }
    xlock_unlock(&rh->lock);
    
    return 0;
}

/* Note, you have to call __branch_put() to release the reference
 */
struct branch_entry *__branch_lookup(char *branch_name)
{
    struct branch_entry *be = NULL;
    struct regular_hash *rh;
    struct hlist_node *pos;
    int i, len;

    len = strlen(branch_name);
    i = __branch_hash(branch_name, len);
    rh = bmgr.bht + i;

    i = 0;
    xlock_lock(&rh->lock);
    hlist_for_each_entry(be, pos, &rh->h, hlist) {
        if (strlen(be->branch_name) == len &&
            memcmp(be->branch_name, branch_name, len)) {
            atomic_inc(&be->ref);
            i = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);
    if (!i)
        be = NULL;

    return be;
}

void branch_put(struct branch_entry *be)
{
    atomic_dec(&be->ref);
}

/* Note, you have to call branch_put to release the reference
 */
struct branch_entry *branch_lookup_load(char *branch_name)
{
    struct branch_entry *be;
    int err = 0;

retry:
    be = __branch_lookup(branch_name);
    if (!be) {
        /* ok, we should load the bh now */
        err = branch_load(branch_name, "");
        if (!err || err == -EEXIST) {
            goto retry;
        } else {
            hvfs_err(xnet, "Load branch '%s' failed w/ %d\n",
                     branch_name, err);
            return ERR_PTR(err);
        }
    }

    return be;
}

int __branch_destroy(struct branch_entry *be)
{
    int err = 0;
    
    if (atomic_read(&be->ref) > 0) {
        return -EBUSY;
    }

    xlock_lock(&be->lock);
    if (list_empty(&be->primary_lines) && 
        list_empty(&be->replica_lines)) {
        /* it is ok to free this entry now */
        xfree(be->bh);
    } else {
        err = -EBUSY;
    }
    xlock_unlock(&be->lock);

    return err;
}

int branch_cleanup(time_t cur)
{
    struct regular_hash *rh;
    struct branch_entry *tpos;
    struct hlist_node *pos, *n;
    int i, err = 0;

    for (i = 0; i < bmgr.hsize; i++) {
        rh = bmgr.bht + i;
        xlock_lock(&rh->lock);
        hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
            if (tpos->update - cur > bmgr.bto) {
                hlist_del(&tpos->hlist);
                err = __branch_destroy(tpos);
                if (!err) {
                    xfree(tpos->branch_name);
                    xfree(tpos);
                    atomic_dec(&bmgr.asize);
                } else {
                    hvfs_err(xnet, "Branch '%s' lingering too long\n",
                             tpos->branch_name);
                }
            }
        }
        xlock_unlock(&rh->lock);
    }
    
    return 0;
}

static inline
struct xnet_group *__get_active_site(struct chring *r)
{
    struct xnet_group *xg = NULL;
    int i, err;

    for (i = 0; i < r->used; i++) {
        err = xnet_group_add(&xg, r->array[i].site_id);
    }

    return xg;
}

u64 __branch_get_replica(u64 *sg, int nr)
{
    struct xnet_group *xg;
    u64 dsite = -1UL;
    int i, j;
    
    /* get another site other than current site group */
    xg = __get_active_site(hmo.chring[CH_RING_MDS]);
    if (!xg) {
        /* oh, there is no active site now, failed myself */
        return -1UL;
    }

    if (nr + 1 >= xg->asize) {
        /* this means that active replica set is larger than active site
         * group, thus we just reject this requst */
        xfree(xg);
        return -1UL;
    }

reselect:
    i = lib_random(xg->asize);
    for (j = 0; j < nr; j++) {
        if (xg->sites[i].site_id == *(sg + j)) {
            /* conflict, reselect */
            goto reselect;
        }
    }
    dsite = xg->sites[i].site_id;
    xfree(xg);

    return dsite;
}

int __branch_replicate(struct branch_entry *be,
                       struct branch_line *bl, u64 dsite)
{
    struct xnet_msg *msg;
    struct branch_line_disk bld = {
        .bl = *bl,
    };
    int err = 0;

    /* setup the rest bld fields */
    if (bl->tag)
        bld.tag_len = strlen(bl->tag);
    else
        bld.tag_len = 0;
    bld.name_len = strlen(be->branch_name);
    
    bld.bl.position = BL_REPLICA;
    
    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_REPLICA,
                      0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &bld, sizeof(bld));
    if (bld.name_len)
        xnet_msg_add_sdata(msg, be->branch_name, bld.name_len);
    if (bld.tag_len)
        xnet_msg_add_sdata(msg, bl->tag, bld.tag_len);
    if (bl->data_len)
        xnet_msg_add_sdata(msg, bl->data, bl->data_len);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() REPLICA '%s' id:%ld to %lx "
                 "failed w/ %d\n",
                 be->branch_name, bl->id, dsite, err);
        goto out_free;
    }

out_free:
    xnet_free_msg(msg);
    
out:
    return err;
}

int __branch_do_replicate(struct xnet_msg *msg, 
                          struct branch_line_disk *bld)
{
    char *branch_name, *tag_name, *p;
    struct branch_entry *be;
    struct branch_line *bl;
    int err = 0;


    bl = &bld->bl;
    bl->life = time(NULL);
    
    branch_name = xzalloc(bld->name_len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }
    tag_name = xzalloc(bld->tag_len + 1);
    if (!tag_name) {
        hvfs_err(xnet, "xzalloc() tag failed\n");
        xfree(branch_name);
        return -ENOMEM;
    }

    p = (void *)bld + sizeof(*bld);
    memcpy(branch_name, p, bld->name_len);
    p += bld->name_len;
    memcpy(tag_name, p, bld->tag_len);
    p += bld->tag_len;

    /* re-init the branch line */
    INIT_LIST_HEAD(&bl->list);
    bl->tag = tag_name;
    bl->data = p;
    bl->position = BL_REPLICA;

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }

    /* add to the replica list */
    xlock_lock(&be->lock);
    list_add_tail(&bl->list, &be->replica_lines);
    xlock_unlock(&be->lock);

    branch_put(be);

    /* finally, send the reply now */
    __branch_err_reply(msg, 0);
    
out:
    xfree(branch_name);
    
    return err;
out_free:
    xfree(branch_name);
    xfree(tag_name);
    goto out;
}

/* __branch_push() will modify the bl->state. It is our's responsibility to
 * transfer the bl->state to BL_SENT.
 */
int __branch_push(struct branch_entry *be,
                  struct branch_line *bl, u64 dsite)
{
    struct xnet_msg *msg;
    struct branch_line_disk bld = {
        .bl = *bl,
    };
    int err = 0;

    /* check if there is another thread sending */
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        /* another thread is sending, give up */
        err = -EBUSY;
        goto out;
    } else {
        be->state = BE_SENDING;
    }

    /* setup the rest bld fields */
    if (bl->tag)
        bld.tag_len = strlen(bl->tag);
    else
        bld.tag_len = 0;
    bld.name_len = strlen(be->branch_name);

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                     hmo.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, BRANCH_CMD_PUSH,
                      0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_add_sdata(msg, &bld, sizeof(bld));
    if (bld.name_len)
        xnet_msg_add_sdata(msg, be->branch_name, bld.name_len);
    if (bld.tag_len)
        xnet_msg_add_sdata(msg, bl->tag, bld.tag_len);
    if (bld.bl.data_len)
        xnet_msg_add_sdata(msg, bl->data, bl->data_len);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(xnet, "xnet_send() PUSH '%s' id %ld to %lx "
                 "failed w/ %d\n",
                 be->branch_name, bl->id, dsite, err);
        goto out_free;
    }

    /* change bl->state to BL_SENT */
    xlock_lock(&be->lock);
    if ((bl->state & BL_STATE_MASK) == BL_NEW) {
        bl->state |= BL_SENT;
    }
    xlock_unlock(&be->lock);

out_free:
    xnet_free_msg(msg);

out:
    return err;
}

static inline
int __branch_pack_bulk_push_header(struct xnet_msg *msg,
                                   struct branch_entry *be,
                                   struct branch_line_push_header *blph,
                                   int nr)
{
    blph->name_len = strlen(be->branch_name);
    blph->nr = nr;

    xnet_msg_add_sdata(msg, blph, sizeof(*blph));
    if (blph->name_len)
        xnet_msg_add_sdata(msg, be->branch_name, blph->name_len);

    return 0;
}

static inline
int __branch_pack_msg(struct xnet_msg *msg, 
                      struct branch_line_disk *bld,
                      struct branch_line *bl)
{
    bld->bl = *bl;
    if (bl->tag)
        bld->tag_len = strlen(bl->tag);
    bld->name_len = 0;
    
    xnet_msg_add_sdata(msg, bld, sizeof(*bld));
    if (bld->tag_len)
        xnet_msg_add_sdata(msg, bl->tag, bld->tag_len);
    if (bl->data_len)
        xnet_msg_add_sdata(msg, bl->data, bl->data_len);

    return 0;
}

/* __branch_bulk_push() try to send more branch_lines as a whole
 *
 */
int __branch_bulk_push(struct branch_entry *be, u64 dsite)
{
    struct branch_line *bl, *start_bl = NULL;
    int nr = 0, err = 0;
    
    /* calculate how many branch entry we can send */
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        /* another thread is sending, give up */
        err = -EBUSY;
    } else {
        list_for_each_entry(bl, &be->primary_lines, list) {
            if (bl->state == BL_NEW) {
                if (nr == 0) {
                    start_bl = bl;
                }
                nr++;
            } else {
                if (nr > 0) {
                    hvfs_err(xnet, "Fatal error, unordered sending?\n");
                    err = -EFAULT;
                    break;
                }
            }
        }
        if (nr > 0)
            be->state = BE_SENDING;
    }
    xlock_unlock(&be->lock);

    if (!err && nr > 0) {
        /* we have got the # of branch lines, let us construct a buge message
         * and send it to the final location */
        /* Step 1: adjust the nr to a proper value */
        struct xnet_msg *msg;
        struct branch_line_disk *bld_array;
        struct branch_line_push_header blph;
        int max = (g_xnet_conf.siov_nr - 3) / 3;

        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(xnet, "xnet_alloc_msg() failed\n");
            err = -ENOMEM;
            goto exit_to_free;
        }
#ifdef XNET_EAGER_WRITEV
        xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                         hmo.xc->site_id, dsite);
        xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH, 
                          BRANCH_CMD_BULK_PUSH, 0);
        
        nr = min(max, nr);
        max = nr;
        bld_array = xzalloc(nr * sizeof(*bld_array));
        if (!bld_array) {
            hvfs_err(xnet, "xzalloc() bld array failed\n");
            err = -ENOMEM;
            goto out_free_msg;
        }
        
        err = __branch_pack_bulk_push_header(msg, be, &blph, nr);
        if (err) {
            hvfs_err(xnet, "pack bulk push header for '%s' "
                     "failed /w/ %d\n",
                     be->branch_name, err);
            xfree(bld_array);
            goto out_free_msg;
        }

        ASSERT(start_bl, xnet);
        bl = start_bl;
        while (nr-- > 0) {
            err = __branch_pack_msg(msg, bld_array + nr, bl);
            bl = list_entry(bl->list.next, struct branch_line, 
                            list);
        }

        /* Step 2: do sending now */
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(xnet, "xnet_send() BULK PUSH '%s' nr %d to "
                     "%lx failed w/ %d\n",
                     be->branch_name, max, dsite, err);
            /* just fallback */
        }
        
        xfree(bld_array);
    out_free_msg:
        xnet_free_msg(msg);

        /* Step 3: on receiving the reply, we set the bl->state to SENT. need
         * be->lock */
        bl = start_bl;
        xlock_lock(&be->lock);
        while (max-- > 0) {
            ASSERT((bl->state & BL_STATE_MASK) == BL_NEW, xnet);
            bl->state |= BL_SENT;
            bl = list_entry(bl->list.next, struct branch_line,
                            list);
        }
        xlock_unlock(&be->lock);
        
        /* Step 4: finally, we change be->state to FREE */
    exit_to_free:
        xlock_lock(&be->lock);
        be->state = BE_FREE;
        xlock_unlock(&be->lock);
    }

    return err;
}

int __branch_line_bcast_ack(char *branch_name, u64 ack_id, 
                            struct xnet_group *xg)
{
    struct xnet_msg *msg;
    int err = 0, i;

    msg = xnet_alloc_msg(XNET_MSG_NORMAL);
    if (!msg) {
        hvfs_err(xnet, "xnet_alloc_msg() failed\n");
        return -ENOMEM;
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_BRANCH,
                      BRANCH_CMD_ACK_REPLICA, ack_id);
    xnet_msg_add_sdata(msg, branch_name, strlen(branch_name));
    
    for (i = 0; i < xg->asize; i++) {
        xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_REPLY,
                         hmo.xc->site_id, xg->sites[i].site_id);
        err = xnet_send(hmo.xc, msg);
        if (err) {
            hvfs_err(xnet, "xnet_send() ACK REPLICA '%s' %ld "
                     "failed w/ %d\n", 
                     branch_name, ack_id, err);
            /* ignore errors */
        }
        /* FIXME: should we chech the reply stat of replica? */
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
    }

    xnet_free_msg(msg);

    return 0;
}

int __branch_do_ack_replica(struct xnet_msg *msg)
{
    struct branch_entry *be;
    struct branch_line *bl, *n;
    char *branch_name;
    int err = 0;

    branch_name = xzalloc(msg->tx.len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }
    memcpy(branch_name, msg->xm_data, msg->tx.len);

    /* find the be and update the replica lines */
    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }

retry:
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        xlock_unlock(&be->lock);
        sleep(1);
        goto retry;
    }
    list_for_each_entry_safe(bl, n, &be->replica_lines, list) {
        if (bl->id <= msg->tx.arg1) {
            /* remove it */
            list_del(&bl->list);
            xfree(bl->tag);
            /* there is no need to free bl->data */
            xfree(bl);
        } else {
            /* already passed, do nothing and break */
            break;
        }
    }
    xlock_unlock(&be->lock);

    branch_put(be);

    /* finally, we send the reply now */
    __branch_err_reply(msg, 0);
    
out_free:
    xfree(branch_name);
    
    return err;
}

int __branch_do_ack(struct xnet_msg *msg,
                    struct branch_line_ack_header *blah)
{
    struct branch_entry *be;
    struct branch_line *bl, *n;
    struct xnet_group *xg = NULL;
    struct list_head ack_bcast;
    char *branch_name;
    u64 *ack_id;
    int err = 0, i;

    branch_name = xzalloc(blah->name_len + 1);
    if (!branch_name) {
        hvfs_err(xnet, "xzalloc() branch name failed\n");
        return -ENOMEM;
    }

    ack_id = (void *)blah + sizeof(*blah) + blah->name_len;

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        err = PTR_ERR(be);
        goto out_free;
    }

    /* Note that, we know the ACK is accumulative */
retry:
    xlock_lock(&be->lock);
    if (be->state == BE_SENDING) {
        xlock_unlock(&be->lock);
        sleep(1);
        goto retry;
    }
    list_for_each_entry_safe(bl, n, &be->primary_lines, list) {
        if (bl->id <= *ack_id) {
            if ((bl->state & BL_STATE_MASK) == BL_SENT) {
                /* we can remove it now */
                list_del_init(&bl->list);
                list_add_tail(&bl->list, &ack_bcast);
            } else if ((bl->state & BL_STATE_MASK) == BL_NEW) {
                hvfs_err(xnet, "ACK a NEW state line %ld ACK %ld\n",
                         bl->id, *ack_id);
            } else {
                /* ACKed state ? remove it now */
                list_del_init(&bl->list);
                list_add_tail(&bl->list, &ack_bcast);
            }
            if (bl->id == *ack_id) {
                break;
            }
        } else {
            /* already passed, do nothing and break */
            break;
        }
    }
    xlock_unlock(&be->lock);
    
    branch_put(be);

    /* we have got a bcast list, then we do bcast */
    list_for_each_entry_safe(bl, n, &ack_bcast, list) {
        for (i = 1; i < bl->replica_nr; i++) {
            err = xnet_group_add(&xg, bl->sites[i]);
        }
        list_del(&bl->list);
        xfree(bl->tag);
        xfree(bl->data);
        xfree(bl);
    }
    
    err = __branch_line_bcast_ack(branch_name, *ack_id, xg);
    if (err) {
        hvfs_err(xnet, "bcast ACK %ld to many sites failed w/ %d\n",
                 *ack_id, err);
        /* ignore the error */
    }
    
    /* finally, send the reply now */
    __branch_err_reply(msg, 0);
    
out_free:
    xfree(branch_name);
    
    return err;
}

/* branch_dispatch() act on the incomming message
 *
 * ABI:
 * @tx.arg0: branch operations
 */
int branch_dispatch(void *arg)
{
    struct xnet_msg *msg = (struct xnet_msg *)arg;
    int err = 0;

    switch (msg->tx.arg0) {
    case BRANCH_CMD_NOPE:
        break;
    case BRANCH_CMD_PUSH:
    {
        /* oh, this must be the process node */
        
        break;
    }
    case BRANCH_CMD_PULL:
    {
        /* pull command is just a reserved cmd */
        break;
    }
    case BRANCH_CMD_ACK:
    {
        struct branch_line_ack_header *blah;

        if (msg->xm_datacheck) {
            blah = (struct branch_line_ack_header *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid ACK request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        
        err = __branch_do_ack(msg, blah);
        if (err) {
            hvfs_err(xnet, "Self do ack <%lx> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_REPLICA:
    {
        struct branch_line_disk *bld;

        if (msg->xm_datacheck) {
            bld = (struct branch_line_disk *)msg->xm_data;
        } else {
            hvfs_err(xnet, "Invalid REPLICA request from %lx\n", 
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        
        err = __branch_do_replicate(msg, bld);
        if (err) {
            hvfs_err(xnet, "Self do replicate <%lx,%ld> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, bld->bl.id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    case BRANCH_CMD_ACK_REPLICA:
    {
        if (!msg->xm_datacheck) {
            hvfs_err(xnet, "Invalid REPLICA ACK request from %lx\n",
                     msg->tx.ssite_id);
            err = -EINVAL;
            __branch_err_reply(msg, err);
            goto out;
        }
        err = __branch_do_ack_replica(msg);
        if (err) {
            hvfs_err(xnet, "Self do ACK REPLICA <%lx> "
                     "failed w/ %d\n",
                     msg->tx.ssite_id, err);
            __branch_err_reply(msg, err);
        }
        break;
    }
    default:
        hvfs_err(xnet, "Invalid branch operations %ld from %lx\n",
                 msg->tx.arg0, msg->tx.ssite_id);
        err = -EINVAL;
        __branch_err_reply(msg, err);
    }

    xnet_free_msg(msg);
out:    
    return err;
}

/* branch_create()
 *
 * Create a new branch named 'branch_name' with a tag 'tag'. The new branch
 * select one primary server as the merging server. All the published
 * infomation are transfered to the primary server. At the primary server,
 * each item is processed with the predefined operations.
 *
 * The metadata of each branch is saved in the /.branches directory. Each site
 * can issue queries to fetch the metadata. All the streamed-in info are saved
 * to disk file as the first step. And then processed with the pre-defined
 * operations. Thus, the primary server should co-located at a MDSL server.
 */
int branch_create(u64 puuid, u64 uuid, char *branch_name, 
                  char *tag, u8 level, struct branch_ops * ops)
{
    struct hstat hs;
    struct branch_header *bh;
    u64 buuid, bsalt;
    void *offset;
    int dlen, nr, i;
    int err = 0;

    /* All the branches are in the same namespace, thus, you can't create
     * duplicated branches. */

    /* Step 0: arg checking */
    if (!tag || !strlen(tag) || strlen(tag) > 32)
        return -EINVAL;
    
    /* Step 1: check if this branch has already existed. */
relookup:
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = __hvfs_stat(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err == -ENOENT) {
        void *data;
        
        hvfs_err(xnet, "Stat root branches failed, we make it!\n");
        /* make the dir now */
        err = hvfs_create("/", ".branches", &data, 1);
        if (err) {
            hvfs_err(xnet, "Create root branches failed w/ %d\n", err);
            goto out;
        }
        hvfs_free(data);
        goto relookup;
    } else if (err) {
        hvfs_err(xnet, "Stat roto branches failed w/ %d\n", err);
        goto out;
    }

    /* stat the GDT to find the salt */
    hs.hash = 0;
    err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                 "failed w/ %d\n", err);
        goto out;
    }

    /* Step 2: create the new branch by touch a new file in /.branches. */
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.name = branch_name;
    err = __hvfs_create(buuid, bsalt, &hs, 0, NULL);
    if (err) {
        hvfs_err(xnet, "Create branch '%s' failed w/ %s(%d)\n",
                 branch_name, strerror(-err), err);
        goto out;
    }

    /* Step 3: save the branch ops in the new branch file */
    /* calculate the file content length */
    if (!ops || !ops->nr) {
        dlen = 0;
        nr = 0;
    } else {
        dlen = 0;
        for (i = 0; i < ops->nr; i++) {
            dlen += ops->ops[i].len;
        }
        nr = ops->nr;
    }

    /* alloc the content buffer */
    bh = xmalloc(sizeof(*bh) + nr * sizeof(struct branch_op) +
                 dlen);
    if (!bh) {
        hvfs_err(xnet, "alloc the content buffer failed.\n");
        goto out;
    }

    /* Use the puuuid, uuid and tag to track the items flowing in */
    memset(bh, 0, sizeof(*bh));
    bh->puuid = puuid;
    bh->uuid = uuid;
    memcpy(bh->tag, tag, strlen(tag));
    bh->level = level;
    bh->ops.nr = nr;

    offset = (void *)bh + sizeof(*bh) + 
        nr * sizeof(struct branch_op);
    for (i = 0; i < nr; i++) {
        bh->ops.ops[i] = ops->ops[i];
        memcpy(offset, ops->ops[i].data, ops->ops[i].len);
        offset += ops->ops[i].len;
    }

    /* calculate which itbid we should stored it in */
    hs.hash = hvfs_hash(hs.puuid, (u64)hs.name, strlen(hs.name),
                        HASH_SEL_EH);
    {
        struct dhe *e;

        e = mds_dh_search(&hmo.dh, hs.puuid);
        if (IS_ERR(e)) {
            hvfs_err(xnet, "mds_dh_search() failed w/ %ld\n",
                     PTR_ERR(e));
            err = PTR_ERR(e);
            xfree(bh);
            goto out;
        }
        hs.hash = mds_get_itbid(e, hs.hash);
        mds_dh_put(e);
    }

    /* do the write now! */
    err = __hvfs_fwrite(&hs, 0, bh, sizeof(*bh) + 
                        nr * sizeof(struct branch_op) + dlen, 
                        &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "write the branch file %s failed w/ %d\n",
                 branch_name, err);
        xfree(bh);
        goto out;
    }

    xfree(bh);
    /* finally, update the metadata */
    {
        struct mdu_update *mu;

        mu = xzalloc(sizeof(*mu) + sizeof(struct mu_column));
        if (!mu) {
            hvfs_err(xnet, "xzalloc() mdu_update failed\n");
            err = -ENOMEM;
            goto out;
        }
        mu->valid = MU_COLUMN;
        mu->column_no = 1;
        hs.mc.cno = 0;

        hs.uuid = 0;
        hs.name = branch_name;
        err = __hvfs_update(hs.puuid, hs.psalt, &hs, mu);
        if (err) {
            hvfs_err(xnet, "do internal update on '%s' failed w/ %d\n",
                     branch_name, err);
            xfree(mu);
            goto out;
        }
        xfree(mu);
    }

out:
    return err;
}

/* branch_load()
 *
 * Load a branch metadata to current site. This operation is always called on
 * MDSs (and the targe MDSL). Based on the metadata, the MDSs can determine
 * the final location of the BRANCH (through itbid). While, MDSs can even do
 * the middle data pre-processing either (through branch_ops).
 *
 * Also note that, all the MDSs can NOT modify the branch metadata themselves.
 *
 * Note, the new BH is inserted to the hash table w/ a BE, you have to do one
 * more lookup to find it.
 */
int branch_load(char *branch_name, char *tag)
{
    struct hstat hs;
    struct branch_header *bh;
    u64 buuid, bsalt;
    int err = 0;

    if (!branch_name)
        return -EINVAL;

    /* Step 1: find the root branch dir */
    memset(&hs, 0, sizeof(hs));
    hs.name = ".branches";
    hs.puuid = hmi.root_uuid;
    hs.psalt = hmi.root_salt;

    err = __hvfs_stat(hmi.root_uuid, hmi.root_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "Root branche does not exist, w/ %d\n",
                 err);
        goto out;
    }
    hs.hash = 0;
    err = __hvfs_stat(hmi.gdt_uuid, hmi.gdt_salt, -1, &hs);
    if (err) {
        hvfs_err(xnet, "do internal dir stat (GDT) on root branch "
                 "failed w/ %d\n", err);
        goto out;
    }

    /* Step 2: find the branch now */
    buuid = hs.uuid;
    bsalt = hs.ssalt;
    memset(&hs, 0, sizeof(hs));
    hs.puuid = buuid;
    hs.psalt = bsalt;
    hs.name = branch_name;
    err = __hvfs_stat(buuid, bsalt, 0, &hs);
    if (err) {
        hvfs_err(xnet, "do internal file stat (SDT) on branch '%s'"
                 " failed w/ %d\n", branch_name, err);
        goto out;
    }

    /* Step 3: read in the branch data content */
    err = __hvfs_fread(&hs, 0, (void *)&bh, &hs.mc.c);
    if (err) {
        hvfs_err(xnet, "read the branch '%s' failed w/ %d\n",
                 branch_name, err);
        goto out;
    }
    /* fix the data pointer in branch_ops */
    if (bh->ops.nr) {
        void *offset = (void *)bh + sizeof(*bh) + bh->ops.nr *
            sizeof(struct branch_op);
        int i;
        for (i = 0; i < bh->ops.nr; i++) {
            bh->ops.ops[i].data = offset;
            offset += bh->ops.ops[i].len;
        }
    }
    
    /* Step 4: register the loaded-in branch to memory hash table */
    err = __branch_insert(branch_name, bh);
    if (err) {
        hvfs_err(xnet, "add branch to hash table failed w/ %d\n",
                 err);
        xfree(bh);
        goto out;
    }

out:
    return err;
}

/* branch_publish() publish one branch line.
 *
 * Note, the caller should alloc the data region and do NOT free it
 *
 * Level will be satisfied with our best effort. Thus, if there is at least
 * one another replica has saved the branch line, we will return success
 * without considering the #N assigned in LEVEL. For example, you can only
 * have 2 replicas even if you have set the fanout factor to 3.
 */
int branch_publish(u64 puuid, u64 uuid, char *branch_name,
                   char *tag, u8 level, void *data, 
                   size_t data_len)
{
    struct branch_line *bl;
    struct branch_entry *be;
    int err = 0;

    bl = xzalloc(sizeof(*bl));
    if (!bl) {
        hvfs_err(xnet, "xzalloc() branch_line failed\n");
        return -ENOMEM;
    }

    /* construct the branch_line and add it to the memory hash table */
    bl->life = time(NULL);
    INIT_LIST_HEAD(&bl->list);
    bl->data = data;
    bl->data_len = data_len;
    /* get the global unique id */
    bl->id = BRANCH_GET_ID();
    if (tag)
        bl->tag = strdup(tag);

    be = branch_lookup_load(branch_name);
    if (IS_ERR(be)) {
        xfree(bl);
        err = PTR_ERR(be);
        goto out;
    }
    /* fallback to default level */
    if (!level)
        level = be->bh->level;

    if ((level & BRANCH_LEVEL_MASK) == BRANCH_FAST) {
        /* it is ok to continue */
        ;
    } else {
        u64 dsite;
        int i, nr = 0;
        
        /* oh, we should transfer the branch_line to other sites */
        bl->replica_nr = level & BRANCH_NR_MASK;
        if (!bl->replica_nr) {
            /* adjust to 1 */
            bl->replica_nr = 1;
        }
        BL_SELF_SITE(bl) = hmo.site_id;
        
        for (i = 1; i < bl->replica_nr; i++) {
            /* find a target site to replicate */
            dsite = __branch_get_replica(bl->sites, i);
            if (dsite == -1UL) {
                bl->sites[i] = -1UL;
                continue;
            }
            /* send the branch_line to replicas */
            err = __branch_replicate(be, bl, dsite);
            if (err) {
                hvfs_err(xnet, "Replicate BL %ld to site %lx "
                         "failed w/ %d\n", bl->id, dsite, err);
                bl->sites[i] = -1UL;
            } else
                bl->sites[i] = dsite;
        }
        /* recalculate how many sites we have sent */
        for (i = 0; i < bl->replica_nr; i++) {
            if (bl->sites[i] != -1UL)
                nr++;
        }
        if (nr == 1 && bl->replica_nr > 1) {
            /* this means we degrade to the FAST mode, reject this publishment
             * now. Otherwise, even if we have degraded, we do not reject the
             * publishment, because we can not cancel the already sent BL to
             * other sites. */
            goto out_reject;
        }
    }

    /* Note that, the tid many be a little randomized, so we have to check if
     * we the max tid */
    xlock_lock(&be->lock);
    list_add_tail(&bl->list, &be->primary_lines);
    xlock_unlock(&be->lock);
    
out_put:
    branch_put(be);

out:
    return err;
out_reject:
    xfree(bl);
    err = -EFAULT;
    goto out_put;
}

int branch_subscribe(u64 puuid, u64 uuid, char *branch_name,
                     char *tag, u8 level, branch_callback_t bc)
{
    int err = 0;

    return err;
}
