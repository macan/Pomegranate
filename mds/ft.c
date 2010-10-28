/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-28 23:44:31 macan>
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

#include "ft.h"

/* FT module is embeded into the gossip thread to exchange site alive
 * information. We get all the MDS nodes from the site_table, and construct a
 * gossip table with self-suspected state.
 *
 * On starting, we have a EMPTY state table w/ all sites state as INITED. When
 * receiving a gossip message, we got a table from site X (as table_X). We
 * update ourself's state in the following maner:
 *
 *  | old_state\table_X.state |  INITED | SUSPECT | FAILED  |    OK    |
 *  |         INITED          |  INITED | SUSPECT | FAILED  |    OK    |
 *  |        SUSPECT          | SUSPECT |  FAILED | FAILED  |    OK    |
 *  |         FAILED          |  FAILED |  FAILED | FAILED  | SUSPECT  |
 *  |           OK            |    OK   |    OK   | SUSPECT |    OK    |
 *
 * If a site is considered as FAILED, ourself will report it to R2 server. And
 * if a site is repaired, R2 server will broadcast the OK(site) message to all
 * the servers.
 */

struct ft_mgr
{
#define FT_INIT         0
#define FT_RUN          1
#define FT_PAUSE        2
#define FT_STOP         3
    u32 state;
    struct xnet_group *xg;
    xlock_t lock;
    struct ft_state_machine *fsm;
};

static struct ft_mgr fm;
static struct ft_state_machine g_fsm = 
{
    .states = {
        {{FT_INITED,}, {FT_INITED,}, {FT_FAILED,}, {FT_INITED,}, {FT_INITED,},},
        {{FT_SUSPECT,}, {FT_SUSPECT, ft_notify_r2,}, {FT_FAILED,}, {FT_SUSPECT,}, {FT_SUSPECT},},
        {{FT_FAILED,}, {FT_FAILED,}, {FT_FAILED,}, {FT_SUSPECT,}, {FT_FAILED},},
        {{FT_INITED,}, {FT_INITED,}, {FT_SUSPECT,}, {FT_OK,}, {FT_OK,},},
        {{FT_REMOVED,}, {FT_REMOVED,}, {FT_REMOVED,}, {FT_REMOVED,}, {FT_REMOVED,},},
    },
};

int ft_init(int do_run)
{
    int err = 0;

    memset(&fm, 0, sizeof(fm));
    xlock_init(&fm.lock);

    /* init the state machine */
    fm.fsm = &g_fsm;

    if (do_run)
        fm.state = FT_RUN;

    return err;
}

void ft_destroy(void)
{
    /* do something ? */
}

static inline
void __ft_state_change(u64 *state, u64 ustate, u64 site)
{
    u64 ostate = *state;
    action_t action;
    int err = 0;

    action = fm.fsm->states[*state][ustate].action;
    *state = fm.fsm->states[*state][ustate].state;
    if (action) {
        err = action(ostate, ustate, *state, site);
        if (err) {
            hvfs_err(mds, "FT %lx state change from (%lx,%lx) to %lx, "
                     "action failed w/ %d\n", 
                     site, ostate, ustate, *state, err);
        }
    }
}

void ft_report(u64 site_id, u64 state)
{
    int i;

    /* pre-check the state */
    if (state >= FT_DYNAMIC) {
        hvfs_err(mds, "For security reasons, you can't use "
                 "ft_report() to set static state!\n");
        return;
    }

    /* Step 1: try to add to the group if it does not exist */
    xlock_lock(&fm.lock);
    xnet_group_add(&fm.xg, site_id);
    xlock_unlock(&fm.lock);

    /* Step 2: change the state now */
    for (i = 0; i < fm.xg->asize; i++) {
        if (site_id == fm.xg->sites[i].site_id) {
            xlock_lock(&fm.lock);
            __ft_state_change(&fm.xg->sites[i].flags, state,
                              site_id);
            xlock_unlock(&fm.lock);
        }
    }
}

void ft_set(u64 site_id, u64 state)
{
    int i;

    /* pre-check the state */
    if (state >= FT_STATE_MAX) {
        hvfs_err(mds, "Invalid state %lx\n", state);
        return;
    }

    /* Step 1: try to add to the group if it does not exist */
    xlock_lock(&fm.lock);
    xnet_group_add(&fm.xg, site_id);
    xlock_unlock(&fm.lock);

    /* Step 2: change the state now */
    for (i = 0; i < fm.xg->asize; i++) {
        if (site_id == fm.xg->sites[i].site_id) {
            xlock_lock(&fm.lock);
            fm.xg->sites[i].flags = state;
            xlock_unlock(&fm.lock);
        }
    }
}

void ft_update_active_site(struct chring *r)
{
    int i;

    if (unlikely(!r))
        return;
    
    for (i = 0; i < r->used; i++) {
        xlock_lock(&fm.lock);
        xnet_group_add(&fm.xg, r->array[i].site_id);
        xlock_unlock(&fm.lock);
    }
}

void ft_gossip_send(void)
{
    struct xnet_msg *msg;
    struct chp *p;
    u64 point;
    int err = 0;

    if (!fm.xg)
        return;
    
    msg = xnet_alloc_msg(XNET_MSG_CACHE);
    if (!msg) {
        /* retry with slow method */
        msg = xnet_alloc_msg(XNET_MSG_NORMAL);
        if (!msg) {
            hvfs_err(mds, "xnet_alloc_msg() in low memory.\n");
            return;
        }
    }

#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(msg->tx));
#endif
    xnet_msg_fill_cmd(msg, HVFS_MDS2MDS_GF, fm.xg->asize, 0);
    xnet_msg_add_sdata(msg, &fm.xg->sites, fm.xg->asize *
                       sizeof(struct xnet_group_entry));

    /* select a random site from the mds ring */
reselect:
    point = hvfs_hash(lib_random(0xfffffff),
                      lib_random(0xfffffff), 0, HASH_SEL_GDT);
    p = ring_get_point2(point, hmo.chring[CH_RING_MDS]);
    if (IS_ERR(p)) {
        hvfs_err(mds, "ring_get_point2() failed w/ %ld\n",
                 PTR_ERR(p));
        goto out_free;
    }

    if (p->site_id == hmo.xc->site_id) {
        /* self gossip? do not do it */
        goto out_free;
    }

    xnet_msg_fill_tx(msg, XNET_MSG_REQ, 0, hmo.xc->site_id,
                     p->site_id);

    err = xnet_send(hmo.xc, msg);
    if (err) {
        hvfs_err(mds, "xnet_send() failed with %d\n", err);
        ft_set(p->site_id, FT_SUSPECT);
        goto reselect;
    } else {
        ft_set(p->site_id, FT_OK);
    }

    xnet_free_msg(msg);
    return;
out_free:
    xnet_raw_free_msg(msg);
}

void ft_gossip_recv(struct xnet_msg *msg)
{
    struct xnet_group_entry *xge = NULL;
    int i;
    
    /* ABI:
     * @tx.arg0: # of xnet_group_entry
     */
    if (!msg->tx.arg0) {
        return;
    }
    if (msg->tx.arg0 * sizeof(struct xnet_group_entry) >
        msg->tx.len) {
        hvfs_warning(mds, "Lose some site ft state? "
                     "(%ld vs %d)\n",
                     msg->tx.arg0 * sizeof(struct xnet_group_entry),
                     msg->tx.len);
        goto out;
    }

    if (msg->xm_datacheck) {
        xge = (struct xnet_group_entry *)msg->xm_data;
    } else {
        hvfs_err(mds, "Internal error, data lossing...\n");
        goto out;
    }
    
    atomic64_inc(&hmo.prof.mds.gossip_ft);
    
    for (i = 0; i < msg->tx.arg0; i++) {
        ft_report((xge + i)->site_id, (xge + i)->flags);
    }
    
out:
    xnet_free_msg(msg);
}

int ft_notify_r2(u64 ostate, u64 ustate, u64 rstate, u64 site)
{
    int err = 0;

    hvfs_err(mds, "do notify r2 about site %lx is down.\n", site);
    
    return err;
}

int ft_print_state(u64 ostate, u64 ustate, u64 rstate, u64 site)
{
    hvfs_warning(mds, "FT %lx state change from (%lx,%lx) to %lx\n",
                 site, ostate, ustate, rstate);
    return 0;
}


