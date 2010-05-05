/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-05 23:17:11 macan>
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

#include "mgr.h"
#include "root.h"

int site_mgr_init(struct site_mgr *sm)
{
    int err = 0, i;
    
    if (!hro.conf.site_mgr_htsize) {
        /* default to ...SITE_MGR_HTSIZE */
        hro.conf.site_mgr_htsize = HVFS_ROOT_SITE_MGR_HTSIZE;
    }

    sm->sht = xzalloc(hro.conf.site_mgr_htsize * sizeof(struct regular_hash));
    if (!sm->sht) {
        hvfs_err(root, "xzalloc() site mgr hash table failed.\n");
        err = -ENOMEM;
        goto out;
    }

    /* init the hash table */
    for (i = 0; i < hro.conf.site_mgr_htsize; i++) {
        INIT_HLIST_HEAD(&(sm->sht + i)->h);
        xlock_init(&(sm->sht + i)->lock);
    }
    
out:
    return err;
}

void site_mgr_destroy(struct site_mgr *sm)
{
    if (sm->sht) {
        xfree(sm->sht);
    }
}

struct site_entry *site_mgr_alloc_se()
{
    struct site_entry *se;

    se = xzalloc(sizeof(*se));
    if (se) {
        INIT_HLIST_NODE(&se->hlist);
    }

    return se;
}

void site_mgr_free_se(struct site_entry *se)
{
    xfree(se);
}

struct site_entry *site_mgr_lookup(struct site_mgr *sm, u64 site_id)
{
    struct site_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx;

    idx = hvfs_hash_site_mgr(site_id, HVFS_ROOT_SITE_MGR_SALT) % 
        hro.conf.site_mgr_htsize;
    rh = sm->sht + idx;
    
    xlock_rlock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (site_id == pos->site_id) {
            /* ok, we find this entry */
            found = 1;
            break;
        }
    }
    xlock_runlock(&rh->lock);

    if (found) {
        return pos;
    } else {
        return ERR_PTR(-ENOENT);
    }
}

struct site_entry *site_mgr_insert(struct site_mgr *sm, struct site_entry *se)
{
    struct site_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_site_mgr(se->site_id, HVFS_ROOT_SITE_MGR_SALT) %
        hro.conf.site_mgr_htsize;
    rh = sm->sht + idx;
    
    xlock_wlock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (site_id == pos->site_id) {
            /* ok, we find a conflict entry */
            found = 1;
            break;
        }
    }
    if (!found) {
        hlist_add_head(&se->hlist, &(sm->sht + idx)->h);
        pos = se;
    }
    xlock_wunlock(&rh->lock);

    return pos;
}

/* site_mgr_lookup_create()
 *
 * This function lookup or create a site entry.
 *
 * Return Value: <0 error; ==0 ok(found); >0 new
 */
int site_mgr_lookup_create(struct site_mgr *sm, u64 site_id, 
                           struct site_entry **ose)
{
    struct site_entry *se;
    int err = 0;

    if (!ose) {
        err = -EINVAL;
        goto out;
    }

    se = site_mgr_lookup(sm, site_id);
    if (IS_ERR(se)) {
        if (ERR_PTR(-ENOENT) == se) {
            /* we should create a new site entry now */
            se = site_mgr_alloc_se();
            if (!se) {
                hvfs_err(root, "site_mgr_alloc_se() failed w/ ENOMEM.\n");
                err = -ENOMEM;
                goto out;
            }
            se->site_id = site_id;
            /* try to insert to the site mgr */
            *ose = site_mgr_insert(sm, se);
            if (IS_ERR(*ose)) {
                hvfs_err(root, "site_mgr_insert() failed w/ %ld\n",
                         PTR_ERR(*ose));
                err = PTR_ERR(*ose);
                site_mgr_free_se(se);
                goto out;
            }
            if (se != *ose) {
                hvfs_err(root, "Someone insert site %lx prior us, self free\n",
                         site_id);
                site_mgr_free_se(se);
            }
            err = 1;
        } else {
            /* error here */
            err = PTR_ERR(se);
            hvfs_err(root, "site_mgr_lookup() failed w/ %d\n", err);
            goto out;
        }
    } else {
        /* set ose to the lookuped entry */
        *ose = se;
    }
    
out:
    return err;
}

int addr_mgr_init(struct addr_mgr *am)
{
    xrwlock_init(&am->lock);
    am->used = 0;
}

void addr_mgr_destroy(struct addr_mgr *am)
{
    /* should we do something */
}

/* addr_mgr_update_one()
 *
 * @flag: HVFS_SITE_REPLACE/ADD/DEL | HVFS_SITE_PROTOCOL_TCP
 */
int addr_mgr_update_one(struct add_mgr *am, u32 flag, u64 site_id, 
                       void *addr)
{
    int err = 0;
    
    /* sanity checking */
    if (!am || site_id < 0 || site_id >= (1 << 20))
        return -EINVAL;

    if (flag & HVFS_SITE_PROTOCOL_TCP) {
        struct hvfs_tcp_addr *hta, *pos, *n;
        struct sockaddr_in *si = (struct sockaddr_in *)addr;

        hta = xzalloc(sizeof(*ht));
        if (!hta) {
            hvfs_err(root, "xzalloc() hvfs_tcp_addr failed.\n");
            err = -ENOMEM;
            goto out;
        }
        INIT_LIST_HEAD(&(hta)->list);
        *((struct sockaddr_in *)&(hta)->sa) = *(si);

        /* next, we should do the OP on the site table */
        if (flag & HVFS_SITE_REPLACE) {
            xrwlock_wlock(&am->lock);
            if (am->xs[site_id]) {
                /* the hvfs_site exists, we just free the table list */
                list_for_each_entry_safe(pos, n, &am->xs[site_id]->addr, list) {
                    list_del(&pos->list);
                    xfree(pos);
                }
                am->xs[site_id]->flag = HVFS_SITE_PROTOCOL_TCP;
                INIT_LIST_HEAD(&am->xs[site_id]->addr);
            } else {
                /* add a new hvfs_site to the table */
                struct hvfs_site *hs;
                
                hs = xzalloc(sizeof(*hs));
                if (!hs) {
                    hvfs_err(root, "xzalloc() hvfs_site failed.\n");
                    err = -ENOMEM;
                    goto out_unlock_replace;
                }
                hs->flag = HVFS_SITE_PROTOCOL_TCP;
                INIT_LIST_HEAD(&hs->addr);
                /* setup the hvfs_site to site table */
                am->xs[site_id] = hs;
            }
            
            /* add the new addr to the list */
            list_add_tail(&(hta)->list, &am->xs[site_id]->addr);
        out_unlock_replace:
            xrwlock_wunlock(&am->lock);
        } else if (flag & HVFS_SITE_ADD) {
            xrwlock_wlock(&am->lock);
            if (!am->xs[site_id]) {
                /* add a new hvfs_site to the table */
                struct hvfs_site *hs;

                hs =xzalloc(sizeof(*hs));
                if (!hs) {
                    hvfs_err(root, "xzalloc() hvfs_site failed.\n");
                    err = -ENOMEM;
                    goto out_unlock_add;
                }
                hs->flag = HVFS_SITE_PROTOCOL_TCP;
                INIT_LIST_HEAD(&hs->addr);
                /* setup the hvfs_site to site table */
                am->xs[site_id] = hs;
            }
            /* add the new addr to the list */
            list_add_tail(&hta->list, &am->xs[site_id]->addr);
        out_unlock_add:
            xrwlock_wunlock(&am->lock);
        } else if (flag & HVFS_SITE_DEL) {
            err = -ENOTEXIST;
            xrwlock_wlock(&am->lock);
            if (am->xs[site_id]) {
                /* iterate on the table to find the entry */
                list_for_each_entry_safe(pos, n, &am->xs[site_id]->addr, list) {
                    if (*si == *((struct sockaddr_in *)&(hta)->sa)) {
                        list_del(&pos->list);
                        xfree(pos);
                        err = 0;
                        break;
                    }
                }
            } else {
                goto out_unlock_del;
            }
        out_unlock_del:
            xrwlock_wunlock(&am->lock);
        } else {
            /* no OP, we just free the allocated resouces */
            xfree(hta);
        }
    }
out:
    return err;
}

int addr_mgr_compact(struct addr_mgr *am, void **data, int *len)
{
}

