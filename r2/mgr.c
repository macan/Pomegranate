/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-02 20:33:38 macan>
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
#include "mds_api.h"
#include "ite.h"
#include "xtable.h"

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

    /* at last, we just open the site entry file */
    ASSERT(hro.conf.site_store, root);
    err = open(hro.conf.site_store, O_CREAT | O_RDWR | O_SYNC,
               S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(root, "open site store %s failed w/ %s\n",
                 hro.conf.site_store, strerror(errno));
        err = -errno;
        goto out;
    }
    hvfs_info(root, "Open site store %s success.\n",
              hro.conf.site_store);
    hro.conf.site_store_fd = err;
    err = 0;

out:
    return err;
}

void site_mgr_destroy(struct site_mgr *sm)
{
    if (sm->sht) {
        xfree(sm->sht);
    }
    if (hro.conf.site_store_fd)
        close(hro.conf.site_store_fd);
}

struct site_entry *site_mgr_alloc_se()
{
    struct site_entry *se;

    se = xzalloc(sizeof(*se));
    if (se) {
        INIT_HLIST_NODE(&se->hlist);
        xlock_init(&se->lock);
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
    int idx, found = 0;

    idx = hvfs_hash_site_mgr(site_id, HVFS_ROOT_SITE_MGR_SALT) % 
        hro.conf.site_mgr_htsize;
    rh = sm->sht + idx;
    
    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (site_id == pos->site_id) {
            /* ok, we find this entry */
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

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
    
    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (se->site_id == pos->site_id) {
            /* ok, we find a conflict entry */
            found = 1;
            break;
        }
    }
    if (!found) {
        hlist_add_head(&se->hlist, &(sm->sht + idx)->h);
        pos = se;
    }
    xlock_unlock(&rh->lock);

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
    int err = 0, i;

    if (!hro.conf.addr_mgr_htsize) {
        /* default to ...ADDR_MGR_HTSIZE */
        hro.conf.addr_mgr_htsize = HVFS_ROOT_ADDR_MGR_HTSIZE;
    }

    am->rht = xzalloc(hro.conf.addr_mgr_htsize * sizeof(struct regular_hash));
    if (!am->rht) {
        hvfs_err(root, "xzalloc() addr mgr hash table failed.\n");
        err = -ENOMEM;
        goto out;
    }
    
    xrwlock_init(&am->rwlock);

    /* init the hash table */
    for (i = 0; i < hro.conf.addr_mgr_htsize; i++) {
        INIT_HLIST_HEAD(&(am->rht + i)->h);
        xlock_init(&(am->rht + i)->lock);
    }

    /* at last, we just open the root entry file */
    ASSERT(hro.conf.addr_store, root);
    err = open(hro.conf.addr_store, O_CREAT | O_RDWR | O_SYNC,
               S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(root, "open addr store %s failed w/ %s\n",
                 hro.conf.addr_store, strerror(errno));
        err = -errno;
        goto out;
    }
    hvfs_info(root, "Open addr store %s success.\n",
              hro.conf.addr_store);
    hro.conf.addr_store_fd = err;
    err = 0;

out:
    return err;
}

void addr_mgr_destroy(struct addr_mgr *am)
{
    /* should we do something */
    xfree(am->rht);
    xrwlock_destroy(&am->rwlock);
    if (hro.conf.addr_store_fd)
        close(hro.conf.addr_store_fd);
}

struct addr_entry *addr_mgr_alloc_ae()
{
    struct addr_entry *ae;

    ae = xzalloc(sizeof(*ae));
    if (ae) {
        INIT_HLIST_NODE(&ae->hlist);
        xrwlock_init(&ae->rwlock);
        ae->used_addr = 0;
        ae->active_site = 0;
    }

    return ae;
}

void addr_mgr_free_ae(struct addr_entry *ae)
{
    xfree(ae);
}

/* addr_mgr_lookup() */
struct addr_entry *addr_mgr_lookup(struct addr_mgr *am, u64 fsid)
{
    struct addr_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(fsid, HVFS_ROOT_ADDR_MGR_SALT) %
        hro.conf.addr_mgr_htsize;
    rh = am->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (fsid == pos->fsid) {
            /* ok, we find the entry */
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found) {
        return pos;
    } else {
        return ERR_PTR(-ENOENT);
    }
}

struct addr_entry *addr_mgr_insert(struct addr_mgr *am, struct addr_entry *ae)
{
    struct addr_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(ae->fsid, HVFS_ROOT_ADDR_MGR_SALT) %
        hro.conf.addr_mgr_htsize;
    rh = am->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (ae->fsid == pos->fsid) {
            /* ok, we find a conflict entry */
            found = 1;
            break;
        }
    }
    if (!found) {
        xrwlock_wlock(&am->rwlock);
        hlist_add_head(&ae->hlist, &(am->rht + idx)->h);
        xrwlock_wunlock(&am->rwlock);
        pos = ae;
    }
    xlock_unlock(&rh->lock);

    return pos;
}

void addr_mgr_remove(struct addr_mgr *am, u64 fsid)
{
    struct addr_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(fsid, HVFS_ROOT_ADDR_MGR_SALT) %
        hro.conf.addr_mgr_htsize;
    rh = am->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (fsid == pos->fsid) {
            /* ok, we find the entry here */
            found = 1;
            break;
        }
    }
    if (found) {
        /* remove it */
        xrwlock_wlock(&am->rwlock);
        hlist_del_init(&pos->hlist);
        xrwlock_wunlock(&am->rwlock);
    } else {
        hvfs_err(root, "Try to remove fsid %ld failed, not found.\n",
                 fsid);
    }
    xlock_unlock(&rh->lock);
}

int addr_mgr_lookup_create(struct addr_mgr *am, u64 fsid,
                           struct addr_entry **oae)
{
    struct addr_entry *ae;
    int err = 0;

    if (!oae) {
        err = -EINVAL;
        goto out;
    }

    ae = addr_mgr_lookup(am, fsid);
    if (IS_ERR(ae)) {
        if (ae == ERR_PTR(-ENOENT)) {
            /* we should create a new addr entry now */
            ae = addr_mgr_alloc_ae();
            if (!ae) {
                hvfs_err(root, "addr_mgr_alloc_re() failed w/ ENOMEM.\n");
                err = -ENOMEM;
                goto out;
            }
            hvfs_err(root, "alloc ae %p\n", ae);
            /* we just create an empty addr entry */
            ae->fsid = fsid;
            /* try to insert to the addr mgr */
            *oae = addr_mgr_insert(am, ae);
            if (IS_ERR(*oae)) {
                hvfs_err(root, "addr_mgr_insert() failed w/ %ld\n",
                         PTR_ERR(*oae));
                err = PTR_ERR(*oae);
                addr_mgr_free_ae(ae);
            }
            if (ae != *oae) {
                hvfs_err(root, "Someone insert addr %ld prior us, self free\n",
                         fsid);
                addr_mgr_free_ae(ae);
            }
            err = 1;
        } else {
            /* error here */
            err = PTR_ERR(ae);
            hvfs_err(root, "addr_mgr_lookup() failed w/ %d\n", err);
            goto out;
        }
    } else {
        /* set oae to the lookuped entry */
        *oae = ae;
    }

out:
    return err;
}

/* addr_mgr_update_one()
 *
 * @flag: HVFS_SITE_REPLACE/ADD/DEL | HVFS_SITE_PROTOCOL_TCP
 */
int addr_mgr_update_one(struct addr_entry *ae, u32 flag, u64 site_id,
                        void *addr)
{
    int err = 0;
    
    /* sanity checking */
    if (!ae || site_id < 0 || site_id >= (1 << 20))
        return -EINVAL;

    if (flag & HVFS_SITE_PROTOCOL_TCP) {
        struct hvfs_addr *hta, *pos, *n;
        struct sockaddr_in *si = (struct sockaddr_in *)addr;

        hta = xzalloc(sizeof(*hta));
        if (!hta) {
            hvfs_err(root, "xzalloc() hvfs_tcp_addr failed.\n");
            err = -ENOMEM;
            goto out;
        }
        hta->flag = HVFS_SITE_PROTOCOL_TCP;
        INIT_LIST_HEAD(&hta->list);
        *((struct sockaddr_in *)&hta->sock.sa) = *(si);

        /* next, we should do the OP on the site table */
        if (flag & HVFS_SITE_REPLACE) {
            xrwlock_wlock(&ae->rwlock);
            if (ae->xs[site_id]) {
                /* the hvfs_site exists, we just free the table list */
                list_for_each_entry_safe(pos, n, &ae->xs[site_id]->addr, 
                                         list) {
                    list_del(&pos->list);
                    ae->xs[site_id]->nr--;
                    ae->used_addr--;
                    xfree(pos);
                }
                INIT_LIST_HEAD(&ae->xs[site_id]->addr);
            } else {
                /* add a new hvfs_site to the table */
                struct hvfs_site *hs;
                
                hs = xzalloc(sizeof(*hs));
                if (!hs) {
                    hvfs_err(root, "xzalloc() hvfs_site failed.\n");
                    err = -ENOMEM;
                    goto out_unlock_replace;
                }
                INIT_LIST_HEAD(&hs->addr);
                /* setup the hvfs_site to site table */
                ae->xs[site_id] = hs;
                ae->active_site++;
            }
            
            /* add the new addr to the list */
            list_add_tail(&hta->list, &ae->xs[site_id]->addr);
            ae->xs[site_id]->nr++;
            ae->used_addr++;
        out_unlock_replace:
            xrwlock_wunlock(&ae->rwlock);
        } else if (flag & HVFS_SITE_ADD) {
            xrwlock_wlock(&ae->rwlock);
            if (!ae->xs[site_id]) {
                /* add a new hvfs_site to the table */
                struct hvfs_site *hs;

                hs =xzalloc(sizeof(*hs));
                if (!hs) {
                    hvfs_err(root, "xzalloc() hvfs_site failed.\n");
                    err = -ENOMEM;
                    goto out_unlock_add;
                }
                INIT_LIST_HEAD(&hs->addr);
                /* setup the hvfs_site to site table */
                ae->xs[site_id] = hs;
                ae->active_site++;
            }
            /* add the new addr to the list */
            list_add_tail(&hta->list, &ae->xs[site_id]->addr);
            ae->xs[site_id]->nr++;
            ae->used_addr++;
        out_unlock_add:
            xrwlock_wunlock(&ae->rwlock);
        } else if (flag & HVFS_SITE_DEL) {
            err = -ENOTEXIST;
            xrwlock_wlock(&ae->rwlock);
            if (ae->xs[site_id]) {
                /* iterate on the table to find the entry */
                list_for_each_entry_safe(pos, n, &ae->xs[site_id]->addr, list) {
                    if ((si->sin_port == 
                         ((struct sockaddr_in *)&hta->sock.sa)->sin_port) ||
                        (si->sin_addr.s_addr ==
                         ((struct sockaddr_in *)&hta->sock.sa)->sin_addr.s_addr) ||
                        (si->sin_family ==
                         ((struct sockaddr_in *)&hta->sock.sa)->sin_family)) {
                        list_del(&pos->list);
                        xfree(pos);
                        ae->xs[site_id]->nr--;
                        ae->used_addr--;
                        err = 0;
                        break;
                    }
                }
            } else {
                goto out_unlock_del;
            }
        out_unlock_del:
            xrwlock_wunlock(&ae->rwlock);
        } else {
            /* no OP, we just free the allocated resouces */
            xfree(hta);
        }
    }
out:
    return err;
}

/* compact to a replace buffer */
int addr_mgr_compact(struct addr_entry *ae, void **data, int *len)
{
    struct hvfs_addr *pos;
    struct hvfs_site_tx *hst;
    int err =0, i, j = 0, k;

    if (!len || !data)
        return -EINVAL;

    /* NOTE THAT: we lock the site table to protect the ae->used_addr and
     * ae->active_site extends. */
    xrwlock_rlock(&ae->rwlock);

    /* try to alloc the memory space */
    *len = sizeof(struct hvfs_site_tx) * ae->active_site +
        sizeof(struct hvfs_addr_tx) * ae->used_addr;
    *data = xmalloc(*len);
    if (!*data) {
        hvfs_err(root, "xmalloc addr space failed.\n");
        err = -ENOMEM;
        goto out_unlock;
    }

    hvfs_err(root, "active site nr %d used addr %d %p\n", 
             ae->active_site, ae->used_addr, *data);
    hst = *data;
    for (i = 0; i < (HVFS_SITE_MAX); i++) {
        if (ae->xs[i]) {
            hst->site_id = i;
            hst->flag = HVFS_SITE_REPLACE;
            hst->nr = ae->xs[i]->nr;
            if (hst->nr) {
                k = 0;
                /* add the addr to the hvfs_addr region */
                list_for_each_entry(pos, &ae->xs[i]->addr, list) {
                    if (pos->flag & HVFS_SITE_PROTOCOL_TCP) {
                        hst->addr[k].flag = pos->flag;
                        hst->addr[k].sock.sa = pos->sock.sa;
#if 0
                        {
                            struct sockaddr_in *sin = (struct sockaddr_in *)
                                &pos->sock.sa;
                            
                            hvfs_err(root, "compact addr %s %d on site %x\n", 
                                     inet_ntoa(sin->sin_addr),
                                     ntohs(sin->sin_port), i);
                        }
#endif
                        k++;
                    } else {
                        hvfs_err(root, "Unknown address protocol type, "
                                 "reject it!\n");
                    }
                }
                if (k > hst->nr) {
                    hvfs_err(root, "Address in site %x extends, we failed\n",
                             i);
                    err = -EFAULT;
                    goto out_free;
                } else if (k < hst->nr) {
                    hvfs_err(root, "Address in site %x shrinks, we continue\n",
                             i);
                    hst->nr = k;
                }
            }
            hst = (void *)hst + hst->nr * sizeof(struct hvfs_addr_tx) +
                sizeof(*hst);
            j++;
        }
    }
    if (j != ae->active_site) {
        hvfs_err(root, "We missed some active sites (%d vs %d).\n",
                 ae->active_site, j);
    }

out_unlock:
    xrwlock_runlock(&ae->rwlock);

    return err;
out_free:
    xrwlock_runlock(&ae->rwlock);
    xfree(*data);
    return err;
}

/* addr_mgr_compact_one
 *
 * This function compact one hvfs_site to a buffer, you can set the flag by
 * yourself.
 */
int addr_mgr_compact_one(struct addr_entry *ae, u64 site_id, u32 flag,
                         void **data, int *len)
{
    struct hvfs_addr *pos;
    struct hvfs_site_tx *hst;
    int err = 0, i = 0;

    if (!len || !data)
        return -EINVAL;

    /* Note that: we lock the site table to protect the ae->xs[i]->nr */
    xrwlock_rlock(&ae->rwlock);
    if (ae->xs[site_id]) {
        *len = sizeof(struct hvfs_site_tx) +
            sizeof(struct hvfs_addr_tx) * ae->xs[site_id]->nr;
        *data = xmalloc(*len);
        if (!*data) {
            hvfs_err(root, "xmalloc addr space failed.\n");
            err = -ENOMEM;
            goto out_unlock;
        }
        hst = *data;
        hst->site_id = site_id;
        hst->flag = flag;
        hst->nr = ae->xs[site_id]->nr;

        if (ae->xs[site_id]->nr) {
            list_for_each_entry(pos, &ae->xs[site_id]->addr, list) {
                if (pos->flag & HVFS_SITE_PROTOCOL_TCP) {
                    hst->addr[i].flag = pos->flag;
                    hst->addr[i].sock.sa = pos->sock.sa;
                    i++;
                } else {
                    hvfs_err(root, "Unknown address protocol type, "
                             "reject it!\n");
                }
            }
            if (i > hst->nr) {
                hvfs_err(root, "Address in site %lx extends, we failed\n",
                         site_id);
                err = -EFAULT;
                goto out_free;
            } else if (i < hst->nr) {
                hvfs_err(root, "Address in site %lx shrinks, we continue\n",
                         site_id);
                hst->nr = i;
            }
        }
    }

out_unlock:
    xrwlock_runlock(&ae->rwlock);

    return err;
out_free:
    xrwlock_runlock(&ae->rwlock);
    xfree(*data);
    return err;
}

int ring_mgr_init(struct ring_mgr *rm)
{
    int err = 0, i;

    if (!hro.conf.ring_mgr_htsize) {
        /* default to ...RING_MGR_HTSIZE */
        hro.conf.ring_mgr_htsize = HVFS_ROOT_RING_MGR_HTSIZE;
    }

    rm->rht = xzalloc(hro.conf.ring_mgr_htsize * sizeof(struct regular_hash));
    if (!rm->rht) {
        hvfs_err(root, "xzalloc() ring mgr hash table failed.\n");
        err = -ENOMEM;
        goto out;
    }

    xrwlock_init(&rm->rwlock);

    /* init the hash table */
    for (i = 0; i < hro.conf.ring_mgr_htsize; i++) {
        INIT_HLIST_HEAD(&(rm->rht + i)->h);
        xlock_init(&(rm->rht + i)->lock);
    }

out:
    return err;
}

void ring_mgr_destroy(struct ring_mgr *rm)
{
    if (rm->rht) {
        xfree(rm->rht);
    }
    xrwlock_destroy(&rm->rwlock);
}

struct ring_entry *ring_mgr_alloc_re()
{
    struct ring_entry *re;

    re = xzalloc(sizeof(*re));
    if (re) {
        INIT_HLIST_NODE(&re->hlist);
        atomic_set(&re->ref, 1);
        // init the chring structure
        xrwlock_init(&re->ring.rwlock);
    }

    return re;
}

void ring_mgr_free_re(struct ring_entry *re)
{
    xfree(re);
}

/* ring_mgr_lookup() to lookup the ring entry
 *
 * @gid: group id => the low 2 bits is the per file system ring id.
 */
struct ring_entry *ring_mgr_lookup(struct ring_mgr *rm, u32 gid)
{
    struct ring_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_ring_mgr(gid, HVFS_ROOT_RING_MGR_SALT) %
        hro.conf.ring_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (gid == pos->ring.group) {
            /* ok, we find the entry */
            found = 1;
            atomic_inc(&pos->ref);
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found) {
        return pos;
    } else {
        return ERR_PTR(-ENOENT);
    }
}

static inline
struct regular_hash *__group2rh(struct ring_mgr *rm, u32 gid)
{
    struct regular_hash *rh;
    int idx;

    idx = hvfs_hash_ring_mgr(gid, HVFS_ROOT_RING_MGR_SALT) %
        hro.conf.ring_mgr_htsize;
    rh = rm->rht + idx;

    return rh;
}

struct ring_entry *ring_mgr_lookup_nolock(struct ring_mgr *rm, u32 gid)
{
    struct ring_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_ring_mgr(gid, HVFS_ROOT_RING_MGR_SALT) %
        hro.conf.ring_mgr_htsize;
    rh = rm->rht + idx;

    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (gid == pos->ring.group) {
            /* ok, we find the entry */
            found = 1;
            atomic_inc(&pos->ref);
            break;
        }
    }

    if (found) {
        return pos;
    } else {
        return ERR_PTR(-ENOENT);
    }
}

void ring_mgr_put(struct ring_entry *re)
{
    atomic_dec(&re->ref);
}

/* Note that you should put the ring_entry after calling insert().
 */
struct ring_entry *ring_mgr_insert(struct ring_mgr *rm, struct ring_entry *re)
{
    struct ring_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_ring_mgr(re->ring.group, HVFS_ROOT_RING_MGR_SALT) %
        hro.conf.ring_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (re->ring.group == pos->ring.group) {
            /* ok, we find a conflict entry */
            found = 1;
            atomic_inc(&re->ref);
            break;
        }
    }
    if (!found) {
        xrwlock_wlock(&rm->rwlock);
        hlist_add_head(&re->hlist, &(rm->rht + idx)->h);
        rm->active_ring++;
        xrwlock_wunlock(&rm->rwlock);
        pos = re;
    }
    xlock_unlock(&rh->lock);

    return pos;
}

void ring_mgr_remove(struct ring_mgr *rm, u32 gid)
{
    struct ring_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_ring_mgr(gid, HVFS_ROOT_RING_MGR_SALT) %
        hro.conf.ring_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (gid == pos->ring.group) {
            /* ok, we find the entry here */
            found = 1;
            break;
        }
    }
    if (found) {
        /* remove it */
        xrwlock_wlock(&rm->rwlock);
        hlist_del_init(&pos->hlist);
        rm->active_ring--;
        xrwlock_wunlock(&rm->rwlock);
    } else {
        hvfs_err(root, "Try to remove ring %d failed, not found.\n",
                 gid);
    }
    xlock_unlock(&rh->lock);
}

/* ring_mgr_compact to get the buffer
 *
 * Note that: if you want to modify the chring, you should hold the
 * rm->rwlock!!!
*/
int ring_mgr_compact(struct ring_mgr *rm, void **data, int *len)
{
    struct ring_entry *pos;
    struct hlist_node *n;
    struct chring_tx *ct;
    int err = 0, i, j = 0;
    
    if (!len || !*data)
        return -EINVAL;

    *len = rm->active_ring * sizeof(struct chring_tx);
    xrwlock_rlock(&rm->rwlock);
    for (i = 0; i < (HVFS_SITE_MAX); i++) {
        hlist_for_each_entry(pos, n, &(rm->rht + i)->h, hlist) {
            *len += pos->ring.used * sizeof(struct chp);
        }
    }
    *data = xmalloc(*len);
    if (!*data) {
        hvfs_err(root, "xmalloc addr space failed.\n");
        err = -ENOMEM;
        goto out_unlock;
    }
    ct = *data;

    for (i = 0; i < HVFS_SITE_MAX; i++) {
        hlist_for_each_entry(pos, n, &(rm->rht + i)->h, hlist) {
            ct[j].group = pos->ring.group;
            ct[j].nr = pos->ring.used;
            memcpy(ct[j].array, pos->ring.array, 
                   ct[j].nr * sizeof(struct chp));
            j++;
        }
    }

    if (j != rm->active_ring) {
        hvfs_err(root, "Detect active ring change in compacting.\n");
        err = -EFAULT;
        goto out_unlock;
    }
    /* NOTE: do not check the # of chp, may buffer overflow? */
    
out_unlock:
    xrwlock_runlock(&rm->rwlock);

    return err;
}

int ring_mgr_compact_one(struct ring_mgr *rm, u32 gid, void **data,
                         int *len) 
{
    struct ring_entry *pos;
    struct chring_tx *ct;
    int err = 0;

    pos = ring_mgr_lookup(rm, gid);
    if(IS_ERR(pos)) {
        hvfs_err(root, "ring_mgr_lookup() failed w/ %ld\n",
                 PTR_ERR(pos));
        return PTR_ERR(pos);
    }
    /* lock the ring */
    xrwlock_rlock(&pos->ring.rwlock);
    *len = pos->ring.used * sizeof(struct chp) + sizeof(*ct);
    *data = xmalloc(*len);
    if (!*data) {
        hvfs_err(root, "xmalloc addr space failed.\n");
        err = -ENOMEM;
        goto out_unlock;
    }
    ct = *data;

    ct->group = gid;
    ct->nr = pos->ring.used;
    memcpy(ct->array, pos->ring.array, ct->nr * sizeof(struct chp));
    
out_unlock:
    xrwlock_runlock(&pos->ring.rwlock);
    
    /* put the ring_entry */
    ring_mgr_put(pos);

    return err;
}

/* ring_mgr_update to update a chring
 *
 * Note that: holding the re->ring.rwlock wlock
 *
 * Note that: we do not do deep copy on the chring.array, so please do not
 * free the array in the caller.
 */
void ring_mgr_re_update(struct ring_mgr *rm, struct ring_entry *re, 
                        struct chring *ring)
{
    while (atomic_read(&re->ref) > 0) {
        xrwlock_wunlock(&re->ring.rwlock);
        xsleep(1);
        xrwlock_wlock(&re->ring.rwlock);
    }

    xrwlock_wlock(&rm->rwlock);

    /* free the current chring */
    xfree(re->ring.array);
    xrwlock_destroy(&re->ring.rwlock);

    /* copy the new chring */
    memcpy(&re->ring, ring, sizeof(struct chring));
    xrwlock_init(&re->ring.rwlock);
    atomic_set(&re->ref, 0);

    xrwlock_wunlock(&rm->rwlock);
}

int root_mgr_init(struct root_mgr *rm)
{
    int err = 0, i;

    if (!hro.conf.root_mgr_htsize) {
        /* default to ...ROOT_MGR_HTSIZE */
        hro.conf.root_mgr_htsize = HVFS_ROOT_ROOT_MGR_HTSIZE;
    }

    rm->rht = xzalloc(hro.conf.root_mgr_htsize * sizeof(struct regular_hash));
    if (!rm->rht) {
        hvfs_err(root, "xzalloc() root mgr hash table failed.\n");
        err = -ENOMEM;
        goto out;
    }

    xrwlock_init(&rm->rwlock);

    /* init the hash table */
    for (i = 0; i < hro.conf.root_mgr_htsize; i++) {
        INIT_HLIST_HEAD(&(rm->rht + i)->h);
        xlock_init(&(rm->rht + i)->lock);
    }

    /* at last, we just open the root entry file */
    ASSERT(hro.conf.root_store, root);
    err = open(hro.conf.root_store, O_CREAT | O_RDWR | O_SYNC,
               S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(root, "open root store %s failed w/ %s\n",
                 hro.conf.root_store, strerror(errno));
        err = -errno;
        goto out;
    }
    hvfs_info(root, "Open root store %s success.\n",
              hro.conf.root_store);
    hro.conf.root_store_fd = err;

    ASSERT(hro.conf.bitmap_store, root);
    err = open(hro.conf.bitmap_store, O_CREAT | O_RDWR | O_SYNC,
               S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(root, "open bitmap store %s failed w/ %s\n",
                 hro.conf.bitmap_store, strerror(errno));
        err = -errno;
        goto out;
    }
    hro.conf.bitmap_store_fd = err;

    xlock_init(&hro.bitmap_lock);
    hro.bitmap_tail = lseek(hro.conf.bitmap_store_fd, 0, SEEK_END);
    if (hro.bitmap_tail == -1UL) {
        hvfs_err(root, "lseek bitmap tail failed w/ %s\n",
                 strerror(errno));
        err = -errno;
        goto out;
    }
    
    hvfs_info(root, "Open bitmap store %s success.\n",
              hro.conf.bitmap_store);
    err = 0;

out:
    return err;
}

void root_mgr_destroy(struct root_mgr *rm)
{
    if (rm->rht) {
        xfree(rm->rht);
    }
    xrwlock_destroy(&rm->rwlock);
    if (hro.conf.root_store_fd)
        close(hro.conf.root_store_fd);
    if (hro.conf.bitmap_store_fd)
        close(hro.conf.bitmap_store_fd);
}

struct root_entry *root_mgr_alloc_re()
{
    struct root_entry *re;

    re = xzalloc(sizeof(*re));
    if (re) {
        INIT_HLIST_NODE(&re->hlist);
    }

    return re;
}

void root_mgr_free_re(struct root_entry *re)
{
    xfree(re);
}

/* root_mgr_lookup() to lookup the root entry
 *
 * @fsid: file system id
 */
struct root_entry *root_mgr_lookup(struct root_mgr *rm, u64 fsid)
{
    struct root_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(fsid, HVFS_ROOT_ROOT_MGR_SALT) %
        hro.conf.root_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (fsid == pos->fsid) {
            /* ok, we find the entry */
            found = 1;
            break;
        }
    }
    xlock_unlock(&rh->lock);

    if (found) {
        return pos;
    } else {
        return ERR_PTR(-ENOENT);
    }
}

struct root_entry *root_mgr_insert(struct root_mgr *rm, struct root_entry *re)
{
    struct root_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(re->fsid, HVFS_ROOT_ROOT_MGR_SALT) %
        hro.conf.root_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (re->fsid == pos->fsid) {
            /* ok, we find a conflict entry */
            found = 1;
            break;
        }
    }
    if (!found) {
        xrwlock_wlock(&rm->rwlock);
        hlist_add_head(&re->hlist, &(rm->rht + idx)->h);
        rm->active_root++;
        xrwlock_wunlock(&rm->rwlock);
        pos = re;
    }
    xlock_unlock(&rh->lock);

    return pos;
}

void root_mgr_remove(struct root_mgr *rm, u64 fsid)
{
    struct root_entry *pos;
    struct hlist_node *n;
    struct regular_hash *rh;
    int idx, found = 0;

    idx = hvfs_hash_root_mgr(fsid, HVFS_ROOT_ROOT_MGR_SALT) %
        hro.conf.root_mgr_htsize;
    rh = rm->rht + idx;

    xlock_lock(&rh->lock);
    hlist_for_each_entry(pos, n, &rh->h, hlist) {
        if (fsid == pos->fsid) {
            /* ok, we find the entry here */
            found = 1;
            break;
        }
    }
    if (found) {
        /* remove it */
        xrwlock_wlock(&rm->rwlock);
        hlist_del_init(&pos->hlist);
        rm->active_root--;
        xrwlock_wunlock(&rm->rwlock);
    } else {
        hvfs_err(root, "Try to remove fsid %ld failed, not found.\n",
                 fsid);
    }
    xlock_unlock(&rh->lock);
}

/* root_mgr_lookup_create()
 *
 * This function lookup or create a root enty and load it. if it does not
 * exist, we just return -ENOENT
 *
 * Return value: <0 error; ==0 ok(found); >0 new
 */
int root_mgr_lookup_create(struct root_mgr *rm, u64 fsid,
                           struct root_entry **ore)
{
    struct root_entry *re;
    int err = 0;

    if (!ore) {
        err = -EINVAL;
        goto out;
    }

    re = root_mgr_lookup(rm, fsid);
    if (IS_ERR(re)) {
        if (re == ERR_PTR(-ENOENT)) {
            /* we should create a new site entry now */
            re = root_mgr_alloc_re();
            if (!re) {
                hvfs_err(root, "root_mgr_alloc_re() failed w/ ENOEM.\n");
                err = -ENOMEM;
                goto out;
            }
            re->fsid = fsid;
            /* we should read in the content of the root entry */
            err = root_read_re(re);
            if (err == -ENOENT) {
                hvfs_err(root, "fsid %ld not exist\n", fsid);
                root_mgr_free_re(re);
                goto out;
            } else if (err) {
                hvfs_err(root, "root_read_re() failed w/ %d\n", err);
                root_mgr_free_re(re);
                goto out;
            }
            /* try to insert to the root mgr */
            *ore = root_mgr_insert(rm, re);
            if (IS_ERR(*ore)) {
                hvfs_err(root, "root_mgr_insert() failed w/ %ld\n",
                         PTR_ERR(*ore));
                err = PTR_ERR(*ore);
                root_mgr_free_re(re);
            }
            if (re != *ore) {
                hvfs_err(root, "Someone insert root %ld prior us, self free\n",
                         fsid);
                root_mgr_free_re(re);
            }
            err = 1;
        } else {
            /* error here */
            err = PTR_ERR(re);
            hvfs_err(root, "root_mgr_lookup() failed w/ %d\n", err);
            goto out;
        }
    } else {
        /* set ore to the lookuped entry */
        *ore = re;
    }
        
out:
    return err;
}

/* root_mgr_lookup_create2()
 *
 * This function lookup or create a root enty. if the root entry does not
 * exist, we just create a new one!
 *
 * Return value: <0 error; ==0 ok(found); >0 new
 */
int root_mgr_lookup_create2(struct root_mgr *rm, u64 fsid,
                           struct root_entry **ore)
{
    struct root_entry *re;
    int err = 0;

    if (!ore) {
        err = -EINVAL;
        goto out;
    }

    re = root_mgr_lookup(rm, fsid);
    if (IS_ERR(re)) {
        if (re == ERR_PTR(-ENOENT)) {
            /* we should create a new site entry now */
            re = root_mgr_alloc_re();
            if (!re) {
                hvfs_err(root, "root_mgr_alloc_re() failed w/ ENOEM.\n");
                err = -ENOMEM;
                goto out;
            }
            re->fsid = fsid;
            /* we should read in the content of the root entry */
            err = root_read_re(re);
            if (err == -ENOENT) {
                hvfs_err(root, "fsid %ld not exist, however we just "
                         "create it\n", fsid);
                re->gdt_uuid = 0;
                re->gdt_salt = lib_random(0xffdefa7);
                re->root_uuid = 1;
                re->root_salt = -1UL;      /* this means that the clients
                                            * should not get a successful
                                            * reg */
                err = root_bitmap_default(re);
                if (err) {
                    hvfs_err(root, "set default bitmap failed w/ %d\n",
                             err);
                    goto out;
                }
            } else if (err) {
                hvfs_err(root, "root_read_re() failed w/ %d\n", err);
                root_mgr_free_re(re);
                goto out;
            }
            /* try to insert to the root mgr */
            *ore = root_mgr_insert(rm, re);
            if (IS_ERR(*ore)) {
                hvfs_err(root, "root_mgr_insert() failed w/ %ld\n",
                         PTR_ERR(*ore));
                err = PTR_ERR(*ore);
                root_mgr_free_re(re);
            }
            if (re != *ore) {
                hvfs_err(root, "Someone insert root %ld prior us, self free\n",
                         fsid);
                root_mgr_free_re(re);
            }
            err = 1;
        } else {
            /* error here */
            err = PTR_ERR(re);
            hvfs_err(root, "root_mgr_lookup() failed w/ %d\n", err);
            goto out;
        }
    } else {
        /* set ore to the lookuped entry */
        *ore = re;
    }
        
out:
    return err;
}

/* root_compact_hxi()
 *
 * This function compact the need info for a request client:
 * mds/mdsl/client. The caller should supply the needed arguments.
 *
 * @site_id: requested site_id
 * @fsid: requested fsid
 * @gid: request group id
 */
int root_compact_hxi(u64 site_id, u64 fsid, u32 gid, union hvfs_x_info *hxi)
{
    struct root_entry *root;
    struct site_entry *se;
    u64 prev_site_id;
    int err = 0;

    if (!hxi)
        return -EINVAL;

    if (HVFS_IS_CLIENT(site_id)) {
        /* we should reject if root->root_salt is -1UL */
        /* Step 1: find site state in the site_mgr */
        se = site_mgr_lookup(&hro.site, site_id);
        if (se == ERR_PTR(-ENOENT)) {
            hvfs_err(root, "site_mgr_lookup() site %lx failed, "
                     "no such site.\n", site_id);
            err = -ENOENT;
            goto out;
        }
        xlock_lock(&se->lock);
        /* check whether the group id is correct */
        if (gid != se->gid) {
            hvfs_err(root, "CHRING group mismatch: "
                     "request %d conflict w/ %d\n", 
                     gid, se->gid);
            err = -EINVAL;
            goto out_client_unlock;
        }
        switch (se->state) {
        case SE_STATE_INIT:
            /* we should init the se->hxi by read or create the hxi */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err == -ENOTEXIST) {
                err = root_create_hxi(se);
                if (err) {
                    hvfs_err(root, "create hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_client_unlock;
                }
                /* write the hxi to disk now */
                err = root_write_hxi(se);
                if (err) {
                    hvfs_err(root, "write hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_client_unlock;
                }
            } else if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_client_unlock;
            }
            se->hxi.hci = hxi->hci;
            se->state = SE_STATE_NORMAL;
            break;
        case SE_STATE_SHUTDOWN:
            /* we should check whether the fsid is the same as in the se->hxi,
             * if not, we must reload the new view from storage. */

            /* fall through */
        case SE_STATE_NORMAL:
            /* we should check whether the fsid is the same as in the
             * se->hxi. if not, we must reject the new request. */
            err = root_mgr_lookup_create(&hro.root, fsid, &root);
            if (err < 0) {
                hvfs_err(root, "root_mgr_lookup() fsid %ld failed w/"
                         "%d\n", fsid, err);
                goto out_client_unlock;
            }

            if (root->gdt_salt != hxi->hci.gdt_salt ||
                root->root_salt != hxi->hci.root_salt) {
                /* hoo, the site requested another fsid, we should change the
                 * current site entry to the new view. But, we must check
                 * whether there is another instance that is running. */
                /* check if the root_salt is -1UL, if it is, we update it */
                ASSERT(fsid != se->fsid, root);

                if (se->state != SE_STATE_SHUTDOWN) {
                    /* ok, we reject the fs change */
                    err = -EEXIST;
                    goto out_client_unlock;
                }
                /* ok, we can change the fs now */
                err = root_read_hxi(site_id, fsid, hxi);
                if (err) {
                    hvfs_err(root, "root_read_hxi() failed w/ %d\n",
                             err);
                    goto out_client_unlock;
                }
                se->hxi.hci = hxi->hci;
                se->state = SE_STATE_NORMAL;
            } else {
                /* ok, do not need fs change */
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* hoo, there is another server instanc running, we should
                     * reject this request. */
                    err = -EEXIST;
                    goto out_client_unlock;
                }

                /* fs not change, we just modify the state */
                hxi->hci = se->hxi.hci;
                se->state = SE_STATE_NORMAL;
            }
            break;
        case SE_STATE_TRANSIENT:
            /* we should just wait for the system come back to normal or error
             * state */
            err = -EHWAIT;
            break;
        case SE_STATE_ERROR:
            /* in the error state means, we can safely reload/unload the se
             * state */
            prev_site_id = se->site_id;

            err = root_write_hxi(se);
            if (err) {
                hvfs_err(root, "root_write_hxi() failed w/ %d\n", err);
            }
            se->state = SE_STATE_INIT;
            /* check if we should init a recover process */
            if (prev_site_id == site_id) {
                hvfs_err(root, "The previous %lx failed to unreg itself, "
                         "we should init a recover process.\n",
                         site_id);
            }

            /* reload the requested fsid */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_client_unlock;
            }
            se->hxi.hci = hxi->hci;
            se->state = SE_STATE_NORMAL;
            (prev_site_id == site_id) ? (err = -ERECOVER) : (err = 0);
            break;
        default:;
        }
        /* Step final: release all the resources */
    out_client_unlock:
        xlock_unlock(&se->lock);
    } else if (HVFS_IS_MDS(site_id)) {
        /* Step 1: find state in the site_mgr */
        se = site_mgr_lookup(&hro.site, site_id);
        if (se == ERR_PTR(-ENOENT)) {
            hvfs_err(root, "site_mgr_lookup() site %lx failed, "
                     "no such site.\n", site_id);
            err = -ENOENT;
            goto out;
        }

        xlock_lock(&se->lock);
        /* check whether the group id is correct */
        if (gid != se->gid) {
            hvfs_err(root, "CHRING group mismatch: "
                     "request %d conflict w/ %d\n",
                     gid, se->gid);
            err = -EINVAL;
            goto out_mds_unlock;
        }

        switch (se->state) {
        case SE_STATE_INIT:
            /* we should init the se->hxi by read the hxi in from MDSL */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err == -ENOTEXIST) {
                err = root_create_hxi(se);
                if (err) {
                    hvfs_err(root, "create hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_mds_unlock;
                }
                /* write the hxi to disk now */
                err = root_write_hxi(se);
                if (err) {
                    hvfs_err(root, "write hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_mds_unlock;
                }
            } else if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_mds_unlock;
            }
            se->hxi.hmi = hxi->hmi;
            se->state = SE_STATE_NORMAL;
            break;
        case SE_STATE_SHUTDOWN:
            /* we should check whether the fsid is the same as in the
             * se->hxi. if not, we must reload the new view from MDSL */

            /* fall through */
        case SE_STATE_NORMAL:
            /* we should check whether the fsid is the same as in the
             * se->hxi. if not, we must reject the new request. */
            err = root_mgr_lookup_create(&hro.root, fsid, &root);
            if (err < 0) {
                hvfs_err(root, "root_mgr_lookup() fsid %ld failed w/"
                         "%d\n", fsid, err);
                goto out_mds_unlock;
            }

            if (root->gdt_salt != hxi->hmi.gdt_salt ||
                root->root_salt != hxi->hmi.root_salt) {
                /* hoo, the site requested another fsid, we should change the
                 * current site entry to the new view. but, we must check
                 * whether there is another instance that is running. */

                /* check if the root_salt is -1UL, if it is, we update it */
                if (hxi->hmi.root_salt == -1UL) {
                    hxi->hmi.root_salt = root->root_salt;
                } else {
                    ASSERT(fsid != se->fsid, root);
                }
                
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* ok, we reject the fs change */
                    err = -EEXIST;
                    goto out_mds_unlock;
                }
                /* ok, we can change the fs now */
                err = root_read_hxi(site_id, fsid, hxi);
                if (err) {
                    hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                    goto out_mds_unlock;
                }
                se->hxi.hmi = hxi->hmi;
                se->state = SE_STATE_NORMAL;
            } else {
                /* ok, do not need fs change */
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* hoo, there is another server instance running, we
                     * should reject this request. */
                    err = -EEXIST;
                    goto out_mds_unlock;
                }
                
                /* fs not change, we just modify the state */
                hxi->hmi = se->hxi.hmi;
                se->state = SE_STATE_NORMAL;
            }
            break;
        case SE_STATE_TRANSIENT:
            /* we should just wait for the system come back to normal or
             * error. */
            err = -EHWAIT;
            break;
        case SE_STATE_ERROR:
            /* in the error state means, we can safely reload/unload the se
             * state. */
            prev_site_id = se->site_id;
            
            err = root_write_hxi(se);
            if (err) {
                hvfs_err(root, "root_write_hxi() failed w/ %d\n", err);
            }
            se->state = SE_STATE_INIT;
            /* check if we should init a recover process */
            if (prev_site_id == site_id) {
                hvfs_err(root, "The previous %lx failed to unreg itself, "
                         "we should init a recover process.\n",
                         site_id);
            }
            
            /* reload the requested fsid */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_mds_unlock;
            }
            se->hxi.hmi = hxi->hmi;
            se->state = SE_STATE_NORMAL;
            (prev_site_id == site_id) ? (err = -ERECOVER) : (err = 0);
            break;
        default:;
        }
        
        /* Step final: release all the resources */
    out_mds_unlock:
        xlock_unlock(&se->lock);
    } else if (HVFS_IS_MDSL(site_id)) {
        /* Step 1: find state in the site_mgr */
        se = site_mgr_lookup(&hro.site, site_id);
        if (se == ERR_PTR(-ENOENT)) {
            hvfs_err(root, "site_mgr_lookup() site %lx failed, "
                     "no such site.\n", site_id);
            err = -ENOENT;
            goto out;
        }

        xlock_lock(&se->lock);
        /* check whether the group id is correct */
        if (gid != se->gid) {
            hvfs_err(root, "CHRING group mismatch: "
                     "request %d conflict w/ %d\n",
                     gid, se->gid);
            err = -EINVAL;
            goto out_mdsl_unlock;
        }

        switch (se->state) {
        case SE_STATE_INIT:
            /* we should init the se->hxi by read the hxi in from MDSL */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err == -ENOTEXIST) {
                err = root_create_hxi(se);
                if (err) {
                    hvfs_err(root, "create hxi %ld %lx failed /w %d\n",
                             se->fsid, se->site_id, err);
                    goto out_mdsl_unlock;
                }
                /* write the hxi to disk now */
                err = root_write_hxi(se);
                if (err) {
                    hvfs_err(root, "write hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_mdsl_unlock;
                }
            } else if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_mdsl_unlock;
            }
            se->hxi.hmi = hxi->hmi;
            se->state = SE_STATE_NORMAL;
            break;
        case SE_STATE_SHUTDOWN:
            /* we should check whether the fsid is the same as in the
             * se->hxi. if not, we must reload the new view from MDSL. */

            /* fall through */
        case SE_STATE_NORMAL:
            /* we should check whether the fsid is the same as in the se->hxi.
             * if not, we must reject the new request. */
            err = root_mgr_lookup_create(&hro.root, fsid, &root);
            if (err < 0) {
                hvfs_err(root, "root_mgr_lookup() fsid %ld failed w/"
                         " %d\n", fsid, err);
                goto out_mdsl_unlock;
            }

            if (root->gdt_salt != hxi->hmi.gdt_salt ||
                root->root_salt != hxi->hmi.root_salt) {
                /* hoo, the site requested another fsid, we should change the
                 * current site entry to the new view. but, we must check
                 * whether there is another instance that is running. */
                if (hxi->hmi.root_salt == -1UL) {
                    hxi->hmi.root_salt = root->root_salt;
                } else {
                    ASSERT(fsid != se->fsid, root);
                }
                
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* ok, we reject the fs change */
                    err = -EEXIST;
                    goto out_mdsl_unlock;
                }
                /* ok, we can change the fs now */
                err = root_read_hxi(site_id, fsid, hxi);
                if (err) {
                    hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                    goto out_mdsl_unlock;
                }
                se->hxi.hmli = hxi->hmli;
                se->state = SE_STATE_NORMAL;
            } else {
                /* ok, do not need fs change */
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* hoo, we reject the request */
                    err = -EEXIST;
                    goto out_mdsl_unlock;
                }
                
                /* fs not change, we just modify the state */
                hxi->hmli = se->hxi.hmli;
                se->state = SE_STATE_NORMAL;
            }
            break;
        case SE_STATE_TRANSIENT:
            /* we should just wait for the system come back to normal or err
             * state */
            err = -EHWAIT;
            break;
        case SE_STATE_ERROR:
            /* in error state means, we can safely reload/unload the state */
            prev_site_id = se->site_id;
            
            err = root_write_hxi(se);
            if (err) {
                hvfs_err(root, "root_write_hxi() failed w/ %d\n", err);
            }
            se->state = SE_STATE_INIT;
            /* check if we should init a recover process */
            if (prev_site_id == site_id) {
                hvfs_err(root, "The previous %lx failed to unreg itself, "
                         "we should init a recover process.\n",
                         site_id);
            }
            
            /* reload the requested fsid */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_mdsl_unlock;
            }
            se->hxi.hmi = hxi->hmi;
            se->state = SE_STATE_NORMAL;
            (prev_site_id == site_id) ? (err = -ERECOVER) : (err = 0);
            break;
        default:;
        }
        /* Step final: release all the resources */
    out_mdsl_unlock:
        xlock_unlock(&se->lock);
    } else if (HVFS_IS_ROOT(site_id)) {
    } else if (HVFS_IS_AMC(site_id)) {
        /* we should reject if root->root_salt is -1UL */
        /* Step 1: find site state in the site_mgr */
        se = site_mgr_lookup(&hro.site, site_id);
        if (se == ERR_PTR(-ENOENT)) {
            hvfs_err(root, "site_mgr_lookup() site %lx failed, "
                     "no such site.\n", site_id);
            err = -ENOENT;
            goto out;
        }
        xlock_lock(&se->lock);
        /* check whether the group id is correct */
        if (gid != se->gid) {
            hvfs_err(root, "CHRING group mismatch: "
                     "request %d conflict w/ %d\n", 
                     gid, se->gid);
            err = -EINVAL;
            goto out_amc_unlock;
        }
        switch (se->state) {
        case SE_STATE_INIT:
            /* we should init the se->hxi by read or create the hxi */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err == -ENOTEXIST) {
                err = root_create_hxi(se);
                if (err) {
                    hvfs_err(root, "create hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_amc_unlock;
                }
                /* write the hxi to disk now */
                err = root_write_hxi(se);
                if (err) {
                    hvfs_err(root, "write hxi %ld %lx failed w/ %d\n",
                             se->fsid, se->site_id, err);
                    goto out_amc_unlock;
                }
            } else if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_amc_unlock;
            }
            se->hxi.ami = hxi->ami;
            se->state = SE_STATE_NORMAL;
            break;
        case SE_STATE_SHUTDOWN:
            /* we should check whether the fsid is the same as in the se->hxi,
             * if not, we must reload the new view from storage. */

            /* fall through */
        case SE_STATE_NORMAL:
            /* we should check whether the fsid is the same as in the
             * se->hxi. if not, we must reject the new request. */
            err = root_mgr_lookup_create(&hro.root, fsid, &root);
            if (err < 0) {
                hvfs_err(root, "root_mgr_lookup() fsid %ld failed w/"
                         "%d\n", fsid, err);
                goto out_amc_unlock;
            }

            if (root->gdt_salt != hxi->ami.gdt_salt ||
                root->root_salt != hxi->ami.root_salt) {
                /* hoo, the site requested another fsid, we should change the
                 * current site entry to the new view. But, we must check
                 * whether there is another instance that is running. */
                /* check if the root_salt is -1UL, if it is, we update it */
                ASSERT(fsid != se->fsid, root);

                if (se->state != SE_STATE_SHUTDOWN) {
                    /* ok, we reject the fs change */
                    err = -EEXIST;
                    goto out_amc_unlock;
                }
                /* ok, we can change the fs now */
                err = root_read_hxi(site_id, fsid, hxi);
                if (err) {
                    hvfs_err(root, "root_read_hxi() failed w/ %d\n",
                             err);
                    goto out_amc_unlock;
                }
                se->hxi.ami = hxi->ami;
                se->state = SE_STATE_NORMAL;
            } else {
                /* ok, do not need fs change */
                if (se->state != SE_STATE_SHUTDOWN) {
                    /* hoo, there is another server instanc running, we should
                     * reject this request. */
                    err = -EEXIST;
                    goto out_amc_unlock;
                }

                /* fs not change, we just modify the state */
                hxi->ami = se->hxi.ami;
                se->state = SE_STATE_NORMAL;
            }
            break;
        case SE_STATE_TRANSIENT:
            /* we should just wait for the system come back to normal or error
             * state */
            err = -EHWAIT;
            break;
        case SE_STATE_ERROR:
            /* in the error state means, we can safely reload/unload the se
             * state */
            prev_site_id = se->site_id;

            err = root_write_hxi(se);
            if (err) {
                hvfs_err(root, "root_write_hxi() failed w/ %d\n", err);
            }
            se->state = SE_STATE_INIT;
            /* check if we should init a recover process */
            if (prev_site_id == site_id) {
                hvfs_err(root, "The previous %lx failed to unreg itself, "
                         "we should init a recover process.\n",
                         site_id);
            }

            /* reload the requested fsid */
            err = root_read_hxi(site_id, fsid, hxi);
            if (err) {
                hvfs_err(root, "root_read_hxi() failed w/ %d\n", err);
                goto out_amc_unlock;
            }
            se->hxi.ami = hxi->ami;
            se->state = SE_STATE_NORMAL;
            (prev_site_id == site_id) ? (err = -ERECOVER) : (err = 0);
            break;
        default:;
        }
        /* Step final: release all the resources */
    out_amc_unlock:
        xlock_unlock(&se->lock);
    } else {
        hvfs_err(root, "Unknown site type: %lx\n", site_id);
        err = -EINVAL;
        goto out;
    }

out:
    return err;
}

int root_read_hxi(u64 site_id, u64 fsid, union hvfs_x_info *hxi)
{
    struct root_entry *root;
    struct site_disk sd;
    u64 offset;
    int err = 0, bl, br;

    /* Note: if the site_id is a new one, we should use fsid to find the root
     * entry. if the root entry does not exist, we just return an error. The
     * mkfs utility can create a new file system w/ a fsid. After reading the
     * root entry we can construct the site by ourself:) */

    if (HVFS_IS_MDS(site_id) || HVFS_IS_MDSL(site_id)) {
        err = root_mgr_lookup_create2(&hro.root, fsid, &root);
        if (err < 0) {
            hvfs_err(root, "lookup create entry %ld failed w/ %d\n",
                     fsid, err);
            goto out;
        } else if (err > 0) {
            hvfs_err(root, "create fs %ld on-the-fly\n", fsid);
            err = 0;
        }
    } else if (HVFS_IS_CLIENT(site_id) || HVFS_IS_AMC(site_id)) {
        err = root_mgr_lookup_create(&hro.root, fsid, &root);
        if (err < 0) {
            hvfs_err(root, "lookup create entry %ld failed w/ %d\n",
                     fsid, err);
            goto out;
        }
        if (root->root_salt == -1UL) {
            hvfs_err(root, "reject %lx w/o mkfs called\n", site_id);
            return -EAGAIN;
        }
    }

    /* read in the site hxi info from site store file */
    /* Note that the site store file's layout is as follows:
     *
     * [fsid:0 [site table]] | [fsid:1 [site table]]
     */
    offset = fsid * SITE_DISK_WHOLE_FS + site_id * sizeof(struct site_disk);

    bl = 0;
    do {
        br = pread(hro.conf.site_store_fd, ((void *)&sd) + bl, sizeof(sd) - bl,
                   offset + bl);
        if (br < 0) {
            hvfs_err(root, "pread site disk %ld %lx failed w/ %s\n",
                     fsid, site_id, strerror(errno));
            err = -errno;
            goto out;
        } else if (br == 0) {
            hvfs_err(root, "pread site disk %ld %lx faild w/ EOF\n",
                     fsid, site_id);
            if (bl == 0)
                err = -ENOTEXIST;
            else
                err = -EINVAL;
            goto out;
        }
        bl += br;
    } while (bl < sizeof(sd));

    if (sd.state != SITE_DISK_VALID) {
        err = -ENOTEXIST;
        goto out;
    }
    
    /* parse site_disk to site_entry->hxi */
    if (sd.fsid != fsid || sd.site_id != site_id) {
        hvfs_err(root, "Internal error, fsid/site_id mismatch!\n");
        err = -EFAULT;
        goto out;
    }
    if (HVFS_IS_CLIENT(site_id)) {
        struct hvfs_client_info *hci = (struct hvfs_client_info *)hxi;

        memcpy(hxi, &sd.hxi, sizeof(*hci));
        if (hci->gdt_salt != root->gdt_salt ||
            hci->root_salt != root->root_salt) {
            hvfs_err(root, "Internal error, salt mismatch in hci and root\n");
            hvfs_err(root, "hci salt %lx root salt %lx\n",
                     hci->gdt_salt, root->gdt_salt);
            if (hci->root_salt == -1UL) {
                hci->gdt_salt = root->gdt_salt;
                hci->root_salt = root->root_salt;
            } else {
                err = -EFAULT;
                goto out;
            }
        }
    } else if (HVFS_IS_MDS(site_id)) {
        struct hvfs_mds_info *hmi = (struct hvfs_mds_info *)hxi;

        memcpy(hxi, &sd.hxi, sizeof(*hmi));
        if (hmi->gdt_salt != root->gdt_salt ||
            hmi->root_salt != root->root_salt) {
            hvfs_err(root, "Internal error, salt mismatch in hmi and root\n");
            hvfs_err(root, "hmi salt %lx root salt %lx\n",
                     hmi->gdt_salt, root->gdt_salt);
            if (hmi->root_salt == -1UL) {
                hmi->gdt_salt = root->gdt_salt;
                hmi->root_salt = root->root_salt;
            } else {
                err = -EFAULT;
                goto out;
            }
        }
    } else if (HVFS_IS_MDSL(site_id)) {
        struct hvfs_mdsl_info *hmli = (struct hvfs_mdsl_info *)hxi;

        memcpy(hxi, &sd.hxi, sizeof(*hmli));
        if (hmli->gdt_salt != root->gdt_salt ||
            hmli->root_salt != root->root_salt) {
            hvfs_err(root, "Internal error, salt mismatch in hmli and root\n");
            if (hmli->root_salt == -1UL) {
                hmli->gdt_salt = root->gdt_salt;
                hmli->root_salt = root->root_salt;
            } else {
                err = -EFAULT;
                goto out;
            }
        }
    } else if (HVFS_IS_AMC(site_id)) {
        struct hvfs_amc_info *ami = (struct hvfs_amc_info *)hxi;

        memcpy(hxi, &sd.hxi, sizeof(*ami));
        if (ami->gdt_salt != root->gdt_salt||
            ami->root_salt != root->root_salt) {
            hvfs_err(root, "Internal error, salt mismatc in ami and root\n");
            if (ami->root_salt == -1UL) {
                ami->gdt_salt = root->gdt_salt;
                ami->root_salt = root->root_salt;
            } else {
                err = -EFAULT;
                goto out;
            }
        }
    }
    
out:
    return err;
}

int root_write_hxi(struct site_entry *se)
{
    struct site_disk sd;
    u64 offset;
    int err = 0, bl, bw;

    sd.state = SITE_DISK_VALID;
    sd.gid = se->gid;
    sd.fsid = se->fsid;
    sd.site_id = se->site_id;
    memcpy(&sd.hxi, &se->hxi, sizeof(se->hxi));

    offset = se->fsid * SITE_DISK_WHOLE_FS + 
        se->site_id * sizeof(struct site_disk);

    bl = 0;
    do {
        bw = pwrite(hro.conf.site_store_fd, ((void *)&sd) + bl,
                    sizeof(sd) - bl, offset + bl);
        if (bw < 0) {
            hvfs_err(root, "pwrite site disk %ld %lx failed w/ %s\n",
                     se->fsid, se->site_id, strerror(errno));
            err = -errno;
            goto out;
        } else if (bw == 0) {
            /* just retry it */
        }
        bl += bw;
    } while (bl < sizeof(sd));

out:
    return err;
}

int root_clean_hxi(struct site_entry *se)
{
    struct site_disk sd;
    u64 offset;
    int err = 0, bw;

    sd.state = SITE_DISK_INVALID;
    offset = se->fsid * SITE_DISK_WHOLE_FS +
        se->site_id * sizeof(struct site_disk);
    offset += offsetof(struct site_disk, state);

    do {
        bw = pwrite(hro.conf.site_store_fd, &sd.state, 1,
                    offset);
        if (bw < 0) {
            hvfs_err(root, "clean site disk %ld %lx failed w/ %s\n",
                     se->fsid, se->site_id, strerror(errno));
            err = -errno;
            goto out;
        }
    } while (bw > 0);

out:
    return err;
}

int root_create_hxi(struct site_entry *se)
{
    struct root_entry *root;
    int err = 0;

    root = root_mgr_lookup(&hro.root, se->fsid);
    if (IS_ERR(root)) {
        hvfs_err(root, "lookup root %ld failed w/ %ld\n",
                 se->fsid, PTR_ERR(root));
        err = PTR_ERR(root);
        goto out;
    }
    if (HVFS_IS_CLIENT(se->site_id)) {
        struct hvfs_client_info *hci = (struct hvfs_client_info *)&se->hxi;

        memset(hci, 0, sizeof(*hci));
        hci->state = HMI_STATE_CLEAN;
        hci->gdt_uuid = root->gdt_uuid;
        hci->gdt_salt = root->gdt_salt;
        hci->root_uuid = root->root_uuid;
        hci->root_salt = root->root_salt;
        hci->group = se->gid;
    } else if (HVFS_IS_MDS(se->site_id)) {
        struct hvfs_mds_info *hmi = (struct hvfs_mds_info *)&se->hxi;

        memset(hmi, 0, sizeof(*hmi));
        hmi->state = HMI_STATE_CLEAN;
        hmi->gdt_uuid = root->gdt_uuid;
        hmi->gdt_salt = root->gdt_salt;
        hmi->root_uuid = root->root_uuid;
        hmi->root_salt = root->root_salt;
        hmi->group = se->gid;
        hmi->uuid_base = (se->site_id & HVFS_SITE_N_MASK) << 45;
        atomic64_set(&hmi->mi_uuid, 2); /* skip gdt/root entry */
    } else if (HVFS_IS_MDSL(se->site_id)) {
        struct hvfs_mdsl_info *hmi = (struct hvfs_mdsl_info *)&se->hxi;

        memset(hmi, 0, sizeof(*hmi));
        hmi->state = HMI_STATE_CLEAN;
        hmi->gdt_uuid = root->gdt_uuid;
        hmi->gdt_salt = root->gdt_salt;
        hmi->root_uuid = root->root_uuid;
        hmi->root_salt = root->root_salt;
        hmi->group = se->gid;
        hmi->uuid_base = (se->site_id & HVFS_SITE_N_MASK) << 45;
        atomic64_set(&hmi->mi_uuid, 2); /* skip gdt/root entry */
    } else if (HVFS_IS_AMC(se->site_id)) {
        struct hvfs_amc_info *ami = (struct hvfs_amc_info *)&se->hxi;

        memset(ami, 0, sizeof(*ami));
        ami->state = HMI_STATE_CLEAN;
        ami->gdt_uuid = root->gdt_uuid;
        ami->gdt_salt = root->gdt_salt;
        ami->root_uuid = root->root_uuid;
        ami->root_salt = root->root_salt;
        ami->group = se->gid;
    }
    
out:
    return err;
}

/* root_read_re() reading the root entry from the file
 *
 * Note: the root file should be sorted by fsid, then we can get the root
 * entry very fast!
 */
int root_read_re(struct root_entry *re)
{
    loff_t offset;
    struct root_disk rd;
    int err = 0, bl, br;

    /* we read the root entry based on the re->fsid */
    if (!hro.conf.root_store_fd) {
        return -EINVAL;
    }

    offset = re->fsid * sizeof(rd);

    bl = 0;
    do {
        br = pread(hro.conf.root_store_fd, ((void *)&rd) + bl, 
                   sizeof(rd) - bl, offset + bl);
        if (br < 0) {
            hvfs_err(root, "read root entry %ld failed w/ %s\n",
                     re->fsid, strerror(errno));
            err = -errno;
            goto out;
        } else if (br == 0) {
            hvfs_err(root, "read root entry %ld failed w/ EOF\n",
                     re->fsid);
            if (bl == 0)
                err = -ENOENT;
            else
                err = -EINVAL;
            goto out;
        }
        bl += br;
    } while (bl < sizeof(rd));

    if (rd.state == ROOT_DISK_INVALID) {
        err = -ENOENT;
    } else {
        void *bitmap;

        if ((rd.gdt_flen % XTABLE_BITMAP_BYTES) != 0) {
            hvfs_err(root, "Interval error, bitmap len is not aligned\n");
            err = -EFAULT;
            goto out;
        }
        
        bitmap = xmalloc(rd.gdt_flen);
        if (!bitmap) {
            hvfs_err(root, "xmalloc gdt bitmap failed\n");
            err = -ENOMEM;
            goto out;
        }
        err = root_read_bitmap(rd.gdt_foffset, rd.gdt_flen, bitmap);
        if (err) {
            hvfs_err(root, "read fsid %ld bitmap @ %ld len %ld failed w/ %d\n",
                     re->fsid, rd.gdt_foffset, rd.gdt_flen, err);
            xfree(bitmap);
            goto out;
        }
        
        re->gdt_uuid = rd.gdt_uuid;
        re->gdt_salt = rd.gdt_salt;
        re->root_uuid = rd.root_uuid;
        re->root_salt = rd.root_salt;
        re->gdt_flen = rd.gdt_flen;
        re->gdt_bitmap = bitmap;
    }

out:
    return err;
}

/* root_write_re() write the root entry to the file
 *
 * Note: we write to the fixed location by lseek
 */
int root_write_re(struct root_entry *re)
{
    loff_t offset;
    struct root_disk rd;
    int err = 0, bl, bw;

    /* we read the root entry based on the re->fsid */
    if (!hro.conf.root_store_fd) {
        return -EINVAL;
    }

    offset = re->fsid * sizeof(rd);

    /* write the bitmap first */
    err = root_write_bitmap(re->gdt_bitmap, re->gdt_flen,
                            &rd.gdt_foffset);
    if (err) {
        hvfs_err(root, "write fsid %ld bitmap failed w/ %d\n",
                 re->fsid, err);
        return err;
    }

    rd.state = ROOT_DISK_VALID;
    rd.fsid = re->fsid;
    rd.gdt_uuid = re->gdt_uuid;
    rd.gdt_salt = re->gdt_salt;
    rd.root_uuid = re->root_uuid;
    rd.root_salt = re->root_salt;
    rd.gdt_flen = re->gdt_flen;

    bl = 0;
    do {
        bw = pwrite(hro.conf.root_store_fd, ((void *)&rd) + bl,
                    sizeof(rd) - bl, offset + bl);
        if (bw < 0) {
            hvfs_err(root, "write root entry %ld failed w/ %s\n",
                     re->fsid, strerror(errno));
            err = -errno;
            goto out;
        } else if (bw == 0) {
            /* we just retry write */
        }
        bl += bw;
    } while (bl < sizeof(rd));

out:
    return err;
}

int root_read_bitmap(u64 offset, u64 len, void *data)
{
    int err = 0, bl, br;
    
    if (!data || !hro.conf.bitmap_store_fd) {
        return -EINVAL;
    }

    bl = 0;
    do {
        br = pread(hro.conf.bitmap_store_fd, data + bl, len - bl,
                   offset + bl);
        if (br < 0) {
            hvfs_err(root, "pread bitmap @ %ld len %ld failed w/ %s\n",
                     offset, len, strerror(errno));
            err = -errno;
            break;
        } else if (br == 0) {
            hvfs_err(root, "pread bitmap @ %ld len %ld failed w/ EOF\n",
                     offset, len);
            err = -EINVAL;
            break;
        }
        bl += br;
    } while (bl < len);

    return err;
}

int root_write_bitmap(void *data, u64 len, u64 *ooffset)
{
    loff_t offset;
    int err = 0, bl, bw;

    if (!data || !ooffset) {
        return -EINVAL;
    }

    xlock_lock(&hro.bitmap_lock);
    offset = hro.bitmap_tail;
    bl = 0;
    do {
        bw = pwrite(hro.conf.bitmap_store_fd, data + bl, len - bl,
                    offset + bl);
        if (bw < 0) {
            hvfs_err(root, "pwrite bitmap @ %ld len %ld failed w/ %s\n",
                     offset, len, strerror(errno));
            err = -errno;
            break;
        } else if (bw == 0) {
            /* just retry to write */
            break;
        }
        bl += bw;
    } while (bl < len);

    *ooffset = hro.bitmap_tail;
    hro.bitmap_tail += len;
    xlock_unlock(&hro.bitmap_lock);
    
    return err;
}

void *root_bitmap_enlarge(void *data, u64 len)
{
    void *new;
    
    len = BITMAP_ROUNDUP(len + XTABLE_BITMAP_BYTES);

    new = xrealloc(data, len);
    if (!new) {
        hvfs_err(root, "xrealloc bitmap region failed\n");
    }
    return new;
}

int root_bitmap_default(struct root_entry *re)
{
    int err = 0, i;

    re->gdt_bitmap = root_bitmap_enlarge(NULL, 0);
    if (!re->gdt_bitmap) {
        hvfs_err(root, "get bitmap region failed, no memory\n");
        err = -ENOMEM;
        goto out;
    }
    re->gdt_flen = XTABLE_BITMAP_BYTES;

    for (i = 0; i < 1; i++) {
        re->gdt_bitmap[i] = 0xff;
    }
out:    
    return err;
}

int __send_msg_create_gdt(int dsite, struct hvfs_index *oi, void *data)
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
        hvfs_err(root, "xzalloc() hvfs_index failed\n");
        return -ENOMEM;
    }
    memcpy(hi, oi, sizeof(*hi));
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
        hvfs_err(root, "xnet_alloc_msg() failed\n");
        err = -ENOMEM;
        goto out;
    }
    xnet_msg_fill_tx(msg, XNET_MSG_REQ, XNET_NEED_DATA_FREE |
                     XNET_NEED_REPLY, hro.xc->site_id, dsite);
    xnet_msg_fill_cmd(msg, HVFS_CLT2MDS_CREATE, 0, 0);
#ifdef XNET_EAGER_WRITEV
    xnet_msg_add_sdata(msg, &msg->tx, sizeof(struct xnet_msg_tx));
#endif
    xnet_msg_add_sdata(msg, hi, dpayload);

    hvfs_debug(root, "MDS dpayload %d (namelen %d, dlen %ld)\n", 
               msg->tx.len, hi->namelen, hi->dlen);
resend:
    err = xnet_send(hro.xc, msg);
    if (err) {
        hvfs_err(root, "xnet_send() failed\n");
        goto out_msg;
    }
    /* this means we have got the reply, parse it! */
    ASSERT(msg->pair, root);
    if (msg->pair->tx.err == -ESPLIT && !recreate) {
        /* the ITB is under spliting, we need retry */
        xnet_set_auto_free(msg->pair);
        xnet_free_msg(msg->pair);
        msg->pair = NULL;
        recreate = 1;
        goto resend;
    } else if (msg->pair->tx.err == -ERESTART) {
        goto resend;
    } else if (msg->pair->tx.err) {
        hvfs_err(root, "CREATE failed @ MDS site %ld w/ %d\n",
                 msg->pair->tx.ssite_id, msg->pair->tx.err);
        err = msg->pair->tx.err;
        goto out_msg;
    }
    if (msg->pair->xm_datacheck)
        hmr = (struct hvfs_md_reply *)msg->pair->xm_data;
    else {
        hvfs_err(root, "Invalid CREATE reply from site %ld.\n",
                 msg->pair->tx.ssite_id);
        err = -EFAULT;
        goto out_msg;
    }
    /* now, checking the hmr err */
    if (hmr->err) {
        /* hoo, sth wrong on the MDS. IMPOSSIBLE code path! */
        hvfs_err(root, "MDS Site %ld reply w/ %d\n",
                 msg->pair->tx.ssite_id, hmr->err);
        xnet_set_auto_free(msg->pair);
        goto out_msg;
    } else if (hmr->len) {
        hmr->data = ((void *)hmr) + sizeof(struct hvfs_md_reply);
    }
    /* ok, we got the correct respond, insert it to the DH */
    hi = hmr_extract(hmr, EXTRACT_HI, &nr);
    if (!hi) {
        hvfs_err(root, "Invalid reply w/o hvfs_index as expected.\n");
        goto skip;
    }
    mdu = hmr_extract(hmr, EXTRACT_MDU, &nr);
    if (!mdu) {
        hvfs_err(root, "Invalid reply w/o MDU as expacted.\n");
        goto skip;
    }
    hvfs_err(root, "Got suuid 0x%lx ssalt %lx puuid %lx psalt %lx.\n", 
               hi->uuid, mdu->salt, mdu->puuid, mdu->psalt);
    /* we should export the self salt to the caller */
    oi->ssalt = mdu->salt;
    
    /* finally, we wait for the commit respond */
skip:
    xnet_set_auto_free(msg->pair);

out_msg:
    xnet_free_msg(msg);
    return err;
out:
    xfree(hi);
    return err;
}

static inline
u64 root_bitmap_cut(u64 offset, u64 end_offset)
{
    u64 mask;
    int nr = fls64(end_offset);

    if (nr < 0)
        return 0;
    mask = (1 << nr) - 1;
    return offset & mask;
}

static inline
u64 root_bitmap_fallback(u64 offset)
{
    int nr = fls64(offset);

    if (nr < 0)
        return 0;
    __clear_bit(nr, &offset);
    return offset;
}

/* convert the hash to itbid by lookup the bitmap */
static inline
u64 root_get_itbid(struct root_entry *re, u64 hash)
{
    u64 offset = hash >> ITB_DEPTH;

    offset = root_bitmap_cut(offset, re->gdt_flen << 3);

    do {
        if (test_bit(offset, (u64 *)(re->gdt_bitmap))) {
            break;
        }
        offset = root_bitmap_fallback(offset);
    } while (offset != 0);

    return offset;
}

int root_mkfs(struct root_entry *re, struct ring_entry *ring, u32 gid)
{
    char data[HVFS_MDU_SIZE];
    struct mdu *mdu = (struct mdu *)data;
    struct hvfs_index hi;
    struct chp *p;
    u64 *i = (u64 *)(data + sizeof(struct mdu));
    int err = 0;

    /* Step 1: calculate the target MDS and send the request */
    /* get the itbid by using re->gdt_bitmap */
    memset(&hi, 0, sizeof(hi));
    hi.puuid = re->gdt_uuid;
    hi.psalt = re->gdt_salt;
    hi.uuid = re->root_uuid;
    hi.hash = hvfs_hash(hi.uuid, re->gdt_salt, 0, HASH_SEL_GDT);
    hi.itbid = root_get_itbid(re, hi.hash);

    p = ring_get_point(hi.itbid, re->gdt_salt, &ring->ring);
    if (IS_ERR(p)) {
        hvfs_err(root, "ring_get_point() failed w/ %ld\n", PTR_ERR(p));
        err = -EFAULT;
        goto out;
    }

    memset(data, 0, HVFS_MDU_SIZE);
    mdu->mode = 0040744;
    mdu->nlink = 2;
    mdu->flags = HVFS_MDU_IF_NORMAL;

    *i = re->root_uuid;
    *(i + 1) = re->root_salt;
    *(i + 2) = re->root_salt;

    hvfs_err(root, "send create root request to %lx\n", p->site_id);
    err = __send_msg_create_gdt(p->site_id, &hi, data);
    if (err) {
        hvfs_err(xnet, "create root GDT entry failed w/ %d\n", err);
        goto out;
    }
    
    /* Step 2: get the root_salt */
    re->root_salt = hi.ssalt;
    hvfs_info(root, "Change root salt to %lx\n", re->root_salt);
    
out:
    return err;
}

void site_mgr_check(time_t ctime)
{
    struct site_entry *pos;
    struct hlist_node *n;
    static time_t ts = 0;
    int i;

    if (ctime - ts < hro.conf.hb_interval) {
        return;
    } else
        ts = ctime;
    
    for (i = 0; i < hro.conf.site_mgr_htsize; i++) {
        hlist_for_each_entry(pos, n, &hro.site.sht[i].h, hlist) {
            xlock_lock(&pos->lock);
            switch (pos->state) {
            case SE_STATE_NORMAL:
                pos->hb_lost++;
                if (pos->hb_lost > TRANSIENT_HB_LOST) {
                    hvfs_err(root, "Site %lx lost %d, transfer to TRANSIENT.\n",
                             pos->site_id, pos->hb_lost);
                    pos->state = SE_STATE_TRANSIENT;
                } else if (pos->hb_lost > MAX_HB_LOST) {
                    hvfs_err(root, "Site %lx lost %d, transfer to ERROR.\n",
                         pos->site_id, pos->hb_lost);
                    pos->state = SE_STATE_ERROR;
                }
                break;
            case SE_STATE_TRANSIENT:
                pos->hb_lost++;
                if (pos->hb_lost > MAX_HB_LOST) {
                    hvfs_err(root, "Site %lx lost %d, transfer to ERROR.\n",
                         pos->site_id, pos->hb_lost);
                    pos->state = SE_STATE_ERROR;
                }
                break;
            default:;
            }
            xlock_unlock(&pos->lock);
        }
    }
}
