/**
 * Copyright (c) 2012 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-11-07 15:38:07 macan>
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
#include "root.h"
#include "xnet.h"
#include "obj.h"

#define HVFS_OM_GET_ENV_atof(name, value) do {   \
        (value) = getenv("hvfs_root_om_" #name); \
        if (value) {                             \
            om.conf.name = atof(value);          \
        }                                        \
    } while (0)

#define HVFS_OM_GET_ENV_atoi(name, value) do {   \
        (value) = getenv("hvfs_root_om_" #name); \
        if (value) {                             \
            om.conf.name = atoi(value);          \
        }                                        \
    } while (0)

#define HVFS_OM_GET_ENV_option(name, uname, value) do {   \
        (value) = getenv("hvfs_root_om_" #name);          \
        if (value) {                                      \
            if (atoi(value) != 0) {                       \
                om.conf.option |= HVFS_OM_OPTION_##uname; \
            }                                             \
        }                                                 \
    } while (0)

/* Defination of object active ratio:
 *
 * ratio = active_objs / total_objs
 *
 */
struct hvfs_om_conf
{
#define HVFS_OM_DEFAULT_ACTIVE_RATIO    0.99
    double active_ratio;        /* object active ratio */
#define HVFS_OM_DEFAULT_OBJ_HSIZE       (1024 * 1024) /* 16M <-> 1PB */
    u32 obj_hsize;              /* hash table size */
#define HVFS_OM_DEFAULT_OSD_HSIZE       1024
    u32 osd_hsize;              /* osd table size */

#define HVFS_OM_OPTION_STORE            0x01
    u32 option;
};

struct hvfs_obj_manager
{
    struct hvfs_om_conf conf;         /* configurations of OM */
    atomic64_t total;                 /* total objs */
    atomic64_t active;                /* active objs */
    struct regular_hash_rw *obj_tab;  /* obj hash table */
    struct regular_hash_rw *osd_tab;  /* osd hash table */

#define HVFS_OM_INIT            0x01
#define HVFS_OM_SAFEMODE        0x02
#define HVFS_OM_RUNNING         0x03
#define HVFS_OM_BACKUP          0x04
    /* the state machine
     *
     * INIT -> SAFEMODE <-> RUNNING
     * INIT -> BACKUP <-> RUNNING
     */
    u32 state;                        /* state of the manager */

    /* object report queue */
    struct list_head queue;
    xlock_t qlock;
    sem_t qsem;
    pthread_t om_thread;
    u32 om_thread_stop:1;
};

struct osd_array
{
    int size;
#if HVFS_SITE_MAX <= (1 << 32)
#define OSD_ARRAY_MOD           u32
    u32 *site;
#else
#define OSD_ARRAY_MOD           u64
    u64 *site;
#endif
#define OSD_ARRAY_UNIT          (sizeof(OSD_ARRAY_MOD))
};

struct objid_array
{
#define OBJID_ARRAY_UNIT_MAX    (1024 * 1024)
    int psize, asize;
    struct objid *obj;
};

struct obj_entry
{
    struct hlist_node hlist;    /* insert to obj_tab */
    struct objid id;
    atomic_t ref;
    atomic_t lock;              /* lock for sites' array */
    struct osd_array sites;
};

struct osd_entry
{
    struct hlist_node hlist;    /* insert to osd_tab */
    u64 site_id;
    atomic_t ref, lock;         /* lock for objs' array */
    struct objid_array objs;
};

static struct hvfs_obj_manager om;
static u32 g_target_type;

static inline
u32 __om_hash(struct objid id)
{
    u32 u1 = JSHash((char *)&id.uuid, sizeof(id.uuid));
    u32 u2 = RSHash((char *)&id.bid, sizeof(id.bid));

    return (u1 ^ u2) % om.conf.obj_hsize;
}

static inline
u32 __om_osd_hash(u64 site)
{
    return JSHash((char *)&site, sizeof(site)) % om.conf.osd_hsize;
}

/* API: add the message to OM.queue
 */
int om_dispatch_objrep(struct xnet_msg *msg)
{
    xlock_lock(&om.qlock);
    list_add_tail(&msg->list, &om.queue);
    xlock_unlock(&om.qlock);
    atomic64_inc(&hro.prof.osd.objrep_recved);
    sem_post(&om.qsem);

    return 0;
}

/* each get_obj caller must call put_obj */
static
struct obj_entry *om_get_obj(struct objid id)
{
    struct obj_entry *oe = NULL;
    struct regular_hash_rw *rh;
    struct hlist_node *pos;
    int i;

    i = __om_hash(id);
    rh = om.obj_tab + i;

    i = 0;
    xrwlock_rlock(&rh->lock);
    hlist_for_each_entry(oe, pos, &rh->h, hlist) {
        if (OBJID_EQUAL(oe->id, id)) {
            atomic_inc(&oe->ref);
            i = 1;
            break;
        }
    }
    xrwlock_runlock(&rh->lock);
    if (!i)
        oe = NULL;

    return oe;
}

/* each get_osd caller must call put_osd */
static
struct osd_entry *om_get_osd(u64 site)
{
    struct osd_entry *osd = NULL;
    struct regular_hash_rw *rh;
    struct hlist_node *pos;
    int i;

    i = __om_osd_hash(site);
    rh = om.osd_tab + i;

    i = 0;
    xrwlock_rlock(&rh->lock);
    hlist_for_each_entry(osd, pos, &rh->h, hlist) {
        if (osd->site_id == site) {
            atomic_inc(&osd->ref);
            i = 1;
            break;
        }
    }
    xrwlock_runlock(&rh->lock);
    if (!i)
        osd = NULL;

    return osd;
}

static
void om_put_obj(struct obj_entry *oe)
{
    if (atomic_dec_return(&oe->ref) < 0) {
        if (oe->sites.size > 0 && oe->sites.site)
            xfree(oe->sites.site);
        xfree(oe);
    }
}

static
void om_put_osd(struct osd_entry *osd)
{
    if (atomic_dec_return(&osd->ref) < 0) {
        if (osd->objs.psize > 0 && osd->objs.obj)
            xfree(osd->objs.obj);
        xfree(osd);
    }
}

static
int __om_insert_obj(struct obj_entry *oe)
{
    struct regular_hash_rw *rh;
    struct obj_entry *tpos;
    struct hlist_node *pos;
    int i;

    i = __om_hash(oe->id);
    rh = om.obj_tab + i;

    i = 0;
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (OBJID_EQUAL(tpos->id, oe->id)) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&oe->hlist, &rh->h);
    xrwlock_wunlock(&rh->lock);

    if (i) {
        return -EEXIST;
    }
    atomic64_inc(&om.active);

    return 0;
}

static
int __om_insert_osd(struct osd_entry *osd)
{
    struct regular_hash_rw *rh;
    struct osd_entry *tpos;
    struct hlist_node *pos;
    int i;

    i = __om_osd_hash(osd->site_id);
    rh = om.osd_tab + i;

    i = 0;
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry(tpos, pos, &rh->h, hlist) {
        if (tpos->site_id == osd->site_id) {
            i = 1;
            break;
        }
    }
    if (!i)
        hlist_add_head(&osd->hlist, &rh->h);
    xrwlock_wunlock(&rh->lock);

    if (i)
        return -EEXIST;

    return 0;
}

static
void __om_remove_obj(struct objid id)
{
    struct regular_hash_rw *rh;
    struct obj_entry *tpos = NULL;
    struct hlist_node *pos, *n;
    int i;

    i = __om_hash(id);
    rh = om.obj_tab + i;

    i = 0;
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (OBJID_EQUAL(tpos->id, id)) {
            if (atomic_read(&tpos->ref) > 0) {
                /* someone is dealing with current obj_entry */
                i = 1;
            }
            hlist_del_init(&tpos->hlist);
            atomic64_dec(&om.active);
            break;
        }
    }
    xrwlock_wunlock(&rh->lock);

    if (!i) {
        if (tpos->sites.size > 0 && tpos->sites.site)
            xfree(tpos->sites.site);
        xfree(tpos);
    } else {
        om_put_obj(tpos);
    }
}

static
void __om_remove_osd(u64 site)
{
    struct regular_hash_rw *rh;
    struct osd_entry *tpos = NULL;
    struct hlist_node *pos, *n;
    int i;

    i = __om_osd_hash(site);
    rh = om.osd_tab + i;

    i = 0;
    xrwlock_wlock(&rh->lock);
    hlist_for_each_entry_safe(tpos, pos, n, &rh->h, hlist) {
        if (tpos->site_id == site) {
            if (atomic_read(&tpos->ref) > 0) {
                /* someone is dealing with current osd_entry */
                i = 1;
            }
            hlist_del_init(&tpos->hlist);
            break;
        }
    }
    xrwlock_wunlock(&rh->lock);

    if (!i) {
        if (tpos->objs.psize > 0 && tpos->objs.obj)
            xfree(tpos->objs.obj);
        xfree(tpos);
    } else {
        om_put_osd(tpos);
    }
}

/* add_or_del: 1=>add; -1=>del
 */
static
void __om_update_obj(struct obj_entry *oe, u64 site, int add_or_del)
{
    struct osd_array new;
    int found = 0, i;

    if (add_or_del != 1 && add_or_del != -1)
        return;

retry:
    for (i = 0; i < oe->sites.size; i++) {
        if (oe->sites.site[i] == site) {
            found = 1;
            break;
        }
    }
    hvfs_info(root, "update obj %lx.%x size %d w/ site %lx, "
             "add_or_del %d, found %d\n",
              oe->id.uuid, oe->id.bid, 
              oe->sites.size, site, add_or_del, found);

    if (atomic_inc_return(&oe->lock) > 1) {
        atomic_dec(&oe->lock);
        sched_yield();
        goto retry;
    }

    if (add_or_del < 0) {
        if (!found) {
            hvfs_err(root, "Del site %lx from objid %lx+%d failed,"
                     " not found.\n",
                     site, oe->id.uuid, oe->id.bid);
            goto out;
        } else {
            /* exchange with the last entry */
            OSD_ARRAY_MOD tmp;

            tmp = oe->sites.site[i];
            oe->sites.site[i] = oe->sites.site[oe->sites.size - 1];
            oe->sites.site[oe->sites.size - 1] = tmp;
        }
    } else if (add_or_del > 0) {
        if (found) {
            /* this means we should just do a in-position update */
            oe->sites.site[i] = site;
            goto out;
        }
    }
    
    new.size = oe->sites.size + add_or_del;
    new.site = xrealloc(oe->sites.site, new.size * OSD_ARRAY_UNIT);
    if (!new.site && new.size) {
        hvfs_err(root, "OM update objid %lx+%d for site %lx failed,"
                 " no free memory (%d unit).\n",
                 oe->id.uuid, oe->id.bid, site, new.size);
        goto out;
    }

    if (add_or_del > 0) {
        new.site[oe->sites.size] = (OSD_ARRAY_MOD)site;
        hvfs_err(root, "add site %lx\n", site);
    }
    oe->sites.size = new.size;
    oe->sites.site = new.site;
    
out:
    atomic_dec(&oe->lock);
}

static
int __osd_array_realloc(struct osd_entry *oe)
{
    struct objid_array new;
    int err = 0;
    
    ASSERT(oe->objs.psize >= oe->objs.asize, root);
    
    if (oe->objs.asize == oe->objs.psize) {
        /* enlarge the buffer */
        if (oe->objs.psize > OBJID_ARRAY_UNIT_MAX) {
            new.psize = oe->objs.psize + OBJID_ARRAY_UNIT_MAX;
        } else {
            new.psize = (oe->objs.psize << 1);
        }
        if (new.psize <= 0)
            new.psize = 1024;   /* default to 1024 entries */

        new.obj = xrealloc(oe->objs.obj, new.psize * sizeof(struct objid));
        if (!new.obj) {
            hvfs_err(root, "OM enlarge obj array for site %lx failed,"
                     " no free memory.\n",
                     oe->site_id);
            goto out;
        }
    } else if (oe->objs.asize < (oe->objs.psize >> 1) &&
               (oe->objs.psize > 1024)) {
        /* shrink the buffer */
        new.psize = (oe->objs.psize >> 1);

        new.obj = xrealloc(oe->objs.obj, new.psize * sizeof(struct objid));
        if (!new.obj) {
            hvfs_err(root, "OM shrink obj array for site %lx failed, "
                     "ignore.\n", oe->site_id);
            goto out;
        }
    } else {
        /* no need to enlarge or shrink */
        goto out;
    }

    oe->objs.psize = new.psize;
    oe->objs.obj = new.obj;

out:
    return err;
}

/* add_or_del: 1=>add; -1=>del
 */
static
void __om_update_osd(struct osd_entry *osd, struct objid id, int add_or_del)
{
    int found = 0, i, err;

    if (add_or_del != 1 && add_or_del != -1)
        return;

retry:
    for (i = 0; i < osd->objs.asize; i++) {
        if (OBJID_EQUAL(osd->objs.obj[i], id)) {
            found = 1;
            break;
        }
    }

    if (atomic_inc_return(&osd->lock) > 1) {
        atomic_dec(&osd->lock);
        sched_yield();
        goto retry;
    }

    if (add_or_del < 0) {
        if (!found) {
            hvfs_err(root, "Del objid %lx+%d from site %lx failed,"
                     " not found.\n",
                     id.uuid, id.bid, osd->site_id);
            goto out;
        } else {
            /* exchange with the last entry */
            struct objid tmp;

            tmp = osd->objs.obj[i];
            osd->objs.obj[i] = osd->objs.obj[osd->objs.asize - 1];
            osd->objs.obj[osd->objs.asize - 1] = tmp;
        }
    } else if (add_or_del > 0) {
        if (found) {
            /* this means we should just do a in-position update */
            osd->objs.obj[i] = id;
            goto out;
        }
    }

    err = __osd_array_realloc(osd);
    if (err && add_or_del > 0) {
        goto out;
    }

    if (add_or_del > 0) {
        osd->objs.obj[osd->objs.asize] = id;
        osd->objs.asize++;
        hvfs_err(root, "add id %lx.%x asize %d\n", id.uuid, id.bid, osd->objs.asize);
    } else {
        osd->objs.asize--;
    }
    
out:
    atomic_dec(&osd->lock);
}

/* add a objid to obj hash table, w/o site info
 */
static int om_add_obj(struct objid id)
{
    struct obj_entry *oe;
    int err = 0;
    
    oe = xzalloc(sizeof(*oe));
    if (!oe) {
        hvfs_err(root, "unable to allocate a new object entry.\n");
        return -ENOMEM;
    }
    
    INIT_HLIST_NODE(&oe->hlist);
    atomic_set(&oe->ref, 0);
    atomic_set(&oe->lock, 0);
    oe->id = id;
    
    /* try to add it to hash table */
    err = __om_insert_obj(oe);
    if (err == -EEXIST) {
        xfree(oe);
    }

    return err;
}

/* add a osd to osd hash table, w/o objid info
 */
static int om_add_osd(u64 site)
{
    struct osd_entry *oe;
    int err = 0;

    oe = xzalloc(sizeof(*oe));
    if (!oe) {
        hvfs_err(root, "unable to allocate a new osd entry.\n");
        return -ENOMEM;
    }
    
    INIT_HLIST_NODE(&oe->hlist);
    atomic_set(&oe->ref, 0);
    atomic_set(&oe->lock, 0);
    oe->site_id = site;
    
    /* try to add it to hash table */
    err = __om_insert_osd(oe);
    if (err == -EEXIST) {
        xfree(oe);
    }

    return err;
}

/* add this site to the objid, if objid not existed, insert it first.
 * And insert this site to the site hash table w/ the objid!
 */
static int om_add_obj_site(struct objid id, u64 site)
{
    struct obj_entry *oe;
    struct osd_entry *osd;
    int err = 0;
    
    /* Step 1: find and update the osd entry */
retry0:
    osd = om_get_osd(site);
    if (osd) {
        __om_update_osd(osd, id, 1);
        om_put_osd(osd);
    } else {
        /* ok, create a new osd entry */
        err = om_add_osd(site);
        if (err == -EEXIST)     /* ignore EEXIST error */
            err = 0;
        if (err) {
            hvfs_err(root, "add new osd %lx failed w/ %d\n",
                     site, err);
            return err;
        }
        goto retry0;
    }

    /* try to find the object */
retry:
    oe = om_get_obj(id);
    if (oe) {
        /* ok, find it, then update it */
        __om_update_obj(oe, site, 1);
        om_put_obj(oe);
    } else {
        /* ok, create a new obj entry */
        err = om_add_obj(id);
        if (err == -EEXIST)     /* ignore EEXIST error */
            err = 0;
        if (err) {
            hvfs_err(root, "add new obj %lx+%d failed w/ %d, leaving a "
                     "dangling obj in site table!\n",
                     id.uuid, id.bid, err);
            return err;
        }
        goto retry;
    }

    return err;
}

/* delete the obj from obj_tab, for obj removing
 */
int om_del_obj(struct objid id)
{
    __om_remove_obj(id);

    return 0;
}

/* delete the site from object's osd array and id from osd's objid array
 */
static int om_del_obj_site(struct objid id, u64 site)
{
    struct obj_entry *oe;
    struct osd_entry *osd;

    /* Step 1: delete from osd's objid array */
    osd = om_get_osd(site);
    if (!osd) {
        hvfs_warning(root, "Site %lx not found, continue deleting "
                     "from obj table.\n", site);
    } else {
        __om_update_osd(osd, id, -1);
        om_put_osd(osd);
    }

    /* Step 2: delete from object's osd array */
    oe = om_get_obj(id);
    if (!oe) {
        hvfs_err(root, "Object %lx+%d not found.\n",
                 id.uuid, id.bid);
        return -ENOENT;
    }

    __om_update_obj(oe, site, -1);

    om_put_obj(oe);

    return 0;
}

/* delete the osd from osd_tab, for osd removing
 *
 * Note: for osd removing, we have to remove all the registered objects for
 * this OSD.
 */
int om_del_osd(u64 site)
{
    struct osd_entry *oe;
    int i;

    oe = om_get_osd(site);
    if (!oe) {
        hvfs_err(root, "Find site %lx in hash table failed!\n", site);
        return -ENOENT;
    }
    
    for (i = 0; i < oe->objs.asize; i++) {
        /* just delete all the objid from obj_table */
        struct obj_entry *obj = om_get_obj(oe->objs.obj[i]);

        if (!obj) {
            hvfs_err(root, "Object %lx+%d not found, ignore it.\n",
                     obj->id.uuid, obj->id.bid);
            continue;
        }
        __om_update_obj(obj, site, -1);
        
        om_put_obj(obj);
    }
    om_put_osd(oe);

    __om_remove_osd(site);

    return 0;
}

/* API: query on object to find active OSD list
 */
struct osd_list *om_query_obj(struct objid id)
{
    struct obj_entry *oe;
    struct osd_list *ol;
    int i;

    oe = om_get_obj(id);
    if (!oe) {
        return ERR_PTR(-ENOENT);
    }
    /* lock the osd_array */
retry:
    if (atomic_inc_return(&oe->lock) > 1) {
        atomic_dec(&oe->lock);
        sched_yield();
        goto retry;
    }
    ol = xzalloc(sizeof(*ol) + oe->sites.size * sizeof(u64));
    if (ol) {
        /* copy the osd array */
        for (i = 0; i < oe->sites.size; i++) {
            ol->site[i] = oe->sites.site[i];
        }
        ol->size = oe->sites.size;
    }
    atomic_dec(&oe->lock);
    om_put_obj(oe);

    return ol;
}

/* block report ABI:
 * ORT->addsize < 0 => do full update
 */
static inline
int __serv_request(void)
{
    struct xnet_msg *msg = NULL, *pos, *n;
    struct obj_report_tx *ort;
    int err = 0, i;

    xlock_lock(&om.qlock);
    list_for_each_entry_safe(pos, n, &om.queue, list) {
        list_del_init(&pos->list);
        msg = pos;
        break;
    }
    xlock_unlock(&om.qlock);

    if (!msg)
        return -EHSTOP;

    /* ok, deal with the object report */
    if (msg->tx.len < sizeof(*ort)) {
        hvfs_err(root, "Invalid OBJ REPORT %d received len %d from %lx\n",
                 msg->tx.reqno, msg->tx.len, msg->tx.ssite_id);
        err = -EINVAL;
        goto out;
    }
    
    ort = msg->xm_data;
    if (ort->add_size < 0) {
        i = -ort->add_size;
    } else
        i = ort->add_size;
    if ((i + ort->rmv_size) * sizeof(struct objid) > msg->tx.len) {
        hvfs_err(root, "Partial OBJ REPORT received (%ld,%d) from %lx\n",
                 (i + ort->rmv_size) * sizeof(struct objid), 
                 msg->tx.len, msg->tx.ssite_id);
        err = -EINVAL;
        goto out;
    }
    atomic64_inc(&hro.prof.osd.objrep_handled);

    if (ort->add_size < 0) {
        /* remove old objects */
        om_del_osd(msg->tx.ssite_id);
        ort->add_size = -ort->add_size;
    }

    /* update report content to OM's obj/site table */
    for (i = 0; i < ort->add_size; i++) {
        /* find and update the old object */
        err = om_add_obj_site(ort->ids[i], msg->tx.ssite_id);
        if (err) {
            hvfs_err(root, "add object %lx+%d site %lx failed.\n",
                     ort->ids[i].uuid, ort->ids[i].bid, msg->tx.ssite_id);
        }
        hvfs_info(root, "ADD OBJ %lx+%d site %lx OK\n", 
                  ort->ids[i].uuid, ort->ids[i].bid, msg->tx.ssite_id);
    }
    for (; i < ort->rmv_size + ort->add_size; i++) {
        /* find and delete the old object */
        err = om_del_obj_site(ort->ids[i], msg->tx.ssite_id);
        if (err) {
            hvfs_err(root, "del object %lx+%d site %lx failed.\n",
                     ort->ids[i].uuid, ort->ids[i].bid, msg->tx.ssite_id);
        }
        hvfs_info(root, "DEL OBJ %lx+%d site %lx OK\n", 
                  ort->ids[i].uuid, ort->ids[i].bid, msg->tx.ssite_id);
    }
    
    /* do not reply to OSD site */
out:
    xnet_free_msg(msg);

    return err;
}

static void *om_main(void *arg)
{
    sigset_t set;
    int err = 0;

    /* first, let us block the SIGALRM and SIGCHLD */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */
    while (!om.om_thread_stop) {
        err = sem_wait(&om.qsem);
        if (err == EINTR)
            continue;
        hvfs_debug(root, "OM thread wakeup to handle object reports.\n");
        /* trying to handle more and more IOs */
        while (1) {
            err = __serv_request();
            if (err == -EHSTOP)
                break;
            else if (err) {
                hvfs_err(root, "OM thread handle report w/ error %d\n",
                         err);
            }
        }
    }
    pthread_exit(0);
}

int om_init(u32 type)
{
    pthread_attr_t attr;
    char *value;
    int err = 0, i;

    memset(&om, 0, sizeof(om));
    INIT_LIST_HEAD(&om.queue);
    xlock_init(&om.qlock);
    sem_init(&om.qsem, 0, 0);
    g_target_type = type;

    /* get the configs from env */
    HVFS_OM_GET_ENV_atof(active_ratio, value);
    HVFS_OM_GET_ENV_atoi(obj_hsize, value);
    HVFS_OM_GET_ENV_atoi(osd_hsize, value);
    HVFS_OM_GET_ENV_option(opt_store, STORE, value);

    /* set default values */
    if (!om.conf.active_ratio)
        om.conf.active_ratio = HVFS_OM_DEFAULT_ACTIVE_RATIO;
    if (!om.conf.obj_hsize)
        om.conf.obj_hsize = HVFS_OM_DEFAULT_OBJ_HSIZE;
    if (!om.conf.osd_hsize)
        om.conf.osd_hsize = HVFS_OM_DEFAULT_OSD_HSIZE;

    /* init the hash tables */
    om.obj_tab = xzalloc(om.conf.obj_hsize * sizeof(struct regular_hash_rw));
    if (!om.obj_tab) {
        hvfs_err(root, "OBJECT hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < om.conf.obj_hsize; i++) {
        INIT_HLIST_HEAD(&om.obj_tab[i].h);
        xrwlock_init(&om.obj_tab[i].lock);
    }
    om.osd_tab = xzalloc(om.conf.osd_hsize * sizeof(struct regular_hash_rw));
    if (!om.osd_tab) {
        hvfs_err(root, "OSD hash table allocation failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < om.conf.osd_hsize; i++) {
        INIT_HLIST_HEAD(&om.osd_tab[i].h);
        xrwlock_init(&om.osd_tab[i].lock);
    }

    /* init the om thread */
    err = pthread_attr_init(&attr);
    if (err) {
        hvfs_err(root, "init pthread attr failed w/ %d\n", err);
        goto out;
    }
    err = pthread_attr_setstacksize(&attr, (1 << 20));
    if (err) {
        hvfs_err(root, "set thread stack size to 1MB failed w/ %d\n", err);
        goto out;
    }
    err = pthread_create(&om.om_thread, &attr, &om_main, NULL);
    if (err) {
        hvfs_err(root, "init OM thread failed w/ %d (%s)\n",
                 err, strerror(err));
        goto out;
    }
    
out:
    return err;
}

void om_destroy(void)
{
    om.om_thread_stop = 1;
    sem_post(&om.qsem);
    pthread_join(om.om_thread, NULL);
    sem_destroy(&om.qsem);
}
