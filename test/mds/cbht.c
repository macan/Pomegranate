/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-15 20:06:51 macan>
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

/*
 * This file is used to do the UNIT TEST for CBHT operations
 */

#ifndef UNIT_TEST
#error "Sorry, you must compile this file with UNIT_TEST defined!"
#endif

#include "hvfs.h"
#include "xtable.h"
#include "mds.h"
#include "ring.h"

#ifdef UNIT_TEST
atomic64_t miss;                /* # of shadow lookup miss */

void hmr_print(struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct mdu *m;
    struct link_source *ls;
    void *p = hmr->data;

    hvfs_info(mds, "hmr-> err %d, mdu_no %d, len %d, flag 0x%x.\n", 
              hmr->err, hmr->mdu_no, hmr->len, hmr->flag);
    if (!p)
        return;
    hi = (struct hvfs_index *)p;
    hvfs_info(mds, "hmr-> HI: len %d, flag 0x%x, uuid %ld, hash %ld, itbid %ld, "
              "puuid %ld, psalt %ld\n", hi->namelen, hi->flag, hi->uuid, 
              hi->hash, hi->itbid, hi->puuid, hi->psalt);
    p += sizeof(struct hvfs_index);
    if (hmr->flag & MD_REPLY_WITH_MDU) {
        m = (struct mdu *)p;
        hvfs_info(mds, "hmr->MDU: size %ld, dev %ld, mode 0x%x, nlink %d, uid %d, "
                  "gid %d, flags 0x%x, atime %lx, ctime %lx, mtime %lx, dtime %lx, "
                  "version %d\n", m->size, m->dev, m->mode, m->nlink, m->uid,
                  m->gid, m->flags, m->atime, m->ctime, m->mtime, m->dtime,
                  m->version);
        p += sizeof(struct mdu);
    }
    if (hmr->flag & MD_REPLY_WITH_LS) {
        ls = (struct link_source *)p;
        hvfs_info(mds, "hmr-> LS: hash %ld, puuid %ld, uuid %ld\n",
                  ls->s_hash, ls->s_puuid, ls->s_uuid);
        p += sizeof(struct link_source);
    }
    if (hmr->flag & MD_REPLY_WITH_BITMAP) {
        hvfs_info(mds, "hmr-> BM: ...\n");
    }
}

void insert_ite(u64 puuid, u64 itbid, char *name, struct mdu_update *imu,
                       struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct mdu_update *mu;
    struct hvfs_txg *txg;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name) + sizeof(struct mdu_update);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = INDEX_CREATE;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) + 
                               strlen(name));
    memcpy(mu, imu, sizeof(struct mdu_update));
    hi->data = mu;

retry:
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);
    if (err == -ESPLIT) {
        sched_yield();
        goto retry;
    } else if (err == -ERESTART || err == -EHWAIT) {
        goto retry;
    } else if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }

    xfree(hi);
}

void remove_ite(u64 puuid, u64 itbid, char *name, 
                       struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct hvfs_txg *txg;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = INDEX_UNLINK | INDEX_BY_NAME;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    hi->data = NULL;

retry:
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);

    if (err == -ESPLIT) {
        sched_yield();
        goto retry;
    } else if (err == -ERESTART || err == -EHWAIT) {
        goto retry;
    } else if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
        mds_cbht_search_dump_itb(hi);
        ASSERT(0, mds);
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
    xfree(hi);
}

void lookup_ite(u64 puuid, u64 itbid, char *name, u64 flag , 
                       struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct hvfs_txg *txg;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag = flag;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    
retry:
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);
    if (err == -ESPLIT) {
        sched_yield();
        goto retry;
    } else if (err == -ERESTART || err == -EHWAIT) {
        goto retry;
    } else if (err && (flag & ITE_ACTIVE)) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s, %lx) failed %d\n", 
                 puuid, itbid, name, hi->hash, err);
        hvfs_err(mds, "ITB hash 0x%20lx.\n", 
                 hvfs_hash(puuid, itbid, sizeof(u64), HASH_SEL_CBHT));
        mds_cbht_search_dump_itb(hi);
    } else if (err) {
        atomic64_inc(&miss);
    }
    
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
    
    xfree(hi);
}

void async_unlink_test(void)
{
    char buf[512];
    struct hvfs_index *hi = (struct hvfs_index *)buf;
    struct hvfs_md_reply hmr;
    struct hvfs_txg *txg;
    struct link_source ls = {.nlink = 2,};
    int a = 0, b = 0, err;

    memset(hi, 0, sizeof(struct hvfs_index));
    hi->flag = INDEX_CREATE_LINK | INDEX_CREATE;

    //SET_TRACING_FLAG(mds, HVFS_DEBUG | HVFS_VERBOSE);

    /* INSERT REGION */
    for (a = 0; a < 1024; a++) {
        sprintf(hi->name, "shit-%d", a);
        if (lib_random(2)) {
            hi->flag = INDEX_CREATE | INDEX_CREATE_LINK;
            hi->data = &ls;
            b++;
        } else {
            hi->flag = INDEX_CREATE;
            hi->data = NULL;
        }
        hi->namelen = strlen(hi->name);
        memset(&hmr, 0, sizeof(hmr));
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(hi, &hmr, txg, &txg);
        txg_put(txg);
        if (err) {
            hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                     0L, 0L, hi->name, err);
        }
    }
    hvfs_info(mds, "=======AFTER INSERT, WE GOT(%d,%d)=======\n", 
              b, a);
    mds_cbht_search_dump_itb(hi);

    /* remove one */
    for (a = 0; a < 1024; a++) {
        sprintf(hi->name, "shit-%d", a);
        hi->namelen = strlen(hi->name);
        hi->flag = INDEX_UNLINK | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
        memset(&hmr, 0, sizeof(hmr));
        txg = mds_get_open_txg(&hmo);
        err = mds_cbht_search(hi, &hmr, txg, &txg);
        txg_put(txg);
        if (err) {
            hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                     0L, 0L, hi->name, err);
        }
    }
    hvfs_info(mds, "=======AFTER REMOVE, WE GOT=======\n");
    mds_cbht_search_dump_itb(hi);
    hvfs_info(mds, "=======BEGIN ASYNC REMOVE, WE GOT========\n");
    /* async unlink */
    {
        struct itbh *ih;
        int dc = 0;
        
        list_for_each_entry(ih, &hmo.async_unlink, unlink) {
            xrwlock_rlock(&ih->lock);
            if (ih->state == ITB_STATE_COWED) {
                xrwlock_runlock(&ih->lock);
                continue;
            }
            async_unlink_ite((struct itb *)ih, &dc);
            xrwlock_runlock(&ih->lock);
            if (dc < hmo.conf.max_async_unlink)
                break;
        }
    }

    mds_cbht_search_dump_itb(hi);
    exit(0);
}

int dh_insert(u64 uuid, u64 puuid, u64 psalt)
{
    struct hvfs_index hi;
    struct dhe *e;
    int err = 0;

    memset(&hi, 0, sizeof(hi));
    hi.uuid = uuid;
    hi.puuid = puuid;
    hi.ssalt = psalt;

    e = mds_dh_insert(&hmo.dh, &hi);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_insert() failed %ld\n", PTR_ERR(e));
        goto out;
    }
    hvfs_info(mds, "Insert dir:%8ld in DH w/  %p\n", uuid, e);
    mds_dh_put(e);
out:
    return err;
}

int dh_search(u64 uuid)
{
    struct dhe *e;
    int err = 0;

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out;
    }
    hvfs_info(mds, "Search dir:%8ld in DH hit %p\n", uuid, e);
    mds_dh_put(e);
out:
    return err;
}

int dh_remove(u64 uuid)
{
    return mds_dh_remove(&hmo.dh, uuid);
}

int bitmap_insert(u64 uuid, u64 offset)
{
    struct dhe *e;
    struct itbitmap *b;
    int err = 0, i;

    b = xzalloc(sizeof(*b));
    if (!b) {
        hvfs_err(mds, "xzalloc() struct itbitmap failed\n");
        err = -ENOMEM;
        goto out;
    }
    INIT_LIST_HEAD(&b->list);
    b->offset = (offset / XTABLE_BITMAP_SIZE) * XTABLE_BITMAP_SIZE;
    b->flag = BITMAP_END;
    /* set all bits to 1, within the previous 8 ITBs */
    for (i = 0; i < ((1 << hmo.conf.itb_depth_default) / 8); i++) {
        b->array[i] = 0xff;
    }

    e = mds_dh_search(&hmo.dh, uuid);
    if (IS_ERR(e)) {
        hvfs_err(mds, "mds_dh_search() failed %ld\n", PTR_ERR(e));
        err = PTR_ERR(e);
        goto out_free;
    }
    err = __mds_bitmap_insert(e, b);
    if (err) {
        mds_dh_put(e);
        hvfs_err(mds, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }
    mds_dh_put(e);

out:
    return err;
out_free:
    xfree(b);
    return err;
}

/* ring_add() add one site to the CH ring
 */
int ring_add(struct chring **r, u64 site)
{
    struct chp *p;
    char buf[256];
    int vid_max, i, err;

    vid_max = hmo.conf.ring_vid_max ? hmo.conf.ring_vid_max : HVFS_RING_VID_MAX;

    if (!*r) {
        *r = ring_alloc(vid_max << 1, 0);
        if (!*r) {
            hvfs_err(mds, "ring_alloc() failed.\n");
            return -ENOMEM;
        }
    }

    p = (struct chp *)xzalloc(vid_max * sizeof(struct chp));
    if (!p) {
        hvfs_err(mds, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < vid_max; i++) {
        snprintf(buf, 256, "%ld.%d", site, i);
        (p + i)->point = hvfs_hash(site, (u64)buf, strlen(buf), HASH_SEL_VSITE);
        (p + i)->vid = i;
        (p + i)->type = CHP_AUTO;
        (p + i)->site_id = site;
        err = ring_add_point(p + i, *r);
        if (err) {
            hvfs_err(mds, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
}

int st_main(int argc, char *argv[])
{
    struct timeval begin, end;
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    u64 puuid, itbid;
    int i, j, k, x, bdepth, icsize;
    char name[HVFS_MAX_NAME_LEN];

    int err = 0;

    if (argc == 5) {
        /* the argv[1] is k, argv[2] is x, argv[3] is bucket.depth, argv[4] is
         * ITB Cache init size */
        k = atoi(argv[1]);
        x = atoi(argv[2]);
        bdepth = atoi(argv[3]);
        icsize = atoi(argv[4]);
    } else {
        k = 100;
        x = 100;
        bdepth = 4;
        icsize = 50;
    }
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    hvfs_info(mds, "CBHT UNIT TESTing (single thread)...(%d,%d,%d,%d)\n", 
              k, x, bdepth, icsize);
    lib_init();
    mds_pre_init();
    err = mds_init(bdepth);
    if (err) {
        hvfs_err(mds, "mds_cbht_init failed %d\n", err);
        goto out;
    }
    /* init misc configrations */
    hmo.site_id = HVFS_MDS(0);
    hmo.gossip_thread_stop = 1;
    hmo.conf.itbid_check = 1;
    hmi.gdt_salt = lib_random(0xfffffff);
    hvfs_info(mds, "Select GDT salt to %ld\n", hmi.gdt_salt);    
    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_dump(hmo.chring[CH_RING_MDS]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);

    /* print the init cbht */
    cbht_print_dir(&hmo.cbht);
    /* init hte itb cache */
    itb_cache_init(&hmo.ic, icsize);
    
    hvfs_info(mds, "ITC init success ...\n");

    hvfs_info(mds, "total struct itb = %ld\n", sizeof(struct itb) + 
              ITB_SIZE * sizeof(struct ite));
    hvfs_info(mds, "sizeof(struct itb) = %ld\n", sizeof(struct itb));
    hvfs_info(mds, "sizeof(struct itbh) = %ld\n", sizeof(struct itbh));
    hvfs_info(mds, "sizeof(struct ite) = %ld\n", sizeof(struct ite));

    /* pre-test the unlink function */
    async_unlink_test();

    /* insert the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < x; j++) {
            mu.valid = MU_MODE | MU_UID;
            mu.mode = i;
            mu.uid = j;
            sprintf(name, "macan-%d-%d", i, j);
            insert_ite(puuid, itbid, name, &mu, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end, x * k);
    hvfs_info(mds, "Insert ite is done ...\n");

    /* lookup the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < x; j++) {
            u64 flag;
            sprintf(name, "macan-%d-%d", i, j);
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end, x * k);
    hvfs_info(mds, "Lookup ite is done ...\n");

    /* unlink the ite, change state to SHADOW */
    lib_timer_start(&begin);
    for (i = 0; i < k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < x; j++) {
            sprintf(name, "macan-%d-%d", i, j);
            remove_ite(puuid, itbid, name, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end, x * k);
    hvfs_info(mds, "Unlink ite is done ...\n");

    /* shadow lookup */
    lib_timer_start(&begin);
    for (i = 0; i < k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < x; j++) {
            u64 flag;
            sprintf(name, "macan-%d-%d", i, j);
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_SHADOW;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end, x * k);
    hvfs_info(mds, "Shadow lookup ite is done, total miss %ld ...\n",
              atomic64_read(&miss));
    
    itb_cache_destroy(&hmo.ic);
    /* print the init cbht */
    hvfs_info(mds, "CBHT dir depth %d\n", hmo.cbht.dir_depth);
#ifdef HVFS_DEBUG_LOCK
    lock_table_print();
#endif
/*     cbht_print_dir(&hmo.cbht); */
    mds_cbht_destroy(&hmo.cbht);
out:
    return err;
}

struct pthread_args
{
    int tid;                    /* thread index */
    int threads;                /* total threads */
    int k, x, icsize;           /* dynamic */
    int bdepth;                 /* should be const */
    pthread_barrier_t *pb;
    double acc[4];              /* 4 operations */
};

/* pt_main()
 *
 * NOTE: This function is used to test parallel insertion to different
 * ITBs. All threads insert/lookup in the different ITB w/o synchronization.
 */
void *pt_main(void *arg)
{
    struct pthread_args *pa = (struct pthread_args *)arg;
    struct timeval begin, end;
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    u64 puuid, itbid, flag;
    int i, j;
    char name[HVFS_MAX_NAME_LEN];

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel insert the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = pa->tid;
        itbid = i;
        for (j = 0; j < pa->x; j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i, j);
            insert_ite(puuid, itbid, name, &mu, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[0]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel lookup the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = pa->tid;
        itbid = i;
        for (j = 0; j < pa->x; j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i, j);
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[1]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel unlink the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = pa->tid;
        itbid = i;
        for (j = 0; j < pa->x; j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i, j);
            remove_ite(puuid, itbid, name, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[2]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);
    
   /* parallel shadow lookup the ite! */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = pa->tid;
        itbid = i;
        for (j = 0; j < pa->x; j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i, j);
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_SHADOW;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[3]);

    pthread_barrier_wait(pa->pb);

    pthread_exit(0);
}

/* pt_main2()
 *
 * NOTE: pt_main2 is used to test the ITB parallel insertion/deletion. All
 * threads parallel insert into the same ITB w/o synchronization.
 */
void *pt_main2(void *arg)
{
    struct pthread_args *pa = (struct pthread_args *)arg;
    struct timeval begin, end;
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    u64 puuid, itbid, flag;
    int i, j;
    char name[HVFS_MAX_NAME_LEN];

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* paralle insert the ite in the same ITB order */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < (pa->x / pa->threads); j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i, 
                    pa->tid + (j * pa->threads));
            insert_ite(puuid, itbid, name, &mu, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[0]);
    
    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel lookup the ite in the same ITB order */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < (pa->x / pa->threads); j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i,
                    pa->tid + (j * pa->threads));
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[1]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel unlink the ite in the same ITB order */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < (pa->x / pa->threads); j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i,
                    pa->tid + (j * pa->threads));
            remove_ite(puuid, itbid, name, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[2]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel shadow lookup the ite in the same ITB order */
    lib_timer_start(&begin);
    for (i = 0; i < pa->k; i++) {
        puuid = 0;
        itbid = i;
        for (j = 0; j < (pa->x / pa->threads); j++) {
            sprintf(name, "macan-%d-%d-%d", pa->tid, i,
                    pa->tid + (j * pa->threads));
            flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_SHADOW;
            lookup_ite(puuid, itbid, name, flag, &hmr);
        }
    }
    lib_timer_stop(&end);
    lib_timer_acc(&begin, &end, &pa->acc[3]);

    pthread_barrier_wait(pa->pb);

    pthread_exit(0);
}

static inline char *idx2str(int i)
{
    switch (i) {
    case 0:
        return "start";
    case 1:
        return "insert";
    case 2:
        return "lookup";
    case 3:
        return "unlink";
    case 4:
        return "shadow";
    default:
        return "NULL";
    }
}

int mt_main(int argc, char *argv[])
{
    pthread_t *t;
    pthread_barrier_t pb;
    struct pthread_args *pa;
    double acc[4];
    int err;
    int i, i1, j, k, x, bdepth, icsize, model, threads;

    hvfs_err(mds, "MT MAIN is broken now, it doesn't work!\n");
    if (argc == 5) {
        /* the argv[1] is k, argv[2] is x, argv[3] is bucket.depth, argv[4] is
         * ITB Cache init size */
        k = atoi(argv[1]);
        x = atoi(argv[2]);
        bdepth = atoi(argv[3]);
        icsize = atoi(argv[4]);
        model = 0;
    } else if (argc == 6) {
        /* new threads' model */
        k = atoi(argv[1]);
        x = atoi(argv[2]);
        bdepth = atoi(argv[3]);
        icsize = atoi(argv[4]);
        model = 1;
    } else {
        k = 100;
        x = 100;
        bdepth = 4;
        icsize = 50;
        model = 0;
    }
#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    hvfs_info(mds, "CBHT UNIT TESTing (multi thread M%d)...(%d,%d,%d,%d)\n", 
              model, k, x, bdepth, icsize);
    lib_init();
    mds_pre_init();
    err = mds_init(bdepth);
    if (err) {
        hvfs_err(mds, "mds_cbht_init failed %d\n", err);
        goto out;
    }
    /* init misc configrations */
    hmo.site_id = HVFS_MDS(0);
    hmi.gdt_salt = lib_random(0xfffffff);
    hmo.gossip_thread_stop = 1;
    hmo.scrub_thread_stop = 1;
    hmo.conf.itbid_check = 1;
    hvfs_info(mds, "Select GDT salt to %ld\n", hmi.gdt_salt);
    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_dump(hmo.chring[CH_RING_MDS]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);
    
    /* print the init cbht */
    cbht_print_dir(&hmo.cbht);
    /* init hte itb cache */
    itb_cache_init(&hmo.ic, icsize);
    hvfs_info(mds, "ITC init success ...\n");

    hvfs_info(mds, "total struct itb = %ld\n", sizeof(struct itb) + 
              ITB_SIZE * sizeof(struct ite));
    hvfs_info(mds, "sizeof(struct itb) = %ld\n", sizeof(struct itb));
    hvfs_info(mds, "sizeof(struct itbh) = %ld\n", sizeof(struct itbh));
    hvfs_info(mds, "sizeof(struct ite) = %ld\n", sizeof(struct ite));

    /* setup multi-threads */
    t = xzalloc(atoi(argv[5]) * sizeof(pthread_t));
    if (!t) {
        hvfs_err(mds, "xzalloc() pthread_t failed.\n");
        err = ENOMEM;
        goto out;
    }
    pa = xzalloc(atoi(argv[5]) * sizeof(struct pthread_args));
    if (!pa) {
        hvfs_err(mds, "xzalloc() pthread_args failed.\n");
        err = ENOMEM;
        goto out_free;
    }

    pthread_barrier_init(&pb, NULL, atoi(argv[5]) + 1);

    /* determine the arguments */
    threads = j = atoi(argv[5]);
    if (!model) {
        k = k / j * j;
        if (!k)
            k = 1;
    } else if (model == 1) {
        x = x / j * j;
        if (!x)
            x = 1;
    }
    for (i = 0; i < j; i++) {
        pa[i].tid = i;
        pa[i].bdepth = bdepth;
        pa[i].icsize = icsize;
        pa[i].pb = &pb;
        pa[i].threads = threads;
        if (!model) {
            pa[i].k = k / j;
            pa[i].x = x;
            err = pthread_create(&t[i], NULL, pt_main, (void *)&pa[i]);
        } else if (model == 1) {
            pa[i].k = k;
            pa[i].x = x;
            err = pthread_create(&t[i], NULL, pt_main2, (void *)&pa[i]);
        }
        if (err) {
            hvfs_err(mds, "pthread_create err %d\n", err);
            goto out_free2;
        }
    }

    /* barrier 4 times */
    for (i = 0; i < 5; i++) {
        pthread_barrier_wait(&pb);
        hvfs_info(mds, "[%s] done.\n", idx2str(i));
    }
    
    /* waiting for all the threads */
    for (i = 0; i < j; i++) {
        pthread_join(t[i], NULL);
    }

    /* get the test result */
    hvfs_info(mds, "TEST result:\n");
    for (i1 = 0; i1 < 4; i1++) {
        acc[i1] = 0.0;
        for (i = 0; i < j; i++) {
            acc[i1] += pa[i].acc[i1];
        }
        acc[i1] /= k * x;
    }
    hvfs_info(mds, "[insert lookup unlink shadow] %lf %lf %lf %lf\n", 
              acc[0], acc[1], acc[2], acc[3]);

    hvfs_info(mds, "CBHT dir depth %d\n", hmo.cbht.dir_depth);
    hvfs_info(mds, "Average ITB read  search depth %lf\n", 
              atomic64_read(&hmo.prof.itb.rsearch_depth) / 2.0 / (k * x));
    hvfs_info(mds, "Average ITB write search depth %lf\n", 
              atomic64_read(&hmo.prof.itb.wsearch_depth) / 2.0 / (k * x));
    hvfs_info(mds, "Total shadow lookup miss %ld.\n",
              atomic64_read(&miss));
    /* print the dir */
/*     cbht_print_dir(&hmo.cbht); */

out:
    return err;
out_free:
    xfree(t);
    goto out;
out_free2:
    xfree(pa);
    goto out_free;
}

int main(int argc, char *argv[])
{
    int err;

    atomic64_set(&miss, 0);
    if (argc == 6) {
        /* may be multi-thread test */
        argc--;
        if (atoi(argv[5]) > 0) {
            err = mt_main(argc, argv);
            goto out;
        }
    } else if (argc == 7) {
        argc--;
        if (atoi(argv[6]) > 0) {
            /* ok, this means we need new threads' model */
            err = mt_main(argc, argv);
            goto out;
        } else {
            /* fall back to normal threads' model */
            argc--;
            err = mt_main(argc, argv);
            goto out;
        }
    }

    err = st_main(argc, argv);
out:
    return err;
}

#endif
