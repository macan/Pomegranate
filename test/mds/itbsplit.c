/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-08 10:30:35 macan>
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

#ifndef UNIT_TEST
#error "Sorry, you must compile this file with UNIT_TEST defined!"
#endif

#include "hvfs.h"
#include "xtable.h"
#include "mds.h"
#include "xnet.h"
#include "lib.h"
#include "ring.h"

atomic64_t miss;                /* # of shadow lookup miss */
u64 split_retry = 0;
u64 create_failed = 0;
u64 lookup_failed = 0;
u64 unlink_failed = 0;

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
    struct dhe *e;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name) + sizeof(struct mdu_update);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->psalt = hmi.gdt_salt;
    hi->flag = INDEX_CREATE;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) + 
                               strlen(name));
    memcpy(mu, imu, sizeof(struct mdu_update));
    hi->data = mu;

    /* let us compute the itbid */
    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        hvfs_err(mds, "mds_dh_search() failed w/ %d\n", err);
        goto out_free;
    }

retry:
    hi->itbid = mds_get_itbid(e, hi->hash);
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);
    if (err == -ESPLIT) {
        sched_yield();
        split_retry++;
        goto retry;
    } else if (err == -ERESTART) {
        goto retry;
    } else if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
        create_failed++;
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }

out_free:
    xfree(hi);
}

void lookup_ite(u64 puuid, u64 itbid, char *name, u64 flag, 
                struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct hvfs_txg *txg;
    struct dhe *e;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->psalt = hmi.gdt_salt;
    hi->flag = flag;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    
    /* let us compute the itbid */
    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        hvfs_err(mds, "mds_dh_search() failed w/ %d\n", err);
        goto out_free;
    }

retry:
    hi->itbid = mds_get_itbid(e, hi->hash);
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);
    if (err == -ESPLIT) {
        sched_yield();
        goto retry;
    } else if (err == -ERESTART) {
        goto retry;
    } else if (err && (flag & ITE_ACTIVE)) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s, %lx) failed %d\n", 
                 puuid, itbid, name, hi->hash, err);
        hvfs_err(mds, "ITB hash 0x%20lx.\n", 
                 hvfs_hash(puuid, itbid, sizeof(u64), HASH_SEL_CBHT));
        mds_cbht_search_dump_itb(hi);
        lookup_failed++;
    } else if (err) {
        atomic64_inc(&miss);
    }
    
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
    
out_free:
    xfree(hi);
}

void remove_ite(u64 puuid, u64 itbid, char *name, 
                struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct hvfs_txg *txg;
    struct dhe *e;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->psalt = hmi.gdt_salt;
    hi->flag = INDEX_UNLINK | INDEX_BY_NAME;
    memcpy(hi->name, name, strlen(name));
    hi->namelen = strlen(name);
    hi->data = NULL;

    /* let us compute the itbid */
    e = mds_dh_search(&hmo.dh, puuid);
    if (IS_ERR(e)) {
        err = PTR_ERR(e);
        hvfs_err(mds, "mds_dh_search() failed w/ %d\n", err);
        goto out_free;
    }

retry:
    hi->itbid = mds_get_itbid(e, hi->hash);
    memset(hmr, 0, sizeof(*hmr));
    txg = mds_get_open_txg(&hmo);
    err = mds_cbht_search(hi, hmr, txg, &txg);
    txg_put(txg);

    if (err == -ESPLIT) {
        sched_yield();
        goto retry;
    } else if (err == -ERESTART) {
        goto retry;
    } else if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
        mds_cbht_search_dump_itb(hi);
        ASSERT(0, mds);
        unlink_failed++;
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
out_free:
    xfree(hi);
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
        hvfs_err(mds, "__mds_bitmap_insert() failed %d\n", err);
        goto out_free;
    }

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

struct pthread_args
{
    int tid;                    /* thread index */
    int entry;                  /* entries for this thread */
    int threads;                /* total threads */
    pthread_barrier_t *pb;
    double acc[4];
};

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

void *random_main(void *arg)
{
    struct pthread_args *pa = (struct pthread_args *)arg;
    lib_timer_def();
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    sigset_t set;
    u64 flag;
    int i;
    char name[HVFS_MAX_NAME_LEN];

    /* block the SIGALRM */
    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &set, NULL); /* oh, we do not care about the
                                             * errs */

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel insert the ite w/ random destinations */
    lib_timer_B();
    for (i = 0; i < pa->entry; i++) {
        sprintf(name, "UT-itbsplit-%d-%d", pa->tid, i);
        insert_ite(0, 0, name, &mu, &hmr);
    }
    lib_timer_E();
    lib_timer_A(&pa->acc[0]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel lookup the ite w/ random destinations */
    lib_timer_B();
    for (i = 0; i < pa->entry; i++) {
        sprintf(name, "UT-itbsplit-%d-%d", pa->tid, i);
        flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_ACTIVE;
        lookup_ite(0, 0, name, flag, &hmr);
    }
    lib_timer_E();
    lib_timer_A(&pa->acc[1]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* parallel unlink the ite w/ random destinations */
    lib_timer_B();
    for (i = 0; i < pa->entry; i++) {
        sprintf(name, "UT-itbsplit-%d-%d", pa->tid, i);
        remove_ite(0, 0, name, &hmr);
    }
    lib_timer_E();
    lib_timer_A(&pa->acc[2]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    /* paralle shadow lookup the ite w/ random destinations */
    lib_timer_B();
    for (i = 0; i < pa->entry; i++) {
        sprintf(name, "UT-itbsplit-%d-%d", pa->tid, i);
        flag = INDEX_LOOKUP | INDEX_BY_NAME | INDEX_ITE_SHADOW;
        lookup_ite(0, 0, name, flag, &hmr);
    }
    lib_timer_E();
    lib_timer_A(&pa->acc[3]);

    /* wait for other threads */
    pthread_barrier_wait(pa->pb);

    pthread_exit(0);
}

void __ut_random(u64 entry, int thread)
{
    pthread_t *t;
    pthread_barrier_t pb;
    struct pthread_args *pa;
    double acc[4];
    int entry_per_thread;
    int err = 0, i, i1;

    /* setup multi-threads */
    t = xzalloc(thread * sizeof(pthread_t));
    if (!t) {
        hvfs_err(mds, "xzalloc() pthread_t failed.\n");
        return;
    }
    pa = xzalloc(thread * sizeof(struct pthread_args));
    if (!pa) {
        hvfs_err(mds, "xzalloc() pthread_args failed.\n");
        goto out_free;
    }
    pthread_barrier_init(&pb, NULL, thread + 1);

    /* determine the arguments */
    entry_per_thread = entry / thread;
    entry = entry_per_thread * thread; /* re-generate the total entries */
    for (i = 0; i < thread; i++) {
        pa[i].tid = i;
        pa[i].threads = thread;
        pa[i].pb = &pb;
        pa[i].entry = entry_per_thread;
        err = pthread_create(&t[i], NULL, random_main, (void *)&pa[i]);
        if (err) {
            hvfs_err(mds, "pthread_create() err %d\n", err);
            goto out_free2;
        }
    }

    /* barrier 4 times */
    for (i = 0; i < 5; i++) {
        pthread_barrier_wait(&pb);
        hvfs_info(mds, "[%s] done.\n", idx2str(i));
    }

    /* waiting for all the threads */
    for (i = 0; i < thread; i++) {
        pthread_join(t[i], NULL);
    }

    /* get the test result */
    hvfs_info(mds, "TEST result:\n");
    for (i1 = 0; i1 < 4; i1++) {
        acc[i1] = 0.0;
        for (i = 0; i < thread; i++) {
            acc[i1] += pa[i].acc[i1];
        }
        acc[i1] /= entry;
    }
    hvfs_info(mds, "[insert lookup unlink shadow] %lf %lf %lf %lf\n", 
              acc[0], acc[1], acc[2], acc[3]);

    hvfs_info(mds, "CBHT dir depth %d\n", hmo.cbht.dir_depth);
    hvfs_info(mds, "Average ITB read  search depth %lf\n", 
              atomic64_read(&hmo.prof.itb.rsearch_depth) / 2.0 / (entry));
    hvfs_info(mds, "Average ITB write search depth %lf\n", 
              atomic64_read(&hmo.prof.itb.wsearch_depth) / 2.0 / (entry));
    hvfs_info(mds, "Total shadow lookup miss %ld.\n",
              atomic64_read(&miss));
    hvfs_info(xnet, "Split_retry %ld, FAILED:[create,lookup,unlink] "
              "%ld %ld %ld\n",
              split_retry, create_failed, lookup_failed, unlink_failed);

out_free2:
    xfree(pa);
out_free:
    xfree(t);
}

#define MODEL_DEFAULT   0
#define MODEL_RANDOM    0       /* NN */
#define MODEL_II        1
#define MODEL_NI        2

static inline
char *model2str(int model)
{
    switch (model) {
    case MODEL_RANDOM:
        return "random";
        break;
    case MODEL_II:
        return "1-to-1";
        break;
    case MODEL_NI:
        return "N-to-1";
        break;
    default:
        return NULL;
    }
}

int main(int argc, char *argv[])
{
    char *value;
    u64 entry = 0;              /* total # of entries inserted */
    int thread = 0;             /* total # of threads */
    int model = 0;              /* test model */
    int csize = 0;
    int err = 0;

    value = getenv("entry");
    if (value) {
        entry = atoi(value);
    }
    if (!entry)
        entry = 1000;

    value = getenv("thread");
    if (value) {
        thread = atoi(value);
    }
    if (!thread)
        thread = 1;

    value = getenv("model");
    if (value) {
        if (strncmp(value, "random", 6) == 0) {
            model = MODEL_RANDOM;
        } else if (strncmp(value, "ii", 2) == 0) {
            model = MODEL_II;
        } else if (strncmp(value, "ni", 2) == 0) {
            model = MODEL_NI;
        } else {
            model = MODEL_DEFAULT;
        }
    } else
        model = MODEL_DEFAULT;

    value = getenv("cache");
    if (value) {
        csize = atoi(value);
    }

    hvfs_info(mds, "ITB SPLIT UNIT TESTing (%ld,%d,%d) Model(%s)...\n",
              entry, thread, csize, model2str(model));

#ifdef HVFS_DEBUG_LOCK
    lock_table_init();
#endif
    lib_init();
    mds_pre_init();
    err = mds_init(10);
    if (err) {
        hvfs_err(mds, "mds_init() failed w/ %d\n", err);
        goto out;
    }
    hmo.site_id = HVFS_MDS(0);
    hmi.gdt_salt = lib_random(0xfffffff);
    hmo.conf.itbid_check = 1;
    hvfs_info(mds, "Select GDT salt to %ld\n", hmi.gdt_salt);

    if (csize) {
        itb_cache_init(&hmo.ic, csize);
    }

    ring_add(&hmo.chring[CH_RING_MDS], HVFS_MDS(0));
    ring_dump(hmo.chring[CH_RING_MDS]);

    /* insert the GDT DH */
    dh_insert(hmi.gdt_uuid, hmi.gdt_uuid, hmi.gdt_salt);
    bitmap_insert(0, 0);

    /* it is ok to begin our test */
    switch (model) {
    case MODEL_RANDOM:
        __ut_random(entry, thread);
        break;
    case MODEL_II:
        break;
    case MODEL_NI:
        break;
    default:
        hvfs_err(mds, "Invalid test model %d\n", model);
    }

    /* finalize */
    dh_remove(hmi.gdt_uuid);
    mds_destroy();

out:
    return err;
}
