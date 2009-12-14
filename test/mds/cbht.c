/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-14 09:01:20 macan>
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

#ifdef UNIT_TEST
void hmr_print(struct hvfs_md_reply *hmr)
{
    struct hvfs_index *hi;
    struct mdu *m;
    struct link_source *ls;
    void *p = hmr->data;

    hvfs_info(mds, "hmr-> err %d, mdu_no %d, len %d, flag 0x%lx.\n", 
              hmr->err, hmr->mdu_no, hmr->len, hmr->flag);
    if (!p)
        return;
    hi = (struct hvfs_index *)p;
    hvfs_info(mds, "hmr-> HI: len %d, flag 0x%x, uuid %ld, hash %ld, itbid %ld, "
              "puuid %ld, psalt %ld\n", hi->len, hi->flag, hi->uuid, hi->hash,
              hi->itbid, hi->puuid, hi->psalt);
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

void insert_itb(u64 puuid, u64 itbid, u64 txg)
{
    struct itb *i;
    int err;
    
    i = get_free_itb();
    i->h.puuid = puuid;
    i->h.itbid = itbid;
    i->h.txg = txg;
    i->h.state = ITB_STATE_CLEAN;

    err = mds_cbht_insert(&hmo.cbht, i);
    if (err) {
        hvfs_err(mds, "mds_cbht_insert() failed %d\n", err);
    }
}

void insert_ite(u64 puuid, u64 itbid, char *name, struct mdu_update *imu,
                struct hvfs_md_reply *hmr, struct hvfs_txg *txg)
{
    struct hvfs_index *hi;
    struct mdu_update *mu;
    int len, err;

    len = sizeof(struct hvfs_index) + strlen(name) + sizeof(struct mdu_update);

    hi = xzalloc(len);
    if (!hi)
        return;

    hi->hash = hvfs_hash(puuid, (u64)name, strlen(name), HASH_SEL_EH);
    hi->puuid = puuid;
    hi->itbid = itbid;
    hi->flag |= INDEX_CREATE;
    memcpy(hi->name, name, strlen(name));
    hi->len = strlen(name);
    mu = (struct mdu_update *)((void *)hi + sizeof(struct hvfs_index) + 
                               strlen(name));
    memcpy(mu, imu, sizeof(struct mdu_update));
    hi->data = mu;

    memset(hmr, 0, sizeof(*hmr));
    err = mds_cbht_search(hi, hmr, txg);
    if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }

    xfree(hi);
}

void remove_ite(u64 puuid, u64 itbid, char *name, struct hvfs_md_reply *hmr,
                struct hvfs_txg *txg)
{
    struct hvfs_index *hi;
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
    hi->len = strlen(name);
    hi->data = NULL;

    memset(hmr, 0, sizeof(*hmr));
    err = mds_cbht_search(hi, hmr, txg);
    if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
}

void lookup_ite(u64 puuid, u64 itbid, char *name, u64 flag , 
                struct hvfs_md_reply *hmr, struct hvfs_txg *txg)
{
    struct hvfs_index *hi;
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
    hi->len = strlen(name);
    
    memset(hmr, 0, sizeof(*hmr));
    err = mds_cbht_search(hi, hmr, txg);
    if (err) {
        hvfs_err(mds, "mds_cbht_search(%ld, %ld, %s) failed %d\n", 
                 puuid, itbid, name, err);
        hvfs_err(mds, "hash 0x%20lx.\n", hvfs_hash(puuid, itbid, 
                                                   sizeof(u64), HASH_SEL_CBHT));
    }
/*     hmr_print(hmr); */
    if (!hmr->err) {
        xfree(hmr->data);
    }
    
    xfree(hi);
}

int st_main(int argc, char *argv[])
{
    struct timeval begin, end;
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    struct hvfs_txg txg = {.txg = 5,};
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
    err = mds_cbht_init(&hmo.cbht, bdepth);
    if (err) {
        hvfs_err(mds, "mds_cbht_init failed %d\n", err);
        goto out;
    }
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
    
    /* alloc one ITB */
    insert_itb(0, 134, 5);

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
            insert_ite(puuid, itbid, name, &mu, &hmr, &txg);
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
            lookup_ite(puuid, itbid, name, flag, &hmr, &txg);
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
            remove_ite(puuid, itbid, name, &hmr, &txg);
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
            lookup_ite(puuid, itbid, name, flag, &hmr, &txg);
        }
    }
    lib_timer_stop(&end);
    lib_timer_echo(&begin, &end, x * k);
    hvfs_info(mds, "Shadow lookup ite is done ...\n");
    
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
    int k, x, icsize;           /* dynamic */
    int bdepth;                 /* should be const */
    pthread_barrier_t *pb;
    double acc[4];              /* 4 operations */
};

void *pt_main(void *arg)
{
    struct pthread_args *pa = (struct pthread_args *)arg;
    struct timeval begin, end;
    struct mdu_update mu;
    struct hvfs_md_reply hmr;
    struct hvfs_txg txg = {.txg = 5,};
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
            insert_ite(puuid, itbid, name, &mu, &hmr, &txg);
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
            lookup_ite(puuid, itbid, name, flag, &hmr, &txg);
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
            remove_ite(puuid, itbid, name, &hmr, &txg);
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
            lookup_ite(puuid, itbid, name, flag, &hmr, &txg);
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
    int err;
    int i, i1, j, k, x, bdepth, icsize;
    pthread_t *t;
    pthread_barrier_t pb;
    struct pthread_args *pa;
    double acc[4];

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
    hvfs_info(mds, "CBHT UNIT TESTing (multi thread)...(%d,%d,%d,%d)\n", 
              k, x, bdepth, icsize);
    err = mds_cbht_init(&hmo.cbht, bdepth);
    if (err) {
        hvfs_err(mds, "mds_cbht_init failed %d\n", err);
        goto out;
    }
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
    j = atoi(argv[5]);
    k = k / j * j;
    for (i = 0; i < j; i++) {
        pa[i].tid = i;
        pa[i].k = k / j;
        pa[i].x = x;
        pa[i].bdepth = bdepth;
        pa[i].icsize = icsize;
        pa[i].pb = &pb;
        err = pthread_create(&t[i], NULL, pt_main, (void *)&pa[i]);
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
    hvfs_info(mds, "Average ITB search depth %lf\n", 
              atomic64_read(&hmo.profiling.itb.rsearch_depth) / 4.0 / (k * x));
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

    if (argc == 6) {
        /* may be multi-thread test */
        argc--;
        if (atoi(argv[5]) > 0) {
            err = mt_main(argc, argv);
            goto out;
        }
    }

    err = st_main(argc, argv);
out:
    return err;
}

#endif
