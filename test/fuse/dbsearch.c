/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-30 16:11:31 macan>
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <attr/xattr.h>
#include <time.h>
#include <sys/time.h>
#include "db.h"

static char *hvfs_home = "/mnt/hvfs/testC";

struct base_dbs
{
    int tag_len;
    int kvs_len;
    char data[0];
};

DB_ENV *env = NULL;
DB *base_db, *type_db;

/* dump the current set of <file, key_value_list>
 */
void branch_dumpbase(void *data, size_t size, char **outstr)
{
    struct base_dbs *bd, *end;
    char *out;
    
    bd = (struct base_dbs *)data;
    end = (void *)bd + size;
    out = malloc(size + 1);
    if (!out) {
        printf("malloc() data region failed\n");
        return;
    }
    memset(out, 0, size + 1);
    *outstr = out;
    while (bd < end) {
        memcpy(out, bd->data, bd->tag_len);
        out += bd->tag_len;
        *out++ = '\t';
        memcpy(out, bd->data + bd->tag_len, bd->kvs_len);
        out += bd->kvs_len;
        *out++ = '\n';
        bd = (void *)bd + sizeof(*bd) + bd->tag_len + 
            bd->kvs_len;
    }
}

void __hvfs_bench_prepare(int nr)
{
    char path[256];
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        err = open(path, O_CREAT, S_IRUSR | S_IWUSR);
        if (err < 0) {
            perror("open('./xattr.tag'):");
            err = errno;
            continue;
        }
        
        close(err);
    }
}

void __hvfs_bench_fina(int nr)
{
    char path[256];
    int i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        unlink(path);
    }
}

char *branch_name = "test_branch";
char *types[] = {
    "png",
    "jpg",
    "gif",
    "svg",
    "eps",
    "bmp",
};
int selrates[] = {
    34, 30, 20, 10, 5, 1,
};

int *selector = NULL;
int bsize = 1024 * 64;

void __hvfs_setup_selector(int nr)
{
    int i, j, idx;
    
    selector = malloc(nr * sizeof(int));
    if (!selector) {
        exit(ENOMEM);
    }
    memset(selector, 0, nr * sizeof(int));

    printf("Setting up selector ... ");
    fflush(stdout);
    for (i = 1; i < 6; i++) {
        for (j = 0; j < nr / 100 * selrates[i]; j++) {
            idx = random() % nr;
            do {
                if (selector[idx] == 0) {
                    selector[idx] = i;
                    break;
                } else {
                    idx++;
                    if (idx >= nr)
                        idx = 0;
                }
            } while (1);
        }
    }
    printf("Done.\n");
    
}

int __hvfs_dbsearch_set(int nr)
{
    char buf[bsize];
    char path[256];
    int err = 0, i;

    if (nr < 100)
        nr = 100;

    /* set up the branch */
    sprintf(buf, "pfs.branch.0.create.%s.tag.1."
            "indexer:1:0:l:plain:DB:00;"
            "indexer:2:0:r:bdb:DB:00",
            branch_name);
    err = setxattr(hvfs_home, buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('.')");
        err = errno;
        goto out;
    }
    printf("OK to create branch '%s'\n", branch_name);

    for (i = 0; i < nr; i++) {
        sprintf(buf, "pfs.tag.1.set.B:%s:type.type=%s", branch_name,
                types[selector[i]]);

        /* setxattr */
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        err = setxattr(path, buf, NULL, 0, 0);
        if (err < 0) {
            perror("setxattr(./xattr.tag):");
            err = errno;
            goto out;
        }
    }

out:
    return err;
}

int __hvfs_dbsearch_search(int nr)
{
    char buf[bsize];
    int err = 0, i;
    struct timeval begin, end;
    
    for (i = 0; i < 6; i++) {
        gettimeofday(&begin, NULL);
        sprintf(buf, "pfs.tag.1.search.B:%s.DB.00.r:type=%s", 
                branch_name, types[i]);
        err = getxattr(hvfs_home, buf, buf, sizeof(buf));
        if (err < 0) {
            err = errno;
            perror("getxattr('./xattr.tag', tag.search):");
            if (err != E2BIG) {
                /* stop now */
                goto out;
            } 
        } else {
            buf[err] = '\0';
        }

        printf("TAG SEARCH 'r:type=%s' => (%dB) {\n", types[i], err);
#if 0
        {
            char *str = NULL;
            
            branch_dumpbase(buf, err, &str);
            
            printf("%s", str);
            free(str);
        }
#endif
        printf("}\n");
        gettimeofday(&end, NULL);
        printf("Average Latency(R:%d):\t%8.2lf us\n", selrates[i], 
               (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                        (end.tv_usec - begin.tv_usec)));
    }

out:
    return err;
}

int __hvfs_dbnative_set(int nr)
{
    char buf[bsize];
    char path[256];
    char str[128];
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(buf, "%s", types[selector[i]]);

        sprintf(str, "pfs.native.1.write");
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);

        /* setxattr */
        err = setxattr(path, str, buf, strlen(buf), 0);
        if (err) {
            perror("setxattr('./xattr.normal'):");
            err = errno;
            goto out;
        }
    }

out:
    return err;
}

int __hvfs_dbnative_search(int nr)
{
    char buf[bsize];
    char path[256];
    char str[128];
    int err = 0, i, j, cnt;
    struct timeval begin, end;

    for (j = 0; j < 6; j++) {
        gettimeofday(&begin, NULL);
        cnt = 0;
        for (i = 0; i < nr; i++) {
            /* read in the entry */
            sprintf(str, "pfs.native.1.read.0.-1");
            sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
            
            err = getxattr(path, str, buf, sizeof(buf));
            if (err < 0) {
                perror("getxattr('./xattr.normal', native.read):");
                err = errno;
                goto out;
            } else {
                buf[err] = '\0';
            }
            if (strcmp(buf, types[j]) == 0) {
                cnt++;
            }
        }
        if (cnt == selrates[j] * nr / 100) {
            printf("Correct at search 'r:type=%s'\n", types[j]);
        } else
            printf("Failed  at search 'r:type=%s', (%d vs %d)\n", 
                   types[j], cnt, selrates[j]);

        gettimeofday(&end, NULL);
        printf("Average Latency(R:%d):\t%8.2lf us\n", selrates[j], 
               (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                        (end.tv_usec - begin.tv_usec)));
    }
    
out:
    return err;
}

int simple_get_sec_key(DB *db, const DBT *pkey,
                       const DBT *pdata, DBT *skey)
{
    /* construct the values */
    skey->data = pdata->data;
    skey->size = pdata->size;

    return 0;
}

int __hvfs_bench_prepare_bdb(void)
{
    char *dbname = "base_db";
    int envflags = DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL;
    int dbflags = DB_CREATE;
    int err = 0;

    /* open the env */
    err = db_env_create(&env, 0);
    if (err) {
        printf("Error creating DB_ENV handle w/ %d\n", err);
        goto out;
    }

    env->set_cachesize(env, 0, 5000000, 1);

    err = env->open(env, hvfs_home, envflags, 0);
    if (err) {
        printf("Opening the environment '%s' failed w/ %d\n",
               dbname, err);
        env->close(env, 0);
        goto out;
    }

    /* open the database */
    err = db_create(&base_db, env, 0);
    if (err) {
        env->err(env, err, "Error creating DB handle");
        goto out_close;
    }
    err = base_db->open(base_db, NULL, dbname, NULL,
                        DB_BTREE, dbflags, 0);
    if (err) {
        base_db->err(base_db, err, "Error opening base_db");
        goto out_close;
    }

    /* open the secondary database: type_db */
    err = db_create(&type_db, env, 0);
    if (err) {
        env->err(env, err, "Error creating type DB handle");
        goto out_close;
    }
    type_db->set_flags(type_db, DB_DUPSORT);
    err = type_db->open(type_db, NULL, "type", NULL, DB_BTREE, dbflags, 0);
    if (err) {
        type_db->err(type_db, err, "Error opening type_db");
        goto out_close;
    }
    err = base_db->associate(base_db, NULL,
                             type_db, simple_get_sec_key, 0);
    if (err) {
        base_db->err(base_db, err, "Error associating type_db");
        goto out_close;
    }
    
out:    
    return err;
out_close:
    env->close(env, 0);
    goto out;
}

void __hvfs_bench_fina_bdb(void)
{
    char cmd[1024];
    int err;
    
    if (!env)
        return;
    if (base_db) {
        err = base_db->close(base_db, 0);
        if (err) {
            printf("Error close base_db\n");
        }
    }
    if (type_db) {
        err = type_db->close(type_db, 0);
        if (err) {
            printf("Error close type_db\n");
        }
    }
    err = env->close(env, 0);
    if (err) {
        printf("Close the environment failed w %d\n", err);
    }
    sprintf(cmd, "rm -rf %s/*", hvfs_home);
    system(cmd);
}

int __hvfs_bdb_set(int nr)
{
    char buf[bsize];
    char path[256];
    DBT key, value;
    DB_TXN *txn = NULL;
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(buf, "%s", types[selector[i]]);
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);

        /* set it into bdb database */
        memset(&key, 0, sizeof(key));
        memset(&value, 0, sizeof(value));
        
        key.data = path;
        key.size = strlen(path);
        value.data = buf;
        value.size = strlen(buf);

        err = base_db->put(base_db, txn, &key, &value, 0);
        switch (err) {
        case 0:
            continue;
        case DB_KEYEXIST:
            base_db->err(base_db, err, "%s already exists\n", path);
            break;
        default:
            base_db->err(base_db, err, "error while inserting %s err %d",
                         path, err);
            break;
        }
    }

    return err;
}

int __hvfs_bdb_search(int nr)
{
    int err = 0, j, cnt;
    struct timeval begin, end;
    DBC *cur;
    DBT key, pkey, value;
    void *oarray = NULL;
    int osize = 0;

    for (j = 0; j < 6; j++) {
        int cflag = DB_NEXT | DB_SET;
        gettimeofday(&begin, NULL);
        cnt = 0;
        err = type_db->cursor(type_db, NULL, &cur, 0);
        if (err) {
            printf("DB(type) create cursor failed w/ %d\n", err);
            continue;
        }
        memset(&key, 0, sizeof(key));
        memset(&pkey, 0, sizeof(pkey));
        memset(&value, 0, sizeof(value));
        key.data = types[j];
        key.size = strlen(types[j]);

        do {
            err = cur->c_pget(cur, &key, &pkey, &value, cflag);
            switch (err) {
            case DB_NOTFOUND:
            /* ignore this cursor, close it */
                break;
            case 0:
            {
                void *__array;
                char skey[key.size + 1];
                char xkey[pkey.size + 1];
                
                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';

                if (strstr(skey, types[j]) != skey ||
                    strcmp(skey, types[j]) < 0) {
                    goto out_close;
                }
                
#if 0
                printf("Get from %s => %s %s\n", types[j], skey, xkey);
#else
                /* stat the orignal file */
                {
                    int fd = open(xkey, O_RDONLY);
                    if (fd > 0)
                        close(fd);
                }
#endif
                __array = realloc(oarray, osize + pkey.size);
                if (!__array) {
                    printf("xrealloc() oarray failed\n");
                    err = -ENOMEM;
                    break;
                }
                memcpy(__array + osize, pkey.data, pkey.size);
                oarray = __array;
                osize += pkey.size;
                cnt++;
                break;
            }
            default:
                printf("Get entries from DB(%s) failed w/ %d\n", 
                       types[j], err);
            }
            cflag = DB_NEXT;
        } while (err == 0);

    out_close:
        err = cur->c_close(cur);
        if (err) {
            printf("Closing cursor failed w/ %d\n", err);
        }
        
        gettimeofday(&end, NULL);
        printf("Average Latency(R:%d:%d):\t%8.2lf us\n", selrates[j], cnt,
               (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                        (end.tv_usec - begin.tv_usec)));
    }

    return err;
}

int main(int argc, char *argv[])
{
    struct timeval begin, end;
    char *value;
    int nr = 1, seed = 100;

    value = getenv("nr");
    if (value)
        nr = atoi(value);
    if (nr < 100)
        nr = 100;
    value = getenv("seed");
    if (value)
        seed = atoi(value);
    
    /* mkdirs */
    mkdir(hvfs_home, 0777);

    __hvfs_setup_selector(nr);

    /* test hvfs w/ DB */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __hvfs_dbsearch_set(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBSEARCH SET=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)) / (double)nr);

    /* wait a moment */
    printf("Press any key to continue ...\n");
    fflush(stdout);
    {
        char key;
        scanf("%c", &key);
    }

    gettimeofday(&begin, NULL);
    __hvfs_dbsearch_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBSEARCH SEARCH=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    __hvfs_bench_fina(nr);

    /* test hvfs native */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __hvfs_dbnative_set(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBNATIVE SET=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec))/ (double)nr);

    gettimeofday(&begin, NULL);
    __hvfs_dbnative_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBNATIVE SEEARCH=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    __hvfs_bench_fina(nr);
    
    /* test external bdb */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    __hvfs_bench_prepare_bdb();
    gettimeofday(&begin, NULL);
    __hvfs_bdb_set(nr);
    gettimeofday(&end, NULL);
    printf("PFS DB-BDB   SET=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));
    
    gettimeofday(&begin, NULL);
    __hvfs_bdb_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS DB-BDB   SEARCH=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));
    __hvfs_bench_fina_bdb();
    __hvfs_bench_fina(nr);
    
    return 0;
}
