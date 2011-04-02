/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-02 16:54:10 macan>
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
#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "db.h"

typedef struct
{
    char *tag;
    char *kvs;
} base;

typedef struct
{
    int tag_len;
    int kvs_len;
    char data[0];
} base_dbs;                     /* base saved to datablse */

base records[] =
{
    {"1::1324:1213", "type=png;tag:color=rgb;tag:location=china;",},
    {"2::1234:1234", "type=jpeg;tag:color=ymk;tag:location=usa;",},
    {"3::4444:4444", "type=svg;tag:color=gray;tag:location=japan;",},
};

int num_records = 3;
DB_ENV *env;
char *env_home = "./";
DB *base_db, *type_db, *tag_color_db, *tag_location_db;

int open_env();
int open_db();
int load_db();
int dump_db();
void close_env();
int get_sec_key(DB *db, const DBT *pkey,
                const DBT *pdata, DBT *skey, char *what);
int type_get_sec_key(DB *db, const DBT *pkey,
                     const DBT *pdata, DBT *skey);
int tag_color_get_sec_key(DB *db, const DBT *pkey,
                          const DBT *pdata, DBT *skey);
int tag_location_get_sec_key(DB *db, const DBT *pkey,
                             const DBT *pdata, DBT *skey);
int read_rec();
int update_rec();
int delete_rec();

int open_env()
{
    int retval = 0;

    retval = db_env_create(&env, 0);
    if(retval != 0)
    {
        printf("Error creating DB_ENV handle: err: %d\n",
               retval);
        return -1;
    }

    env->set_errpfx(env, "hvfs_bdb");
    env->set_data_dir(env, "./");
    env->set_cachesize(env, 0, 5000000, 1);

    int envflags = DB_CREATE | DB_INIT_LOCK |
        DB_INIT_LOG | DB_INIT_MPOOL |
        DB_INIT_TXN | DB_RECOVER;

    retval = env->open(env, env_home, envflags, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "Error opening the environment");
        env->close(env, 0);
        return -1;
    }

    return 0;
}

int open_db()
{
    int retval = 0;
    /* open the primary database */
    retval = db_create(&base_db, env, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "Error creating DB handle");
        return -1;
    }
    base_db->set_errpfx(base_db, "hvfs_bdb:base_db");
    int dbflags = DB_CREATE | DB_AUTO_COMMIT;
    retval = base_db->open(base_db, NULL, "base_db",
                             NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                       "Error opening base_db");
        return -1;
    }
    /* open the secondary database: type */
    retval = db_create(&type_db, env, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "Error creating DB handle");
        return -1;
    }
    type_db->set_errpfx(type_db, "hvfs_bdb:type_db");
    type_db->set_flags(type_db, DB_DUPSORT);
    retval = type_db->open(type_db, NULL,
                           "type_db", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
                     "Error opening type_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                type_db, type_get_sec_key, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                     "Error associating type_db");
        return -1;
    }

    /* open the secondary database: tag_color */
    retval = db_create(&tag_color_db, env, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "Error creating DB handle");
        return -1;
    }
    tag_color_db->set_errpfx(tag_color_db, "hvfs_bdb:tag_color_db");
    tag_color_db->set_flags(tag_color_db, DB_DUPSORT);
    retval = tag_color_db->open(tag_color_db, NULL,
                                "tag_color_db", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        tag_color_db->err(tag_color_db, retval,
                          "Error opening tag_color_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                tag_color_db, tag_color_get_sec_key, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                     "Error associating tag_color_db");
        return -1;
    }
    /* open the secondary database: tag_location */
    retval = db_create(&tag_location_db, env, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "Error creating DB handle");
        return -1;
    }
    tag_location_db->set_errpfx(tag_location_db, "hvfs_bdb:tag_location_db");
    tag_location_db->set_flags(tag_location_db, DB_DUPSORT);
    retval = tag_location_db->open(tag_location_db, NULL,
                                "tag_location_db", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        tag_location_db->err(tag_location_db, retval,
                          "Error opening tag_location_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                tag_location_db, tag_location_get_sec_key, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                     "Error associating tag_location_db");
        return -1;
    }
    return 0;
}

int get_sec_key(DB *db, const DBT *pkey,
                const DBT *pdata, DBT *skey, char *what)
{
    base_dbs *bd = (base_dbs *)(pdata->data);
    char kvs[bd->kvs_len + 1];
    char regex[256];
    char errbuf[100];
    regex_t preg;
    regmatch_t *pmatch;
    int err = 0, len;

    if (!strlen(what)) {
        goto set_default;
    }

    snprintf(regex, 255, "(^|[ \t;,]+)%s[ \t]*=[ \t]*([^=;,]*)[,;]*", 
             what);

    memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
    kvs[bd->kvs_len] = '\0';

    /* parse the key/value pairs */
    pmatch = malloc(3 * sizeof(regmatch_t));
    if (!pmatch) {
        printf("malloc regmatch_t failed\n");
        goto set_default;
    }
    memset(pmatch, 0, 3 * sizeof(regmatch_t));

    err = regcomp(&preg, regex, REG_EXTENDED);
    if (err) {
        printf("regcomp failed w/ %d\n", err);
        goto free_pmatch;
    }

    err = regexec(&preg, kvs, 3, pmatch, 0);
    if (err == REG_NOMATCH) {
        printf("regexec '%s' without any match.\n", kvs);
        goto free_reg;
    } else if (err) {
        regerror(err, &preg, errbuf, 100);
        printf("regexec failed w/ %s\n", errbuf);
        goto free_reg;
    }

    len = pmatch[2].rm_eo - pmatch[2].rm_so;
    memcpy(errbuf, kvs + pmatch[2].rm_so, len);
    errbuf[len] = '\0';
    printf("Matched value: '%s' for %s\n", errbuf, what);

    /* construct the values */
    skey->data = bd->data + bd->tag_len + pmatch[2].rm_so;
    skey->size = len;
               
    regfree(&preg);
    free(pmatch);
    
    return 0;
free_reg:
    regfree(&preg);
free_pmatch:
    free(pmatch);
set_default:
    /* construct default values */
    skey->data = "NULL";
    skey->size = 4;
    return 0;
}

int type_get_sec_key(DB *db, const DBT *pkey,
                     const DBT *pdata, DBT *skey)
{
    return get_sec_key(db, pkey, pdata, skey, "type");
}

int tag_color_get_sec_key(DB *db, const DBT *pkey,
                          const DBT *pdata, DBT *skey)
{
    return get_sec_key(db, pkey, pdata, skey, "tag:color");
}

int tag_location_get_sec_key(DB *db, const DBT *pkey,
                             const DBT *pdata, DBT *skey)
{
    return get_sec_key(db, pkey, pdata, skey, "tag:location");
}

int load_db()
{
    int retval = 0;

    DBT key;
    DBT value;
    DB_TXN *txn;
    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in load_db::txn_begin");
        return -1;
    }
    int i;
    for(i = 0; i < num_records; i++){
        base *p = &records[i];
        base_dbs *bd;

        bd = malloc(sizeof(*bd) + strlen(p->tag) + strlen(p->kvs));
        if (!bd)
            continue;

        bd->tag_len = strlen(p->tag);
        bd->kvs_len = strlen(p->kvs);
        memcpy(bd->data, p->tag, strlen(p->tag));
        memcpy(bd->data + strlen(p->tag), p->kvs, strlen(p->kvs));
        
        printf("inserting: tag: %s, kvs: %s\n",
               p->tag, p->kvs);

        memset(&key, 0, sizeof(key));
        memset(&value, 0, sizeof(value));

        key.data = p->tag;
        key.size = strlen(p->tag);

        value.data = bd;
        value.size = sizeof(*bd) + strlen(p->tag) + strlen(p->kvs);

        retval = base_db->put(base_db, txn, &key, &value, 0);
        switch(retval)
        {
        case 0:
            printf("put successful\n");
            continue;
        case DB_KEYEXIST:
            base_db->err(base_db, retval,
                         "%d already exists\n", records[i].tag);
            break;
        default:
            base_db->err(base_db, retval,
                         "error while inserting %d error %d",
                         records[i].tag, retval);
            break;
        }
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
            return -1;
        }
        free(bd);
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        return -1;
    }
    return 0;
}

int update_rec()
{
    int retval = 0;
    char *tag = "2::1234:1234";
    DBT key;
    DBT value;
    DB_TXN *txn;

    memset(&key, 0, sizeof(key));
    memset(&key, 0, sizeof(value));

    key.data = tag;
    key.size = strlen(tag);
    
    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in load_db::txn_begin");
        return -1;
    }
    retval = base_db->get(base_db, txn, &key, &value, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval, "error in get");
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
        }
        return -1;
    }

    base_dbs *bd = (base_dbs *)(value.data);
    base_dbs *nbd;
    char *new_kvs = "type=gif;tag:color=rgb;tag:location=china.henan";
    int len = sizeof(*bd) + bd->tag_len + strlen(new_kvs);

    nbd = malloc(len);
    if (!nbd) {
        base_db->err(base_db, retval, "failed to malloc base_dbs");
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
        }
        return -1;
    }
    nbd->tag_len = bd->tag_len;
    nbd->kvs_len = strlen(new_kvs);
    memcpy(nbd->data, bd->data, bd->tag_len);
    memcpy(nbd->data + bd->tag_len, new_kvs, strlen(new_kvs));

    value.data = nbd;
    value.size = len;
    retval = base_db->put(base_db, txn, &key, &value, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval, "error in put");
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
        }
        free(nbd);
        return -1;
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        free(nbd);
        return -1;
    }
    free(nbd);
    return 0;
}

int read_rec()
{
    int retval = 0;
    char *tag = "1::1324:1213";
    DBT key;
    DBT value;
    DB_TXN *txn;

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    key.data = tag;
    key.size = strlen(tag);

    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in load_db::txn_begin");
        return -1;
    }
    retval = base_db->get(base_db, txn,
                          &key, &value, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval, "error in get");
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
            return -1;
        }
        return -1;
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        return -1;
    }
    base_dbs *p = (base_dbs *)(value.data);
    char kvs[p->kvs_len + 1];

    memcpy(kvs, p->data + p->tag_len, p->kvs_len);
    kvs[p->kvs_len] = '\0';
    printf("Single read: Found for tag: %s: kvs %s\n", tag, kvs);

    return 0;
}
int delete_rec()
{
    int retval = 0;
    DB_TXN *txn;
    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in delete_rec::txn_begin");
        return -1;
    }
    char *tag = "1::1324:1213";
    DBT key;
    memset(&key, 0, sizeof(key));
    key.data = tag;
    key.size = strlen(tag);
    retval = base_db->del(base_db, txn, &key, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval, "error in delete_rec::del");
        retval = txn->abort(txn);
        if(retval != 0)
        {
            env->err(env, retval,
                     "error while aborting transaction");
            return -1;
        }
        return -1;
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        return -1;
    }
    return 0;
}

int dump_db()
{
    DBT key, value;
    DBC *cur;
    int retval = 0;
    DB_TXN *txn;
    base_dbs *bd;

    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in dump_db::txn_begin");
        return -1;
    }
    retval = base_db->cursor(base_db, txn, &cur, 0);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                     "error while opening cursor");
    }

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    while(!(retval =
            cur->c_get(cur, &key, &value, DB_NEXT)))
    {
        char tag[key.size + 1];
        memcpy(tag, key.data, key.size);
        tag[key.size] = '\0';

        bd = (base_dbs *)(value.data);
        char kvs[bd->kvs_len + 1];

        memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
        kvs[bd->kvs_len] = '\0';
        printf("Found - tag: %s, kvs %s\n", tag, kvs);
    }
    retval = cur->c_close(cur);
    if(retval != 0)
    {
        base_db->err(base_db, retval,
                     "error while closing cursor");
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        return -1;
    }
    return 0;
}

int dump_other_db(DB *db)
{
    DBT key, value;
    DBC *cur;
    int retval = 0;
    DB_TXN *txn;
    base_dbs *bd;

    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in dump_db::txn_begin");
        return -1;
    }
    retval = db->cursor(db, txn, &cur, 0);
    if(retval != 0)
    {
        db->err(db, retval,
                     "error while opening cursor");
    }

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    while(!(retval =
            cur->c_get(cur, &key, &value, DB_NEXT)))
    {
        char skey[key.size + 1];
        memcpy(skey, key.data, key.size);
        skey[key.size] = '\0';
        char tag[value.size + 1];
        memcpy(tag, value.data, value.size);
        tag[value.size] = '\0';
        printf("Found - key: %s, refer to primary key: %s(%d)\n", 
               skey, tag, value.size);
    }
    retval = cur->c_close(cur);
    if(retval != 0)
    {
        db->err(db, retval,
                     "error while closing cursor");
    }
    retval = txn->commit(txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error while committing transaction");
        return -1;
    }
    return 0;
}

void close_env()
{
    int retval = 0;
    if(tag_location_db != NULL)
    {
        retval = tag_location_db->close(tag_location_db, 0);
        if(retval != 0)
            printf("error closing type_db\n");
    }
    if(tag_color_db != NULL)
    {
        retval = tag_color_db->close(tag_color_db, 0);
        if(retval != 0)
            printf("error closing type_db\n");
    }
    if(type_db != NULL)
    {
        retval = type_db->close(type_db, 0);
        if(retval != 0)
            printf("error closing type_db\n");
    }
    if(base_db != NULL)
    {
        retval = base_db->close(base_db, 0);
        if(retval != 0)
            printf("error closing base_db\n");
    }
    if(env != NULL)
    {
        retval = env->close(env, 0);
        if(retval != 0)
            printf("error closing env\n");
    }
}
int main(int argc, char **argv)
{
    if(open_env())
        return;
    if(open_db())
        return;
    if(load_db())
        return;
    dump_db();
    read_rec();
    delete_rec();
    printf("dump after delete\n");
    dump_db();

    update_rec();
    printf("dump after update\n");
    dump_db();
    dump_other_db(type_db);
    dump_other_db(tag_color_db);    
    dump_other_db(tag_location_db);
    close_env();
}
