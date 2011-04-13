/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-12 11:04:00 macan>
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
#include <search.h>
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
    {"4::4344:4444", "type=sxx;tag:color=grab;tag:location=japan_A;",},
    {"5::4344:4555", "type=xyz;tag:color=grab;tag:location=india;",},
};

int num_records = 5;
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
int dynamic_get_sec_key(DB *db, const DBT *pkey,
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
    type_db->set_errpfx(type_db, "hvfs_bdb:db_type");
    type_db->set_flags(type_db, DB_DUPSORT);
    retval = type_db->open(type_db, NULL,
                           "db_type", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
                     "Error opening type_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                type_db, dynamic_get_sec_key, 0);
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
                                "db_tag:color", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        tag_color_db->err(tag_color_db, retval,
                          "Error opening tag_color_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                tag_color_db, dynamic_get_sec_key, 0);
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
                                   "db_tag:location", NULL, DB_BTREE, dbflags, 0);
    if(retval != 0)
    {
        tag_location_db->err(tag_location_db, retval,
                          "Error opening tag_location_db");
        return -1;
    }

    retval = base_db->associate(base_db, NULL,
                                tag_location_db, dynamic_get_sec_key, 0);
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

int dynamic_get_sec_key(DB *db, const DBT *pkey,
                        const DBT *pdata, DBT *skey)
{
    base_dbs *bd = (base_dbs *)(pdata->data);
    char kvs[bd->kvs_len + 1];
    char regex[256];
    char errbuf[100];
    regex_t preg;
    regmatch_t *pmatch;
    int err = 0, len;

    memcpy(errbuf, db->fname + 3, strlen(db->fname) - 3);
    errbuf[strlen(db->fname) - 3] = '\0';
    snprintf(regex, 255, "(^|[ \t;,]+)%s[ \t]*=[ \t]*([^=;,]*)[,;]*", 
             errbuf);

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
    printf("Matched value: '%s'\n", errbuf);

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
#if 0
    /* construct default values */
    skey->data = "NULL";
    skey->size = 4;
#else
    return DB_DONOTINDEX;
#endif
    return 0;
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
        bd = (base_dbs *)(value.data);
        char tag[bd->tag_len + 1];
        memcpy(tag, bd->data, bd->tag_len);
        tag[bd->tag_len] = '\0';
        char kvs[bd->kvs_len + 1];
        memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
        kvs[bd->kvs_len] = '\0';
        printf("Found - key: %s, refer to primary key: %s => %s\n", 
               skey, tag, kvs);
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

int lookup_type_db(char *type)
{
    DBT key, value, pkey;
    DBC *cur;
    int retval = 0;
    DB_TXN *txn;
    base_dbs *bd;

    memset(&key, 0, sizeof(key));
    memset(&pkey, 0, sizeof(pkey));
    memset(&value, 0, sizeof(value));
    key.data = type;
    key.size = strlen(type);

    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in dump_db::txn_begin");
        return -1;
    }
    retval = type_db->pget(type_db, txn, &key, &pkey, &value, 0);
    if (retval != 0) {
        env->err(env, retval,
                 "error in lookup_type_db::pget");
        retval = txn->abort(txn);
        if(retval != 0) {
            env->err(env, retval,
                     "error while aborting transaction");
            return -1;
        }
        return -1;
    }

    {
        char skey[key.size + 1];
        memcpy(skey, key.data, key.size);
        skey[key.size] = '\0';

        char xkey[pkey.size + 1];
        memcpy(xkey, pkey.data, pkey.size);
        xkey[pkey.size] = '\0';

        printf("LOOKUP - key: %s, refer to primary key: %s\n", 
               skey, xkey);
        
        bd = (base_dbs *)(value.data);
        char tag[bd->tag_len + 1];
        memcpy(tag, bd->data, bd->tag_len);
        tag[bd->tag_len] = '\0';

        char kvs[bd->kvs_len + 1];
        memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
        kvs[bd->kvs_len] = '\0';

        printf("LOOKUP - primary key: %s => %s\n", 
               tag, kvs);
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

int cursor_lookup_type_db(char *type)
{
    DBT key, value, pkey;
    DBC *cur;
    int retval = 0;
    DB_TXN *txn;
    base_dbs *bd;
    int cflag = DB_NEXT | DB_SET_RANGE;

    memset(&key, 0, sizeof(key));
    memset(&pkey, 0, sizeof(pkey));
    memset(&value, 0, sizeof(value));
    key.data = type;
    key.size = strlen(type);

    retval = env->txn_begin(env, NULL, &txn, 0);
    if(retval != 0)
    {
        env->err(env, retval,
                 "error in dump_db::txn_begin");
        return -1;
    }
    retval = type_db->cursor(type_db, txn,
                               &cur, 0);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
                     "error while opening cursor");
        goto cur_close;
    }

    do {
        retval = cur->c_pget(cur, &key, &pkey, &value, cflag);
        switch (retval) {
        case DB_NOTFOUND:
            break;
        case 0:
        {
            char skey[key.size + 1];
            memcpy(skey, key.data, key.size);
            skey[key.size] = '\0';
            
            char xkey[pkey.size + 1];
            memcpy(xkey, pkey.data, pkey.size);
            xkey[pkey.size] = '\0';

            if (!strstr(skey, type) || strcmp(skey, type) <= 0) {
                /* we have to test the range by ourselves, it is time to
                 * break */
                goto cur_close;
            }
            printf("RLOOKUP - key: %s, refer to primary key: %s\n", 
                   skey, xkey);
            
            bd = (base_dbs *)(value.data);
            char tag[bd->tag_len + 1];
            memcpy(tag, bd->data, bd->tag_len);
            tag[bd->tag_len] = '\0';
            
            char kvs[bd->kvs_len + 1];
            memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
            kvs[bd->kvs_len] = '\0';
            
            printf("RLOOKUP - primary key: %s => %s\n", 
                   tag, kvs);
            break;
        }
        default:
            type_db->err(type_db, retval,
                         "error while pgeting from cursor");
        }
        cflag = DB_NEXT;
    } while (retval == 0);

cur_close:
    retval = cur->c_close(cur);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
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

int join_db(char *type, char *tag_color, char *tag_location)
{
    DBT key, value, pkey;
    DBC *type_cur = NULL, *tag_color_cur = NULL, 
        *tag_location_cur = NULL, *join_cur = NULL;
    DBC *carray[4];
    int retval = 0;
    DB_TXN *txn = NULL;
    base_dbs *bd;
    db_recno_t dbr = 0;
    int cflag = DB_SET_RANGE, i = 0;

    memset(carray, 0, sizeof(carray));
    memset(&key, 0, sizeof(key));
    memset(&pkey, 0, sizeof(pkey));
    memset(&value, 0, sizeof(value));

    retval = type_db->cursor(type_db, txn, &type_cur, 0);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
                     "error while opening cursor");
        goto cur_close0;
    }
    retval = tag_color_db->cursor(tag_color_db, txn, &tag_color_cur, 0);
    if(retval != 0)
    {
        tag_color_db->err(tag_color_db, retval,
                          "error while opening cursor");
        goto cur_close1;
    }
    retval = tag_location_db->cursor(tag_location_db, txn, 
                                     &tag_location_cur, 0);
    if(retval != 0)
    {
        tag_location_db->err(tag_location_db, retval,
                             "error while opening cursor");
        goto cur_close2;
    }

    if (type) {
        key.data = type;
        key.size = strlen(type);
        retval = type_cur->c_get(type_cur, &key, &value, cflag);
        if (retval != 0) {
            type_db->err(type_db, retval, "error while getting from cursor");
            goto cur_close3;
        }
        carray[i++] = type_cur;
        retval = type_cur->c_count(type_cur, &dbr, 0);
        printf("TYPE cur nr %d\n", dbr);
    }

    if (tag_color) {
        key.data = tag_color;
        key.size = strlen(tag_color);
        retval = tag_color_cur->c_get(tag_color_cur, &key, &value, cflag);
        if (retval != 0) {
            tag_color_db->err(tag_color_db, retval, 
                              "error while getting from cursor");
            goto cur_close3;
        }
        carray[i++] = tag_color_cur;
        retval = tag_color_cur->c_count(tag_color_cur, &dbr, 0);
        printf("TAG:COLOR cur nr %d\n", dbr);
    }

    if (tag_location) {
        key.data = tag_location;
        key.size = strlen(tag_location);
        retval = tag_location_cur->c_get(tag_location_cur, &key, &value, cflag);
        if (retval != 0) {
            tag_location_db->err(tag_location_db, retval,
                             "error while getting from cursor");
            goto cur_close3;
        }
        carray[i++] = tag_location_cur;
        retval = tag_location_cur->c_count(tag_location_cur, &dbr, 0);
        printf("TAG:LOCATION cur nr %d\n", dbr);
    }
    
    retval = base_db->join(base_db, carray, &join_cur, 0);
    if (retval) {
        base_db->err(base_db, retval,
                     "error while joining the cursor");
        goto cur_close3;
    }

    do {
        retval = join_cur->c_get(join_cur, &key, &value, 0);
        switch (retval) {
        case DB_NOTFOUND:
            break;
        case 0:
        {
            bd = (base_dbs *)(value.data);
            char tag[bd->tag_len + 1];
            memcpy(tag, bd->data, bd->tag_len);
            tag[bd->tag_len] = '\0';
            
            char kvs[bd->kvs_len + 1];
            memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
            kvs[bd->kvs_len] = '\0';
            
            printf("JOIN - primary key: %s => %s\n", 
                   tag, kvs);
            break;
        }
        default:
            type_db->err(type_db, retval,
                         "error while pgeting from cursor");
        }
    } while (retval == 0);
    
    retval = join_cur->c_close(join_cur);
    
cur_close3:
    if (tag_location_cur) {
        retval = tag_location_cur->c_close(tag_location_cur);
        if(retval != 0)
        {
            tag_location_db->err(tag_location_db, retval,
                                 "error while closing cursor");
        }
    }
cur_close2:
    if (tag_color_cur) {
        retval = tag_color_cur->c_close(tag_color_cur);
        if(retval != 0)
        {
            tag_color_db->err(tag_color_db, retval,
                              "error while closing cursor");
        }
    }
cur_close1:
    if (type_cur) {
        retval = type_cur->c_close(type_cur);
        if(retval != 0)
        {
            type_db->err(type_db, retval,
                         "error while closing cursor");
        }
    }
cur_close0:

    return 0;
}

struct set_entry;
struct set_entry_aux
{
    size_t size;
    struct set_entry **array;
};

struct set_entry
{
    char *key;
    int nr;                     /* use atomic_t instead */
    int target;
    DB *db;
    struct set_entry_aux *sea;
};

void *root = NULL;

int __set_compare(const void *pa, const void *pb)
{
    return strcmp(((struct set_entry *)pa)->key, 
                  ((struct set_entry *)pb)->key);
}

void __set_free(void *nodep)
{
    struct set_entry *se = (struct set_entry *)nodep;

    free(se->key);
    free(se);
}

void
__set_action(const void *nodep, const VISIT which, const int depth)
{
    struct set_entry *se;
    DBT key, value;
    int retval;
    
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    
    switch (which) {
    case preorder:
        break;
    case postorder:
        se = *(struct set_entry **)nodep;
        printf("I %s nr %d\n", se->key, se->nr);
        if (se->nr == se->target) {
            key.data = se->key;
            key.size = strlen(se->key);
            
            retval = base_db->get(base_db, NULL, &key, &value, 0);
            if (retval) {
                env->err(env, retval, "error while doing get");
            } else {
                base_dbs *p = (base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];
            
                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                printf("SET: Found for tag: %s: kvs %s\n", se->key, kvs);
            }
        }
        break;
    case endorder:
        break;
    case leaf:
        se = *(struct set_entry **)nodep;
        printf("L %s nr %d\n", se->key, se->nr);
        if (se->nr == se->target) {
            key.data = se->key;
            key.size = strlen(se->key);
            
            retval = base_db->get(base_db, NULL, &key, &value, 0);
            if (retval) {
                env->err(env, retval, "error while doing get");
            } else {
                base_dbs *p = (base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];
            
                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                printf("SET: Found for tag: %s: kvs %s\n", se->key, kvs);
            }
        }
        break;
    }
}

void
__set_action_final(const void *nodep, const VISIT which, const int depth)
{
    struct set_entry *se;
    DBT key, value;
    int retval;
    
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    
    switch (which) {
    case preorder:
        break;
    case postorder:
        se = *(struct set_entry **)nodep;
        printf("I %s nr %d\n", se->key, se->nr);
        if (se->nr == se->target) {
            key.data = se->key;
            key.size = strlen(se->key);
            
            retval = base_db->get(base_db, NULL, &key, &value, 0);
            if (retval) {
                env->err(env, retval, "error while doing get");
            } else {
                base_dbs *p = (base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];
            
                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                printf("SET: Found for tag: %s: kvs %s\n", se->key, kvs);
            }
            se->nr = 1;
        } else {
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = realloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                printf("failed to realloc\n");
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            printf("inGot setp %p\n", se);
            sea->size++;
            sea->array = p;
        }
        break;
    case endorder:
        break;
    case leaf:
        se = *(struct set_entry **)nodep;
        printf("L %s nr %d\n", se->key, se->nr);
        if (se->nr == se->target) {
            key.data = se->key;
            key.size = strlen(se->key);
            
            retval = base_db->get(base_db, NULL, &key, &value, 0);
            if (retval) {
                env->err(env, retval, "error while doing get");
            } else {
                base_dbs *p = (base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];
            
                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                printf("SET: Found for tag: %s: kvs %s\n", se->key, kvs);
            }
            se->nr = 1;
        } else {
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = realloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                printf("failed to realloc\n");
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            printf("inGot setp %p\n", se);
            sea->size++;
            sea->array = p;
        }
        break;
    }
}

int __set_add_key(char *key, DB *db, int target, struct set_entry_aux *sea)
{
    struct set_entry *se;
    void *val;

    se = malloc(sizeof(*se));
    if (!se) {
        return -ENOMEM;
    }
    se->key = strdup(key);
    se->nr = 1;
    se->db = db;
    se->target = target;
    se->sea = sea;
    
    val = tsearch((void *)se, &root, __set_compare);
    printf("Add %p\n", se);
    if (!val) {
        return -EFAULT;
    } else if (*(struct set_entry **)val != se) {
        printf("This key has already exist!\n");
        free(se);
        se = *(struct set_entry **)val;
        se->nr++;
        return -EEXIST;
    }

    return 0;
}

int range_join_db(char *type, char *tag_color, char *tag_location)
{
    DBT key, value, pkey;
    DBC *type_cur = NULL, *tag_color_cur = NULL, 
        *tag_location_cur = NULL, *join_cur = NULL;
    DBC *carray[4];
    int retval = 0;
    DB_TXN *txn = NULL;
    base_dbs *bd;
    db_recno_t dbr = 0;
    struct set_entry_aux sea;
    int cflag = DB_SET_RANGE, i = 0;

    memset(carray, 0, sizeof(carray));
    memset(&key, 0, sizeof(key));
    memset(&pkey, 0, sizeof(pkey));
    memset(&value, 0, sizeof(value));

    retval = type_db->cursor(type_db, txn, &type_cur, 0);
    if(retval != 0)
    {
        type_db->err(type_db, retval,
                     "error while opening cursor");
        goto cur_close0;
    }
    retval = tag_color_db->cursor(tag_color_db, txn, &tag_color_cur, 0);
    if(retval != 0)
    {
        tag_color_db->err(tag_color_db, retval,
                          "error while opening cursor");
        goto cur_close1;
    }
    retval = tag_location_db->cursor(tag_location_db, txn, 
                                     &tag_location_cur, 0);
    if(retval != 0)
    {
        tag_location_db->err(tag_location_db, retval,
                             "error while opening cursor");
        goto cur_close2;
    }

    sea.size = 0;
    sea.array = NULL;

    if (type) {
        key.data = type;
        key.size = strlen(type);
        do {
            retval = type_cur->c_pget(type_cur, &key, &pkey, &value, cflag);
            switch (retval) {
            case DB_NOTFOUND:
                break;
            case 0:
            {
                char skey[key.size + 1];
                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';

                char xkey[pkey.size + 1];
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';

                if (strstr(skey, type) != skey || 
                    strcmp(skey, type) < 0) {
                    goto out_type;
                }
                printf("TYPE %s pKEY %s\n", skey, xkey);
                __set_add_key(xkey, base_db, 3, &sea);
                break;
            }
            default:;
            }
            cflag = DB_NEXT;
        } while (retval == 0);
        out_type:;
    }

    printf("type tree\n");
    twalk(root, __set_action);

    if (tag_color) {
        key.data = tag_color;
        key.size = strlen(tag_color);
        cflag = DB_SET_RANGE;
        do {
            retval = tag_color_cur->c_pget(tag_color_cur, &key, &pkey, 
                                           &value, cflag);
            switch (retval) {
            case DB_NOTFOUND:
                break;
            case 0:
            {
                char skey[key.size + 1];
                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';

                char xkey[pkey.size + 1];
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';

                if (strstr(skey, tag_color) != skey || 
                    strcmp(skey, tag_color) < 0) {
                    goto out_color;
                }
                printf("COLOR %s pKEY %s\n", skey, pkey);
                __set_add_key(xkey, base_db, 3, &sea);
                break;
            }
            default:;
            }
            cflag = DB_NEXT;
        } while (retval == 0);
    out_color:;
    }

    printf("color tree\n");
    twalk(root, __set_action);

    if (tag_location) {
        key.data = tag_location;
        key.size = strlen(tag_location);
        cflag = DB_SET_RANGE;
        do {
            retval = tag_location_cur->c_pget(tag_location_cur, &key, &pkey, 
                                              &value, cflag);
            switch (retval) {
            case DB_NOTFOUND:
                break;
            case 0:
            {
                char skey[key.size + 1];
                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';

                char xkey[pkey.size + 1];
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';

                if (strstr(skey, tag_location) != skey || 
                    strcmp(skey, tag_location) < 0) {
                    goto out_location;
                }
                printf("LOCATION %s pKEY %s\n", skey, pkey);
                __set_add_key(xkey, base_db, 3, &sea);
                break;
            }
            default:;
            }
            cflag = DB_NEXT;
        } while (retval == 0);
    out_location:;
    }

    printf("location tree\n");
    twalk(root, __set_action_final);
    /* delete the entries */
    printf("sea.size %d\n", sea.size);
    for (i = 0; i < sea.size; i++) {
        struct set_entry **se, *_se;
        
        se = tfind(sea.array[i], &root, __set_compare);
        printf("Got setp %p vs. %p\n", sea.array[i], *se);
        _se = *se;
        tdelete(sea.array[i], &root, __set_compare);
        free((_se)->key);
        free(_se);
    }
    twalk(root, __set_action);
    tdestroy(root, __set_free);

cur_close3:
    if (tag_location_cur) {
        retval = tag_location_cur->c_close(tag_location_cur);
        if(retval != 0)
        {
            tag_location_db->err(tag_location_db, retval,
                                 "error while closing cursor");
        }
    }
cur_close2:
    if (tag_color_cur) {
        retval = tag_color_cur->c_close(tag_color_cur);
        if(retval != 0)
        {
            tag_color_db->err(tag_color_db, retval,
                              "error while closing cursor");
        }
    }
cur_close1:
    if (type_cur) {
        retval = type_cur->c_close(type_cur);
        if(retval != 0)
        {
            type_db->err(type_db, retval,
                         "error while closing cursor");
        }
    }
cur_close0:

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
    printf("dump after base db\n");
    dump_other_db(type_db);
    printf("dump after type db\n");
    dump_other_db(tag_color_db);
    printf("dump after color db\n");
    dump_other_db(tag_location_db);
    printf("dump after location db\n");
    /* do point query */
    lookup_type_db("gif");
    lookup_type_db("svg");
    /* do range query */
    cursor_lookup_type_db("s");
    /* extended point join */
    join_db("s", "gray", "j");
    /* range join */
    range_join_db("s", "grab", "j");
    close_env();
}
