/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-14 09:35:17 macan>
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

#include "branch.h"

#ifdef USE_BDB
int dynamic_get_sec_key(DB *db, const DBT *pkey,
                        const DBT *pdata, DBT *skey);

static int bdb_dir_make_exist(char *path)
{
    int err;

    err = mkdir(path, 0755);
    if (err) {
        err = -errno;
        if (errno == EEXIST) {
            err = 0;
        } else if (errno == EACCES) {
            hvfs_err(xnet, "Failed to create the dir %s, no permission.\n",
                     path);
        } else {
            hvfs_err(xnet, "mkdir %s failed w/ %d\n", path, errno);
        }
    }

    return err;
}

struct bdb *bdb_open(char *branch_name, char *dbname, char *prefix)
{
    char db[256];
    struct bdb *bdb;
    int envflags = DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL;
    int err = 0;
    
    err = bdb_dir_make_exist(HVFS_BP_HOME);
    if (err) {
        return NULL;
    }

    snprintf(db, 255, "%s/%s", HVFS_BP_HOME, branch_name);
    err = bdb_dir_make_exist(db);
    if (err) {
        return NULL;
    }

    snprintf(db, 255, "%s/%s/%s-%s", HVFS_BP_HOME, branch_name,
             dbname, prefix);
    err = bdb_dir_make_exist(db);
    if (err) {
        return NULL;
    }

    bdb = xzalloc(sizeof(*bdb));
    if (!bdb) {
        hvfs_err(xnet, "xzalloc() BDB failed\n");
        return NULL;
    }

    err = db_env_create(&bdb->env, 0);
    if (err) {
        hvfs_err(xnet, "Error creating DB_ENV handle w/ %d\n", err);
        goto out_free;
    }

    bdb->env->set_cachesize(bdb->env, 0, 5000000, 1);

    err = bdb->env->open(bdb->env, db, envflags, 0);
    if (err) {
        hvfs_err(xnet, "Opening the environment '%s' failed w/ %d\n",
                 db, err);
        bdb->env->close(bdb->env, 0);
        goto out_free;
    }
    INIT_LIST_HEAD(&bdb->dbs);

    return bdb;
out_free:
    xfree(bdb);
    return NULL;
}

void bdb_close(struct bdb *bdb)
{
    struct dynamic_db *pos, *n;
    int err = 0;

    if (!bdb)
        return;
    /* close active DBs */
    list_for_each_entry_safe(pos, n, &bdb->dbs, list) {
        list_del(&pos->list);
        __bdb_db_close(pos);
        xfree(pos);
    }
    
    if (bdb->env != NULL) {
        err = bdb->env->close(bdb->env, 0);
        if (err) {
            hvfs_err(xnet, "Closing env failed w/ %d\n",
                     err);
        }
    }
}

/* Now(04/12/2011), we aleays disable TXN subsystem */
#ifdef USE_BDB_TXN__DISABLED__
static inline int TXN_BEGIN(DB_ENV *env, DB_TXN *parent, 
                            DB_TXN **tid, u_int32_t flags)
{
    int err = 0;

    err = env->txn_begin(env, parent, tid, flags);
    if (err) {
        hvfs_err(xnet, "txn_begin() failed w/ %d\n", err);
        return -err;
    }

    return 0;
}
static inline int TXN_ABORT(DB_TXN *tid)
{
    return -env->txn_abort(tid);
}
static inline int TXN_COMMIT(DB_TXN *tid, u_int32_t flags)
{
    return -env->txn_commit(tid, flags);
}
#else
#define TXN_BEGIN(a, b, c, d) ({0;})
#define TXN_ABORT(a) ({0;})
#define TXN_COMMIT(a, b) ({0;})
#endif

/* db_prepare() prepare the DBs to store the line
 */
int bdb_db_prepare(struct bdb *bdb, char *db)
{
    struct dynamic_db *pos, *ddb = NULL, *base = NULL;
    int dbflags = DB_CREATE;
    int err = 0;
    
    /* traverse the list to search the active database handle */
    list_for_each_entry_reverse(pos, &bdb->dbs, list) {
        if (strcmp(pos->name, "db_base") == 0) {
            base = pos;
            break;
        }
    }

    if (!base) {
        /* if there is no BASE database, we should create it now */
        ddb = xmalloc(sizeof(*ddb));
        if (!ddb) {
            hvfs_err(xnet, "xmalloc() dynamic_db failed, drop this line\n");
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&ddb->list);
        ddb->name = strdup("db_base");
        err = db_create(&ddb->db, bdb->env, 0);
        if (err) {
            hvfs_err(xnet, "Creating base DB handle failed w/ %d\n",
                     err);
            xfree(ddb);
            return err;
        }
        err = ddb->db->open(ddb->db, NULL, "db_base", NULL, DB_BTREE,
                            dbflags, 0);
        if (err) {
            hvfs_err(xnet, "Opening db_base failed w/ %d\n", err);
            ddb->db->close(ddb->db, 0);
            xfree(ddb);
            return err;
        }
        list_add(&ddb->list, &bdb->dbs);
        base = ddb;
    }
    
    /* reset ddb to NULL to detect whether sub-database exist */
    ddb = NULL;
    list_for_each_entry(pos, &bdb->dbs, list) {
        if (strcmp(pos->name, db) == 0) {
            ddb = pos;
            break;
        }
    }

    if (!ddb) {
        /* create the sub-database now */
        ddb = xmalloc(sizeof(*ddb));
        if (!ddb) {
            hvfs_err(xnet, "xmalloc() dynamic_db failed, drop this line\n");
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&ddb->list);
        ddb->name = strdup(db);

        /* open the database */
        err = db_create(&ddb->db, bdb->env, 0);
        if (err) {
            hvfs_err(xnet, "Creating DB'%s' handle failed w/ %d\n", 
                     db, err);
            xfree(ddb);
            return -err;
        }
        ddb->db->set_flags(ddb->db, DB_DUPSORT | DB_DUP);
        err = ddb->db->open(ddb->db, NULL, db, NULL, DB_BTREE,
                            dbflags, 0);
        if (err) {
            hvfs_err(xnet, "Opening DB'%s' failed w/ %d\n", db, err);
            ddb->db->close(ddb->db, 0);
            xfree(ddb);
            return -err;
        }

        /* associate to the base db now */
        err = base->db->associate(base->db, NULL,
                                  ddb->db, dynamic_get_sec_key, 0);
        if (err) {
            hvfs_err(xnet, "Associating %s to base_db failed w/ %d\n",
                     db, err);
            ddb->db->close(ddb->db, 0);
            xfree(ddb);
            return -err;
        }
        
        /* add this db to the list */
        list_add(&ddb->list, &bdb->dbs);
    }

    return err;
}

/* db_put() push one line to database
 */
int bdb_db_put(struct bdb *bdb, struct base *p)
{
    struct dynamic_db *pos, *ddb = NULL;
    DB_TXN *txn = NULL;
    DBT key, value;
    int err = 0;
    
    /* traverse the list to search the active database handle */
    list_for_each_entry(pos, &bdb->dbs, list) {
        if (strcmp(pos->name, "db_base") == 0) {
            ddb = pos;
            break;
        }
    }

    if (!ddb) {
        hvfs_err(xnet, "Base database is missing, reject any put\n");
        return -EFAULT;
    }
    
    /* handle current line, put it to the base database */
    err = TXN_BEGIN(bdb->env, NULL, &txn, 0);
    if (err) {
        hvfs_err(xnet, "Begin a TXN failed w/ %d\n", err);
        goto out;
    }

    {
        struct base_dbs *bd;

        bd = malloc(sizeof(*bd) + strlen(p->tag) + strlen(p->kvs));
        if (!bd) {
            hvfs_err(xnet, "malloc base_dbs failed, ignore this line "
                     "'%s %s'\n", p->tag, p->kvs);
            goto bypass;
        }

        bd->tag_len = strlen(p->tag);
        bd->kvs_len = strlen(p->kvs);
        memcpy(bd->data, p->tag, strlen(p->tag));
        memcpy(bd->data + strlen(p->tag), p->kvs, strlen(p->kvs));

        hvfs_err(xnet, "inserting: tag: %s, kvs: %s\n",
                 p->tag, p->kvs);

        memset(&key, 0, sizeof(key));
        memset(&value, 0, sizeof(value));

        key.data = p->tag;
        key.size = strlen(p->tag);

        value.data = bd;
        value.size = sizeof(*bd) + strlen(p->tag) + strlen(p->kvs);

        err = ddb->db->put(ddb->db, txn, &key, &value, 0);
        switch (err) {
        case 0:
            /* ok */
            break;
        case DB_KEYEXIST:
            hvfs_err(xnet, "Key %s already exists\n", p->tag);
            break;
        default:
            hvfs_err(xnet, "Inserting %s failed w/ %d\n",
                     p->tag, err);
        }
        xfree(bd);
    bypass:;
    }
    
    err = TXN_COMMIT(txn, 0);
    if (err) {
        hvfs_err(xnet, "Commit TXN %d failed w/ %d\n", 
                 txn->id(txn), err);
        goto out;
    }

out:
    if (err > 0)
        err = -err;
    return err;
}

/* db_close() close one database
 */
int __bdb_db_close(struct dynamic_db *ddb)
{
    int err = 0;
    
    if (!ddb)
        return 0;
    err = ddb->db->close(ddb->db, 0);
    if (err) {
        hvfs_err(xnet, "Closing DB %s failed w/ %d\n",
                 ddb->name, err);
        err = -err;
    }
    xfree(ddb->name);

    return err;
}

int bdb_db_close(struct bdb *bdb, char *db)
{
    struct dynamic_db *pos, *n;
    int found = 0;

    list_for_each_entry_safe(pos, n, &bdb->dbs, list) {
        if (strcmp(db, pos->name) == 0) {
            found = 1;
            list_del(&pos->list);
            break;
        }
    }
    if (found) {
        __bdb_db_close(pos);
        xfree(pos);
    }

    return 0;
}

int dynamic_get_sec_key(DB *db, const DBT *pkey,
                        const DBT *pdata, DBT *skey)
{
    struct base_dbs *bd = (struct base_dbs *)(pdata->data);
    char kvs[bd->kvs_len + 1];
    char errbuf[100];
    char *regex;
    regex_t preg;
    regmatch_t pmatch[3];
    int err = 0, len;

    len = strlen(db->fname);
    regex = alloca(len + 64);

    memcpy(errbuf, db->fname + 3, len - 3);
    errbuf[len - 3] = '\0';
    snprintf(regex, len + 63, "(^|[ \t;,]+)%s[ \t]*=[ \t]*([^=;,]*)[,;]*",
             errbuf);

    memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
    kvs[bd->kvs_len] = '\0';

    /* parse the key/value pairs */
    memset(pmatch, 0, sizeof(pmatch));

    err = regcomp(&preg, regex, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp failed w/ %d\n", err);
        goto set_default;
    }

    err = regexec(&preg, kvs, 3, pmatch, 0);
    if (err == REG_NOMATCH) {
        hvfs_err(xnet, "regexec '%s' for %s without any match.\n", 
                 kvs, errbuf);
        goto free_reg;
    } else if (err) {
        regerror(err, &preg, errbuf, 100);
        hvfs_err(xnet, "regexec failed w/ %s\n", errbuf);
        goto free_reg;
    }

    len = pmatch[2].rm_eo - pmatch[2].rm_so;
    memcpy(errbuf, kvs + pmatch[2].rm_so, len);
    errbuf[len] = '\0';
    hvfs_err(xnet, "Matched value: '%s'\n", errbuf);

    /* construct the values */
    skey->data = bd->data + bd->tag_len + pmatch[2].rm_so;
    skey->size = len;

    regfree(&preg);

    return 0;
free_reg:
    regfree(&preg);
set_default:
    return DB_DONOTINDEX;
}

/* __get_db() get a reference from the DBs list, feel free to use it, we do
 * not close the DB until close the INDEXER operator.
 */
DB *__get_db(struct bdb *bdb, char *dbname)
{
    struct dynamic_db *pos;
    DB *__db = ERR_PTR(-ENOENT);
    char *__dbname;
    int len, err = 0;

    if (!dbname)
        return ERR_PTR(-EINVAL);
    len = strlen(dbname);
    if (!len)
        return ERR_PTR(-EINVAL);
    
    __dbname = alloca(len + 4);
    memcpy(__dbname, "db_", 3);
    memcpy(__dbname + 3, dbname, len);
    __dbname[len + 3] = '\0';

    err = bdb_db_prepare(bdb, __dbname);
    if (err) {
        hvfs_err(xnet, "Prepare DB(%s) failed w/ %d\n",
                 __dbname, err);
        goto out;
    }

    /* ok, we know this DB do exist, then we search it in the list */
    list_for_each_entry(pos, &bdb->dbs, list) {
        if (strcmp(pos->name, __dbname) == 0) {
            __db = pos->db;
            break;
        }
    }

    return __db;
out:
    if (err > 0)
        __db = ERR_PTR(-err);
    else if (err < 0)
        __db = ERR_PTR(err);

    return __db;
}

void __put_db(DB *db)
{
    /* do nothing */
}

/* for simple point query, we just do cursor lookup
 */
int bdb_point_simple(struct bdb *bdb, struct basic_expr *be,
                     void **oarray, size_t *osize)
{
    struct atomic_expr *pos = NULL;
    DB *db;
    DBC *cur;
    DBT key, pkey, value;
    int err = 0, cflag = DB_NEXT | DB_SET;

    list_for_each_entry(pos, &be->exprs, list) {
        break;
    }
    if (!pos) {
        hvfs_err(xnet, "Simple query failed w/o any valid EXPR\n");
        return -EINVAL;
    }

    /* get the database */
    db = __get_db(bdb, pos->attr);
    if (IS_ERR(db)) {
        hvfs_err(xnet, "__get_db(%s) failed w/ %ld\n", 
                 pos->attr, PTR_ERR(db));
        err = PTR_ERR(db);
        goto out;
    }

    err = db->cursor(db, NULL, &cur, 0);
    if (err) {
        hvfs_err(xnet, "DB(%s) create cursor failed w/ %d\n",
                 pos->attr, err);
        goto out_put;
    }
    
    memset(&key, 0, sizeof(key));
    memset(&pkey, 0, sizeof(pkey));
    memset(&value, 0, sizeof(value));
    key.data = pos->value;
    key.size = strlen(pos->value);
    if (*osize == 0)
        *oarray = NULL;

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

            if (strstr(skey, pos->value) != skey ||
                strcmp(skey, pos->value) < 0) {
                goto out_close;
            }

            hvfs_warning(xnet, "Get from %s => %s %s\n",
                         pos->attr, skey, xkey);
            __array = xrealloc(*oarray, *osize + value.size);
            if (!__array) {
                hvfs_err(xnet, "xrealloc() oarray failed\n");
                err = -ENOMEM;
                break;
            }
            memcpy(__array + *osize, value.data, value.size);
            *oarray = __array;
            *osize += value.size;
            break;
        }
        default:
            hvfs_err(xnet, "Get entries from DB(%s) failed w/ %d\n",
                     pos->attr, err);
        }
        cflag = DB_NEXT;
    } while (err == 0);

out_close:
    err = cur->c_close(cur);
    if (err) {
        hvfs_err(xnet, "Closing cursor failed w/ %d\n", err);
    }
    
out_put:
    __put_db(db);
out:
    return err;
}

/* for point AND, we just do normal equal join
 */
int bdb_point_and(struct bdb *bdb, struct basic_expr *be,
                  void **oarray, size_t *osize)
{
    struct atomic_expr *pos;
    DB *db;
    DBC **carray, *cur;
    DBT key, value;
    int nr = 1, i = 0, err = 0;

    list_for_each_entry(pos, &be->exprs, list) {
        nr++;
    }
    /* ok, we should alloc DBC array */
    carray = xzalloc(nr * sizeof(*carray));
    if (!carray) {
        hvfs_err(xnet, "xzalloc() DBC carray failed\n");
        err = -ENOMEM;
        goto out;
    }

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    list_for_each_entry(pos, &be->exprs, list) {
        db = __get_db(bdb, pos->attr);
        if (IS_ERR(db)) {
            hvfs_err(xnet, "__get_db(%s) failed w/ %ld\n",
                     pos->attr, PTR_ERR(db));
            err = PTR_ERR(db);
            goto out_release;
        }
        err = db->cursor(db, NULL, &cur, 0);
        if (err) {
            hvfs_err(xnet, "DB(%s) create cursor failed w/ %d\n", 
                     pos->attr, err);
            __put_db(db);
            goto out_release;
        }
        key.data = pos->value;
        key.size = strlen(pos->value);
        err = cur->c_get(cur, &key, &value, DB_SET);
        if (err == DB_NOTFOUND) {
            *oarray = NULL;
            err = 0;
            __put_db(db);
            goto out_release;
        } else if (err) {
            hvfs_err(xnet, "Cursor on DB(%s) c_get failed w/ %d\n",
                     pos->attr, err);
            __put_db(db);
            goto out_release;
        }
        carray[i++] = cur;
        __put_db(db);
    }

    /* do join now */
    db = __get_db(bdb, "base");
    if (IS_ERR(db)) {
        hvfs_err(xnet, "__get_db(base) failed w/ %ld\n",
                 PTR_ERR(db));
        err = PTR_ERR(db);
        goto out_release;
    }
    err = db->join(db, carray, &cur, 0);
    if (err) {
        hvfs_err(xnet, "Join on base DB failed w/ %d\n", err);
        __put_db(db);
        goto out_release;
    }
    /* get entries from the joined cursor */
    if (*osize == 0) {
        *oarray = NULL;
    }
    do {
        err = cur->c_get(cur, &key, &value, 0);
        switch (err) {
        case DB_NOTFOUND:
            break;
        case 0:
        {
            struct base_dbs *bd = (struct base_dbs *)(value.data);
            char tag[bd->tag_len + 1];
            char kvs[bd->kvs_len + 1];
            void *__array;

            memcpy(tag, bd->data, bd->tag_len);
            tag[bd->tag_len] = '\0';
            memcpy(kvs, bd->data + bd->tag_len, bd->kvs_len);
            kvs[bd->kvs_len] = '\0';

            hvfs_warning(xnet, "JOIN - primary key: %s => %s\n",
                         tag, kvs);
            __array = xrealloc(*oarray, *osize + value.size);
            if (!__array) {
                hvfs_err(xnet, "xrealloc() oarray failed\n");
                err = -ENOMEM;
                break;
            }
            memcpy(__array + *osize, value.data, value.size);
            *oarray = __array;
            *osize += value.size;
            break;
        }
        default:
            hvfs_err(xnet, "Get entries from joined cursor "
                     "failed w/ %d\n", err);
        }
    } while (err == 0);

    err = cur->c_close(cur);
    if (err) {
        hvfs_err(xnet, "Closing joined cursor failed w/ %d\n",
                 err);
    }
    __put_db(db);
    
out_release:
    /* FIXME: release the resource we got */
    for (i = 0; i < nr; i++) {
        if (carray[i]) {
            err = carray[i]->c_close(carray[i]);
            if (err) {
                hvfs_err(xnet, "Closing non-joined cursor failed w/ %d\n",
                         err);
            }
        }
    }

out:
    return err;
}

int __set_compare(const void *pa, const void *pb)
{
    return strcmp(((struct set_entry *)pa)->key,
                  ((struct set_entry *)pb)->key);
}

void __set_free(void *nodep)
{
    struct set_entry *se = (struct set_entry *)nodep;

    xfree(se->key);
    xfree(se);
}

void __set_action_and(const void *nodep, const VISIT which, 
                      const int depth)
{
    struct set_entry *se;
    DBT key, value;
    int err = 0;

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    switch (which) {
    case preorder:
        break;
    case postorder:
        se = *(struct set_entry **)nodep;
        if (se->target > 0 && se->nr >= se->target) {
            key.data = se->key;
            key.size = strlen(se->key);

            err = se->db->get(se->db, NULL, &key, &value, 0);
            if (err) {
                hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                         se->key, err);
            } else {
                struct base_dbs *p = (struct base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];

                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n", 
                         se->key, kvs);
            }
            /* reset the nr to 1 */
            se->target = -1;
            se->nr = 1;
        } else {
            /* add this entry to the pointer array */
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = xrealloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                hvfs_err(xnet, "xrealloc() set_entry * failed, "
                         "reserve this entry. Query tained! :(\n");
                se->nr = 1;
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            sea->size++;
            sea->array = p;
        }
        break;
    case endorder:
        break;
    case leaf:
        se = *(struct set_entry **)nodep;
        if (se->target > 0 && se->nr >= se->target) {
            key.data = se->key;
            key.size = strlen(se->key);

            err = se->db->get(se->db, NULL, &key, &value, 0);
            if (err) {
                hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                         se->key, err);
            } else {
                struct base_dbs *p = (struct base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];

                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n",
                         se->key, kvs);
            }
            /* reset the nr to 1 */
            se->target = -1;
            se->nr = 1;
        } else {
            /* add this entry to the pointer array */
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = xrealloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                hvfs_err(xnet, "xrealloc() set_entry * failed, "
                         "reserve this entry. Query tained! :(\n");
                se->nr = 1;
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            sea->size++;
            sea->array = p;
        }
        break;
    }
}

void __set_action_or(const void *nodep, const VISIT which, 
                     const int depth)
{
    struct set_entry *se;
    DBT key, value;
    int err = 0;

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    switch (which) {
    case preorder:
        break;
    case postorder:
        se = *(struct set_entry **)nodep;
        if (se->nr >= se->target) {
            key.data = se->key;
            key.size = strlen(se->key);

            err = se->db->get(se->db, NULL, &key, &value, 0);
            if (err) {
                hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                         se->key, err);
            } else {
                struct base_dbs *p = (struct base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];

                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n", 
                         se->key, kvs);
            }
            /* reset the nr to 1 */
            se->target = -1;
            se->nr = 1;
        } else {
            /* add this entry to the pointer array */
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = xrealloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                hvfs_err(xnet, "xrealloc() set_entry * failed, "
                         "reserve this entry. Query tained! :(\n");
                se->nr = 1;
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            sea->size++;
            sea->array = p;
        }
        break;
    case endorder:
        break;
    case leaf:
        se = *(struct set_entry **)nodep;
        if (se->nr >= se->target) {
            key.data = se->key;
            key.size = strlen(se->key);

            err = se->db->get(se->db, NULL, &key, &value, 0);
            if (err) {
                hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                         se->key, err);
            } else {
                struct base_dbs *p = (struct base_dbs *)(value.data);
                char kvs[p->kvs_len + 1];

                memcpy(kvs, p->data + p->tag_len, p->kvs_len);
                kvs[p->kvs_len] = '\0';
                hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n",
                         se->key, kvs);
            }
            /* reset the nr to 1 */
            se->target = -1;
            se->nr = 1;
        } else {
            /* add this entry to the pointer array */
            struct set_entry_aux *sea;
            struct set_entry **p;

            se = *(struct set_entry **)nodep;
            sea = se->sea;
            p = xrealloc(sea->array, (sea->size + 1) * sizeof(se));
            if (!p) {
                hvfs_err(xnet, "xrealloc() set_entry * failed, "
                         "reserve this entry. Query tained! :(\n");
                se->nr = 1;
                break;
            }
            sea->array = p;
            p[sea->size] = se;
            sea->size++;
            sea->array = p;
        }
        break;
    }
}

/* set_action_getall() put all the TREE node to the external array
 */
void __set_action_getall(const void *nodep, const VISIT which, 
                         const int depth)
{
    struct set_entry *se;
    struct set_entry_aux *sea;
    DBT key, value;
    int err = 0;

    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));

    switch (which) {
    case preorder:
        break;
    case postorder:
        se = *(struct set_entry **)nodep;
        key.data = se->key;
        key.size = strlen(se->key);
        
        err = se->db->get(se->db, NULL, &key, &value, 0);
        if (err) {
            hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                     se->key, err);
        } else {
            struct base_dbs *p = (struct base_dbs *)(value.data);
            struct set_entry **__p;
            char kvs[p->kvs_len + 1];
            
            memcpy(kvs, p->data + p->tag_len, p->kvs_len);
            kvs[p->kvs_len] = '\0';
            hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n", 
                     se->key, kvs);

            /* add this entry to the data array */
            sea = se->sea;
            __p = xrealloc(sea->array, sea->size + value.size);
            if (!__p) {
                hvfs_err(xnet, "xrealloc() base_dbs failed. "
                         "Query tained! :(\n");
                break;
            }
            memcpy((void *)__p + sea->size, value.data, value.size);
            sea->size += value.size;
            sea->array = __p;
        }
        break;
    case endorder:
        break;
    case leaf:
        se = *(struct set_entry **)nodep;
        key.data = se->key;
        key.size = strlen(se->key);
        
        err = se->db->get(se->db, NULL, &key, &value, 0);
        if (err) {
            hvfs_err(xnet, "Getting '%s' from the DB failed w/ %d\n",
                     se->key, err);
        } else {
            struct base_dbs *p = (struct base_dbs *)(value.data);
            struct set_entry **__p;
            char kvs[p->kvs_len + 1];
            
            memcpy(kvs, p->data + p->tag_len, p->kvs_len);
            kvs[p->kvs_len] = '\0';
            hvfs_err(xnet, "SET: Found for tag: %s: kvs %s\n", 
                     se->key, kvs);

            /* add this entry to the data array */
            sea = se->sea;
            __p = xrealloc(sea->array, sea->size + value.size);
            if (!__p) {
                hvfs_err(xnet, "xrealloc() base_dbs failed. "
                         "Query tained! :(\n");
                break;
            }
            memcpy((void *)__p + sea->size, value.data, value.size);
            sea->size += value.size;
            sea->array = __p;
        }
        break;
    }
}

int __set_add_key(void **tree, char *key, DB *db, int target,
                  struct set_entry_aux *sea)
{
    struct set_entry *se;
    void *val;

    se = xmalloc(sizeof(*se));
    if (!se) {
        return -ENOMEM;
    }
    se->key = strdup(key);
    se->nr = 1;
    se->db = db;
    se->target = target;
    se->sea = sea;

    val = tsearch((void *)se, tree, __set_compare);
    if (!val) {
        return -EFAULT;
    } else if (*(struct set_entry **)val != se) {
        xfree(se);
        se = *(struct set_entry **)val;
        se->nr++;
        se->target = target;
        return -EEXIST;
    }

    return 0;
}

/* for point OR, we should do manual OR
 */
int bdb_point_or(struct bdb *bdb, struct basic_expr *be, 
                 void **otree, struct set_entry_aux *sea)
{
    struct atomic_expr *pos;
    DB *db, *base_db;
    DBC *cur;
    DBT key, pkey, value;
    int cflag, err = 0;

    base_db = __get_db(bdb, "base");
    if (IS_ERR(base_db)) {
        hvfs_err(xnet, "__get_db(base) failed w/ %ld\n",
                 PTR_ERR(base_db));
        return PTR_ERR(base_db);
    }

    list_for_each_entry(pos, &be->exprs, list) {
        db = __get_db(bdb, pos->attr);
        if (IS_ERR(db)) {
            hvfs_err(xnet, "__get_db(%s) failed w/ %ld\n",
                     pos->attr, PTR_ERR(db));
            err = PTR_ERR(db);
            continue;
        }
        err = db->cursor(db, NULL, &cur, 0);
        if (err) {
            hvfs_err(xnet, "DB(%s) create cursor failed w/ %d\n",
                     pos->attr, err);
            __put_db(db);
            continue;
        }

        /* ok, we should insert the entries to tree */
        memset(&key, 0, sizeof(key));
        memset(&pkey, 0, sizeof(pkey));
        memset(&value, 0, sizeof(value));
        key.data = pos->value;
        key.size = strlen(pos->value);
        cflag = DB_SET;
        do {
            err = cur->c_pget(cur, &key, &pkey, &value, cflag);
            switch (err) {
            case DB_NOTFOUND:
                /* ignore this cursor, close it */
                break;
            case 0:
            {
                char skey[key.size + 1];
                char xkey[pkey.size + 1];

                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';

                if (strstr(skey, pos->value) != skey ||
                    strcmp(skey, pos->value) < 0) {
                    goto out_close;
                }
                hvfs_warning(xnet, "Got from %s => %s %s\n",
                             pos->attr, skey, xkey);
                __set_add_key(otree, xkey, base_db, 1, sea);
                break;
            }
            default:
                hvfs_err(xnet, "Cursor on DB(%s) c_get "
                         "failed w/ %d\n", pos->attr, err);
            }
            cflag = DB_NEXT;
        } while (err == 0);
        
    out_close:
        err = cur->c_close(cur);
        if (err) {
            hvfs_err(xnet, "Closing the CURSOR for DB(%s) "
                     "failed w/ %d\n", pos->attr, err);
        }
        __put_db(db);
    }
    __put_db(base_db);

    return err;
}

static inline
int __range_andor(struct bdb *bdb, struct basic_expr *be, void **tree, 
                  struct set_entry_aux *sea, DB *base_db, 
                  int end, int target)
{
    struct atomic_expr *pos;
    DB *db;
    DBC *cur;
    DBT key, pkey, value;
    struct set_entry *se;
    int cflag, err = 0, i = 0;
    
    memset(&key, 0, sizeof(key));
    memset(&value, 0, sizeof(value));
    
    list_for_each_entry(pos, &be->exprs, list) {
        db = __get_db(bdb, pos->attr);
        if (IS_ERR(db)) {
            hvfs_err(xnet, "__get_db(%s) failed w/ %ld\n",
                     pos->attr, PTR_ERR(db));
            err = PTR_ERR(db);
            continue;
        }
        err = db->cursor(db, NULL, &cur, 0);
        if (err) {
            hvfs_err(xnet, "DB(%s) create cursor failed w/ %d\n",
                     pos->attr, err);
            __put_db(db);
            continue;
        }
        
        /* ok, we should insert the entries to tree */
        key.data = pos->value;
        key.size = strlen(pos->value);
        memset(&pkey, 0, sizeof(pkey));
        cflag = DB_SET_RANGE;
        do {
            err = cur->c_pget(cur, &key, &pkey, &value, cflag);
            switch (err) {
            case DB_NOTFOUND:
                /* ignore this currsor, close it */
                break;
            case 0:
            {
                char skey[key.size + 1];
                char xkey[pkey.size + 1];
                
                memcpy(skey, key.data, key.size);
                skey[key.size] = '\0';
                memcpy(xkey, pkey.data, pkey.size);
                xkey[pkey.size] = '\0';
                
                if (strstr(skey, pos->value) != skey ||
                    strcmp(skey, pos->value) < 0) {
                    goto out_close;
                }
                hvfs_err(xnet, "Got from %s => %s %s\n",
                         pos->attr, skey, xkey);
                __set_add_key(tree, xkey, base_db, target, sea);
                break;
            }
            default:
                hvfs_err(xnet, "Cursor on DB(%s) c_get "
                         "failed w/ %d\n", pos->attr, err);
            }
            cflag = DB_NEXT;
        } while (err == 0);
        
    out_close:
        err = cur->c_close(cur);
        if (err) {
            hvfs_err(xnet, "Closing the CURSOR for DB(%s) "
                     "failed w/ %d\n", pos->attr, err);
        }
        __put_db(db);
        /* we have to break if we have handled enough exprs */
        if (++i == end) {
            /* clean up the tree now */
            struct set_entry **__se;
            
            if (end == target)
                twalk(*tree, __set_action_or);
            else
                twalk(*tree, __set_action_and);
            for (i = 0; i < sea->size; i++) {
                __se = tfind(sea->array[i], tree, __set_compare);
                if (!__se) {
                    hvfs_err(xnet, "Result tree entry is missing?\n");
                    continue;
                }
                se = *__se;
                tdelete(sea->array[i], tree, __set_compare);
                hvfs_err(xnet, "Delete SE %s from the tree in STAGE(%s)\n", 
                         se->key, pos->attr);
                xfree(se->key);
                xfree(se);
            }
            xfree(sea->array);
            memset(sea, 0, sizeof(*sea));
            break;
        }
    }

    return err;
}

/* for range AND, we should do manual range AND and or.
 *
 * Note that, we will CHANGE the basic_expr->exprs list, and restore it
 * finally!
 */
int bdb_range_andor(struct bdb *bdb, struct basic_expr *be, void **tree,
                    struct set_entry_aux *sea)
{
    struct atomic_expr *pos, *n;
    DB *base_db;
    struct list_head tlist;
    int nr, err = 0, i;
    int type;

    base_db = __get_db(bdb, "base");
    if (IS_ERR(base_db)) {
        hvfs_err(xnet, "__get_db(base) failed w/ %ld\n",
                 PTR_ERR(base_db));
        return PTR_ERR(base_db);
    }

    INIT_LIST_HEAD(&tlist);
start_loop:
    nr = 0;
    i = 0;
    type = BRANCH_SEARCH_OP_INIT;
    list_for_each_entry(pos, &be->exprs, list) {
        if (pos->type == BRANCH_SEARCH_OP_INIT) {
            nr = 1;
            break;
        }
        if (type == BRANCH_SEARCH_OP_INIT) {
            type = pos->type;
            nr++;
        } else if (type == BRANCH_SEARCH_OP_AND) {
            if (pos->type == BRANCH_SEARCH_OP_AND) {
                nr++;
            } else if (pos->type == BRANCH_SEARCH_OP_OR) {
                break;
            }
        } else if (type == BRANCH_SEARCH_OP_OR) {
            break;
        }
    }

    if (!nr)
        goto out_put;

    if (type == BRANCH_SEARCH_OP_INIT) {
        err = __range_andor(bdb, be, tree, sea, base_db, 1, 1);
        list_for_each_entry_safe(pos, n, &be->exprs, list) {
            if (pos->type == BRANCH_SEARCH_OP_INIT) {
                list_del_init(&pos->list);
                list_add_tail(&pos->list, &tlist);
                break;
            }
        }
    } else if (type == BRANCH_SEARCH_OP_AND) {
        err = __range_andor(bdb, be, tree, sea, base_db, nr, nr + 1);
        list_for_each_entry_safe(pos, n, &be->exprs, list) {
            if (i++ < nr) {
                list_del_init(&pos->list);
                list_add_tail(&pos->list, &tlist);
            }
        }
    } else if (type == BRANCH_SEARCH_OP_OR) {
        ASSERT(nr == 1, xnet);
        err = __range_andor(bdb, be, tree, sea, base_db, 1, 1);
        list_for_each_entry_safe(pos, n, &be->exprs, list) {
            if (i++ < nr) {
                list_del_init(&pos->list);
                list_add_tail(&pos->list, &tlist);
            }
        }
    }
    if (err) {
        hvfs_err(xnet, "__range_andor() failed w/ %d\n", err);
        goto out_put;
    }
    goto start_loop;
    
out_put:
    list_for_each_entry_safe(pos, n, &tlist, list) {
        list_del_init(&pos->list);
        list_add_tail(&pos->list, &be->exprs);
    }
    __put_db(base_db);

    return err;
}

#else  /* BDB dummy */
struct bdb *bdb_open(char *branch_name, char *dbname, char *prefix)
{
    hvfs_err(xnet, "Dummy BDB: open database %s-%s\n", dbname, prefix);
    /* return -EINVAL to pass NULL checking */
    return ERR_PTR(-EINVAL);
}

void bdb_close(struct bdb *bdb)
{
    hvfs_err(xnet, "Dummy BDB: close database\n");
}

int bdb_db_prepare(struct bdb *bdb, char *db)
{
    hvfs_err(xnet, "Dummy BDB: prepare database %s\n", db);
    return 0;
}

int bdb_db_put(struct bdb *bdb, struct base *p)
{
    hvfs_err(xnet, "Dummy BDB: put KV %s => %s\n",
             p->tag, p->kvs);
    return 0;
}

int bdb_point_simple(struct bdb *bdb, struct basic_expr *be,
                     void **oarray, size_t *osize)
{
    hvfs_err(xnet, "Dummy BDB: point simple lookup\n");
    return 0;
}

int bdb_point_and(struct bdb *bdb, struct basic_expr *be,
                  void **oarray, size_t *osize)
{
    hvfs_err(xnet, "Dummy BDB: point AND\n");
    return 0;
}

int bdb_point_or(struct bdb *bdb, struct basic_expr *be, void **otree,
                 struct set_entry_aux *sea)
{
    hvfs_err(xnet, "Dummy BDB: point OR\n");
    return 0;
}

int bdb_range_andor(struct bdb *bdb, struct basic_expr *be, void **tree,
                    struct set_entry_aux *sea)
{
    hvfs_err(xnet, "Dummy BDB: range AND\n");
    return 0;
}

#endif
