/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-18 00:04:47 macan>
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

#include "mds.h"

/* The native trigger code is defined as followed:
 *
 * KEYWORDS:
 * 1. if [op/metadata/column]
 *
 *    try to detect what operation/metadata/column this trigger want to act
 *    on. For example, you can detect on mdu.ctime to find out the creation
 *    time.
 *
 * 2. update [index/op/metadata/column/log]
 *
 *    try to update the secondary index, operation(hi), metadata(mdu), or
 *    column.
 */

/* mds_prepare_dir_trigger w/ ref+1
 */
struct dhe *mds_prepare_dir_trigger(struct hvfs_index *hi)
{
    struct dhe *e;
    struct dir_trigger_mgr *dtm;

    e = mds_dh_search(&hmo.dh, hi->puuid);
    if (IS_ERR(e)) {
        return ERR_PTR(-ENOENT);
    }

    dtm = e->data;

    if (dtm && dtm->nr > 0)
        return e;
    else {
        mds_dh_put(e);
        return ERR_PTR(-ENOTRIG);
    }
}

void mds_fina_dir_trigger(struct dhe *e)
{
    if (!IS_ERR(e)) {
        /* put the dhe */
        mds_dh_put(e);
    }
}

/* Return value:
 *
 * ABORT or CONTINUE
 */
int mds_dir_trigger(u16 where, struct itb *i, struct ite *e,
                    struct hvfs_index *hi, int status,
                    struct dir_trigger_mgr *dtm)
{
    int err = TRIG_CONTINUE;
    int idx;
    
    if (!dtm || !dtm->nr)
        return TRIG_CONTINUE;

    /* travel the trigger list */
    for (idx = 0; idx < dtm->nr; idx++) {
        if (dtm->dt[idx].where != where)
            continue;
        /* do trigger operations */
        switch (dtm->dt[idx].type) {
        case DIR_TRIG_NATIVE:
            break;
        case DIR_TRIG_C:
        {
            struct dt_ccode *dc = (struct dt_ccode *)dtm->dt[idx].code;

            hvfs_info(mds, "DC %p DTM %p\n", dc, dtm);
            err = dc->dtmain(where, i, e, hi, status, &dtm->dt[idx]);
            break;
        }
        case DIR_TRIG_PYTHON:
            err = ebpy(where, i, e, hi, status, &dtm->dt[idx]);
            break;
        default:;
        }
    }
    
    return err;
}

int __mds_trigger_parse_type(struct dir_trigger *dt, char *type)
{
    int err = 0;

    if (strncmp(type, "NATV", 4) == 0) {
        dt->type = DIR_TRIG_NATIVE;
    } else if (strncmp(type, "CCCC", 4) == 0) {
        dt->type = DIR_TRIG_C;
    } else if (strncmp(type, "PYTH", 4) == 0) {
        dt->type = DIR_TRIG_PYTHON;
    } else
        err = -EINVAL;

    return err;
}

int __mds_trigger_parse_where(struct dir_trigger *dt, char *where)
{
    int err = 0;

    if (strncmp(where, "NONE", 4) == 0) {
        dt->where = DIR_TRIG_NONE;
    } else if (strncmp(where, "FORCEA", 6) == 0) {
        dt->where = DIR_TRIG_PRE_FORCE;
    } else if (strncmp(where, "FORCEB", 6) == 0) {
        dt->where = DIR_TRIG_POST_FORCE;
    } else if (strncmp(where, "CREATEA", 7) == 0) {
        dt->where = DIR_TRIG_PRE_CREATE;
    } else if (strncmp(where, "CREATEB", 7) == 0) {
        dt->where = DIR_TRIG_POST_CREATE;
    } else if (strncmp(where, "LOOKUPA", 7) == 0) {
        dt->where = DIR_TRIG_PRE_LOOKUP;
    } else if (strncmp(where, "LOOKUPB", 7) == 0) {
        dt->where = DIR_TRIG_POST_LOOKUP;
    } else if (strncmp(where, "UNLINKA", 7) == 0) {
        dt->where = DIR_TRIG_PRE_UNLINK;
    } else if (strncmp(where, "UNLINKB", 7) == 0) {
        dt->where = DIR_TRIG_POST_UNLINK;
    } else if (strncmp(where, "LINKADDA", 8) == 0) {
        dt->where = DIR_TRIG_PRE_LINKADD;
    } else if (strncmp(where, "LINKADDB", 8) == 0) {
        dt->where = DIR_TRIG_POST_LINKADD;
    } else if (strncmp(where, "UPDATEA", 7) == 0) {
        dt->where = DIR_TRIG_PRE_UPDATE;
    } else if (strncmp(where, "UPDATEB", 7) == 0) {
        dt->where = DIR_TRIG_POST_UPDATE;
    } else if (strncmp(where, "LISTA", 5) == 0) {
        dt->where = DIR_TRIG_PRE_LIST;
    } else if (strncmp(where, "LISTB", 5) == 0) {
        dt->where = DIR_TRIG_POST_LIST;
    } else
        err = -EINVAL;

    return err;
}

/* We know the dtrigger layout is as following:
 *
 * header region: TYPE(4B),WHERE(8B),PRIORITY(4B),LENGTH(4B)
 *                for now, there are three types: NATV, CCCC, PYTH
 *                WHERE: NONE, FORCE, CREATE, LOOKUP, UNLINK,
 *                       LINKADD, UPDATE, LIST (A/B)
 * trigger content: dtrigger content
 * 
 */
struct dir_trigger_mgr *mds_dtrigger_parse(void *data, size_t len)
{
    struct dir_trigger_mgr *dtm = ERR_PTR(-EINVAL);
    char *type, *where, *error;
    size_t li = 0;
    int length;
    int nr = 0, err = 0, bl, bw;

    /* find out the DTM length */
    while (li < len) {
        type = (char *)(data + li);
        where = (char *)(data + li + 4);
        length = *((int *)(data + li + 16));
        li += length + 20;
        hvfs_debug(mds, "Read to DT off %ld: type %s where %s length %d\n", 
                   li, type, where, length);
        nr++;
    }

    /* allocate the DTM */
    dtm = xzalloc(sizeof(*dtm) + nr * sizeof(struct dir_trigger));
    if (!dtm) {
        hvfs_err(mds, "xzalloc() DTM failed\n");
        return ERR_PTR(-ENOMEM);
    }

    /* fill the DTM */
    li = 0;
    nr = 0;
    while (li < len) {
        type = (char *)(data + li);
        where = (char *)(data + li + 4);
        length = *((u32 *)(data + li + 16));
        li += 20;
        err = __mds_trigger_parse_type(&dtm->dt[nr], type);
        if (err)
            goto next;
        err = __mds_trigger_parse_where(&dtm->dt[nr], where);
        if (err)
            goto next;
        dtm->dt[nr].len = length;
        if (dtm->dt[nr].type == DIR_TRIG_C) {
            /* we save the binary code to a tmp file and dlopen it */
            struct dt_ccode *dc;
            int fd;

            dc = xzalloc(sizeof(*dc));
            if (!dc) {
                hvfs_err(mds, "xmalloc() dt_ccode failed\n");
                err = -ENOMEM;
                goto next;
            }
            snprintf(dc->tmp_file, 31, "/tmp/%lx-%lx", 
                     hmo.site_id & HVFS_SITE_N_MASK,
                     lib_random(RAND_MAX));
            fd = open(dc->tmp_file, O_CREAT | O_TRUNC | O_RDWR, 
                      S_IRUSR | S_IWUSR);
            if (fd < 0) {
                hvfs_err(mds, "open to write DT file %s failed w/ %d\n",
                         dc->tmp_file, errno);
                xfree(dc);
                goto next;
            }

            bl = 0;
            do {
                bw = write(fd, data + li + bl, length - bl);
                if (bw < 0) {
                    if (errno == EINTR)
                        continue;
                    err = -errno;
                    hvfs_err(mds, "write to DT file %s failed w/ %d\n",
                             dc->tmp_file, errno);
                    break;
                }
                bl += bw;
            } while (bl < length);

            close(fd);
            hvfs_debug(mds, "Have written file %s %p\n", dc->tmp_file, dc);

            if (err) {
                unlink(dc->tmp_file);
                xfree(dc);
                goto next;
            }

            /* dlopen it */
            dc->dlhandle = dlopen(dc->tmp_file, RTLD_NOW | RTLD_LOCAL);
            if (!dc->dlhandle) {
                hvfs_err(mds, "dlopen() %s failed w/ %s\n",
                         dc->tmp_file, dlerror());
                unlink(dc->tmp_file);
                xfree(dc);
                goto next;
            }
            dlerror();
            /* get the dt_main function */
            dc->dtmain = dlsym(dc->dlhandle, "dt_main");
            if ((error = dlerror()) != NULL) {
                hvfs_err(mds, "dlsym() dt_main failed w/ %s\n",
                         error);
                dlclose(dc->dlhandle);
                unlink(dc->tmp_file);
                xfree(dc);
                goto next;
            }
            dtm->dt[nr].code = dc;
            hvfs_debug(mds, "DCCODE: %s dlhandle %p %p\n", 
                       dc->tmp_file, dc->dlhandle, dc->dtmain);
        } else if (dtm->dt[nr].type == DIR_TRIG_PYTHON) {
            /* we save the python source code to a memory buffer */
            struct dt_python *dp;
            int fd;

            dp = xzalloc(sizeof(*dp));
            if (!dp) {
                hvfs_err(mds, "xmalloc() dt_python failed\n");
                err = -ENOMEM;
                goto next;
            }
            snprintf(dp->module, 15, "%lx", lib_random(RAND_MAX));
            snprintf(dp->tmp_file, 31, "/tmp/%s.py", dp->module);
            
            fd = open(dp->tmp_file, O_CREAT | O_TRUNC | O_RDWR,
                      S_IRUSR | S_IWUSR);
            if (fd < 0) {
                hvfs_err(mds, "open to write DT file %s failed w/ %d\n",
                         dp->tmp_file, errno);
                xfree(dp);
                goto next;
            }

            bl = 0;
            do {
                bw = write(fd, data + li + bl, length - bl);
                if (bw < 0) {
                    if (errno == EINTR)
                        continue;
                    err = -errno;
                    hvfs_err(mds, "write to DT file %s failed w/ %d\n",
                             dp->tmp_file, errno);
                    break;
                }
                bl += bw;
            } while (bl < length);

            close(fd);

            if (err) {
                unlink(dp->tmp_file);
                xfree(dp);
                goto next;
            }

            dtm->dt[nr].code = dp;
        }
        nr++;
    next:
        li += length;
    }
    dtm->nr = nr;

    if (!nr) {
        xfree(dtm);
        dtm = ERR_PTR(-EINVAL);
    }

    hvfs_debug(mds, "DTM nr %d %p %p\n", nr, dtm, dtm->dt[0].code);

    return dtm;
}

void mds_dh_dt_destory(struct dhe *e)
{
    struct dir_trigger_mgr *dtm = e->data;

    e->data = NULL;
    if (!dtm || !dtm->nr) {
        xfree(dtm);
        return;
    }

    mds_dt_destroy(dtm);
    xfree(dtm);
}

void mds_dt_destroy(struct dir_trigger_mgr *dtm)
{
    int i;
    
    for (i = 0; i < dtm->nr; i++) {
        if (dtm->dt[i].type == DIR_TRIG_C) {
            /* dlclose and unlink */
            struct dt_ccode *dc = dtm->dt[i].code;

            if (dc) {
                hvfs_debug(mds, "Destroy %s dlhandle %p %p\n", 
                           dc->tmp_file, dc->dlhandle, dc);
                dlclose(dc->dlhandle);
                unlink(dc->tmp_file);
                xfree(dc);
                dtm->dt[i].code = NULL;
            }
        } else if (dtm->dt[i].type == DIR_TRIG_PYTHON) {
            /* free the python code buffer */
            struct dt_python *dp = dtm->dt[i].code;

            if (dp) {
                unlink(dp->tmp_file);
                xfree(dp);
                dtm->dt[i].code = NULL;
            }
        } else if (dtm->dt[i].type == DIR_TRIG_NATIVE) {
            dtm->dt[i].code = NULL;
        }
    }
}
