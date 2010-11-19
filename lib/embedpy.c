/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-20 00:19:38 macan>
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

#include "lib.h"
#include "Python.h"
#include "xtable.h"

/* This is a shadow structure of python class DT. Just for reference, nobody
 * use it in c files :) */
struct DT
{
    int where;
    int status;
    /* region for itb */
    u8 itb_depth;
    u8 itb_adepth;
    u32 itb_entries;
    u32 itb_max_offset;
    u32 itb_conflicts;
    u64 itb_puuid;
    u64 itb_itbid;
    u64 itb_hash;
    u64 itb_len;
    u64 itb_txg;
    int itb_compress_algo;
    int itb_inf;
    int itb_itu;
    int itb_ref;
    /* region for ite */
    u64 ite_hash;
    u64 ite_uuid;
    u64 ite_flag;
    u64 ite_namelen;
    /* struct column ite_column[6]; !!*/
    /* region for mdu/ls */
    u32 mdu_flags;
    u32 mdu_uid;
    u32 mdu_gid;
    u16 mdu_mode;
    u16 mdu_nlink;
    u64 mdu_size;
    u64 mdu_dev;
    u64 mdu_atime;
    u64 mdu_ctime;
    u64 mdu_mtime;
    u64 mdu_dtime;
    u32 mdu_version;
    /* sdt specific */
    void *name;
    /* link_source specific */
    u64 ls_hash;
    u64 ls_puuid;
    u64 ls_uuid;
    /* llfs_ref specific */
    u64 llfs_fsid;
    u64 llfs_rfino;
    /* gdt specific */
    u64 gdt_puuid;
    u64 gdt_salt;
    u64 gdt_psalt;
    /* kv specific */
    u32 kv_flags;
    u32 kv_len;
    u64 kv_key;
    u32 kv_klen;
    void *kv_value;
    /* hvfs_index */
    u16 hi_namelen;
    u16 hi_column;                 /* the same entry as op and kvflag */
    u32 hi_flag;
    u64 hi_uuid;
    u64 hi_hash;
    u64 hi_itbid;
    u64 hi_puuid;
    u64 hi_psalt;
    void *hi_data;
    void *hi_name;
    /* DTM? do we really need it? */
};

#define C2PY_DICT_SET(dict, input, key, value, err, out) do {       \
        value = PyLong_FromLong((input));                           \
        if (!value) {                                               \
            hvfs_err(lib, "Convert " #key " to PyLong failed.\n");  \
            goto out;                                               \
        }                                                           \
        err = PyDict_SetItemString(dict, #key, value);              \
        if (err) {                                                  \
            hvfs_err(lib, "Set " #key " to dict failed.\n");        \
            goto out;                                               \
        }                                                           \
    } while (0)

#define PY2C_MGR_SET(dict, output, key, value, err, out) do {    \
        long __tmp;                                              \
                                                                 \
        value = PyDict_GetItemString(dict, #key);                \
        if (!value) {                                            \
            hvfs_err(lib, "Get " #key " from dict failed.\n");   \
            goto out;                                            \
        }                                                        \
        __tmp = PyLong_AsLong(value);                            \
        if (__tmp == -1) {                                       \
            hvfs_err(lib, "Convert " #key " to C long failed.\n");  \
            goto out;                                               \
        }                                                           \
        output = __tmp;                                             \
    } while (0)

struct DT_mgr
{
    int where;
    int status;
    struct itb *itb;
    struct ite *ite;
    struct hvfs_index *hi;
    struct dir_trigger *dt;
};

int ebpy_c2py(struct DT_mgr *dt_mgr, PyObject **pArgs)
#ifdef USE_DT_PYTHON
{
    PyObject *pDict, *value, *pTuple;
    int err = -EINVAL;

    pDict = PyDict_New();
    
    /* general region */
    C2PY_DICT_SET(pDict, dt_mgr->where, where, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->status, status, value, err, out);

    /* region for itb */
    if (dt_mgr->itb) {
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.depth, itb_depth, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.adepth, itb_adepth, 
                      value, err, out);
        C2PY_DICT_SET(pDict, atomic_read(&dt_mgr->itb->h.entries), 
                      itb_entries, value, err, out);
        C2PY_DICT_SET(pDict, atomic_read(&dt_mgr->itb->h.max_offset), 
                      itb_max_offset, value, err, out);
        C2PY_DICT_SET(pDict, atomic_read(&dt_mgr->itb->h.conflicts), 
                      itb_conflicts, value, err, out);

        C2PY_DICT_SET(pDict, dt_mgr->itb->h.puuid, itb_puuid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.itbid, itb_itbid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.hash, itb_hash, value, err, out);
        C2PY_DICT_SET(pDict, atomic_read(&dt_mgr->itb->h.len), 
                      itb_len, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.txg, itb_txg, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.compress_algo, 
                      itb_compress_algo, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.inf, itb_inf, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->itb->h.itu, itb_itu, value, err, out);
        C2PY_DICT_SET(pDict, atomic_read(&dt_mgr->itb->h.ref),
                      itb_ref, value, err, out);
    }
    
    /* region for ite */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->hash, ite_hash, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->uuid, ite_uuid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->flag, ite_flag, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->namelen, ite_namelen, value, err, out);
    }
    
    /* region for column info */
    if (dt_mgr->ite) {
        PyObject *pList, *column;
        int i, __err;

        pList = PyList_New(6);
        if (!pList) {
            hvfs_err(lib, "create list object failed\n");
            goto out;
        }
        for (i = 0; i < 6; i++) {
            column = PyList_New(3);
            if (!column) {
                hvfs_err(lib, "create column list failed\n");
                Py_DECREF(pList);
                goto out;
            }
            value = PyLong_FromLong(dt_mgr->ite->column[i].stored_itbid);
            if (!value) {
                hvfs_err(lib, "Convert column %d stored_itbid failed.\n",
                         i);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            __err = PyList_Append(column, value);
            if (__err) {
                hvfs_err(lib, "Append stored_itbid to list failed\n");
                Py_DECREF(value);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            value = PyLong_FromLong(dt_mgr->ite->column[i].len);
            if (!value) {
                hvfs_err(lib, "Convert column %d len failed.\n", i);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            __err = PyList_Append(column, value);
            if (__err) {
                hvfs_err(lib, "Append len to list failed\n");
                Py_DECREF(value);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            value = PyLong_FromLong(dt_mgr->ite->column[i].offset);
            if (!value) {
                hvfs_err(lib, "Convert column %d offset failed.\n", i);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            __err = PyList_Append(column, value);
            if (__err) {
                hvfs_err(lib, "Append offset to list failed\n");
                Py_DECREF(value);
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
            /* append this column to the list */
            __err = PyList_Append(pList, column);
            if (__err) {
                hvfs_err(lib, "Append column to list failed\n");
                Py_DECREF(column);
                Py_DECREF(pList);
                goto out;
            }
        }
        /* set plist to the dict */
        err = PyDict_SetItemString(pDict, "columns", pList);
        if (err) {
            hvfs_err(lib, "Set columns to dict failed.\n");
            goto out;
        }
    }

    /* region for mdu/ls */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.flags, mdu_flags, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.uid, mdu_uid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.gid, mdu_gid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.mode, mdu_mode, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.nlink, mdu_nlink, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.size, mdu_size, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.dev, mdu_dev, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.atime, mdu_atime, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.ctime, mdu_ctime, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.mtime, mdu_mtime, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.dtime, mdu_dtime, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.version, mdu_version, value, err, out);
    }
    
    /* region for sdt specific */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, (u64)dt_mgr->ite->s.name, name, value, err, out);
    }
    
    /* region for link_source */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.ls.s_hash, ls_hash, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.ls.s_puuid, ls_puuid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.ls.s_uuid, ls_uuid, value, err, out);
    }
    
    /* region for llfs_ref */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.lr.fsid, llfs_fsid, 
                      value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->s.mdu.lr.rfino, llfs_rfino, 
                      value, err, out);
    }
    
    /* region for gdt specific */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->g.puuid, gdt_puuid, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->g.salt, gdt_salt, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->g.psalt, gdt_psalt, value, err, out);
    }
    
    /* region for kv specific */
    if (dt_mgr->ite) {
        C2PY_DICT_SET(pDict, dt_mgr->ite->v.flags, kv_flags, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->v.len, kv_len, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->v.key, kv_key, value, err, out);
        C2PY_DICT_SET(pDict, dt_mgr->ite->v.klen, kv_klen, value, err, out);
        C2PY_DICT_SET(pDict, (u64)dt_mgr->ite->v.value, kv_value, value, err, out);
    }

    /* region for hvfs_index */
    C2PY_DICT_SET(pDict, dt_mgr->hi->namelen, hi_namelen, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->column, hi_column, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->flag, hi_flag, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->uuid, hi_uuid, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->hash, hi_hash, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->itbid, hi_itbid, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->puuid, hi_puuid, value, err, out);
    C2PY_DICT_SET(pDict, dt_mgr->hi->psalt, hi_psalt, value, err, out);
    C2PY_DICT_SET(pDict, (u64)dt_mgr->hi->data, hi_data, value, err, out);
    C2PY_DICT_SET(pDict, (u64)dt_mgr->hi->name, hi_name, value, err, out);
    
    pTuple = PyTuple_New(1);
    PyTuple_SetItem(pTuple, 0, pDict);

    *pArgs = pTuple;
    err = 0;
    
    return err;
out:
    PyDict_Clear(pDict);
    Py_DECREF(pDict);

    return err;
}
#else
{
    return 0;
}
#endif

int ebpy_py2c(PyObject *pInstance, struct DT_mgr *dt_mgr)
#ifdef USE_DT_PYTHON
{
    PyObject *pDict, *value;
    int err = -EINVAL;
    
    pDict = PyObject_GetAttrString(pInstance, "dt");
    if (!pDict) {
        hvfs_err(lib, "Get object attr:dt failed\n");
        goto out;
    }
    /* try to get the values */
    if (dt_mgr->ite) {
        PY2C_MGR_SET(pDict, dt_mgr->ite->s.mdu.version, 
                     mdu_version, value, err ,out);
    }

out:
    return err;
}
#else
{
    return 0;
}
#endif

/* ebpy() is the main function for calling python code
 */
int ebpy(u16 where, void *i, void *e, void *hi, int status, 
         void *dt)
#ifdef USE_DT_PYTHON
{
    struct DT_mgr dm = {
        .where = where,
        .status = status,
        .itb = i,
        .ite = e,
        .hi = hi,
        .dt = dt,
    };
    struct dt_python *dp = ((struct dir_trigger *)dt)->code;
    PyObject *pName, *pModule, *pDict, *pFunc, *pDT, *pInstance;
    PyObject *pArgs, *pValue, *pIncModule;
    int err = TRIG_CONTINUE;
    
    Py_Initialize();

    /* set the path now */
    PySys_SetPath("/tmp:./");
    
    pName = PyString_FromString("dtinc");
    pIncModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (!pIncModule) {
        PyErr_Print();
        hvfs_err(lib, "Import module dtinc failed\n");
        Py_Finalize();
        return -EINVAL;
    }
    pDict = PyModule_GetDict(pIncModule);
    
    /* construct the DT class */
    pDT = PyDict_GetItemString(pDict, "DT");
    if (!pDT) {
        PyErr_Print();
        hvfs_err(lib, "get DT class failed\n");
        goto out;
    }
    /* prepare the DT object */
    err = ebpy_c2py(&dm, &pArgs);
    if (err) {
        hvfs_err(lib, "prepare the DT object failed w/ %d\n", err);
        goto out;
    }

    pInstance = PyObject_CallObject(pDT, pArgs);
    if (!pInstance) {
        PyErr_Print();
        hvfs_err(lib, "construct DT class failed\n");
        Py_DECREF(pArgs);
        goto out;
    }
    Py_DECREF(pDT);
    Py_DECREF(pArgs);

    pName = PyString_FromString(dp->module);
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pDict = PyModule_GetDict(pModule);
        pValue = PyInt_FromLong(0);
        PyDict_SetItemString(pDict, "TRIG_CONTINUE", pValue);
        pValue = PyInt_FromLong(1);
        PyDict_SetItemString(pDict, "TRIG_ABORT", pValue);

        pFunc = PyObject_GetAttrString(pModule, "dtdefault");

        if (pFunc && PyCallable_Check(pFunc)) {
            /* call with the instance */
            pArgs = PyTuple_New(1);
            PyTuple_SetItem(pArgs, 0, pInstance);
            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);
            if (pValue != NULL) {
                hvfs_debug(lib, "Result of call: %ld\n", PyInt_AsLong(pValue));
                err = ebpy_py2c(pInstance, &dm);
                /* ignore the errors */
                err = PyInt_AsLong(pValue);
                Py_DECREF(pValue);
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                hvfs_err(lib,"DT Python call failed\n");
                goto out;
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            hvfs_err(lib, "DT Python cannot find function \"dtdefault\"\n");
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        hvfs_err(lib, "DT Python failed to load \"%s\"\n", dp->module);
        return TRIG_CONTINUE;
    }

    Py_DECREF(pInstance);

out:
    Py_DECREF(pIncModule);
    Py_Finalize();

    return err;
}
#else
{
    return TRIG_CONTINUE;
}
#endif
