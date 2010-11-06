/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-06 21:24:42 macan>
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
{
    PyObject *pDict, *value, *pTuple;
    int err = -EINVAL;

    pDict = PyDict_New();
    /* general region */
    value = PyInt_FromLong(dt_mgr->where);
    if (!value) {
        hvfs_err(lib, "Convert where to PyInt failed.\n");
        goto out;
    }
    err = PyDict_SetItemString(pDict, "where", value);
    if (err) {
        hvfs_err(lib, "Set where to directory failed.\n");
        goto out;
    }
    value = PyInt_FromLong(dt_mgr->status);
    if (!value) {
        hvfs_err(lib, "Convert status to PyInt failed.\n");
        goto out;
    }
    err = PyDict_SetItemString(pDict, "status", value);
    if (err) {
        hvfs_err(lib, "Set status to directory failed.\n");
        goto out;
    }
    
    /* region for itb */
    value = PyInt_FromLong(dt_mgr->itb->h.puuid);
    if (!value) {
        hvfs_err(lib, "Convert itb_puuid to PyInt failed.\n");
        goto out;
    }
    err = PyDict_SetItemString(pDict, "itb_puuid", value);
    if (err) {
        hvfs_err(lib, "Set itb_puuid to directory failed.\n");
        goto out;
    }

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

int ebpy_py2c(PyObject *pInstace, struct DT_mgr *dt_mgr)
{
    int err = 0;

    return err;
}

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
    int err = 0;
    
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
        return 1;
    }

    Py_DECREF(pInstance);

out:
    Py_DECREF(pIncModule);
    Py_Finalize();

    return 0;
}
#else
{
    return 0;
}
#endif
