/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-11 17:04:57 macan>
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

#include "hvfs.h"
#include "xnet.h"
#include "mds.h"
#include "ring.h"
#include "lib.h"
#include "root.h"
#include "amc_api.h"
#include <getopt.h>
#include "branch.h"

#ifdef UNIT_TEST
void bp_cb_branch_destroy(void *arg)
{
    branch_destroy();
}

int __run_as_bp(void)
{
    struct branch_local_op blo = {
        .stat = __hvfs_stat,
        .create = __hvfs_create,
        .update = __hvfs_update,
        .read = __hvfs_fread_local,
        .write = __hvfs_fwrite_local,
    };
    int err = 0;
    
    err = branch_init(0, 0, 0, &blo);
    if (err) {
        hvfs_err(xnet, "Init the branch subsystem failed w/ %d\n", err);
        return err;
    }
    hmo.branch_dispatch = branch_dispatch_split;
    hmo.cb_branch_destroy = bp_cb_branch_destroy;

    return err;
}

void __bp_test(void)
{
    int __UNUSED__ err = 0;
    
#if 0
    err = branch_load("hello", "", 1);
    if (err) {
        hvfs_err(xnet, "branch_load() failed w/ %d\n", err);
    }
    err = branch_publish(0, 0, "hello", "test", 1, "hello world!", 12);
    if (err) {
        hvfs_err(xnet, "branch_publish() failed w/ %d\n", err);
    }
#elif 0
    struct basic_expr be = {.flag = BRANCH_SEARCH_EXPR_CHECK,};
    err = __expr_parser("r:type=svg & tag:color=gray", &be);
    if (err) {
        hvfs_err(xnet, "parse EXPR failed w/ %d\n", err);
    } else {
        __expr_close(&be);
    }
#endif
}

int main(int argc, char *argv[])
{
    char *value, *id, str_port[10], *fsid, *type, *root;
    int err = 0, port;
    
    value = getenv("id");
    if (value) {
        id = strdup(value);
    } else {
        id = "0";
    }
    value = getenv("root");
    if (value) {
        root = strdup(value);
    } else {
        root = "127.0.0.1";
    }
    value = getenv("port");
    if (value) {
        port = atoi(value) + atoi(id);
    } else {
        port = 7900 + atoi(id);
    }
    sprintf(str_port, "%d", port);
    value = getenv("fsid");
    if (value) {
        fsid = strdup(value);
    } else {
        fsid = "0";
    }
    value = getenv("type");
    if (value) {
        type = strdup(value);
    } else {
        type = "bp";
    }

    {
        char *cargv[] = {
            "bp.ut", "-d", id, "-r", root, "-p", str_port, 
            "-f", fsid, "-y", type,
        };
        argc = 11;
        
        err = __core_main(argc, cargv);
        if (err) {
            hvfs_err(xnet, "__core_main() failed w/ '%s'\n",
                     strerror(err > 0 ? err : -err));
            return err;
        }
    }

    /* ok, calling our incarnation */
    err = __run_as_bp();
    hvfs_info(xnet, "BP is UP for serving requests now.\n");

    __bp_test();

    while (1) {
        xnet_wait_any(hmo.xc);
    }

    __core_exit();

    return err;
}
#endif
