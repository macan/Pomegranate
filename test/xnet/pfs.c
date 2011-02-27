/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-02-24 11:43:12 macan>
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

#include "pfs.h"
#include "xnet.h"

/* Please use environment variables to pass HVFS specific values
 */
int main(int argc, char *argv[])
{
    char *hargv[20], *value;
    int hargc;
    int err = 0;

    /* reconstruct the HVFS arguments */
    /* setup client's self id */
    hargv[0] = "pfs.ut";
    value = getenv("id");
    if (value) {
        hargv[1] = "-d";
        hargv[2] = strdup(value);
    } else {
        hvfs_err(xnet, "Please set client ID through env: id=xxx!\n");
        return EINVAL;
    }
    /* setup root server's ip address */
    value = getenv("root");
    if (value) {
        hargv[3] = "-r";
        hargv[4] = strdup(value);
    } else {
        hvfs_err(xnet, "Please set root IP through env: root=IP!\n");
        return EINVAL;
    }
    /* setup fsid */
    value = getenv("fsid");
    if (value) {
        hargv[5] = "-f";
        hargv[6] = strdup(value);
    } else {
        hargv[5] = "-f";
        hargv[6] = "0";
    }
    /* setup client type */
    {
        hargv[7] = "-y";
        hargv[8] = "client";
    }
    /* setup self port */
    value = getenv("port");
    if (value) {
        hargv[9] = "-p";
        hargv[10] = strdup(value);
        hargc = 11;
    } else {
        hargc = 9;
    }
    /* set page size of internal page cache */
    value = getenv("ps");
    if (value) {
        size_t ps = atol(value);

        g_pagesize = getpagesize();
        if (ps > g_pagesize) {
            g_pagesize = PAGE_ROUNDUP(ps, g_pagesize);
        } else
            g_pagesize = 0;
    }
    
    err = __core_main(hargc, hargv);
    if (err) {
        hvfs_err(xnet, "__core_main() failed w/ '%s'\n",
                 strerror(err > 0 ? err : -err));
        return err;
    }
    
#if FUSE_USE_VERSION >= 26
    err = fuse_main(argc, argv, &pfs_ops, NULL);
#else
    err = fuse_main(argc, argv, &pfs_ops);
#endif
    if (err) {
        hvfs_err(xnet, "fuse_main() failed w/ %s\n",
                 strerror(err > 0 ? err : -err));
        goto out;
    }
out:
    __core_exit();

    return err;
}
