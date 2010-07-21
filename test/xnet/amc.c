/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-07-21 23:00:00 macan>
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

/* Note that the AMC client just wrapper the mds core functions to act as a
 * standalone program. The API exported by this file can be called by the
 * python program.
 */

#ifdef UNIT_TEST
int main(int argc, char *argv[])
{
    u64 uuid, salt;
    int err = 0;
    
    err = __core_main(argc, argv);
    if (err) {
        hvfs_err(xnet, "__core_main() failed w/ '%s'\n", 
                 strerror(err > 0 ? err : -err));
        return err;
    }

    err = hvfs_create_root();
    if (err) {
        hvfs_err(xnet, "hvfs_create_root() failed w/ %d\n", err);
        goto out;
    }

    err = hvfs_create_table("table_a");
    if (err) {
        hvfs_err(xnet, "hvfs_create_table() failed w/ %d\n", err);
        goto out;
    }

    err = hvfs_find_table("table_a", &uuid, &salt);
    if (err) {
        hvfs_err(xnet, "hvfs_find_table() failed w/ %d\n", err);
        goto out;
    }
    hvfs_info(xnet, "table_a uuid %lx salt %lx\n", uuid, salt);

    {
        char *line;
        
        err = hvfs_put("table_a", 0x0001, "hello, world!", 0);
        if (err) {
            hvfs_err(xnet, "hvfs_put() failed w/ %d\n", err);
            goto clean;
        }
        err = hvfs_get("table_a", 0x0001, &line, 0);
        if (err) {
            hvfs_err(xnet, "hvfs_get() failed w/ %d\n", err);
            goto clean;
        }
        hvfs_info(xnet, "get value '%s'\n", line);
    }
    
clean:
    err = hvfs_drop_table("table_a");
    if (err) {
        hvfs_err(xnet, "hvfs_drop_table() failed w/ %d\n", err);
        goto out;
    }
    
out:    
    __core_exit();
}
#endif
