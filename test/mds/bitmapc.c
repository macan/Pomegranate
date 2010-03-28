/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-28 14:28:15 macan>
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
#include "mds.h"

#ifdef UNIT_TEST

int main(int argc, char *argv[])
{
    struct bc_entry *be;
    int err = 0, counter = 0, i;
    int a = 513, b = 512, c = -1;

    if (argc == 4) {
        a = atoi(argv[1]);
        b = atoi(argv[2]);
        c = atoi(argv[3]);
    }

    /* dump info */
    hvfs_info(mds, "Running w/ %d entries inserted %d entries locked, "
              "%d lookups\n", a, (c + 1), b);

    mds_pre_init();
    mds_config();
    mds_init(10);
    mds_verify();

    for (i = 0; i < a; i++) {
        be = mds_bc_get(i, 0);
        if (be == ERR_PTR(-ENOENT)) {
            be = mds_bc_new();
            if (!be) {
                hvfs_err(mds, "New BC entry failed.\n");
                err = -ENOMEM;
                break;
            }
            mds_bc_set(be, i, 0);
            mds_bc_insert(be);
            hvfs_debug(mds, "total %d free %d\n", 
                       atomic_read(&hmo.bc.total), atomic_read(&hmo.bc.free));
        }
        if (i > c)
            mds_bc_put(be);
    }

    hvfs_info(mds, "Insert done, total %d free %d\n", 
              atomic_read(&hmo.bc.total), atomic_read(&hmo.bc.free));

    for (i = 0; i < b; i++) {
        be = mds_bc_get(i, 0);
        if (be == ERR_PTR(-ENOENT)) {
            counter++;
        } else 
            mds_bc_put(be);
    }
    
    hvfs_info(mds, "Missed %d entries.\n", counter);
    hvfs_info(mds, "Lookup done, total %d free %d\n", 
              atomic_read(&hmo.bc.total), atomic_read(&hmo.bc.free));
    
    mds_destroy();
    return err;
}

#endif
