/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-02 11:59:28 macan>
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
#include "mdsl.h"

#ifdef UNIT_TEST
int main(int argc, char *argv[])
{
    int err = 0;
    int self;

    hvfs_info(mdsl, "MDSL Unit Testing...\n");

    if (argc < 2) {
        hvfs_err(mdsl, "Self ID is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        self = atoi(argv[1]);
        hvfs_info(mdsl, "Self type+ID is mdsl:%d.\n", self);
    }

    err = mdsl_init();
    if (err) {
        hvfs_err(mdsl, "mdsl_init() failed %d\n", err);
        goto out;
    }

    /* init misc configrations */
    hmo.site_id = self;
    hmi.gdt_salt = 0;
    hvfs_info(mdsl, "Select GDT salt to  %lx\n", hmi.gdt_salt);
    hmi.root_uuid = 1;
    hmi.root_salt = 0xdfeadb0;
    hvfs_info(mdsl, "Select root salt to %lx\n", hmi.root_salt);

    mdsl_destroy();
out:
    return err;
}
#endif
