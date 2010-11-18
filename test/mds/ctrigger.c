/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-18 00:28:55 macan>
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

int main(int argc, char *argv[])
{
    struct dt_ccode dc = {}, saved_dc;
    char *error;
    int err = 0;

    if (argc < 2) {
        hvfs_info(mds, "Usage: %s so_file\n", argv[0]);
        return -EINVAL;
    }

    strcpy(dc.tmp_file, argv[1]);

    dc.dlhandle = dlopen(dc.tmp_file, RTLD_NOW | RTLD_LOCAL);
    if (!dc.dlhandle) {
        hvfs_err(mds, "dlopen() %s failed w/ %s\n",
                 dc.tmp_file, dlerror());
        err = -errno;
        goto out;
    }

    dlerror();

    dc.dtmain = dlsym(dc.dlhandle, "dt_main");
    if ((error = dlerror()) != NULL) {
        hvfs_err(mds, "dlsym() dt_main failed w/ %s\n",
                 error);
        goto out;
    }

    /* call the dt_main function now */
    {
        struct itb i;
        struct ite e;
        struct hvfs_index hi;
        struct dir_trigger dt = {
            .code = &dc,
        };

        i.h.puuid = 900;
        e.s.mdu.ctime = 10000;
        err = dc.dtmain(10, &i, &e, &hi, 10, &dt);
        printf("ITE.s.mdu.version = %d\n", e.s.mdu.version);
    }

    dlclose(dc.dlhandle);

out:    
    return err;
}
