/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-05-22 11:10:41 macan>
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
    struct itb i;
    struct ite e;
    struct hvfs_index hi;
    struct dt_python dp;
    struct dir_trigger dt = {
        .code = &dp,
    };
    int err = 0;

    snprintf(dp.module, 16, "dtdefault");
    i.h.puuid = 900;
    e.s.mdu.ctime = 10000;
    err = ebpy(10, &i, &e, &hi, 10, &dt);
    printf("ITE.s.mdu.version = %d\n", e.s.mdu.version);
    
    return err;
}
