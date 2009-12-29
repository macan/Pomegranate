/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-29 16:59:25 macan>
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

#ifdef UNIT_TEST
char *ipaddr1[] = {
    "10.10.111.117",
};

char *ipaddr2[] = {
    "10.10.111.117",
};

short port1[] = {
    8412,
};

short port2[] = {
    8210,
};

int main(int argc, char *argv[])
{
    struct xnet_context *xc;
    int err = 0;
    short port;

    hvfs_info(xnet, "XNET Simple UNIT TESTing ...\n");

    if (argc == 2) {
        port = 8210;
    } else
        port = 8412;

    st_init();
    xc = xnet_register_type(0, port, NULL);
    if (IS_ERR(xc)) {
        err = PTR_ERR(xc);
        goto out;
    }

    xnet_update_ipaddr(0, 1, ipaddr1, port1);
    xnet_update_ipaddr(1, 1, ipaddr2, port2);

    xnet_unregister_type(xc);
    st_destroy();
    
out:
    return err;
}
#endif
