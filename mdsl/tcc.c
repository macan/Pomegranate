/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-02 15:59:01 macan>
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

int mdsl_tcc_init(void)
{
    struct txg_open_entry *toe;
    int i;
    
    INIT_LIST_HEAD(&hmo.tcc.open_list);
    INIT_LIST_HEAD(&hmo.tcc.wbed_list);
    xrwlock_init(&hmo.tcc.open_lock);
    xrwlock_init(&hmo.tcc.wbed_lock);

    if (!hmo.conf.tcc_size)
        hmo.conf.tcc_size = 32;

    toe = xzalloc(sizeof(*toe) * hmo.conf.tcc_size);
    if (!toe) {
        hvfs_warning(mdsl, "Init TCC failed, ignore it.\n");
        atomic_set(&hmo.tcc.size, 0);
        atomic_set(&hmo.tcc.used, 0);
        return 0;
    }
    for (i = 0; i < hmo.conf.tcc_size; i++) {
        INIT_LIST_HEAD(&((toe + i)->list));
        list_add_tail(&((toe + i)->list), &hmo.tcc.open_list);
    }
    atomic_set(&hmo.tcc.size, hmo.conf.tcc_size);
    atomic_set(&hmo.tcc.used, 0);

    return 0;
}

void mdsl_tcc_destroy(void)
{
    /* do not need to free any items */
    xrwlock_destroy(&hmo.tcc.open_lock);
    xrwlock_destroy(&hmo.tcc.wbed_lock);
}

