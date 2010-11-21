/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-11-19 00:56:22 macan>
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

int dt_main(u16 where, struct itb *itb, struct ite *ite,
            struct hvfs_index *hi, int status, void *arg)
{
    struct dir_trigger __attribute__((unused)) *dt = 
        (struct dir_trigger *)arg;

    hvfs_info(mds, "DT @ %d status %d\n", where, status);
    if (ite) {
        if (hi->flag & INDEX_BY_NAME) {
            char name[257];
            memcpy(name, hi->name, hi->namelen);
            name[hi->namelen] = '\0';
            hvfs_info(mds, "puuid %lx itbid %ld ctime %ld "
                      "version %d name %s\n", 
                      itb->h.puuid, itb->h.itbid, ite->s.mdu.ctime,
                      ite->s.mdu.version, name);
        } else if (hi->flag & INDEX_BY_UUID) {
            hvfs_info(mds, "puuid %lx itbid %ld ctime %ld "
                      "version %d uuid %lx\n", 
                      itb->h.puuid, itb->h.itbid, ite->s.mdu.ctime,
                      ite->s.mdu.version, hi->uuid);
        } else {
            hvfs_info(mds, "puuid %lx itbid %ld ctime %ld version %d\n", 
                      itb->h.puuid, itb->h.itbid, ite->s.mdu.ctime,
                      ite->s.mdu.version);
        }
        ite->s.mdu.version++;
    }

    return TRIG_CONTINUE;
}
