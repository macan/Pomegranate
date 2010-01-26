/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-26 14:46:34 macan>
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

#ifndef __HVFS_ITB_H__
#define __HVFS_ITB_H__

static inline void itb_index_rlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_rlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_lock((xlock_t *)l);
    }
}

static inline void itb_index_wlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_wlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_lock((xlock_t *)l);
    }
}

static inline void itb_index_runlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_runlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_unlock((xlock_t *)l);
    }
}

static inline void itb_index_wunlock(struct itb_lock *l)
{
    if (hmo.conf.option & HVFS_MDS_ITB_RWLOCK) {
        xrwlock_wunlock((xrwlock_t *)l);
    } else if (hmo.conf.option & HVFS_MDS_ITB_MUTEX) {
        xlock_unlock((xlock_t *)l);
    }
}


#endif
