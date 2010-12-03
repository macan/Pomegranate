/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-12-03 18:33:46 macan>
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
#include "ring.h"
#include "lib.h"
#include "root.h"
#include "amc_api.h"
#include "branch.h"

struct branch_processor
{
    struct regular_hash *bht;
    int hsize;
    atomic_t asize;
#define BP_DEFAULT_BTO          (600) /* ten minutes */
    /* the following region is the branch processor memory table */
#define BP_DEFAULT_MEMLIMIT     (64 * 1024 * 1024)
    u64 memlimit;
};
