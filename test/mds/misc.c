/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-01-29 15:53:00 macan>
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
#include "xtable.h"
#include "tx.h"
#include "xnet.h"
#include "mds.h"
#include "lib.h"

int main(int argc, char *argv[])
{
    int err = 0;
    int offset;
    u64 a = XTABLE_BITMAP_SIZE;
    

    offset = fls64(a);
    hvfs_info(mds, "[FLS64]: First set bit in 0x%lx is %d.\n", a, offset);
    offset = fls(a);
    hvfs_info(mds, "[FLS  ]: First set bit in 0x%lx is %d.\n", a, offset);
    
    return err;
}
