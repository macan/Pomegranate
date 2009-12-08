/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-12-08 17:11:18 macan>
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

#include "lib.h"

static u64 hvfs_hash_eh(u64 key1, u64 key2, u64 key2len)
{
    return 0;
}

static u64 hvfs_hash_cbht(u64 key1, u64 key2, u64 key2len)
{
    u64 val1, val2;
    
    val1 = hash_64(key1, 64);
    val2 = hash_64(key2, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

static u64 hvfs_hash_ring(u64 key1, u64 key2, u64 key2len)
{
    u64 val1, val2;
    
    val1 = hash_64(key2, 64);
    val2 = hash_64(key1, 64);
    val1 = val1 ^ (val2 ^ GOLDEN_RATIO_PRIME);

    return val1;
}

u64 hvfs_hash(u64 key1, u64 key2, u64 key2len, u32 sel)
{
    switch (sel) {
    case HASH_SEL_EH:
        return hvfs_hash_eh(key1, key2, key2len);
        break;
    case HASH_SEL_CBHT:
        return hvfs_hash_cbht(key1, key2, key2len);
        break;
    case HASH_SEL_RING:
        return hvfs_hash_ring(key1, key2, key2len);
        break;
    default:
        hvfs_err(lib, "Invalid hash function selector.\n");
    }
    return 0;
}
