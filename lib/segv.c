/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-09 14:54:42 macan>
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>

#define BT_SIZE 50

struct backtrace_info
{
    void *bt[BT_SIZE];
    int size;
};

static struct backtrace_info bi;

void lib_segv(int signum, siginfo_t *info, void *ptr)
{
    char **bts;
    int i;

    memset(&bi, 0, sizeof(bi));
    bi.size = backtrace(bi.bt, BT_SIZE);
    if (bi.size > 0) {
        bts = backtrace_symbols(bi.bt, bi.size);
        if (bts) {
            for (i = 0; i < bi.size; i++) {
                hvfs_info(lib, "%s\n", bts[i]);
            }
            free(bts);
        }
    }
    exit(EFAULT);
}
