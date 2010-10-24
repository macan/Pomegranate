/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-23 20:28:48 macan>
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
#define BT_FLEN 512

struct backtrace_info
{
    void *bt[BT_SIZE];
    int size;
};

static struct backtrace_info bi;

void lib_segv(int signum, siginfo_t *info, void *ptr)
{
    char **bts;
    char cmd[BT_FLEN] = "addr2line -e ";
    char str[BT_FLEN];
    FILE *fp;
    int i;

    memset(&bi, 0, sizeof(bi));
    bi.size = backtrace(bi.bt, BT_SIZE);
    if (bi.size > 0) {
        bts = backtrace_symbols(bi.bt, bi.size);
        if (bts) {
            for (i = 1; i < bi.size; i++) {
                sprintf(str, "%s %p", cmd, bi.bt[i]);
                fp = popen(str, "r");
                if (!fp) {
                    hvfs_info(lib, "%s\n", bts[i]);
                    continue;
                } else {
                    fscanf(fp, "%s", str);
                    hvfs_info(lib, "%s %s\n", bts[i], str);
                }
                pclose(fp);
            }
            free(bts);
        }
    }
    exit(EFAULT);
}
