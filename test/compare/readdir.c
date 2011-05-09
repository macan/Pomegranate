/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-09 11:12:51 macan>
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

#include <dirent.h>
#include <stdio.h>

int main (int argc, char *argv[])
{
    if (argc == 1) {
        argv[1] = ".";
    }
    printf("opened %s\n", argv[1]);
    DIR *d = opendir(argv[1]);
    struct dirent *e = NULL, se;
    long int pos = 0;
    int i = 0;

    do {
        if (i == 3) {
            pos = telldir(d);
        }
        e = readdir(d);
        if (i == 3) {
            if (e)
                se = *e;
            else
                pos = 0;
        }
        i++;
    } while (e);

    if (pos) {
        seekdir(d, pos);
        e = readdir(d);
        if (e) {
            if (se.d_fileno != e->d_fileno ||
                strcmp(se.d_name, e->d_name) != 0) {
                printf("seekdir -> readdir FAILED\n");
            } else {
                printf("OK\n");
            }
        } else
            printf("seekdir FAILED!\n");
    }

    closedir(d);

    return 0;
} 
