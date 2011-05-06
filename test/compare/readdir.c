/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-04 09:21:35 macan>
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
    struct dirent *e = readdir(d);
    long int pos = 0;
    int i = 0;

    while (e) {
        printf("%lx %s\n", e->d_fileno, e->d_name);
        if (i == 3) {
            pos = telldir(d);
            printf(" => Position: %li\n", pos);
        }
        e = readdir(d);
        i++;
    }

    if (pos) {
        printf(" => read %s at Position %li\n", argv[1], pos);
        seekdir(d, pos);
        e = readdir(d);
        printf("%lx %s\n", e->d_fileno, e->d_name);
    }
    closedir(d);

    return 0;
} 
