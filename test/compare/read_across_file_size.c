/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-02-16 11:11:53 macan>
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* This file test whether the read syscall will return an error on larger
 * read. The result is NO.
 */

int main(int argc, char *argv[])
{
    int err = 0;
    int fd;
    off_t offset;
    char buf[4096];

    fd = open("./XYZ", O_CREAT | O_TRUNC | O_RDWR);
    if (fd < 0) {
        goto out;
    }
    offset = lseek(fd, 8192, SEEK_SET);
    if (offset < 0) {
        goto out_close;
    }
    err = read(fd, buf, 1024);
    if (err) {
        perror("read");
        goto out_close;
    } else {
        printf("read across buffer is ok! %d\n", err);
    }

out_close:
    close(fd);
    unlink("./XYZ");
out:
    return err;
}
