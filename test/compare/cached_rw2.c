/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-20 21:09:00 macan>
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
#include <string.h>
#include <errno.h>
#include <assert.h>

/* This file is using to find the write bug */

int main(int argc, char *argv[])
{
    int err = 0;
    int fd;
    off_t offset;
    char buf[4096];

    fd = open("./XYZ", O_CREAT | O_TRUNC | O_RDWR, 
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
        goto out;
    }

    /* write 1B to offset 2047 */
    offset = lseek(fd, 2047, SEEK_SET);
    if (offset < 0) {
        goto out_close;
    }
    memset(buf, '1', 4096);
    err = write(fd, buf, 1);
    if (err < 0) {
        perror("write 1");
        goto out_close;
    } else {
        printf("written 1B '1' w/ %d\n", err);
    }

    /* write 2048B to offset 0 */
    offset = lseek(fd, 0, SEEK_SET);
    if (offset < 0) {
        goto out_close;
    }
    memset(buf, '2', 4096);
    err = write(fd, buf, 2048);
    if (err < 0) {
        perror("write 1");
        goto out_close;
    } else {
        printf("written 1B '1' w/ %d\n", err);
    }
    close(fd);

    fd = open("./XYZ", O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        goto out;
    }
    /* read 4096B to offset 4096 */
    offset = lseek(fd, 0, SEEK_SET);
    if (offset < 0) {
        goto out_close;
    }
    memset(buf, 0, 4096);
    err = read(fd, buf, 2048);
    if (err < 0) {
        perror("read 2");
        goto out_close;
    } else {
        printf("read 2048B w/ %d\n", err);
    }
    assert(buf[1] == '2');

    if (err != 2048) {
        printf("Cached read failed for this build!\n");
        err = EFAULT;
    }
    close(fd);

out_unlink:
    unlink("./XYZ");
    
out:
    return err;
out_close:
    close(fd);
    goto out_unlink;
}
