/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-02-16 11:11:38 macan>
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
    offset = lseek(fd, 0, SEEK_SET);
    if (offset < 0) {
        goto out_close;
    }

    err = ftruncate(fd, 20480);
    if (err < 0) {
        perror("ftruncate");
        goto out_close;
    }

    /* write 4096B to offset 0 */
    memset(buf, '1', 4096);
    err = write(fd, buf, 4096);
    if (err < 0) {
        perror("write 1");
        goto out_close;
    } else {
        printf("written 4096B '1' w/ %d\n", err);
    }
    /* write 4096B to offset 4096 */
    memset(buf, '2', 4096);
    err = write(fd, buf, 4096);
    if (err < 0) {
        perror("write 2");
        goto out_close;
    } else {
        printf("written 4096B '2' w/ %d\n", err);
    }
    /* write 1808B to offset 8192 */
    memset(buf, '3', 1808);
    err = write(fd, buf, 1808);
    if (err < 0) {
        perror("write 3");
        goto out_close;
    } else {
        printf("written 1808B '3' w/ %d\n", err);
    }
    /* write 2288B to offset 10000 */
    memset(buf, '4', 2288);
    err = write(fd, buf, 2288);
    if (err < 0) {
        perror("write 4");
        goto out_close;
    } else {
        printf("written 2288B '4' w/ %d\n", err);
    }
    /* write 4096B to offset 12288 */
    memset(buf, '5', 4096);
    err = write(fd, buf, 4096);
    if (err < 0) {
        perror("write 5");
        goto out_close;
    } else {
        printf("written 4096B '5' w/ %d\n", err);
    }
    /* write 3616B to offset 16384 */
    memset(buf, '6', 3616);
    err = write(fd, buf, 3616);
    if (err < 0) {
        perror("write 6");
        goto out_close;
    } else {
        printf("written 3616B '6' w/ %d\n", err);
    }
    /* write 480B to offset 20000 */
    memset(buf, '7', 480);
    err = write(fd, buf, 480);
    if (err < 0) {
        perror("write 7");
        goto out_close;
    } else {
        printf("written 480B '7' w/ %d\n", err);
    }

out_close:
    close(fd);
    unlink("./XYZ");
    
out:
    return err;
}
