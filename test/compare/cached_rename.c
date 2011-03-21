/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-20 20:37:33 macan>
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
#include <unistd.h>

/* This file is using to find the write bug */

int main(int argc, char *argv[])
{
    int err = 0;
    int fd, fd2;
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

    /* write 4096B to offset 0 */
    memset(buf, '1', 4096);
    err = write(fd, buf, 8);
    if (err < 0) {
        perror("write 1");
        goto out_close;
    } else {
        printf("written 8B '1' w/ %d\n", err);
    }

    /* rename file 'XYZ' to 'ABC' */
    err = rename("./XYZ", "./ABC");
    if (err) {
        perror("rename");
        goto out_close;
    }

    /* open file 'ABC' */
    fd2 = open("./ABC", O_RDWR);
    if (fd2 < 0) {
        goto out_close;
    }

    sleep(2);

    {
        struct stat buf;

        err = fstat(fd2, &buf);
        if (err < 0) {
            perror("fstat 3");
            goto out_close2;
        }
    }

    /* read 4096 bytes from offset 0 */
    memset(buf, 0, 4096);
    err = read(fd2, buf, 4096);
    if (err < 0) {
        perror("read 2");
        goto out_close2;
    } else {
        printf("read 4096B w/ %d\n", err);
    }
    assert(buf[0] == '1');

    if (err != 8) {
        printf("Cached/Rename read failed for this build!\n");
        err = EFAULT;
    }

    /* old fd write */
    memset(buf, '2', 4096);
    err = write(fd, buf, 8);
    if (err < 0) {
        perror("write 1");
        goto out_close;
    } else {
        printf("written 8B '2' w/ %d\n", err);
    }

    /* new fd read 4096 bytes from offset 8 */
    memset(buf, 0, 4096);
    err = read(fd2, buf, 4096);
    if (err < 0) {
        perror("read 2");
        goto out_close2;
    } else {
        printf("read 4096B w/ %d\n", err);
    }
    assert(buf[0] == '2');

    close(fd);
    unlink("./ABC");
    
out_close2:
    close(fd2);
out_unlink:
    unlink("./XYZ");
    
out:
    return err;
out_close:
    close(fd);
    goto out_unlink;
}
