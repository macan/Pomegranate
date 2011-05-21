/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-21 15:10:26 macan>
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <attr/xattr.h>

/* get next xattr token */
#define HVFS_XATTR_NT(key, p, s, err, out) do { \
        char *__in = NULL;                      \
        if (!p) {                               \
            __in = key;                         \
        }                                       \
        p = strtok_r(__in, ". ", (s));          \
        if (!p) {                               \
            err = -EINVAL;                      \
            goto out;                           \
        }                                       \
    } while (0)

int __native_optest(int argc, char *argv[])
{
    char buf[4096];
    char *p = NULL, *s = NULL;
    unsigned long itbid;
    ssize_t len;
    off_t offset;
    int err = 0;

    err = open("./xattr.native", O_CREAT, S_IRUSR | S_IWUSR);
    if (err < 0) {
        perror("open('./xattr.native'):");
        err = errno;
        goto out;
    }

    close(err);

    /* setxattr */
    err = setxattr("./xattr.native", "pfs.native.1.write", "hello, world!",
                   13, 0);
    if (err) {
        perror("setxattr('./xattr.native'):");
        err = errno;
        goto out;
    }

    /* getxattr */
    memset(buf, 0, sizeof(buf));
    err = getxattr("./xattr.native", "pfs.native.1.lookup", buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.native'):");
        err = errno;
        goto out;
    }

    /* parse the triple */
    printf("Triple: '%s'\n", buf);
    HVFS_XATTR_NT(buf, p, &s, err, out);
    itbid = atol(p);

    HVFS_XATTR_NT(buf, p, &s, err, out);
    len = atol(p);

    HVFS_XATTR_NT(buf, p, &s, err, out);
    offset = atol(p);

    /* read in the entry */
    sprintf(buf, "pfs.native.1.read.%ld.%ld", 0UL, len);
    err = getxattr("./xattr.native", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.native', native.read):");
        err = errno;
        goto out;
    } else {
        buf[err] = '\0';
    }

    /* dump the buffer */
    printf("Len %dB: '%s'\n", err, buf);

    /* finally, unlink the file */
    unlink("./xattr.native");

out:
    return err;
}

int __dt_optest(int argc, char *argv[])
{
    char buf[1024];
    int err = 0, fd;

    if (argc < 2) {
        printf("Usage: %s dtrigger_file\n", argv[0]);
        return EINVAL;
    }
    
    err = mkdir("./xattr.dt", 0777);
    if (err < 0) {
        perror("mkdir():");
        err = errno;
        goto out;
    }

    /* setxattr */
    sprintf(buf, "pfs.dt.0.create.%d.%d.%d.%s", 1, 6, 100, argv[1]);
    err = setxattr("./xattr.dt", buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('./xattr.dt'):");
        err = errno;
        goto out_rmdir;
    }

    /* getxattr */
    memset(buf, 0, sizeof(buf));
    err = getxattr("./xattr.dt", "pfs.dt.0.cat", buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.dt', dt.cat):");
        err = errno;
        goto out_rmdir;
    } else {
        buf[err] = '\0';
    }

    /* dump the buffer */
    printf("Len %dB: '%s'\n", err, buf);

    /* create a entry in the directory and stat it */
    fd = open("./xattr.dt/abc", O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open('./*/abc'):");
        goto out_rmdir;
    }

    close(fd);

    /* sleep a few seconds to invalid fuse client cache */
    sleep(2);

    /* stat it to trigger the DT */
    {
        struct stat st;

        err = stat("./xattr.dt/abc", &st);
        if (err) {
            perror("fstat('./*/abc'):");
            goto out_rmdir;
        }
        printf("OK to stat file 'abc'\n");
    }

    /* clear the DT */
    err = getxattr("./xattr.dt", "pfs.dt.0.clear", buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.dt', dt.clear):");
        err = errno;
        goto out_rmdir;
    }
    printf("OK to clear DT\n");

    unlink("./xattr.dt/abc");
    
out_rmdir:
    /* finally, rmdir  */
    rmdir("./xattr.dt");
    
out:
    return err;
}

int __branch_optest(int argc, char *argv[])
{
    char buf[1024];
    int err = 0;

    if (argc < 3) {
        printf("Usage: %s dtrigger_file branch_name\n", argv[0]);
        return EINVAL;
    }

    /* setxattr */
    sprintf(buf, "pfs.branch.0.create.%s.tag.1."
            "filter:1:0:l:.*;count:2:0:r:.*:all;"
            "avg:3:1:l:.*:all;sum:4:1:r:.*:all;"
            "max:5:2:l:.*:all;min:6:2:r:.*:all;"
            "knn:7:3:l:.*:all:linear:100:+-10;"
            "groupby:8:3:r:.*:all:sum/avg/max/min;"
            "indexer:9:4:l:plain:DB:00;"
            "indexer:10:4:r:bdb:DB:00",
            argv[2]);
    err = setxattr(".", buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('.')");
        err = errno;
        goto out;
    }

    printf("OK to create branch '%s'\n", argv[2]);

out:
    return err;
}

int main(int argc, char *argv[])
{
    __native_optest(argc, argv);
    __dt_optest(argc, argv);
    __branch_optest(argc, argv);

    return 0;
}
