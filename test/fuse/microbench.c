/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-27 22:38:35 macan>
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
#include <time.h>
#include <sys/time.h>

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

static long totalbytes = 0;
static int seed = 0;
static char *hvfs_home = "/mnt/hvfs/testA";
static char *norm_home = "/mnt/hvfs/testB";
static long bsize = 1024;

void __hvfs_bench_prepare(int nr)
{
    char path[256];
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/xattr.native.%d", hvfs_home, i);
        err = open(path, O_CREAT, S_IRUSR | S_IWUSR);
        if (err < 0) {
            perror("open('./xattr.native'):");
            err = errno;
            continue;
        }
        
        close(err);
    }
}

void __hvfs_bench_fina(int nr)
{
    char path[256];
    int i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/xattr.native.%d", hvfs_home, i);
        unlink(path);
    }
}

int __hvfs_bench(int nr)
{
    char buf[bsize];
    char path[256], cmd[64];
    ssize_t nbytes;
    int err = 0, i, j;

    srandom(seed);
    memset(buf, 'A', sizeof(buf));

    for (i = 0; i < nr; i++) {
        for (j = 0; j < 3; j++) {
            sprintf(path, "%s/xattr.native.%d", hvfs_home, i);
            nbytes = random() % bsize;
            totalbytes += nbytes;

            /* setxattr */
            sprintf(cmd, "pfs.native.%d.write", j);
            err = setxattr(path, cmd, buf, nbytes, 0);
            if (err) {
                perror("setxattr('./xattr.native'):");
                err = errno;
                goto out;
            }
            
            /* read in the entry */
            sprintf(buf, "pfs.native.%d.read.%ld.%ld", j, 0UL, -1UL);
            err = getxattr(path, buf, buf, sizeof(buf));
            if (err < 0) {
                perror("getxattr('./xattr.native', native.read):");
                err = errno;
                goto out;
            } else {
                buf[err] = '\0';
            }
        }
    }

    /* finally, unlink the file */
    unlink(path);

out:
    return err;
}

void __xattr_bench_prepare(int nr)
{
    char path[256];
    int err = 0, i, j;
    
    for (i = 0; i < nr; i++) {
        for (j = 0; j < 3; j++) {
            sprintf(path, "%s/xattr.normal.%d.%d", norm_home, i, j);
            err = open(path, O_CREAT, S_IRUSR | S_IWUSR);
            if (err < 0) {
                perror("open('./xattr.normal'):");
                err = errno;
                continue;
            }
            close(err);
        }
    }
}

void __xattr_bench_fina(int nr)
{
    char path[256];
    int i, j;
    
    for (i = 0; i < nr; i++) {
        for (j = 0; j < 3; j++) {
            sprintf(path, "%s/xattr.normal.%d.%d", norm_home, i, j);
            unlink(path);
        }
    }
}

int __xattr_bench(int nr)
{
    char buf[bsize];
    char path[256];
    char str[128];
    ssize_t nbytes;
    int err = 0, i, j;

    srandom(seed);
    memset(buf, 'A', sizeof(buf));

    for (i = 0; i < nr; i++) {
        for (j = 0; j < 3; j++) {
            sprintf(path, "%s/xattr.normal.%d.%d", norm_home, i, j);
            nbytes = random() % bsize;
            totalbytes += nbytes;

            /* setxattr */
            sprintf(str, "pfs.native.1.write");
            err = setxattr(path, str, buf, nbytes, 0);
            if (err) {
                perror("setxattr('./xattr.normal'):");
                err = errno;
                goto out;
            }
            
            /* read in the entry */
            sprintf(str, "pfs.native.1.read.0.-1");
            err = getxattr(path, str, buf, sizeof(buf));
            if (err < 0) {
                perror("getxattr('./xattr.normal', native.read):");
                err = errno;
                goto out;
            } else {
                buf[err] = '\0';
            }
        }
    }
    
out:
    return err;
}

int __norm_bench(int nr)
{
    char buf[bsize];
    char path[256];
    ssize_t nbytes;
    int err = 0, i, j, fd, bw;

    srandom(seed);
    memset(buf, 'A', sizeof(buf));

    for (i = 0; i < nr; i++) {
        for (j = 0; j < 3; j++) {
            sprintf(path, "%s/xattr.normal.%d.%d", norm_home, i, j);
            nbytes = random() % bsize;
            totalbytes += nbytes;

            /* setxattr */
            err = open(path, O_RDWR | O_TRUNC);
            if (err < 0) {
                perror("open():");
                err = errno;
                goto out;
            }

            fd = err;
            bw = 0;
            do {
                err = write(fd, buf + bw, nbytes - bw);
                if (err < 0) {
                    perror("setxattr('./xattr.normal'):");
                    err = errno;
                    goto out;
                }
                bw += err;
            } while (bw < nbytes);
            
            /* read in the entry */
            do {
                err = read(fd, buf + bw, nbytes - bw);
                if (err < 0) {
                    perror("read()");
                    err = errno;
                    goto out;
                }
                bw += err;
            } while (bw < nbytes);

            /* fsync(PFS sync data automatically) and close it */
            fsync(fd);
            close(fd);
        }
    }
    
out:
    return err;
}

int main(int argc, char *argv[])
{
    struct timeval begin, end;
    char *value;
    int nr = 1;

    value = getenv("nr");
    if (value)
        nr = atoi(value);
    if (nr < 0)
        nr = 1;
    value = getenv("seed");
    if (value)
        seed = atoi(value);
    value = getenv("bsize");
    if (value)
        bsize = atol(value);
    
    /* mkdirs */
    mkdir(hvfs_home, 0777);
    mkdir(norm_home, 0777);

    /* test hvfs */
    __hvfs_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __hvfs_bench(nr);
    gettimeofday(&end, NULL);
    __hvfs_bench_fina(nr);
    printf("PFS =>\n");
    printf("Total Bytes:\t %ld\n", totalbytes);
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)) / (double)nr);

    /* test hvfs */
    totalbytes = 0;
    __xattr_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __xattr_bench(nr);
    gettimeofday(&end, NULL);
    __xattr_bench_fina(nr);
    printf("NOR =>\n");
    printf("Total Bytes:\t %ld\n", totalbytes);
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)) / (double)nr);

    return 0;
}
