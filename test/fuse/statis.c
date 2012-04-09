/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-02-17 15:55:41 macan>
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
#include "branch.h"

/* In this test, we create NR files in a HOME directory. Then, write random
 * bytes to each file. After that, we issue getbor to get the statis result
 * from bp server; and compare it with brute-force scanning.
 */

/* Statis we want to gather is: file NR, total write bytes, largest file,
 * smallest file.
 */
struct statis
{
    long nr;
    long wbytes;
    long max;
    long min;
};

struct statis generated, bored, scaned;

static void dump_statis(struct statis *s)
{
    printf("NR %ld WB %ld MAX %ld MIN %ld\n",
           s->nr, s->wbytes, s->max, s->min);
}

static void update_statis(struct statis *s, int flen, int fid)
{
    s->nr++;
    s->wbytes += flen;
    if (s->max < flen)
        s->max = flen;
    if (s->min > flen)
        s->min = flen;
}

#define HVFS_HOME "/mnt/hvfs/testS"
#define HARD_MAX (10 * 1024)
static char buf[HARD_MAX + 1];

void __hvfs_bench_prepare(int nr)
{
    char path[256];
    long w;
    int err = 0, i, fd;

    memset(&generated, 0, sizeof(generated));
    memset(&bored, 0, sizeof(bored));
    memset(&scaned, 0, sizeof(scaned));
    
    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/statis.%d", HVFS_HOME, i);
        fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            perror("open('./statis'):");
            continue;
        }

        /* write random bytes */
        w = random() % HARD_MAX + 1;
        err = write(fd, buf, w);
        if (err <= 0) {
            perror("write('./statis'):");
            goto next;
        }
        update_statis(&generated, err, i);

    next:
        close(fd);
    }
}

void __hvfs_bench_fina(int nr)
{
    char path[256];
    int i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/statis.%d", HVFS_HOME, i);
        unlink(path);
    }
}

void __hvfs_statis_search()
{
#if 0                           /* use dumpbor is complex, use python client
                                 * to get the result :( */
    struct branch_op_result *bor = NULL;
    int err = 0;
    
    err = branch_dumpbor("statis", 0, &bor); /* UNFIXED branch name! */
    if (err) {
        printf("branch_dumpbor() failed w/ %d\n", err);
    }
#endif
}

void __hvfs_bf_search(int nr)
{
    char path[256];
    struct stat buf;
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        memset(&buf, 0, sizeof(buf));
        sprintf(path, "%s/statis.%d", HVFS_HOME, i);
        err = stat(path, &buf);
        if (err < 0) {
            perror("stat('./statis'):");
            err = errno;
            continue;
        }
        update_statis(&scaned, buf.st_size, i);
    }
    dump_statis(&scaned);
}

int main(int argc, char *argv[])
{
    struct timeval begin, end;
    char *value;
    int nr = 1, seed = 100, err = 0;

    value = getenv("nr");
    if (value)
        nr = atoi(value);
    if (nr < 100)
        nr = 100;
    value = getenv("seed");
    if (value)
        seed = atoi(value);
    
    /* mkdirs */
    if (!mkdir(HVFS_HOME, 0777)) {
        printf("Test home directory: %s just created, please "
               "register the dtriggers\n", HVFS_HOME);
        goto out;
    }

    /* test hvfs w/ dtriggers */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    dump_statis(&generated);

    gettimeofday(&begin, NULL);
    __hvfs_statis_search();
    gettimeofday(&end, NULL);
    printf("PFS STATIS Search=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    /* test hvfs w/ brute-force scanning */
    gettimeofday(&begin, NULL);
    __hvfs_bf_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS BRUTEF Search=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    //__hvfs_bench_fina(nr);

out:
    return err;
}
