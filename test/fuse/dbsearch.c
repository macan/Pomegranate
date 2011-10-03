/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-04 06:51:15 macan>
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

static char *hvfs_home = "/mnt/hvfs/testC";

struct base_dbs
{
    int tag_len;
    int kvs_len;
    char data[0];
};

/* dump the current set of <file, key_value_list>
 */
void branch_dumpbase(void *data, size_t size, char **outstr)
{
    struct base_dbs *bd, *end;
    char *out;
    
    bd = (struct base_dbs *)data;
    end = (void *)bd + size;
    out = malloc(size + 1);
    if (!out) {
        printf("malloc() data region failed\n");
        return;
    }
    memset(out, 0, size + 1);
    *outstr = out;
    while (bd < end) {
        memcpy(out, bd->data, bd->tag_len);
        out += bd->tag_len;
        *out++ = '\t';
        memcpy(out, bd->data + bd->tag_len, bd->kvs_len);
        out += bd->kvs_len;
        *out++ = '\n';
        bd = (void *)bd + sizeof(*bd) + bd->tag_len + 
            bd->kvs_len;
    }
}

void __hvfs_bench_prepare(int nr)
{
    char path[256];
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        err = open(path, O_CREAT, S_IRUSR | S_IWUSR);
        if (err < 0) {
            perror("open('./xattr.tag'):");
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
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        unlink(path);
    }
}

char *branch_name = "test_branch";
char *types[] = {
    "png",
    "jpg",
    "gif",
    "svg",
    "eps",
    "bmp",
};
int selrates[] = {
    34, 30, 20, 10, 5, 1,
};

int *selector = NULL;
int bsize = 1024 * 64;

void __hvfs_setup_selector(int nr)
{
    int i, j, idx;
    
    selector = malloc(nr * sizeof(int));
    if (!selector) {
        exit(ENOMEM);
    }
    memset(selector, 0, nr * sizeof(int));

    printf("Setting up selector ... ");
    fflush(stdout);
    for (i = 1; i < 6; i++) {
        for (j = 0; j < nr / 100 * selrates[i]; j++) {
            idx = random() % nr;
            do {
                if (selector[idx] == 0) {
                    selector[idx] = i;
                    break;
                } else {
                    idx++;
                    if (idx >= nr)
                        idx = 0;
                }
            } while (1);
        }
    }
    printf("Done.\n");
    
}

int __hvfs_dbsearch_set(int nr)
{
    char buf[bsize];
    char path[256];
    int err = 0, i;

    if (nr < 100)
        nr = 100;

    /* set up the branch */
    sprintf(buf, "pfs.branch.0.create.%s.tag.1."
            "indexer:1:0:l:plain:DB:00;"
            "indexer:2:0:r:bdb:DB:00",
            branch_name);
    err = setxattr(hvfs_home, buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('.')");
        err = errno;
        goto out;
    }
    printf("OK to create branch '%s'\n", branch_name);

    for (i = 0; i < nr; i++) {
        sprintf(buf, "pfs.tag.1.set.B:%s:type.type=%s", branch_name,
                types[selector[i]]);

        /* setxattr */
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
        err = setxattr(path, buf, NULL, 0, 0);
        if (err < 0) {
            perror("setxattr(./xattr.tag):");
            err = errno;
            goto out;
        }
    }

out:
    return err;
}

int __hvfs_dbsearch_search(int nr)
{
    char buf[bsize];
    int err = 0, i;
    struct timeval begin, end;
    
    for (i = 0; i < 6; i++) {
        gettimeofday(&begin, NULL);
        sprintf(buf, "pfs.tag.1.search.B:%s.DB.00.r:type=%s", 
                branch_name, types[i]);
        err = getxattr(hvfs_home, buf, buf, sizeof(buf));
        if (err < 0) {
            perror("getxattr('./xattr.tag', tag.search):");
            err = errno;
            goto out;
        } else {
            buf[err] = '\0';
        }

        printf("TAG SEARCH 'r:type=%s' => (%dB) {\n", types[i], err);
#if 0
        {
            char *str = NULL;
            
            branch_dumpbase(buf, err, &str);
            
            printf("%s", str);
            free(str);
        }
#endif
        printf("}\n");
        gettimeofday(&end, NULL);
        printf("Average Latency(R:%d):\t%8.2lf us\n", selrates[i], 
               (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                        (end.tv_usec - begin.tv_usec)));
    }

out:
    return err;
}

int __hvfs_dbnative_set(int nr)
{
    char buf[bsize];
    char path[256];
    char str[128];
    int err = 0, i;

    for (i = 0; i < nr; i++) {
        sprintf(buf, "%s", types[selector[i]]);

        sprintf(str, "pfs.native.1.write");
        sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);

        /* setxattr */
        err = setxattr(path, str, buf, strlen(buf), 0);
        if (err) {
            perror("setxattr('./xattr.normal'):");
            err = errno;
            goto out;
        }
    }

out:
    return err;
}

int __hvfs_dbnative_search(int nr)
{
    char buf[bsize];
    char path[256];
    char str[128];
    int err = 0, i, j, cnt;
    struct timeval begin, end;

    for (j = 0; j < 6; j++) {
        gettimeofday(&begin, NULL);
        cnt = 0;
        for (i = 0; i < nr; i++) {
            /* read in the entry */
            sprintf(str, "pfs.native.1.read.0.-1");
            sprintf(path, "%s/xattr.tag.%d", hvfs_home, i);
            
            err = getxattr(path, str, buf, sizeof(buf));
            if (err < 0) {
                perror("getxattr('./xattr.normal', native.read):");
                err = errno;
                goto out;
            } else {
                buf[err] = '\0';
            }
            if (strcmp(buf, types[j]) == 0) {
                cnt++;
            }
        }
        if (cnt == selrates[j] * nr / 100) {
            printf("Correct at search 'r:type=%s'\n", types[j]);
        } else
            printf("Failed  at search 'r:type=%s', (%d vs %d)\n", 
                   types[j], cnt, selrates[j]);

        gettimeofday(&end, NULL);
        printf("Average Latency(R:%d):\t%8.2lf us\n", selrates[j], 
               (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                        (end.tv_usec - begin.tv_usec)));
    }
    
out:
    return err;
}

int main(int argc, char *argv[])
{
    struct timeval begin, end;
    char *value;
    int nr = 1, seed = 100;

    value = getenv("nr");
    if (value)
        nr = atoi(value);
    if (nr < 100)
        nr = 100;
    value = getenv("seed");
    if (value)
        seed = atoi(value);
    
    /* mkdirs */
    mkdir(hvfs_home, 0777);

    __hvfs_setup_selector(nr);

    /* test hvfs w/ DB */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __hvfs_dbsearch_set(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBSEARCH SET=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)) / (double)nr);

    /* wait a moment */
    printf("Press any key to continue ...\n");
    fflush(stdout);
    {
        char key;
        scanf("%c", &key);
    }

    gettimeofday(&begin, NULL);
    __hvfs_dbsearch_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBSEARCH SEARCH=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    __hvfs_bench_fina(nr);

    /* test hvfs native */
    srandom(seed);
    __hvfs_bench_prepare(nr);
    gettimeofday(&begin, NULL);
    __hvfs_dbnative_set(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBNATIVE SET=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec))/ (double)nr);

    gettimeofday(&begin, NULL);
    __hvfs_dbnative_search(nr);
    gettimeofday(&end, NULL);
    printf("PFS DBNATIVE SEEARCH=>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    __hvfs_bench_fina(nr);
    

    return 0;
}
