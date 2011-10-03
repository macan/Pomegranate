/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-04 06:51:40 macan>
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

#define HVFS_MDU_IF_LARGE       0x04000000 /* large file */

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

int __native_umftest(int argc, char *argv[])
{
    char buf[4096];
    int err = 0;

    err = mkdir("./xattr.umf", 0777);
    if (err < 0) {
        perror("mkdir():");
        err = errno;
        goto out;
    }

    /* setxattr */
    sprintf(buf, "pfs.native.0.umf.set.%d", HVFS_MDU_IF_LARGE);
    err = setxattr("./xattr.umf", buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('./xattr.umf'):");
        err = errno;
        goto out_rmdir;
    }

    /* check the flag value */
    sprintf(buf, "pfs.native.0.umf.cat");
    err = getxattr("./xattr.umf", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.umf'):");
        err = errno;
        goto out_rmdir;
    }
    if (*(unsigned int *)buf & HVFS_MDU_IF_LARGE) {
        printf("OK to cat the LARGE flag.\n");
    } else {
        printf("BAD, failed with LARGE flag.\n");
    }

out_rmdir:
    /* finally, rmdir */
    rmdir("./xattr.umf");

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
            perror("fstat('./xattr.dt/abc'):");
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

    /* It is a little difficult to delete the BRANCH metafile and log
     * files. User can delete these files as if regular files. */

out:
    return err;
}

int __branch_delete(int argc, char *argv[])
{
    char buf[1024];

    sprintf(buf, "./branches/%s", argv[2]);
    unlink(buf);
    sprintf(buf, "./branches/.%s.filter.f1", argv[2]);
    unlink(buf);
    sprintf(buf, "./branches/.%s.indexer.p9", argv[2]);
    unlink(buf);
    sprintf(buf, "./branches/.%s.e0000", argv[2]);
    unlink(buf);

    return 0;
}

int __integrated_optest(int argc, char *argv[])
{
    char buf[1024];
    struct stat st;
    int err = 0;

    if (argc < 5) {
        printf("Usage: %s dtrigger_file branch_name search_expr "
               "dtrigger_file\n",
               argv[0]);
        return EINVAL;
    }

    /* make a new directory */
    err = mkdir("./xattr.integrated", 0777);
    if (err < 0) {
        perror("mkdir():");
        err = errno;
        goto out;
    }
    
    /* setxattr to setup a automated dtrigger */
    sprintf(buf, "pfs.dt.0.create.%d.%d.%d.%s", 1, 4, 100, argv[4]);
    err = setxattr("./xattr.integrated", buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('./xattr.integrated'):");
        err = errno;
        goto out_rmdir;
    }

    sprintf(buf, "pfs.dt.0.create.%d.%d.%d.%s", 1, 8, 100, argv[4]);
    err = setxattr("./xattr.integrated", buf, NULL, 0, 0);
    if (err) {
        perror("setxattr('./xattr.integrated'):");
        err = errno;
        goto out_rmdir;
    }

    /* insert some entry into the directory */
    err = open("./xattr.integrated/a", O_CREAT, S_IRUSR | S_IWUSR);
    if (err < 0) {
        perror("open('./xattr.integrated/a'):");
        err = errno;
        goto out_rmdir;
    }
    close(err);

    err = open("./xattr.integrated/b", O_CREAT, S_IRUSR | S_IWUSR);
    if (err < 0) {
        perror("open('./xattr.integrated/b'):");
        err = errno;
        goto out_rmdir;
    }
    close(err);

    err = open("./xattr.integrated/c", O_CREAT, S_IRUSR | S_IWUSR);
    if (err < 0) {
        perror("open('./xattr.integrated/c'):");
        err = errno;
        goto out_rmdir;
    }
    close(err);

    /* wait a moment */
    sleep(30);

    /* get the ino of this directory */
    err = stat("./xattr.integrated", &st);
    if (err) {
        perror("stat('./xattr.integrated'):");
        err = errno;
        goto out_rmdir;
    }
    
    /* search the newly inserted files */
    sprintf(buf, "pfs.tag.1.search.B:default-%lx.default_db.default."
            "r:@ctime>100",
            st.st_ino);
    err = getxattr("./xattr.integrated", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.integrated', tag.search):");
        err = errno;
        goto out_rmdir;
    } else {
        buf[err] = '\0';
    }

    printf("TAG SEARCH '@ctime>100' => (%dB) {\n", err);
    {
        char *str = NULL;
        
        branch_dumpbase(buf, err, &str);

        printf("%s", str);
        free(str);
    }
    printf("}\n");

out_rmdir:
    unlink("./xattr.integrated/a");
    unlink("./xattr.integrated/b");    
    unlink("./xattr.integrated/c");
    rmdir("./xattr.integrated");
    
out:
    return err;
}

int __tag_optest(int argc, char *argv[])
{
    char buf[1024];
    int err = 0, fd;

    if (argc < 4) {
        printf("Usage: %s dtrigger_file branch_name search_expr"
               "[e.g. r:type=jpg]\n", argv[0]);
        return EINVAL;
    }

    /* create a new file */
    fd = open("./xattr.tag", O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open('./xattr.tag'):");
        goto out;
    }
    close(fd);
    
    /* setxattr to attach a tag list to it and index it in one BRANCH */
    sprintf(buf, "pfs.tag.1.set.B:%s:type:@ctime.type=png;@ctime=2000",
            argv[2]);
    err = setxattr("./xattr.tag", buf, NULL, 0, 0);
    if (err < 0) {
        perror("setxattr(./xattr.tag):");
        goto out_unlink;
    }

    printf("OK to set a tag\n");

    /* read in the tag entry */
    sprintf(buf, "pfs.native.1.read.%d.%d", 0, -1);
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.tag', native.read):");
        err = errno;
        goto out_unlink;
    } else {
        buf[err] = '\0';
    }

    printf("Len %dB: '%s'\n", err, buf);

    /* getxattr to test an exist key */
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "pfs.tag.1.test.B.type");
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr(./xattr.tag, tag.test):");
        err = errno;
        goto out_unlink;
    } else {
        buf[err] = '\0';
    }

    printf("TAG TEST: key type => '%s'\n", buf);

    /* getxattr to test a non-exist key */
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "pfs.tag.1.test.B.typexx");
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        printf("TAG TEST: key typexx => %s\n", strerror(errno));
    } else {
        printf("getxattr() a non-exist key succeed?\n");
        goto out_unlink;
    }

    /* setxattr to update type key */
    sprintf(buf, "pfs.tag.1.update.B:%s.type.jpg", argv[2]);
    err = setxattr("./xattr.tag", buf, NULL, 0, 0);
    if (err < 0) {
        perror("setxattr(./xattr.tag, tag.update):");
        goto out_unlink;
    }

    printf("OK to update a tag\n");

    /* read in the tag entry */
    sprintf(buf, "pfs.native.1.read.%d.%d", 0, -1);
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.tag', native.read):");
        err = errno;
        goto out_unlink;
    } else {
        buf[err] = '\0';
    }

    printf("Len %dB: '%s'\n", err, buf);

    /* setxattr to delete @ctime key */
    sprintf(buf, "pfs.tag.1.delete.B:%s.@ctime", argv[2]);
    err = setxattr("./xattr.tag", buf, NULL, 0, 0);
    if (err < 0) {
        perror("setxattr(./xattr.tag, tag.delete):");
        goto out_unlink;
    }

    printf("OK to delete a tag key\n");

    /* read in the tag entry */
    sprintf(buf, "pfs.native.1.read.%d.%d", 0, -1);
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.tag', native.read):");
        err = errno;
        goto out_unlink;
    } else {
        buf[err] = '\0';
    }

    printf("Len %dB: '%s'\n", err, buf);

    /* we must wait at lease 30 seconds to search it */
    sleep(30);

    /* getxattr to search type key: r:type=png */
    sprintf(buf, "pfs.tag.1.search.B:%s.DB.00.%s", argv[2], argv[3]);
    err = getxattr("./xattr.tag", buf, buf, sizeof(buf));
    if (err < 0) {
        perror("getxattr('./xattr.tag', tag.search):");
        err = errno;
        goto out_unlink;
    } else {
        buf[err] = '\0';
    }

    printf("TAG SEARCH '%s' => (%dB) {\n", argv[3], err);
    {
        char *str = NULL;
        
        branch_dumpbase(buf, err, &str);

        printf("%s", str);
        free(str);
    }
    printf("}\n");

    /* delete the file */
out_unlink:
    unlink("./xattr.tag");
    
out:
    return err;
}

int main(int argc, char *argv[])
{
    printf("NOTE: you must run this test in the root directory of PFS "
           "(aka mountpoint).\n");

    printf("Perform XATTR native optest ...\n");
    __native_optest(argc, argv);
    printf("Done.\n");
    
    printf("Perform XATTR native UMF test ...\n");
    __native_umftest(argc, argv);
    printf("Done.\n");

    printf("Perform XATTR DT optest ...\n");
    __dt_optest(argc, argv);
    printf("Done.\n");

    printf("Perform XATTR branch optest ...\n");
    if (__branch_optest(argc, argv) == 0) {
        printf("Done.\n");
        printf("Perform XATTR tag optest ...\n");
        __tag_optest(argc, argv);
    }
    printf("Done.\n");

    printf("Perform XATTR integrated optest ...\n");
    __integrated_optest(argc, argv);
    printf("Done.\n");

    /* clean up branch */
    __branch_delete(argc, argv);

    return 0;
}
