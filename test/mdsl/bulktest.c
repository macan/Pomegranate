/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-03-03 12:35:27 macan>
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

#include "hvfs.h"
#include "xnet.h"
#include "mdsl.h"

#ifdef UNIT_TEST

int bufsize = 1024 * 1024;      /* default to 1MB */

int __test_bulk_load(u64 duuid, int column, struct timeval *begin,
                     struct timeval *end)
{
    void *data = xmalloc(bufsize);
    struct iovec data_iov = {0,};
    struct mdsl_storage_access msa = {
        .iov = &data_iov,
        .iov_nr = 1,
    };
    struct fdhash_entry *fde;
    int err = 0;

    if (!data)
        return -ENOMEM;

    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_DATA,
                                        column);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create DATA file failed w/ %ld\n",
                 PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }

    msa.offset = 0;
    msa.arg = (void *)MDSL_FILE_BULK_LOAD_DROP;
    msa.iov->iov_base = data;
    msa.iov->iov_len = bufsize;

    gettimeofday(begin, NULL);
    err = mdsl_storage_bulk_load(fde, &msa);
    gettimeofday(end, NULL);
    if (err) {
        hvfs_err(mdsl, "fd read failed w/ %d\n", err);
        goto out_put;
    }

out_put:
    mdsl_storage_fd_put(fde);
out:
    return err;
}

int __test_rand_load(u64 duuid, int column, struct timeval *begin,
                     struct timeval *end)
{
    void *data = xmalloc(bufsize);
    struct iovec data_iov = {0,};
    struct mdsl_storage_access msa = {
        .iov = &data_iov,
        .iov_nr = 1,
    };
    struct fdhash_entry *fde;
    u64 *roff, max_offset;
    int err = 0, i, j, o, ronr = 0;

    if (!data)
        return -ENOMEM;

    fde = mdsl_storage_fd_lookup_create(duuid, MDSL_STORAGE_DATA,
                                        column);
    if (IS_ERR(fde)) {
        hvfs_err(mdsl, "lookup create DATA file failed w/ %ld\n",
                 PTR_ERR(fde));
        err = PTR_ERR(fde);
        goto out;
    }

    /* calculate how many random offsets we need */
    max_offset = mdsl_storage_fd_max_offset(fde);
    if (max_offset == -1UL) {
        hvfs_err(mdsl, "get max offset failed\n");
        err = -EFAULT;
        goto out;
    }
    ronr = max_offset / bufsize + 1;
    roff = xmalloc(ronr * sizeof(u64));
    if (!roff) {
        hvfs_err(mdsl, "xmalloc() offset array failed\n");
        err = -ENOMEM;
        goto out;
    }
    for (i = 0; i < ronr; i++)
        roff[i] = -1UL;

    for (i = 0; i < ronr; i++) {
    retry:
        o = random() % ronr;
        for (j = 0; j < ronr; j++) {
            if (roff[j] == o * bufsize)
                goto retry;
        }
        roff[i] = o * bufsize;
    }
    
    /* loop for random offset */
    gettimeofday(begin, NULL);
    for (i = 0; i < ronr; i++) {
        msa.offset = roff[i];
        msa.iov->iov_base = data;
        if (roff[i] + bufsize > max_offset)
            msa.iov->iov_len = max_offset - roff[i];
        else
            msa.iov->iov_len = bufsize;
        
        err = mdsl_storage_fd_read(fde, &msa);
        if (err) {
            hvfs_err(mdsl, "fd read failed w/ %d\n", err);
            goto out_put;
        }
    }
    gettimeofday(end, NULL);

out_put:
    mdsl_storage_fd_put(fde);
out:
    return err;
}

int main(int argc, char *argv[])
{
    struct timeval begin, end;
    u64 duuid = 0;
    char *value;
    int column = 0;
    int err = 0;

    hvfs_info(mdsl, "BULK LOAD Unit Test ...\n");

    value = getenv("duuid");
    if (value)
        duuid = atol(value);
    value = getenv("column");
    if (value)
        column = atoi(value);
    value = getenv("bsize");
    if (value)
        bufsize = atoi(value);

    mdsl_pre_init();
    mdsl_init();
    hmo.site_id = HVFS_MDSL(0);
    mdsl_verify();

    /* drop the cache now */
    system("echo 3 > /proc/sys/vm/drop_caches");

    err = __test_bulk_load(duuid, column, &begin, &end);
    if (err) {
        hvfs_err(mdsl, "test_bulk_load() failed w/ %d\n", err);
        goto out;
    }
    printf("PFS BULK LOAD =>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    /* drop the cache now */
    system("echo 3 > /proc/sys/vm/drop_caches");

    err = __test_rand_load(duuid, column, &begin, &end);
    if (err) {
        hvfs_err(mdsl, "test_bulk_load() failed w/ %d\n", err);
        goto out;
    }
    printf("PFS RAND LOAD =>\n");
    printf("Average Latency:\t%8.2lf us\n", 
           (double)((end.tv_sec - begin.tv_sec) * 1000000.0 + 
                    (end.tv_usec - begin.tv_usec)));

    mdsl_destroy();
out:
    return err;
}
#endif
