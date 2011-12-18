/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-12-18 20:52:01 macan>
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

int main(int argc, char *argv[])
{
    u64 duuid = 1;
    char path[256];
    char *type;
    struct stat stat;
    int fd;
    int err = 0, sid = 0, ext = 0;

    hvfs_info(mdsl, "MDSL Append Buffer Backend File Fixer.\n");

    /* got the site_id, uuid from user */
    if (argc < 4) {
        hvfs_err(mdsl, "Usage: %s site_id dir_uuid col/ext\n", argv[0]);
        return EINVAL;
    } else {
        sid = atoi(argv[1]);
        duuid = atol(argv[2]);
        ext = atoi(argv[3]);
    }

    type = getenv("type");
    if (!type)
        type = "data";
    if (strcmp(type, "data") == 0 ||
        strcmp(type, "itb") == 0) {
        hvfs_info(mdsl, "Begin Fix Directory %lx/%s.\n", duuid, type);
    } else {
        hvfs_err(mdsl, "Invalid fix type %s.\n", type);
        err = EINVAL;
        goto out;
    }

    mdsl_init();
    hmo.site_id = HVFS_MDSL(sid);
    mdsl_verify();

    /* open the file */
    sprintf(path, "%s/%lx/%lx/%s-%d", hmo.conf.mdsl_home, 
            hmo.site_id, duuid, type, ext);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        hvfs_err(mdsl, "open file %s failed w/ %d\n", path, errno);
        goto out_clean;
    }
    
    /* get the file length */
    err = fstat(fd, &stat);
    if (err < 0) {
        hvfs_err(mdsl, "fd %d fstat failed w/ %d.\n",
                 fd, errno);
        err = -errno;
        goto out_close;
    }
    hvfs_info(mdsl, "Get file size: %ld B.\n", stat.st_size);
    
    /* truncate the file to proper size */
    {
        u64 offset = PAGE_ROUNDUP(stat.st_size, getpagesize());

        if (stat.st_size & (getpagesize() - 1) &&
            offset > stat.st_size) {
            hvfs_info(mdsl, "Trunc it to: %ld B\n", offset);
            err = ftruncate(fd, offset);
            if (err) {
                hvfs_err(mdsl, "ftruncate() file failed w/ %d\n", errno);
                goto out_close;
            }
        }
    }

out_close:
    close(fd);
out_clean:
    mdsl_destroy();
    
out:
    return err;
}
#endif
