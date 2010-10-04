/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-09-09 09:50:15 macan>
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
#include "root.h"
#include "lib.h"

#ifdef UNIT_TEST
int main(int argc, char *argv[])
{
    char path[256];
    struct root_disk rd;
    u64 offset;
    int fsid = 0, fd, bl, bw;
    int err = 0;

    hvfs_info(xnet, "ROOT Tool for creating root entry.\n");

    if (argc < 2) {
        hvfs_err(xnet, "fsid is not provided.\n");
        err = EINVAL;
        goto out;
    } else {
        fsid = atoi(argv[1]);
        hvfs_info(xnet, "fsid: %d\n", fsid);
    }

    snprintf(path, 255, "%s/%s", HVFS_ROOT_HOME, HVFS_ROOT_STORE);
    
    offset = fsid * sizeof(rd);

    /* Open or create the file now */
    err = open(path, O_CREAT | O_RDWR | O_SYNC, S_IRUSR | S_IWUSR);
    if (err < 0) {
        hvfs_err(xnet, "open root store %s failed w/ %s\n",
                 path, strerror(errno));
        err = -errno;
        goto out;
    }
    hvfs_info(xnet, "Open root store %s success.\n", path);
    fd = err;

    /* Set the rdisk now */
    memset(&rd, 0, sizeof(rd));
    rd.state = ROOT_DISK_VALID;
    rd.fsid = 1;
    rd.gdt_uuid = 0;
    rd.gdt_salt = lib_random(0xffdefa7);
    rd.root_uuid = 1;
    rd.root_salt = lib_random(0xffdeaedf);
    rd.gdt_flen = XTABLE_BITMAP_BYTES;

    /* ok, write it to disk */
    bl = 0;
    do {
        bw = pwrite(fd, ((void *)&rd) + bl, sizeof(rd) - bl, offset + bl);
        if (bw < 0) {
            hvfs_err(xnet, "write root entry %d failed w/ %s\n",
                     fsid, strerror(errno));
            err = -errno;
            goto out_close;
        } else if (bw == 0) {
            /* we just retry write */
        }
        bl += bw;
    } while (bl < sizeof(rd));

    hvfs_info(xnet, "Write root store successfully.\n");

out_close:
    close(fd);
out:
    return err;
}
#endif
