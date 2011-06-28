/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-28 10:13:50 macan>
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

int main(int argc, char *argv[])
{
    char path[256];
    struct txg_begin tb;
    struct txg_end te;
    struct itb_info *ii;
    void *other;
    int osize;
    int bl, br, i;
    int fd, err = 0;
    
    /* open the txg file */
    sprintf(path, "%s/txg", HVFS_MDSL_HOME);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        hvfs_err(mdsl, "open file %s failed w/ %s\n",
                 path, strerror(errno));
        err = -errno;
        goto out;
    }

    /* read in the content */
    do {
        /* get the txg_begin entry */
        bl = 0;
        do {
            br = read(fd, (void *)&tb + bl, sizeof(tb) - bl);
            if (br < 0) {
                hvfs_err(mdsl, "read file failed w/ %d\n", errno);
                goto out;
            } else if (br == 0) {
                hvfs_warning(mdsl, "EOF, break now!\n");
                goto out;
            }
            bl += br;
        } while (bl < sizeof(tb));
        
        /* get the itb info */
        ii = xzalloc(sizeof(*ii) * tb.itb_nr);
        if (!ii) {
            hvfs_err(mdsl, "xzalloc() failed to alloc itb info\n");
            goto out;
        }
        for (i = 0; i < tb.itb_nr; i++) {
            bl = 0;
            do {
                br = read(fd, (void *)&ii[i].duuid + bl,
                          ITB_INFO_DISK_SIZE - bl);
                if (br < 0) {
                    hvfs_err(mdsl, "read file failed w/ %d\n", errno);
                    goto out;
                } else if (br == 0) {
                    hvfs_warning(mdsl, "EOF, break now!\n");
                    goto out;
                }
                bl += br;
            } while (bl < ITB_INFO_DISK_SIZE);
        }
        /* get other region */
        osize = tb.dir_delta_nr * 
            sizeof(struct hvfs_dir_delta) +
            tb.rdd_nr *
            sizeof(struct hvfs_dir_delta) +
            tb.bitmap_delta_nr * 
            sizeof(struct bitmap_delta) +
            tb.ckpt_nr * 
            sizeof(struct checkpoint) +
            tb.rd_nr * sizeof(u64);
        if (osize) {
            other = xzalloc(osize);
            if (!other) {
                hvfs_err(mdsl, "xzalloc() other region failed\n");
                goto out;
            }
            bl = 0;
            do {
                br = read(fd, other + bl, osize - bl);
                if (br < 0) {
                    hvfs_err(mdsl, "read file failed w/ %d\n", errno);
                    goto out;
                } else if (br == 0) {
                    hvfs_warning(mdsl, "EOF, break now!\n");
                    goto out;
                }
                bl += br;
            } while (bl < osize);
        } else
            other = NULL;
        
        /* get the txg_end */
        bl = 0;
        do {
            br = read(fd, (void *)&te + bl, sizeof(te) - bl);
            if (br < 0) {
                hvfs_err(mdsl, "read file failed w/ %d\n", errno);
                goto out;
            } else if (br == 0) {
                hvfs_warning(mdsl, "EOF, break now!\n");
                goto out;
            }
            bl += br;
        } while (bl < sizeof(te));
        /* free resources */
        hvfs_info(mdsl, "Got site %lx TXG %ld w/ %d itbs osize %d\n", 
                  tb.site_id, tb.txg, tb.itb_nr, osize);
        xfree(ii);
        xfree(other);
    } while (1);

    close(fd);
out:
    return err;
}
