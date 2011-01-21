/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-01-21 17:06:53 macan>
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
#include "mds.h"

TRACING_FLAG(ia, HVFS_DEFAULT_LEVEL);

int main(int argc, char *argv[])
{
    struct itb *itb;
    char *line = NULL;
    size_t len = 0;
    u64 offset;
    int bl, br;
    int fd;
    int err;

    if (argc < 2) {
        hvfs_info(ia, "Usage: %s filename\n", argv[0]);
        return EINVAL;
    }

    itb = xzalloc(sizeof(struct itb) + ITB_SIZE * sizeof(struct ite));
    if (!itb) {
        hvfs_err(ia, "xzalloc() itb failed.\n");
        return ENOMEM;
    }
    
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        hvfs_err(ia, "open file %s failed w/ %d\n", argv[1], errno);
        return errno;
    }
    
    fprintf(stdout, "ITB Analyzer to debug the ITB write-backed "
            "snapshot. (%sDo NOT support LZO compressed itb!%s)\n",
            HVFS_COLOR_RED, HVFS_COLOR_END);

    while (1) {
        fprintf(stdout, "Please input the file offset to load the "
                "itb into memory.\n");
        fprintf(stdout, "Input CMD > ");
        err = getline(&line, &len, stdin);
        if (err == -1) {
            hvfs_err(ia, "errno %d\n", errno);
            continue;
        }
        if (isalpha(line[0])) {
            if (line[0] == 'q')
                goto out;
            else {
                hvfs_err(ia, "invalied offset got\n");
                continue;
            }
        }
        offset = atol(line);

        fprintf(stdout, "Read ITB @ %ld[%lx] in file %s\n", 
                offset, offset, argv[1]);

        bl = 0;
        do {
            br = pread(fd, ((void *)itb) + bl, sizeof(struct itb) - bl, 
                      offset + bl);
            if (br < 0) {
                hvfs_err(ia, "fread failed w/ %d\n", errno);
                goto out;
            } else if (br == 0) {
                hvfs_err(ia, "reach the EOF\n");
                goto out;
            }
            bl += br;
        } while (bl < sizeof(struct itb));
        
        /* read the ITE regions now */
        hvfs_info(ia, "ITB [%ld] header loaded, total len %d ...\n",
                  itb->h.itbid, atomic_read(&itb->h.len));
        bl = 0;
        do {
            br = pread(fd, ((void *)itb) + sizeof(struct itb) + bl, 
                       atomic_read(&itb->h.len) - bl, offset + bl + sizeof(struct itb));
            if (br < 0) {
                hvfs_err(ia, "fread failed w/ %d\n", errno);
                goto out;
            } else if (br == 0) {
                hvfs_err(ia, "reach the EOF\n");
                goto out;
            }
            bl += br;
        } while (bl < atomic_read(&itb->h.len));

        /* dump now */
        itb_dump(itb);
        memset(itb, sizeof(struct itb) + ITB_SIZE * sizeof(struct ite), 0);
    }

out:
    close(fd);
    return 0;
}

