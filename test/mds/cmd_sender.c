/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-06-20 22:39:50 macan>
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

TRACING_FLAG(cs, HVFS_DEFAULT_LEVEL);

int main(int argc, char *argv[])
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX,};
    char data[256] = {0,};
    char *str;
    char *line = NULL;
    struct dconf_req *dcr = (struct dconf_req *)data;
    size_t len = 0;
    pid_t pid;
    int bs, cmd, arg0, bl = 0;
    int fd, err;

    fd = socket(AF_UNIX, SOCK_STREAM, AF_UNIX);
    if (fd == -1) {
        hvfs_err(cs, "create unix socket failed %d\n", errno);
        goto out;
    }
    if (argc < 2) {
        hvfs_err(cs, "Usage: %s pid\n", argv[0]);
        err = -EINVAL;
        goto out;
    } else {
        pid = atoi(argv[1]);
    }
    
    sprintf(addr.sun_path, "/tmp/.MDS.DCONF.%d", pid);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        hvfs_err(cs, "connect to unix socket %s failed '%s'\n", 
                 addr.sun_path, strerror(errno));
        goto out;
    }

    while (1) {
        fprintf(stdout, 
                "CMD [0, echo_info]\n"
                "    [1, set_txg_intv]\n"
                "    [2, set_prof_intv]\n"
                "    [3, set_unlk_intv]\n"
                "    [4, set_mds_flag]\n"
                "    [5, set_xnet_flag]\n"
                "    [6, get_latency]\n"
            );
        fprintf(stdout,
                "INPUT CMD > ");
        err = getline(&line, &len, stdin);
        if (err == -1) {
            hvfs_err(cs, "err %d errno %d\n", err, errno);
            continue;
        }
        if (isalpha(line[0])) {
            if (line[0] == 'q')
                goto out;
        }
        err = sscanf(line, "%d", &cmd);
        if (err == EOF) {
            hvfs_err(cs, "err %d errno %d\n", err, errno);
            continue;
        }

        fprintf(stdout,
                "INPUT CMD ARG0 > ");
        err = getline(&line, &len, stdin);
        if (err == -1) {
            hvfs_err(cs, "err %d errno %d\n", err, errno);
            continue;
        }
        if (isalpha(line[0])) {
            if (line[0] == 'q')
                goto out;
        }
        err = sscanf(line, "%d", &arg0);
        if (err == -1) {
            hvfs_err(cs, "err %d errno %d\n", err, errno);
            continue;
        }

        memset(data, 0, 256);
        dcr->cmd = cmd;
        dcr->arg0 = arg0;
        fprintf(stdout,
                "SEND '<%ld,%ld>' to MDS DCONF ...\n", dcr->cmd, dcr->arg0);

        bl = 0;
        do {
            bs = send(fd, data + bl, 256 - bl, 0);
            if (bs == -1) {
                hvfs_err(cs, "send error %d\n", errno);
                goto out;
            }
            bl += bs;
        } while (bl < 256);
        /* try to read in the reply, the format is: len(4B) + string */
        bl = 0;
        do {
            bs = recv(fd, (void *)&len + bl, sizeof(int) - bl,
                      MSG_WAITALL);
            if (bs == -1) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                hvfs_err(cs, "recv error %s(%d)\n", strerror(errno), errno);
                goto out;
            }
            bl += bs;
        } while (bl < sizeof(int));

        str = xzalloc(len + 1);
        if (!str) {
            hvfs_err(cs, "xzalloc result buffer failed\n");
            goto out;
        }

        bl = 0;
        do {
            bs = recv(fd, str + bl, len - bl, MSG_WAITALL);
            if (bs == -1) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                hvfs_err(cs, "recv errno %s(%d)\n", strerror(errno), errno);
                goto out;
            }
            bl += bs;
        } while (bl < len);
        hvfs_plain(cs, "%s", str);
    }
out:
    close(fd);
    free(line);
    return 0;
}
