/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-03-09 16:17:21 macan>
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

#include "lib.h"

int get_site(parser_state_t *ps, char *line, 
             char **type, char **node, int *port, int *id)
{
    int res = PARSER_OK;
    char *p = line;
    char *str = NULL;

    if (*ps != PARSER_EXPECT_SITE) {
        hvfs_err(lib, "invalid parser state, %s need the %s state\n",
                 __FUNCTION__, "PARSER_EXPECT_SITE");
        res = PARSER_FAILED;
        goto out;
    }

    if (line[0] == '\n' || line[0] == '#') {
        res = PARSER_CONTINUE;
        return res;
    }
    /* get the site type */
    str = strtok(p, ": \t\n");
    if (!str) {
        res = PARSER_FAILED;
        goto out;
    }
    if (strcmp(str, "r2") == 0) {
        *type = "r2";
    } else if (strcmp(str, "mdsl") == 0) {
        *type = "mdsl";
    } else if (strcmp(str, "mds") == 0) {
        *type = "mds";
    } else if (strcmp(str, "client") == 0) {
        *type = "client";
    } else if (strcmp(str, "amc") == 0) {
        *type = "amc";
    } else if (strcmp(str, "bp") == 0) {
        *type = "bp";
    } else {
        res = PARSER_FAILED;
        goto out;
    }

    /* get the site address */
    str = strtok(NULL, ": \t\n");
    if (!str) {
        res = PARSER_FAILED;
        goto out;
    }
    if (isdigit(str[0])) {
        /* ip address */
        hvfs_debug(lib, "> get site ip address: %s\n", str);
    } else if (isalpha(str[0])) {
        hvfs_debug(lib, "> get site host name: %s\n", str);
    } else {
        res = PARSER_FAILED;
        goto out;
    }
    *node = strdup(str);

    /* get the port number */
    str = strtok(NULL, ": \t\n");
    if (!str) {
        res = PARSER_FAILED;
        goto out;
    }
    if (isdigit(str[0])) {
        *port = atoi(str);
    } else {
        res = PARSER_FAILED;
        goto out;
    }

    /* get the site logical id */
    str = strtok(NULL, ": \t\n");
    if (!str) {
        res = PARSER_FAILED;
        goto out;
    }
    if (isdigit(str[0])) {
        *id = atoi(str);
    } else {
        res = PARSER_FAILED;
        goto out;
    }

out:
    return res;
}

u64 conf_site_id(char *type, int id)
{
    u64 site_id;

    if (strcmp(type, "mdsl") == 0) {
        site_id = HVFS_MDSL(id);
    } else if (strcmp(type, "mds") == 0) {
        site_id = HVFS_MDS(id);
    } else if (strcmp(type, "r2") == 0) {
        site_id = HVFS_RING(id);
    } else if (strcmp(type, "client") == 0) {
        site_id = HVFS_CLIENT(id);
    } else if (strcmp(type, "amc") == 0) {
        site_id = HVFS_AMC(id);
    } else if (strcmp(type, "bp") == 0) {
        site_id = HVFS_BP(id);
    } else {
        site_id = -1UL;
    }

    return site_id;
}

int conf_parse(char *conf_file, struct conf_site *cs, int *csnr)
{
    parser_state_t ps = PARSER_INIT;
    FILE *fp;
    size_t len = 0;
    char *line = NULL;
    int err = 0, i = 0, pln = 0, br;
    
    if (!csnr || *csnr == 0)
        return -EINVAL;

    if (!conf_file) {
        conf_file = "./conf/hvfs.conf";
    }
    fp = fopen(conf_file, "r");
    if (!fp) {
        hvfs_err(lib, "fopen() file %s failed w/ %s\n", 
                 conf_file, strerror(errno));
        err = -errno;
        goto out;
    }

    while ((br = getline(&line, &len, fp)) != -1) {
        pln++;
    retry:
        switch (ps) {
        case PARSER_INIT:
            ps = PARSER_EXPECT_SITE;
            goto retry;
            break;
        case PARSER_EXPECT_SITE:
            err = get_site(&ps, line, &(cs + i)->type, &(cs + i)->node,
                           &(cs + i)->port, &(cs + i)->id);
            if (err == PARSER_CONTINUE)
                continue;
            if (err == PARSER_FAILED)
                goto out_close;
            i++;
            if (i >= *csnr) {
                err = -EINVAL;
                goto out_close;
            }
            break;
        case PARSER_EXPECT_FS:
            break;
        default:;
        }
    }

    *csnr = i;
    {
        int j;
        for (j = 0; j < i; j++) {
            hvfs_info(lib, "> type %s node %s port %d id %d\n",
                      cs[j].type, cs[j].node, cs[j].port, cs[j].id);
        }
    }

    err = 0;
out_close:
    fclose(fp);
out:
    return err;
}

