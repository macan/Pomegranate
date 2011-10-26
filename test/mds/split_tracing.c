/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-26 23:52:30 macan>
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
#include "ring.h"
#include "lib.h"
#include "mds.h"
#include "root.h"

#ifdef UNIT_TEST
struct chring mds_ring;

/* ring_add() add one site to the CH ring
 */
int ring_add(struct chring *r, u64 site, char *str)
{
    struct chp *p;
    char buf[256];
    int vid_max, i, err;

    vid_max = HVFS_RING_VID_MAX;

    p = (struct chp *)xzalloc(vid_max * sizeof(struct chp));
    if (!p) {
        hvfs_err(xnet, "xzalloc() chp failed\n");
        return -ENOMEM;
    }

    for (i = 0; i < vid_max; i++) {
        snprintf(buf, 256, "%s.%ld.%d", str, site, i);
        (p + i)->point = hvfs_hash(site, (u64)buf, strlen(buf),
                                   HASH_SEL_VSITE);
        (p + i)->vid = i;
        (p + i)->type = CHP_AUTO;
        (p + i)->site_id = site;
        err = ring_add_point_nosort(p + i, r);
        if (err) {
            hvfs_err(xnet, "ring_add_point() failed.\n");
            return err;
        }
    }
    return 0;
}

int setup_ring(char *conf_file)
{
    int nr = 10000, mnr = 0;
    struct conf_site cs[nr];
    int err = 0, i;
    
    /* read in the config file */
    err = conf_parse(conf_file, cs, &nr);
    if (err) {
        hvfs_err(xnet, "conf_parse failed w/ %d\n", err);
        goto out;
    }
    
    memset(&mds_ring, 0, sizeof(mds_ring));
    mds_ring.group = CH_RING_MDS;

    for (i = 0; i < nr; i++) {
        if (strcmp(cs[i].type, "mdsl") == 0) {
            continue;
        } else if (strcmp(cs[i].type, "mds") == 0) {
            ring_add(&mds_ring, HVFS_MDS(cs[i].id), "mds-*-");
            mnr++;
        }
    }
    ring_resort_nolock(&mds_ring);
    SET_TRACING_FLAG(lib, HVFS_DEBUG);
    ring_stat(&mds_ring, mnr);

out:
    return err;
}

int main(int argc, char *argv[]) 
{
    char *value, *conf_file = NULL;
    char *line = NULL;
    size_t len;
    ssize_t size;
    u64 salt = 0, key;

    value = getenv("cfile");
    if (value) {
        conf_file = strdup(value);
    }
    if (!conf_file) {
        hvfs_err(xnet, "Invalid conf file, use env 'cfile=XXX'\n");
        return EINVAL;
    }
    value = getenv("salt");
    if (value) {
        salt = strtol(value, NULL, 16);
    }
    hvfs_info(xnet, "Get salt 0x%lx\n", salt);

    setup_ring(conf_file);

    /* read in from stdin, compute hash value */
    while ((size = getline(&line, &len, stdin)) > 0) {
        if (line[size - 1] == '\n')
            line[size - 1] = '\0';
        key = strtol(line, NULL, 10);

        /* find in the chring */
        {
            struct chp *p;

            p = ring_get_point(key, salt, &mds_ring);
            hvfs_info(xnet, "Get %s => %lx => %lx -> S %lx.%d\n", 
                      line,
                      hvfs_hash(key, salt, sizeof(salt),
                                HASH_SEL_RING),
                      p->point, p->site_id, p->vid);
        }
    }

    return 0;
}

#endif
