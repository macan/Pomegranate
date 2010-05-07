/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-07 16:34:36 macan>
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

#include "root.h"
#include "root_config.h"

#ifdef HVFS_TRACING
u32 hvfs_root_tracing_flags = HVFS_DEFAULT_LEVEL;
#endif

/* root_pre_init()
 * 
 * setting up the internal configs.
 */
void root_pre_init()
{
    /* prepare the hro */
    memset(&hro, 0, sizeof(hro));
    /* setup the state */
    hro.state = HRO_STATE_LAUNCH;
}

/* root_verify()
 */
int root_verify(void)
{
    /* check sth */
    return 0;
}

/* root_config()
 *
 * Get configs from the env
 */
int root_config(void)
{
    char *value;

    if (hro.state != HRO_STATE_LAUNCH) {
        hvfs_err(root, "ROOT state is not in launching, please call "
                 "root_pre_init() firstly!\n");
        return -EINVAL;
    }

    HVFS_ROOT_GET_ENV_atoi(site_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(ring_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(root_mgr_htsize, value);
    HVFS_ROOT_GET_ENV_atoi(service_threads, value);
    HVFS_ROOT_GET_ENV_atoi(ring_push_interval, value);
    HVFS_ROOT_GET_ENV_atoi(prof_plot, value);

    HVFS_MDS_GET_ENV_option(opt_memonly, MEMONLY, value);

    /* default configs */
    if (!hro.conf.ring_push_interval) {
        hro.conf.ring_push_interval = 600;
    }

    return 0;
}

int root_init(void)
{
    int err = 0;

    /* lib init */
    lib_init();

    /* FIXME: decode the cmdline */

    /* FIXME: configrations */
    /* default configurations */
    hmo.conf.ring_push_interval = 600; /* 600 seconds */

    /* get configs from env */
    root_config();

    /* FIXME: in the service threads' pool */
    err = root_spool_create();
    if (err)
        goto out_spool;

    /* ok to run */
    hro.state = HMO_STATE_RUNNING;

out_spool:
    return err;
}

void root_destroy(void)
{
    hvfs_verbose(root, "OK, stop it now ...\n");

    /* free something */

    /* destroy the service thread pool */
    root_spool_destory();
}
