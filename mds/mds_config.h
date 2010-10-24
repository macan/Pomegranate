/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-21 22:33:14 macan>
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

#ifndef __MDS_CONFIG_H__
#define __MDS_CONFIG_H__

#define HVFS_MDS_GET_ENV_strncpy(name, value, len) do { \
        (value) = getenv("hvfs_mds_" #name);            \
        if (value) {                                    \
            strncpy(hmo.conf.name, value, len);         \
        }                                               \
    } while (0)

#define HVFS_MDS_GET_ENV_cpy(name, value) do {  \
        (value) = getenv("hvfs_mds_" #name);    \
        if (value) {                            \
            hmo.conf.name = value;;             \
        }                                       \
    } while (0)

#define HVFS_MDS_GET_ENV_atoi(name, value) do { \
        (value) = getenv("hvfs_mds_" #name);    \
        if (value) {                            \
            hmo.conf.name = atoi(value);        \
        }                                       \
    } while (0)

#define HVFS_MDS_GET_ENV_atol(name, value) do { \
        (value) = getenv("hvfs_mds_" #name);    \
        if (value) {                            \
            hmo.conf.name = atol(value);        \
        }                                       \
    } while (0)

#define HVFS_MDS_GET_ENV_option(name, uname, value) do { \
        (value) = getenv("hvfs_mds_" #name);             \
        if (value) {                                     \
            if (atoi(value) != 0) {                      \
                hmo.conf.option |= HVFS_MDS_##uname;     \
            }                                            \
        }                                                \
    } while (0)

#define HVFS_MDS_GET_kmg(name, value) do {          \
        double base;                                \
        char *p;                                    \
        (value) = getenv("hvfs_mds_" #name);        \
        if (value) {                                \
            base = strtod(value, &p);               \
            if (*p == 'g' || *p == 'G') {           \
                base *= 1024 * 1024 * 1024;         \
            } else if (*p == 'm' || *p == 'M') {    \
                base *= 1024 * 1024;                \
            } else if (*p == 'k' || *p == 'K') {    \
                base *= 1024;                       \
            }                                       \
            hmo.conf.name = (u64)base;              \
        }                                           \
    } while (0)

/* APIs */
int mds_config(void);

#endif
