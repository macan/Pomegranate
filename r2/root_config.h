/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-05-05 20:17:08 macan>
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

#ifndef __ROOT_CONFIG_H__
#define __ROOT_CONFIG_H__

#define HVFS_ROOT_GET_ENV_strncpy(name, value, len) do { \
        (value) = getenv("hvfs_root_" #name);            \
        if (value) {                                     \
            strncpy(hro.conf.name, value, len);          \
        }                                                \
    } while (0)

#define HVFS_ROOT_GET_ENV_cpy(name, value) do {  \
        (value) = getenv("hvfs_root_" #name);    \
        if (value) {                             \
            hro.conf.name = value;;              \
        }                                        \
    } while (0)

#define HVFS_ROOT_GET_ENV_atoi(name, value) do { \
        (value) = getenv("hvfs_root_" #name);    \
        if (value) {                             \
            hro.conf.name = atoi(value);         \
        }                                        \
    } while (0)

#define HVFS_ROOT_GET_ENV_atol(name, value) do { \
        (value) = getenv("hvfs_root_" #name);    \
        if (value) {                             \
            hro.conf.name = atol(value);         \
        }                                        \
    } while (0)

#define HVFS_ROOT_GET_ENV_option(name, uname, value) do { \
        (value) = getenv("hvfs_root_" #name);             \
        if (value) {                                      \
            if (atoi(value) != 0) {                       \
                hro.conf.option |= HVFS_ROOT_##uname;     \
            }                                             \
        }                                                 \
    } while (0)

/* APIs */
int root_config(void);

#endif
