/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-08-22 12:35:55 macan>
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

#ifndef __MDS_REDO_H__
#define __MDS_REDO_H__

struct redo_log_entry
{
    u64 txg;
    u32 id;
    u32 len;
#define LOG_CLI_NOOP            0
#define LOG_CLI_CREATE          1
#define LOG_CLI_UPDATE          2
#define LOG_CLI_UNLINK          3
#define LOG_CLI_SYMLINK         4
#define LOG_CLI_AUSPLIT         5
#define LOG_CLI_BITMAP          6
    u16 op;
};

struct redo_log_cli             /* requests from client */
{
    struct hvfs_index hi;
};

struct redo_log_ausplit
{
    u64 ssite;
};

struct redo_log_site_disk
{
    struct redo_log_entry rle;
    union 
    {
        struct redo_log_cli rlc;
        struct redo_log_ausplit rla;
        /* add other log info here */
    } u;
    u8 data[0];
};

struct redo_log_site
{
    struct list_head list;
    struct redo_log_site_disk rlsd;
};

/* for HVFS_MDS_HA reqeust, commands */
#define HA_REPLICATE            0
#define HA_REAP                 1
#define HA_APPLY                2
/* for HVFS_MDS_RECOVERY request, commands */
#define HA_QUERY                3
#define HA_GET                  4

/* redo.c INTERNAL interface */
struct xnet_msg *__prepare_replicate_log_entry(void);
int __construct_replicate_log_entry(struct xnet_msg *msg, 
                                    struct redo_log_site *rls);
int __replicate_log_entry(struct xnet_msg *msg);
int __trunc_log_file(void);
void redo_log_reap(time_t cur);

#endif
