/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-07 15:06:47 macan>
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

#ifndef __OSD_PROF_H__
#define __OSD_PROF_H__

struct osd_client_prof
{
    atomic64_t objrnr;          /* # of read objects */
    atomic64_t objwnr;          /* # of write objects */
    atomic64_t objrbytes;       /* # of read bytes */
    atomic64_t objwbytes;       /* # of write bytes */
};

struct osd_ring_prof
{
    atomic64_t update;          /* # of ring update msg */
    atomic64_t size;            /* total size of ring update msg */
};

struct osd_mds_prof
{
};

struct osd_mdsl_prof
{
    atomic64_t objrnr;          /* # of read objects */
    atomic64_t objwnr;          /* # of write objects */
    atomic64_t objrbytes;       /* # of read bytes */
    atomic64_t objwbytes;       /* # of write bytes */
};

struct osd_misc_prof
{
    atomic64_t reqin_total;     /* # of total requests coming in */
    atomic64_t reqin_handle;    /* # of handled requests */
};

struct osd_storage_prof
{
    atomic64_t wbytes;          /* # of bytes written */
    atomic64_t rbytes;          /* # of bytes read */
    atomic64_t wreq;            /* # of requests written */
    atomic64_t rreq;            /* # of requests read */
    atomic64_t cpbytes;         /* # of bytes copied to mmap region */
};

struct osd_prof
{
    time_t ts;
    struct osd_client_prof client;
    struct osd_ring_prof ring;
    struct osd_mds_prof mds;
    struct osd_mdsl_prof mdsl;
    struct osd_misc_prof misc;
    struct osd_storage_prof storage;
    struct xnet_prof *xnet;
};

#ifdef hvfs_pf
#undef hvfs_pf
#endif

#ifndef hvfs_pf
#define hvfs_pf(f, a...) do {                   \
        if (hoo.conf.pf_file) {                 \
            FPRINTK(hoo.conf.pf_file, f, ## a); \
            FFLUSH(hoo.conf.pf_file);           \
        } else {                                \
            PRINTK(f, ## a);                    \
            FFLUSH(stdout);                     \
        }                                       \
    } while (0)
#endif

#endif
