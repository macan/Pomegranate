/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-03-02 09:44:36 macan>
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

#ifndef __MDSL_PROF_H__
#define __MDSL_PROF_H__

struct mdsl_client_prof
{
};

struct mdsl_ring_prof
{
    atomic64_t reqout;
    atomic64_t update;          /* # of ring update msg */
    atomic64_t size;            /* total size of ring update msg */
};

struct mdsl_mds_prof
{
    atomic64_t itb;             /* # of itb loading */
    atomic64_t bitmap;          /* # of bitmap loading */
    atomic64_t txg;             /* # of txg writing */
};

struct mdsl_mdsl_prof
{
    atomic64_t range_in;        /* # of ranges in */
    atomic64_t range_out;       /* # of ranges out */
    atomic64_t range_copy;      /* # of ranges copied */
};

struct mdsl_misc_prof
{
    atomic64_t reqin_total;     /* # of total requests coming in */
    atomic64_t reqin_handle;    /* # of handled requests */
};

struct mdsl_prof
{
    time_t ts;
    struct mdsl_client_prof client;
    struct mdsl_ring_prof ring;
    struct mdsl_mds_prof mds;
    struct mdsl_mdsl_prof mdsl;
    struct mdsl_misc_prof misc;
    struct xnet_prof *xnet;
};

#endif
