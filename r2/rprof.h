/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-10 10:42:54 macan>
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

#ifndef __ROOT_PROF_H__
#define __ROOT_PROF_H__

struct root_client_prof
{
};

struct root_ring_prof
{
};

struct root_mds_prof
{
};

struct root_mdsl_prof
{
};

struct root_misc_prof
{
    atomic64_t reqin_total;     /* # of total requests coming in */
    atomic64_t reqin_handle;    /* # of handled requests */
};

struct root_osd_prof
{
    atomic64_t objrep_recved;   /* # of recved object reports */
    atomic64_t objrep_handled;  /* # of handled object reports */
};

struct root_storage_prof
{
};

struct root_prof
{
    time_t ts;
    struct root_client_prof client;
    struct root_ring_prof ring;
    struct root_mds_prof mds;
    struct root_mdsl_prof mdsl;
    struct root_misc_prof misc;
    struct root_storage_prof storage;
    struct root_osd_prof osd;
    struct xnet_prof *xnet;
};

#endif
