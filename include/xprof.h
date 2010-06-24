/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-06-22 09:26:57 macan>
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

#ifndef __XPROF_H__
#define __XPROF_H__

struct xnet_prof
{
    atomic64_t msg_alloc;
    atomic64_t msg_free;
    atomic64_t inbytes;
    atomic64_t outbytes;

    atomic64_t active_links;
};

struct mds_prof_tx
{
    u64 ts;
    u32 ic_csize;
    u64 cbht_lookup;
    u64 cbht_modify;
    u64 cbht_split;
    u64 cbht_buckets;
    u64 cbht_depth;
    u64 cbht_aitb;
    u64 itb_cowed;
    u64 itb_async_unlink;
    u64 itb_split_submit;
    u64 mds_split;
    u64 mds_forward;
    u64 mds_ausplit;
    u64 txc_ftx;
    u64 txc_total;
    u64 msg_alloc;
    u64 msg_free;
    u64 inbytes;
    u64 outbytes;
    u64 active_links;
    u64 mds_loop_fwd;
    u64 mds_paused_mreq;
    u64 cbht_aentry;
    u64 misc_au_submit;
    u64 misc_au_handle;
    u64 misc_au_bitmap;
    u64 misc_au_dd;
    u64 misc_au_ddr;
};

#endif
