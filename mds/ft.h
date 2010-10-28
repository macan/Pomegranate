/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-10-28 19:30:04 macan>
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
#include "mds.h"

#define FT_INITED       0
#define FT_SUSPECT      1
#define FT_FAILED       2
#define FT_OK           3

/* the following state is static and can not change */
#define FT_DYNAMIC      4       /* used for judgement */
#define FT_REMOVED      4

#define FT_STATE_MAX    5

/* we should define a state change action table and check if we should do
 * hooked operations */
typedef int (*action_t)(u64, u64, u64, u64);

struct ft_state 
{
    u64 state;
    action_t action;
};

struct ft_state_machine
{
    struct ft_state states[FT_STATE_MAX][FT_STATE_MAX];
};

/* ostate: old state
 * ustate: update state
 * rstate: result state
 */
int ft_notify_r2(u64 ostate, u64 ustate, u64 rstate, u64 site);
int ft_print_state(u64 ostate, u64 ustate, u64 rstate, u64 site);
