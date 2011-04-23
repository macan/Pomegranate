/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-04-23 19:49:11 macan>
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

#ifndef __HVFS_CONST_H__
#define __HVFS_CONST_H__

#define HVFS_SUPER_MAGIC        (0x4af5)

#ifdef USE_SHORT_LEN            /* short length means we have short name length */
#define HVFS_MAX_NAME_LEN       128
#define XTABLE_VALUE_SIZE       (192)
#else
#define HVFS_MAX_NAME_LEN       256
#define XTABLE_VALUE_SIZE       (320)
#endif

#define MDS_DCONF_MAX_NAME_LEN  64
#define MDSL_DCONF_MAX_NAME_LEN MDS_DCONF_MAX_NAME_LEN
#define ROOT_DCONF_MAX_NAME_LEN MDS_DCONF_MAX_NAME_LEN
#define HVFS_RING_VID_MAX       256

#define HVFS_GDT_BITMAP_COLUMN  0 /* default bitmap data column in GDT dir */
#define HVFS_TRIG_COLUMN        1 /* default trigger column for each
                                   * directory */

#define HVFS_DEFAULT_UMASK      0644
#define HVFS_DIR_UMASK          0755

#define MPCHECK_SENSITIVE_MAX   (5)
#define SECOND_IN_US            (1000000)
#define HALF_SECOND_IN_US       (500000) /* 1x faster */
#define QUAD_SECOND_IN_US       (250000) /* 2x */
#define EIGHTH_SECOND_IN_US     (125000) /* 4x */
#define SIXTEENTH_SECOND_IN_US  (62500)  /* 8x */
#define THIRTYND_SECOND_IN_US   (31250)  /* 16x */

#define HVFS_TINY_FILE_LEN      (4097)

/* UUID bits
 *
 * |<-63..43->|<-42..0->|
 */
#define HVFS_MAX_UUID_PER_MDS   (0x7ffffffffff) /* 2^43 - 1 */
#define HVFS_UUID_HIGHEST_BIT   (0x8000000000000000)

static char *hvfs_ccolor[] __attribute__((unused)) = 
{
    "\033[0;40;31m",            /* red */
    "\033[0;40;32m",            /* green */
    "\033[0;40;33m",            /* yellow */
    "\033[0;40;34m",            /* blue */
    "\033[0;40;35m",            /* pink */
    "\033[0;40;36m",            /* yank */
    "\033[0;40;37m",            /* white */
    "\033[0m",                  /* end */
};
#define HVFS_COLOR(x)   (hvfs_ccolor[x])
#define HVFS_COLOR_RED  (hvfs_ccolor[0])
#define HVFS_COLOR_GREEN        (hvfs_ccolor[1])
#define HVFS_COLOR_YELLOW       (hvfs_ccolor[2])
#define HVFS_COLOR_BLUE         (hvfs_ccolor[3])
#define HVFS_COLOR_PINK         (hvfs_ccolor[4])
#define HVFS_COLOR_YANK         (hvfs_ccolor[5])
#define HVFS_COLOR_WHITE        (hvfs_ccolor[6])
#define HVFS_COLOR_END          (hvfs_ccolor[7])

#define ETXCED          1025    /* TXC Evicted */
#define ECHP            1026    /* Consistent Hash Point error */
#define ERINGCHG        1027    /* Ring Changed */
#define ESPLIT          1028    /* Need SPLIT */
#define ENOTEXIST       1029    /* Not Exist */
#define EHSTOP          1030    /* Stop */
#define EBITMAP         1031    /* Bitmap not correct, you should reload the
                                 * bitmap */
#define EUPDATED        1032    /* the delta has already been applied,
                                 * although thereis an error in another
                                 * logic */
#define EHWAIT          1033    /* wait a few seconds and retry */
#define ERECOVER        1034    /* notify a recover process to the caller */
#define EISEMPTY        1035    /* the bitmap slice is empty */
#define EDTRIGSTOP      1036    /* operation stopped by dtrigger */
#define ENOTRIG         1037    /* no trigger defined */
#define EIGNORE         1038    /* ignore something, i.e. ignore the branch
                                 * line */
#define EADJUST         1039    /* someone should adjust themself */
#define EFWD            1040    /* already forwarded */
#define ELOCKED         1041    /* lease locked */
#define ERACE           1042    /* lease raced */
#define EABORT          1043    /* transaction aborted */

#endif
