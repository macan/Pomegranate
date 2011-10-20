/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-18 06:48:00 macan>
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

#ifndef __HVFS_FUSE_STAT_C__
#define __HVFS_FUSE_STAT_C__

/* if HVFS_FUSE_STAT defined, we do latency stat */
#ifdef HVFS_FUSE_STAT

#warning "Enable FUSE client Latency Statistics."

/* histogram */
struct fc_hist
{
    u64 total;
    /* for 0 to 5s */
#define FC_LAT_SMALL_RESOLUTION         (100)
#define FC_LAT_SMALL_MAX                (5 * 1000 * 1000 /  \
                                         FC_LAT_SMALL_RESOLUTION)
#define FC_LAT_LARGE_RESOLUTION         (100000)
#define FC_LAT_LARGE_MAX                (60 * 1000 * 1000 / \
                                         FC_LAT_LARGE_RESOLUTION)
    atomic64_t small[FC_LAT_SMALL_MAX];
    atomic64_t large[FC_LAT_LARGE_MAX];
};

struct __fc_stat_mgr
{
#define FC_STAT_CREATE          0
#define FC_STAT_GETATTR         1
#define FC_STAT_UNLINK          2

#define FC_STAT_MAX             3
    struct fc_hist fh[FC_STAT_MAX];
};

static inline char *__fc_stat_name(int which)
{
    switch (which) {
    case FC_STAT_CREATE:
        return "CREATE";
    case FC_STAT_GETATTR:
        return "GETATTR";
    case FC_STAT_UNLINK:
        return "UNLINK";
    default:
        return "";
    }
    return NULL;
}

void fc_hist_init(struct fc_hist *fh)
{
    memset(fh->small, 0, sizeof(fh->small));
}

/* point distribution, mean, stdev, 99.9% */

/* global variables and init */
struct __fc_stat_mgr fc_stat_mgr;

int fc_stat_init(void)
{
    int i;

    for (i = 0; i < FC_STAT_MAX; i++) {
        fc_hist_init(&fc_stat_mgr.fh[i]);
    }
    
    return 0;
}

static inline
void fc_hist_update(struct timeval begin, struct timeval end, int which)
{
    int idx;

    fc_stat_mgr.fh[which].total++;
    
    idx = ((end.tv_sec - begin.tv_sec) * 1000000 + 
           (end.tv_usec - begin.tv_usec));
    if (idx < 0)
        idx = 0;

    idx /= FC_LAT_SMALL_RESOLUTION;
    if (idx < FC_LAT_SMALL_MAX) {
        atomic64_inc(&fc_stat_mgr.fh[which].small[idx]);
    } else {
        idx -= (FC_LAT_SMALL_MAX);
        idx /= (FC_LAT_LARGE_RESOLUTION / FC_LAT_SMALL_RESOLUTION);
        if (idx < FC_LAT_LARGE_MAX) {
            atomic64_inc(&fc_stat_mgr.fh[which].large[idx]);
        } else {
            atomic64_inc(&fc_stat_mgr.fh[which].large[FC_LAT_LARGE_MAX - 1]);
        }
    }
}

static inline
int __fc_hist_out(struct fc_hist *fh, char *p)
{
    u64 all = 0;
    int n = 0, t = 0, i;
    
    for (i = 0; i < FC_LAT_SMALL_MAX; i++) {
        if (atomic64_read(&fh->small[i])) {
            all += atomic64_read(&fh->small[i]);
            n = sprintf(p, "\t%03.4f%s <= %7.1f ms %ld %ld S\n",
                        (double)all / fh->total * 100, "%",
                        (double)((i + 1) * FC_LAT_SMALL_RESOLUTION) / 1000, 
                        all, atomic64_read(&fh->small[i]));
            p += n;
            t += n;
        }
    }
    for (i = 0; i < FC_LAT_LARGE_MAX; i++) {
        if (atomic64_read(&fh->large[i])) {
            all += atomic64_read(&fh->large[i]);
            n = sprintf(p, "\t%03.4f%s <= %8.0f ms %ld %ld L\n",
                        (double)all / fh->total * 100, "%",
                        (double)((i + 1) * FC_LAT_LARGE_RESOLUTION) / 1000 +
                        (FC_LAT_SMALL_MAX * FC_LAT_SMALL_RESOLUTION / 1000),
                        all, atomic64_read(&fh->large[i]));
            p += n;
            t += n;
        }
    }

    return t;
}

/* Callback for DCONF latency output
 */
void pfs_cb_latency(void *arg)
{
    char *p = NULL;
    int i;

    p = xzalloc((FC_LAT_SMALL_MAX + FC_LAT_LARGE_MAX) * 100);
    if (!p) {
        hvfs_err(xnet, "xzalloc() cb_latency array failed\n");
        return;
    }
    
    *((char **)arg) = p;

    for (i = 0; i < FC_STAT_MAX; i++) {
        p += sprintf(p, "Latency Distribution of '%s':\n", __fc_stat_name(i));
        p += __fc_hist_out(&fc_stat_mgr.fh[i], p);
    }

    return;
}

#define FC_TIMER_DEF lib_timer_def
#define FC_TIMER_B lib_timer_B
#define FC_TIMER_E lib_timer_E
#define FC_TIMER_EaU(which) do {                \
        FC_TIMER_E();                           \
        fc_hist_update(begin, end, which);      \
    } while (0)

#else  /* no latency stat */

#define fc_stat_init()
#define FC_TIMER_DEF()
#define FC_TIMER_B()
#define FC_TIMER_E()
#define FC_TIMER_EaU(which)

void pfs_cb_latency(void *arg)
{
    return NULL;
}

#endif

#endif
