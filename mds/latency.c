/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-10-18 06:32:21 macan>
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

#ifndef __HVFS_LATENCY_STAT_C__
#define __HVFS_LATENCY_STAT_C__

/* if HVFS_LATENCY_STAT defined, we do latency stat */
#ifdef HVFS_LATENCY_STAT

/* histogram */
struct lat_hist
{
    atomic64_t total;
    /* for 0 to 2s */
#define LAT_SMALL_RESOLUTION            (10)
#define LAT_SMALL_MAX                   (2 * 1000 * 1000 /      \
                                         LAT_SMALL_RESOLUTION)
#define LAT_LARGE_RESOLUTION            (100000)
#define LAT_LARGE_MAX                   (10 * 1000 * 1000 /     \
                                         LAT_LARGE_RESOLUTION)
    atomic64_t small[LAT_SMALL_MAX];
    atomic64_t large[LAT_LARGE_MAX];
};

struct __lat_stat_mgr
{
#define LAT_STAT_CREATE         0
#define LAT_STAT_LOOKUP         1
#define LAT_STAT_UNLINK         2

#define LAT_STAT_MAX            3
    struct lat_hist lh[LAT_STAT_MAX];
};

static inline char *__lat_stat_name(int which)
{
    switch (which) {
    case LAT_STAT_CREATE:
        return "CREATE";
    case LAT_STAT_LOOKUP:
        return "LOOKUP";
    case LAT_STAT_UNLINK:
        return "UNLINK";
    default:
        return "";
    }
    return NULL;
}

void lat_hist_init(struct lat_hist *lh)
{
    memset(lh->small, 0, sizeof(lh->small));
}

/* point distribution, mean, stdev, 99.9% */

/* global variables and init */
static struct __lat_stat_mgr lat_stat_mgr;

int lat_stat_init(void)
{
    int i;

    for (i = 0; i < LAT_STAT_MAX; i++) {
        lat_hist_init(&lat_stat_mgr.lh[i]);
    }
    
    return 0;
}

static inline
void lat_hist_update(struct timeval begin, struct timeval end, int which)
{
    int idx;

    atomic64_inc(&lat_stat_mgr.lh[which].total);
    
    idx = ((end.tv_sec - begin.tv_sec) * 1000000 + 
           (end.tv_usec - begin.tv_usec));
    if (idx < 0)
        idx = 0;

    idx /= LAT_SMALL_RESOLUTION;
    if (idx < LAT_SMALL_MAX) {
        atomic64_inc(&lat_stat_mgr.lh[which].small[idx]);
    } else {
        idx -= (LAT_SMALL_MAX);
        idx /= (LAT_LARGE_RESOLUTION / LAT_SMALL_RESOLUTION);
        if (idx < LAT_LARGE_MAX) {
            atomic64_inc(&lat_stat_mgr.lh[which].large[idx]);
        } else {
            atomic64_inc(&lat_stat_mgr.lh[which].large[LAT_LARGE_MAX - 1]);
        }
    }
}

static inline
int __lat_hist_out(struct lat_hist *lh, char *p)
{
    u64 all = 0;
    int n = 0, t = 0, i;
    
    for (i = 0; i < LAT_SMALL_MAX; i++) {
        if (atomic64_read(&lh->small[i])) {
            all += atomic64_read(&lh->small[i]);
            n = sprintf(p, "\t%03.4f%s <= %7.2f ms %ld %ld S\n",
                        (double)all / atomic64_read(&lh->total) * 100, "%",
                        (double)((i + 1) * LAT_SMALL_RESOLUTION) / 1000, 
                        all, atomic64_read(&lh->small[i]));
            p += n;
            t += n;
        }
    }
    for (i = 0; i < LAT_LARGE_MAX; i++) {
        if (atomic64_read(&lh->large[i])) {
            all += atomic64_read(&lh->large[i]);
            n = sprintf(p, "\t%03.4f%s <= %8.0f ms %ld %ld L\n",
                        (double)all / atomic64_read(&lh->total) * 100, "%",
                        (double)((i + 1) * LAT_LARGE_RESOLUTION) / 1000 +
                        (LAT_SMALL_MAX * LAT_SMALL_RESOLUTION / 1000),
                        all, atomic64_read(&lh->large[i]));
            p += n;
            t += n;
        }
    }

    return t;
}

/* Callback for DCONF latency output
 */
void mds_cb_latency(void *arg)
{
    char *p = NULL;
    int i;

    p = xzalloc((LAT_SMALL_MAX + LAT_LARGE_MAX) * 100);
    if (!p) {
        hvfs_err(xnet, "xzalloc() cb_latency array failed\n");
        return;
    }
    
    *((char **)arg) = p;

    for (i = 0; i < LAT_STAT_MAX; i++) {
        p += sprintf(p, "Latency Distribution of '%s':\n", __lat_stat_name(i));
        p += __lat_hist_out(&lat_stat_mgr.lh[i], p);
    }

    return;
}

#define TIMER_DEF lib_timer_def
#define TIMER_B lib_timer_B
#define TIMER_E lib_timer_E
#define TIMER_EaU(which) do {                \
        TIMER_E();                           \
        lat_hist_update(begin, end, which);  \
    } while (0)

#else  /* no latency stat */

#define lat_stat_init()
#define TIMER_DEF()
#define TIMER_B()
#define TIMER_E()
#define TIMER_EaU(which)

void mds_cb_latency(void *arg)
{
    return;
}

#endif

#endif
