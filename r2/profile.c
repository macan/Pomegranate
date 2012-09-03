/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2012-08-10 17:33:11 macan>
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

#include "root.h"

static struct hvfs_profile_mds_rate g_hpmr = {0, 0.0, 0.0, 0, 0,};
static struct hvfs_profile_mdsl_rate g_hpmlr = {0, 0.0, 0.0, 0, 0,};

/* This profile unit recv requests from other sites and write to corresponding
 * log file
 */
void hvfs_mds_profile_setup(struct hvfs_profile_ex *hp)
{
    int i = 0;

    HVFS_PROFILE_NAME_ADDIN(hp, i, "timestamp");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ic.csize");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.lookup");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.modify");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.split");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.buckets");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.depth");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.aitb");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.cowed");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.async_unlink");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.split_submit");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.split_local");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.split");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.forward");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.ausplit");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "txc.ftx");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "txc.total");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_alloc");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_free");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.inbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.outbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.active_links");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.loop_fwd");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.paused_mreq");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "cbht.aentry");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.au_submit");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.au_handle");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.au_bitmap");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.au_dd");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.au_ddr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.bitmap_in");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.bitmap_out");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.itb_load");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.itb_wb");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.bitmap");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.gossip_bitmap");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_total");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_handle");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_drop");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.gossip_ft");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.rsearch_depth");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "itb.wsearch_depth");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_qd");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "redo.client_redo_nr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "redo.in_rep_redo_nr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "redo.reap_rep_redo_nr");
    hp->nr = i;
}

void hvfs_mdsl_profile_setup(struct hvfs_profile_ex *hp)
{
    int i = 0;

    HVFS_PROFILE_NAME_ADDIN(hp, i, "timestamp");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ring.reqout");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ring.update");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ring.size");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.itb");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.bitmap");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mds.txg");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.range_in");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.range_out");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.range_copy");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_total");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_handle");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_alloc");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_free");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.inbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.outbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.active_links");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.wbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.rbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.wreq");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.rreq");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.cpbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.aio_submitted");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.aio_handled");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.tcc_size");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.tcc_used");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.active");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.memcache");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "hmo.pending_ios");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "hmi.mi_bused");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "hmi.mi_bfree");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "hmi.mi_bwrite");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "hmi.mi_bread");
    hp->nr = i;
}

void hvfs_osd_profile_setup(struct hvfs_profile_ex *hp)
{
    int i = 0;

    HVFS_PROFILE_NAME_ADDIN(hp, i, "timestamp");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "client.objrnr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "client.objwnr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "client.objrbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "client.objwbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ring.update");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "ring.size");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.objrnr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.objwnr");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.objrbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "mdsl.objwbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_total");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "misc.reqin_handle");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_alloc");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.msg_free");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.inbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.outbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "xnet.active_links");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.wbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.rbytes");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.wreq");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.rreq");
    HVFS_PROFILE_NAME_ADDIN(hp, i, "storage.cpbytes");
    hp->nr = i;
}

int root_setup_profile(void)
{
    struct hvfs_profile_ex *hp;
    FILE *fp;
    char fname[256];
    char data[4096];
    size_t len;
    int i;

    /* sanity check */
    if (!hro.conf.profiling_file) {
        return -EINVAL;
    }
    
    /* Setup up mds profile */
    hp = &hro.hp_mds;
    memset(hp, 0, sizeof(*hp));
    hvfs_mds_profile_setup(hp);
    memset(fname, 0, sizeof(fname));
    snprintf(fname, 255, "%s.mds", hro.conf.profiling_file);
    fp = fopen(fname, "w+");
    if (!fp) {
        hvfs_err(xnet, "fopen() profiling file %s failed %d\n",
                 fname, errno);
        return -EINVAL;
    }
    len = fwrite("## ##\n", 1, 6, fp);
    if (len < 6) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    memset(data, 0, 4096);
    len = sprintf(data, "@HVFS MDS PLOT DATA FILE :)\nlocal_ts");
    for (i = 0; i < hp->nr; i++) {
        len += sprintf(data + len, " %s", hp->hpe[i].name);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    fflush(fp);
    hro.hp_mds.fp = fp;
    
    /* Setup up mdsl profile */
    hp = &hro.hp_mdsl;
    memset(hp, 0, sizeof(*hp));
    hvfs_mdsl_profile_setup(hp);
    memset(fname, 0, sizeof(fname));
    snprintf(fname, 255, "%s.mdsl", hro.conf.profiling_file);
    fp = fopen(fname, "w+");
    if (!fp) {
        hvfs_err(xnet, "fopen() profiling file %s faield %d\n",
                 fname, errno);
        return -EINVAL;
    }
    len = fwrite("## ##\n", 1, 6, fp);
    if (len < 6) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    memset(data, 0, 4096);
    len = sprintf(data, "@HVFS MDSL PLOT DATA FILE :)\nlocal_ts");
    for (i = 0; i < hp->nr; i++) {
        len += sprintf(data + len, " %s", hp->hpe[i].name);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    fflush(fp);
    hro.hp_mdsl.fp = fp;

    /* Setup up osd profile */
    hp = &hro.hp_osd;
    memset(hp, 0, sizeof(*hp));
    hvfs_osd_profile_setup(hp);
    memset(fname, 0, sizeof(fname));
    snprintf(fname, 255, "%s.osd", hro.conf.profiling_file);
    fp = fopen(fname, "w+");
    if (!fp) {
        hvfs_err(xnet, "fopen() profiling file %s faield %d\n",
                 fname, errno);
        return -EINVAL;
    }
    len = fwrite("## ##\n", 1, 6, fp);
    if (len < 6) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    memset(data, 0, 4096);
    len = sprintf(data, "@HVFS OSD PLOT DATA FILE :)\nlocal_ts");
    for (i = 0; i < hp->nr; i++) {
        len += sprintf(data + len, " %s", hp->hpe[i].name);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file %s failed %d\n",
                 fname, errno);
        return -errno;
    }
    fflush(fp);
    hro.hp_osd.fp = fp;

    /* FIXME: Setup up bp profile */
    /* FIXME: Setup up client profile */

    return 0;
}

/* try to update metadata rate on each mds profile update */
static inline
void __root_profile_update_mds_rate(struct hvfs_profile_ex *hp)
{
    time_t cur = time(NULL);

    if (cur == g_hpmr.last_update)
        return;
    
    /* 3th entry is modify counter */
    g_hpmr.modify = (double)(hp->hpe[3].value - g_hpmr.last_modify) /
        (cur - g_hpmr.last_update);
    g_hpmr.nonmodify = (double)(hp->hpe[2].value - g_hpmr.last_nonmodify) /
        (cur - g_hpmr.last_update);

    g_hpmr.last_update = cur;
    g_hpmr.last_modify = hp->hpe[3].value;
    g_hpmr.last_nonmodify = hp->hpe[2].value;
}

/* try to update data I/O rate on each mdsl profile update */
static inline
void __root_profile_update_mdsl_rate(struct hvfs_profile_ex *hp)
{
    time_t cur = time(NULL);

    if (cur == g_hpmlr.last_update)
        return;
    
    /* 17th entry is write counter */
    g_hpmlr.write = (double)(hp->hpe[17].value - g_hpmlr.last_write) /
        (cur - g_hpmlr.last_update);
    g_hpmlr.read = (double)(hp->hpe[18].value - g_hpmlr.last_read) /
        (cur - g_hpmlr.last_update);

    g_hpmlr.last_update = cur;
    g_hpmlr.last_write = hp->hpe[17].value;
    g_hpmlr.last_read = hp->hpe[18].value;
}

int root_profile_update_mds(struct hvfs_profile *hp, 
                            struct xnet_msg *msg)
{
    int err = 0, i;

    if (hp->nr != hro.hp_mds.nr) {
        hvfs_err(xnet, "Invalid MDS request from %lx, nr mismatch "
                 "%d vs %d\n",
                 msg->tx.ssite_id, hp->nr, hro.hp_mds.nr);
        goto out;
    }

    for (i = 0; i < hp->nr; i++) {
        HVFS_PROFILE_VALUE_UPDATE(&hro.hp_mds, hp, i);
    }

    __root_profile_update_mds_rate(&hro.hp_mds);
    
out:
    return err;
}

int root_profile_update_mdsl(struct hvfs_profile *hp,
                             struct xnet_msg *msg)
{
    int err = 0, i;

    if (hp->nr != hro.hp_mdsl.nr) {
        hvfs_err(xnet, "Invalid MDSL request from %lx, nr mismatch "
                 "%d vs %d\n",
                 msg->tx.ssite_id, hp->nr, hro.hp_mdsl.nr);
        goto out;
    }

    for (i = 0; i < hp->nr; i++) {
        HVFS_PROFILE_VALUE_UPDATE(&hro.hp_mdsl, hp, i);
    }

    __root_profile_update_mdsl_rate(&hro.hp_mdsl);

out:
    return err;
}

int root_profile_update_osd(struct hvfs_profile *hp,
                            struct xnet_msg *msg)
{
    int err = 0, i;

    if (hp->nr != hro.hp_osd.nr) {
        hvfs_err(xnet, "Invalid OSD request from %lx, nr mismatch "
                 "%d vs %d\n",
                 msg->tx.ssite_id, hp->nr, hro.hp_osd.nr);
        goto out;
    }

    for (i = 0; i < hp->nr; i++) {
        HVFS_PROFILE_VALUE_UPDATE(&hro.hp_osd, hp, i);
    }

out:
    return err;
}

int root_profile_update_bp(struct hvfs_profile *hp,
                           struct xnet_msg *msg)
{
    hvfs_err(xnet, "BP profile has not been implemented yet\n");
    return -ENOSYS;
}

int root_profile_update_client(struct hvfs_profile *hp,
                               struct xnet_msg *msg)
{
    hvfs_err(xnet, "Client profile has not been implemented yet\n");
    return -ENOSYS;
}

void root_profile_flush(time_t cur)
{
    static time_t last = 0;
    char data[1024];
    size_t len;
    int i;

    if (cur >= last + hro.conf.profile_interval) {
        last = cur;
    } else {
        return;
    }
    
    /* flush mds profile */
    memset(data, 0, sizeof(data));
    len = sprintf(data, "%ld", cur);
    for (i = 0; i < hro.hp_mds.nr; i++) {
        len += sprintf(data + len, " %ld", hro.hp_mds.hpe[i].value);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, hro.hp_mds.fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file MDS failed %d\n",
                 errno);
    }
    fflush(hro.hp_mds.fp);
    
    /* flush mdsl profile */
    memset(data, 0, sizeof(data));
    len = sprintf(data, "%ld", cur);
    for (i = 0; i < hro.hp_mdsl.nr; i++) {
        len += sprintf(data + len, " %ld", hro.hp_mdsl.hpe[i].value);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, hro.hp_mdsl.fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file MDSL failed %d\n",
                 errno);
    }
    fflush(hro.hp_mdsl.fp);
    
    /* flush osd profile */
    memset(data, 0, sizeof(data));
    len = sprintf(data, "%ld", cur);
    for (i = 0; i < hro.hp_osd.nr; i++) {
        len += sprintf(data + len, " %ld", hro.hp_osd.hpe[i].value);
    }
    len += sprintf(data + len, "\n");
    if (fwrite(data, 1, len, hro.hp_osd.fp) < len) {
        hvfs_err(xnet, "fwrite() profiling file OSD failed %d\n",
                 errno);
    }
    fflush(hro.hp_osd.fp);

    /* FIXME: flush bp profile */
    /* FIXME: flush client profile */
}

int root_info_mds(u64 arg, void **buf)
{
    char *p;
    int err = 0, i;

    p = xzalloc(4096 << 2);
    if (!p) {
        hvfs_err(root, "xzalloc() info mds buffer failed\n");
        err = -ENOMEM;
        goto out;
    }
    *buf = (void *)p;
    
    switch (arg) {
    case HVFS_SYSINFO_MDS_RAW:
        p += sprintf(p, "MDS RAW:\n");
        for (i = 0; i < hro.hp_mds.nr; i++) {
            p += sprintf(p, " -> %20s\t\t%ld\n", hro.hp_mds.hpe[i].name,
                         hro.hp_mds.hpe[i].value);
        }
        break;
    default:
    case HVFS_SYSINFO_MDS_RATE:
        p += sprintf(p, "MDS Rate:\n -> [Modify] %10.4f/s "
                     "[NonModify] %10.4f/s\n",
                     g_hpmr.modify, g_hpmr.nonmodify);
    }

out:
    return err;
}

int root_info_mdsl(u64 arg, void **buf)
{
    char *p;
    int err = 0, i;

    p = xzalloc(4096 << 2);
    if (!p) {
        hvfs_err(root, "xzalloc() info mdsl buffer failed\n");
        err = -ENOMEM;
        goto out;
    }
    *buf = (void *)p;

    switch (arg) {
    case HVFS_SYSINFO_MDSL_RAW:
        p += sprintf(p, "MDSL RAW:\n");
        for (i = 0; i < hro.hp_mdsl.nr; i++) {
            p += sprintf(p, " -> %20s\t\t%ld\n", hro.hp_mdsl.hpe[i].name,
                         hro.hp_mdsl.hpe[i].value);
         }
        break;
    default:
    case HVFS_SYSINFO_MDSL_RATE:
        p += sprintf(p, "MDSL I/O Rate:\n -> [Write ] %10.4f/s "
                     "[Read     ] %10.4f/s\n",
                     g_hpmlr.write, g_hpmlr.read);
    }

out:
    return err;
}

int root_info_osd(u64 arg, void **buf)
{
    char *p;
    int err = 0, i;

    p = xzalloc(4096 << 2);
    if (!p) {
        hvfs_err(root, "xzalloc() info osd buffer failed\n");
        err = -ENOMEM;
        goto out;
    }
    *buf = (void *)p;

    switch (arg) {
    default:
    case HVFS_SYSINFO_OSD_RAW:
        p += sprintf(p, "OSD RAW:\n");
        for (i = 0; i < hro.hp_osd.nr; i++) {
            p += sprintf(p, " -> %20s\t\t%ld\n", hro.hp_osd.hpe[i].name,
                         hro.hp_osd.hpe[i].value);
        }
        break;
    }

out:
    return err;
}

int root_info_root(u64 arg, void **buf)
{
    char *p;
    int err = 0;

    p = xzalloc(4096 << 2);
    if (!p) {
        hvfs_err(root, "xzalloc() info osd buffer failed\n");
        err = -ENOMEM;
        goto out;
    }
    *buf = (void *)p;

    p += sprintf(p, " -> %20s\t\t%ld\n", "misc.reqin_total", 
                 atomic64_read(&hro.prof.misc.reqin_total));
    p += sprintf(p, " -> %20s\t\t%ld\n", "misc.reqin_handle", 
                 atomic64_read(&hro.prof.misc.reqin_handle));
    p += sprintf(p, " -> %20s\t\t%ld\n", "osd.objrep_recved", 
                 atomic64_read(&hro.prof.osd.objrep_recved));
    p += sprintf(p, " -> %20s\t\t%ld\n", "osd.objrep_handled", 
                 atomic64_read(&hro.prof.osd.objrep_handled));
    

out:
    return err;
}
