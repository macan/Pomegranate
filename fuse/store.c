/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2011-05-03 14:22:55 macan>
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
#include "lib.h"
#include "store.h"

struct hvfs_datastore_mgr g_hdm;

void hvfs_datastore_init(void)
{
    memset(&g_hdm, 0, sizeof(g_hdm));
    INIT_LIST_HEAD(&g_hdm.g_dstore_list);
}

int hvfs_datastore_adding(char *conf_filename)
{
    char line[HVFS_MAX_NAME_LEN];
    char pathname[HVFS_MAX_NAME_LEN];
    char type[32];
    char errbuf[100];
    char *regex = "[ \t]*([a-zA-Z0-9_]+)[ \t]*=[ \t]*([^,\n]*)[ \t]*[,]+"
        "[ \t]*([a-zA-Z0-9_]+)[ \t]*=[ \t]*([^,\n]*)[ \t]*[,]*";

    struct hvfs_datastore *hd = NULL;
    regex_t preg;
    regmatch_t pmatch[5];
    FILE *fp = NULL;
    size_t len;
    int i, err = 0;

    fp = fopen(conf_filename, "r");
    if (!fp) {
        hvfs_err(xnet, "fopen(%s) mode R failed w/ %s(%d)\n",
                 conf_filename, strerror(errno), errno);
        return -errno;
    }

    memset(pmatch, 0, sizeof(pmatch));
    err = regcomp(&preg, regex, REG_EXTENDED);
    if (err) {
        hvfs_err(xnet, "regcomp failed w/ %d\n", err);
        goto out_close;
    }
    
    /* loop on each config line, extract kv pairs from each line and construct
     * them as a datastore entry */
    while (fgets(line, HVFS_MAX_NAME_LEN, fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;
        err = regexec(&preg, line, 7, pmatch, 0);
        if (err) {
            regerror(err, &preg, errbuf, 100);
            hvfs_err(xnet, "regexec failed w/ '%s'\n", errbuf);
            goto out_close;
        }

        for (i = 1; i < 5; i++) {
            if (pmatch[i].rm_so == -1)
                break;
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            memcpy(errbuf, line + pmatch[i].rm_so, len);
            errbuf[len] = '\0';
            switch (i) {
            case 1:
                /* this is the first key */
                if (strcmp(errbuf, "fstype") != 0) {
                    goto out_clean;
                }
                break;
            case 2:
                /* this is the first value */
                memcpy(type, line + pmatch[i].rm_so, len);
                type[len] = '\0';
                break;
            case 3:
                /* this is the second key */
                if (strcmp(errbuf, "mountpoint") != 0) {
                    goto out_clean;
                }
                break;
            case 4:
                /* this is the second value */
                memcpy(pathname, line + pmatch[i].rm_so, len);
                pathname[len] = '\0';
                break;
            default:
                hvfs_err(xnet, "Invlid k/v entry at %d\n", i);
            }
        }
        /* add a new store entry */
        hd = hvfs_datastore_add_new(hvfs_type_revert(type), pathname);
        if (IS_ERR(hd)) {
            hvfs_err(xnet, "Add datastore T:%s MP:%s failed w/ %ld\n",
                     type, pathname, PTR_ERR(hd));
        }
    out_clean:
        regfree(&preg);
        if (err)
            goto out_close;
    }

out_close:        
    fclose(fp);

    return err;
}

/*
 * This function hash the input string 'name' using the ELF hash
 * function for strings.
 *
 * Note: ELF(type)|ELF(name)
 */
u64 hvfs_datastore_fsid(char *type, char *name)
{
    u32 h = 0;
	u32 g;
    u64 r = 0;

	while(*type) {
		h = (h<<4) + *name++;
		if ((g = (h & 0xf0000000)))
			h ^=g>>24;
		h &=~g;
	}
    r = h;
    
	while(*name) {
		h = (h<<4) + *name++;
		if ((g = (h & 0xf0000000)))
			h ^=g>>24;
		h &=~g;
	}
    r = h | (r << 32);
    
	return r;
}

struct hvfs_datastore *hvfs_datastore_add_new(u32 type, char *pathname)
{
    struct hvfs_datastore *hd;
    struct stat buf;
    int err;

    hvfs_info(xnet, "Add new type %s MP: %s\n", hvfs_type_convert(type),
              pathname);
    /* pre-checking */
    if (type == LLFS_TYPE_ERR)
        return ERR_PTR(-EINVAL);

    /* Step 1: sanity check, pathname exists? */
    err = stat(pathname, &buf);
    if (err || !S_ISDIR(buf.st_mode)) {
        hvfs_err(xnet, "Mountpoint '%s' is not a directory "
                 "or syscall failed w/ %d\n",
                 pathname, err);
        return ERR_PTR(-EINVAL);
    }

    /* Step 2: alloc and init hd */
    err = -ENOMEM;
    hd = xzalloc(sizeof(*hd));
    if (!hd) {
        return ERR_PTR(err);
    }

    hd->type = type;
    strncpy(hd->pathname, pathname, HVFS_MAX_NAME_LEN - 1);
    hd->state = HVFS_DSTORE_VALID;
    list_add_tail(&hd->list, &g_hdm.g_dstore_list);
    g_hdm.nr++;

    return hd;
}

struct hvfs_datastore *hvfs_datastore_get(u32 type, u64 fsid)
{
    struct hvfs_datastore *pos;
    int select = 0, cur = 0;

    if (!g_hdm.nr)
        return NULL;

    if (type & LLFS_TYPE_ANY)
        select = lib_random(g_hdm.nr);

    list_for_each_entry(pos, &g_hdm.g_dstore_list, list) {
        if ((type == pos->type &&
             fsid == hvfs_datastore_fsid(hvfs_type_convert(type),
                                         pos->pathname)) ||
            ((type & LLFS_TYPE_ANY) && select == cur))
            return pos;
        cur++;
    }
    return NULL;
}

char *hvfs_datastore_getone(u32 type, u64 fsid, char *entry)
{
    struct hvfs_datastore *hd;
    char glue[HVFS_MAX_NAME_LEN + strlen(entry)];
    char *result = NULL;

    hd = hvfs_datastore_get(type, fsid);
    if (!hd) {
        hvfs_err(xnet, "No active datastore or internal error\n");
        return NULL;
    }

    strcpy(glue, hd->pathname);
    strcat(glue, "/");
    strcat(glue, entry);
    result = strdup(glue);

    return result;
}

void hvfs_datastore_free(struct hvfs_datastore *hd)
{
    list_del(&hd->list);
    if (hd->state & HVFS_DSTORE_VALID) {
        /* free any resource */
        ;
    }
    xfree(hd);
    g_hdm.nr--;
}

void hvfs_datastore_exit(void)
{
    struct hvfs_datastore *pos, *n;

    list_for_each_entry_safe(pos, n, &g_hdm.g_dstore_list, list) {
        hvfs_datastore_free(pos);
    }
}


