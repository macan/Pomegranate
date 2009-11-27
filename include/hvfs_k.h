/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2009-11-27 08:35:29 macan>
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

#ifndef __HVFS_K_H__
#define __HVFS_K_H__

/* header files need by kernel-level client */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/backing-dev.h>
#include <linux/statfs.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include <linux/writeback.h>
#include <linux/proc_fs.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include <linux/exportfs.h>
#include <linux/dcache.h>
#include <linux/splice.h>
#include <linux/pagemap.h>
#include <linux/hash.h>
#include <linux/sort.h>
#include <linux/rwsem.h>

#endif  /* __HVFS_K_H__ */
