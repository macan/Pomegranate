/**
 * Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
 *                           <macan@ncic.ac.cn>
 *
 * Armed with EMACS.
 * Time-stamp: <2010-02-02 13:57:38 macan>
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

#ifndef __TRACING_H__
#define __TRACING_H__

/* hvfs tracing flags */
#define HVFS_INFO       0x80000000
#define HVFS_WARN       0x40000000
#define HVFS_ERR        0x20000000
#define HVFS_PLAIN      0x10000000

#define HVFS_ENTRY      0x00000008
#define HVFS_VERBOSE    0x00000004 /* more infos than debug mode */
#define HVFS_PRECISE    0x00000002
#define HVFS_DEBUG      0x00000001

#define HVFS_DEFAULT_LEVEL      0xf0000000
#define HVFS_DEBUG_ALL          0x0000000f

#ifdef __KERNEL__
#define PRINTK printk
#define FFLUSH
#else  /* !__KERNEL__ */
#define PRINTK printf
#define FFLUSH(f) fflush(f)
#define KERN_INFO       "[INFO] "
#define KERN_ERR        "[ERR ] "
#define KERN_WARNING    "[WARN] "
#define KERN_DEBUG      "[DBG ] "
#define KERN_VERB       "[VERB] "
#define KERN_PLAIN      ""
#endif

#ifdef HVFS_TRACING
#define hvfs_tracing(mask, flag, lvl, f, a...) do {             \
        if (unlikely(mask & flag)) {                            \
            if (mask & HVFS_PRECISE) {                          \
                PRINTK(lvl "HVFS (%16s, %5d): %s[%lx]: " f,     \
                       __FILE__, __LINE__, __func__,            \
                       pthread_self(), ## a);                   \
                FFLUSH(stdout);                                 \
            } else                                              \
                PRINTK(lvl f, ## a);                            \
        }                                                       \
    } while (0)
#else
#define hvfs_tracing(mask, flag, lvl, f, a...)
#endif  /* !HVFS_TRACING */

#define IS_HVFS_DEBUG(module) ({                            \
            int ret;                                        \
            if (hvfs_##module##_tracing_flags & HVFS_DEBUG) \
                ret = 1;                                    \
            else                                            \
                ret = 0;                                    \
            ret;                                            \
        })

#define IS_HVFS_VERBOSE(module) ({                              \
            int ret;                                            \
            if (hvfs_##module##_tracing_flags & HVFS_VERBOSE)   \
                ret = 1;                                        \
            else                                                \
                ret = 0;                                        \
            ret;                                                \
        })

#define hvfs_info(module, f, a...)                          \
    hvfs_tracing(HVFS_INFO, hvfs_##module##_tracing_flags,  \
                 KERN_INFO, f, ## a)

#define hvfs_plain(module, f, a...)                         \
    hvfs_tracing(HVFS_PLAIN, hvfs_##module##_tracing_flags, \
                 KERN_PLAIN, f, ## a)

#define hvfs_verbose(module, f, a...)           \
    hvfs_tracing((HVFS_VERBOSE | HVFS_PRECISE), \
                 hvfs_##module##_tracing_flags, \
                 KERN_VERB, f, ## a)

#define hvfs_debug(module, f, a...)             \
    hvfs_tracing((HVFS_DEBUG | HVFS_PRECISE),   \
                 hvfs_##module##_tracing_flags, \
                 KERN_DEBUG, f, ## a)

#define hvfs_entry(module, f, a...)             \
    hvfs_tracing((HVFS_ENTRY | HVFS_PRECISE),   \
                 hvfs_##module##_tracing_flags, \
                 KERN_DEBUG, "entry: " f, ## a)

#define hvfs_exit(module, f, a...)              \
    hvfs_tracing((HVFS_ENTRY | HVFS_PRECISE),   \
                 hvfs_##module##_tracing_flags, \
                 KERN_DEBUG, "exit: " f, ## a)

#define hvfs_warning(module, f, a...)           \
    hvfs_tracing((HVFS_WARN | HVFS_PRECISE),    \
                 hvfs_##module##_tracing_flags, \
                 KERN_WARNING, f, ##a)

#define hvfs_err(module, f, a...)               \
    hvfs_tracing((HVFS_ERR | HVFS_PRECISE),     \
                 hvfs_##module##_tracing_flags, \
                 KERN_ERR, f, ##a)

#define SET_TRACING_FLAG(module, flag) do {     \
        hvfs_##module##_tracing_flags |= flag;  \
    } while (0)
#define CLR_TRACING_FLAG(module, flag) do {     \
        hvfs_##module##_tracing_flags &= ~flag; \
    } while (0)

#define TRACING_FLAG(name, v) u32 hvfs_##name##_tracing_flags = v
#define TRACING_FLAG_DEF(name) extern u32 hvfs_##name##_tracing_flags

#ifdef __KERNEL__
#define ASSERT(i, m) BUG_ON(!(i))
#else  /* !__KERNEL__ */
#define ASSERT(i, m) do {                               \
        if (!(i)) {                                     \
            hvfs_err(m, "Assertion " #i " failed!\n");  \
            exit(-EINVAL);                              \
        }                                               \
    } while (0)
#endif

#define HVFS_VV PRINTK
/* Use HVFS_BUG() to get the SIGSEGV signal to debug in the GDB */
#define HVFS_BUG() (*((int *)0) = 1)

#endif  /* !__TRACING_H__ */
