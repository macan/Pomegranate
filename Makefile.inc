##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-06-26 10:46:43 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

CC = gcc
LD = gcc
AR = ar

INC_PATH = $(HOME_PATH)/include
LIB_PATH = $(HOME_PATH)/lib
MDS = $(HOME_PATH)/mds
MDSL = $(HOME_PATH)/mdsl
R2 = $(HOME_PATH)/r2
XNET = $(HOME_PATH)/xnet
TEST = $(HOME_PATH)/test
CONF = $(HOME_PATH)/conf

COMPILE_DATE = `date`
COMPILE_HOST = `hostname`

# for now we know the number of cores of the target machines is 8, so just set
# it manually.
# GET_CORE = `cat /proc/cpuinfo | grep processor | wc -l`
GET_CORE = 8

ifeq ($(CPU_CORE),)
	__CORES__=$(GET_CORE)
endif

# Debuging the memory and locks
XCFLAGS = -O2 -rdynamic -g -pg -std=gnu99

CFLAGS += $(XCFLAGS)
CFLAGS += -Wall -DCDATE="\"$(COMPILE_DATE)\"" \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) \
			-I$(LIB_PATH) -I$(MDS) -I$(MDSL) -I$(R2) -D_GNU_SOURCE\
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY -DHVFS_DEBUG_LOCK_ \
            -D_USE_SPINLOCK_ -DHVFS_DEBUG_LATENCY_ -DXNET_BLOCKING \
			-DXNET_EAGER_WRITEV -DCPU_CORE=$(__CORES__)
LFLAGS += -lrt -lpthread

# Region for depend files
TEST_MDS_SOURCE = cbht.c tx.c dh.c cmd_sender.c misc.c itbsplit.c \
                  itb_analyzer.c bitmapc.c
TEST_MDSL_SOURCE = mdsl.c storage.c
TEST_XNET_SOURCE = xnet.c mds.c fpmds.c m2m.c xs.c ausplit.c mdsl.c client.c \
					root.c r2cli.c

MDS_AR_SOURCE = itb.c mds.c txg.c cbht.c tx.c prof.c conf.c dh.c xtable.c \
				dispatch.c c2m.c fe.c async.c m2m.c spool.c bitmapc.c \
                ddc.c scrub.c
MDSL_AR_SOURCE = mdsl.c spool.c tcc.c dispatch.c m2ml.c prof.c storage.c \
				 aio.c c2ml.c
LIB_AR_SOURCE = lib.c ring.c time.c bitmap.c xlock.c segv.c conf.c md5.c
XNET_AR_SOURCE = xnet.c xnet_simple.c
R2_AR_SOURCE = mgr.c root.c spool.c x2r.c dispatch.c bparser.c

INC_H_SOURCE = atomic.h err.h hvfs.h hvfs_common.h hvfs_const.h hvfs_k.h \
				hvfs_u.h ite.h mds_api.h mdsl_api.h memory.h site.h tx.h \
				tracing.h txg.h xhash.h xlist.h xlock.h xnet.h xtable.h \
				xprof.h hvfs_addr.h
MDS_H_SOURCE = mds.h cbht.h dh.h itb.h prof.h async.h bitmapc.h mds_config.h
MDSL_H_SOURCE = mdsl.h lprof.h mdsl_config.h
R2_H_SOURCE = root.h mgr.h root_config.h rprof.h
LIB_H_SOURCE = lib.h ring.h

inc_h_depend_files = $(patsubst %.h, $(INC_PATH)/%.h, $(INC_H_SOURCE)) \
						$(LIB_PATH)/hash.c
mds_h_depend_files = $(patsubst %.h, $(MDS)/%.h, $(MDS_H_SOURCE))
mdsl_h_depend_fils = $(patsubst %.h, $(MDSL)/%.h, $(MDSL_H_SOURCE))
lib_h_depend_files = $(patsubst %.h, $(LIB_PATH)/%.h, $(LIB_H_SOURCE))
r2_h_depend_files = $(patsubst %.h, $(R2)/%.h, $(R2_H_SOURCE))
header_depend_files = $(inc_h_depend_files) $(mds_h_depend_files) \
						$(lib_h_depend_files) $(mdsl_h_depend_files) \
						$(r2_h_depend_files)

ut_depend_files = $(patsubst %.c, $(TEST)/mds/%.c, $(TEST_MDS_SOURCE)) \
					$(patsubst %.c, $(TEST)/xnet/%.c, $(TEST_XNET_SOURCE)) \
					$(header_depend_files)
mds_depend_files = $(patsubst %.c, $(MDS)/%.c, $(MDS_AR_SOURCE)) \
					$(header_depend_files)
mdsl_depend_files = $(patsubst %.c, $(MDSL)/%.c, $(MDSL_AR_SOURCE)) \
					$(header_depend_files)
lib_depend_files = $(patsubst %.c, $(LIB_PATH)/%.c, $(LIB_AR_SOURCE)) \
					$(header_depend_files)
xnet_depend_files = $(patsubst %.c, $(XNET)/%.c, $(XNET_AR_SOURCE)) \
					$(header_depend_files)
r2_depend_files = $(patsubst %.c, $(R2)/%.c, $(R2_AR_SOURCE)) \
					$(header_depend_files)

HVFS_LIB = $(LIB_PATH)/libhvfs.a
MDS_LIB = $(MDS)/libmds.a
MDSL_LIB = $(MDSL)/libmdsl.a
R2_LIB = $(R2)/libr2.a
XNET_LIB = $(XNET)/libxnet.a