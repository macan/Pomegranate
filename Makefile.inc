##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-20 15:24:21 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

CC = gcc
LD = gcc
AR = ar
PYTHON = /bin/env python

INC_PATH = $(HOME_PATH)/include
LIB_PATH = $(HOME_PATH)/lib
MDS = $(HOME_PATH)/mds
MDSL = $(HOME_PATH)/mdsl
R2 = $(HOME_PATH)/r2
XNET = $(HOME_PATH)/xnet
TEST = $(HOME_PATH)/test
CONF = $(HOME_PATH)/conf
BIN = $(HOME_PATH)/bin
API = $(HOME_PATH)/api
TRIGGERS = $(HOME_PATH)/triggers
BRANCH = $(HOME_PATH)/branch

COMPILE_DATE = `date`
COMPILE_HOST = `hostname`
PYTHON_IX = /usr/include/python
PYTHON_VERSION = $(shell /bin/env python -V 2>&1 | awk '{print $$2}' | sed -e 's/\.[0-9]$$//g')
PYTHON_LIB = /usr/lib/

# for now we know the number of cores of the target machines is 8, so just set
# it manually.
# GET_CORE = `cat /proc/cpuinfo | grep processor | wc -l`
GET_CORE = 8

ifeq ($(CPU_CORE),)
__CORES__=$(GET_CORE)
endif

ifndef PYTHON_INC
export PYTHON_INC = $(PYTHON_IX)$(PYTHON_VERSION)
$(info ========================================================)
$(info You should SET 'PYTHON_INC' as the Python include path!!)
$(info HVFS supports directory trigger and you can write Python)
$(info plugins now. Have a try!)
$(info )
$(info We GUESS the python include path @ $(PYTHON_INC).)
$(info )
$(info ========================================================)
endif

# Debuging the memory and locks
XCFLAGS = -O2 -rdynamic -g -pg -std=gnu99 -fPIC
DEADCODESTRIP := -fdata-sections -ffunction-sections \
				 -Wl,--gc-sections
O3_OPT = -frename-registers -funroll-loops

CFLAGS += $(XCFLAGS) $(O3_OPT)
CFLAGS += -Wall -DCDATE="\"$(COMPILE_DATE)\"" \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) \
			-I$(PYTHON_INC) -I$(API) -I$(BRANCH) \
			-I$(LIB_PATH) -I$(MDS) -I$(MDSL) -I$(R2) -D_GNU_SOURCE\
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY -DHVFS_DEBUG_LOCK_ \
            -D_USE_SPINLOCK_ -DHVFS_DEBUG_LATENCY_ -DXNET_BLOCKING \
			-DXNET_EAGER_WRITEV -DCPU_CORE=$(__CORES__) \
			-DMDSL_ACC_SYNC -DMDSL_RADICAL_DEL

ifdef USE_JEMALLOC
CFLAGS += -DUSE_JEMALLOC
LFLAGS += -ljemalloc
endif

ifeq ($(DISABLE_PYTHON),)
CFLAGS += -DUSE_DT_PYTHON
LFLAGS += $(PYTHON_LIB)libpython$(PYTHON_VERSION).a -lm -lutil
endif
LFLAGS += -lrt -ldl -lpthread

# Region for depend files
TEST_MDS_SOURCE = cbht.c tx.c dh.c cmd_sender.c misc.c itbsplit.c \
                  itb_analyzer.c bitmapc.c embedpy.c ctrigger.c
TEST_MDSL_SOURCE = mdsl.c storage.c gc.c
TEST_XNET_SOURCE = xnet.c mds.c fpmds.c m2m.c xs.c ausplit.c mdsl.c client.c \
					root.c r2cli.c amc.c cr.c client_lat.c
TRIGGERS_SOURCE = example.c

MDS_AR_SOURCE = itb.c mds.c txg.c cbht.c tx.c prof.c conf.c dh.c xtable.c \
				dispatch.c c2m.c fe.c async.c m2m.c spool.c bitmapc.c \
                ddc.c scrub.c gossip.c capi.c ft.c trigger.c
MDSL_AR_SOURCE = mdsl.c spool.c tcc.c dispatch.c m2ml.c prof.c storage.c \
				 aio.c c2ml.c local.c gc.c
LIB_AR_SOURCE = lib.c ring.c time.c bitmap.c xlock.c segv.c conf.c md5.c \
                embedpy.c minilzo.c
XNET_AR_SOURCE = xnet.c xnet_simple.c
R2_AR_SOURCE = mgr.c root.c spool.c x2r.c dispatch.c bparser.c cli.c
API_AR_SOURCE = api.c
BRANCH_AR_SOURCE = branch.c bp.c

INC_H_SOURCE = atomic.h err.h hvfs.h hvfs_common.h hvfs_const.h hvfs_k.h \
				hvfs_u.h ite.h mds_api.h mdsl_api.h memory.h site.h tx.h \
				tracing.h txg.h xhash.h xlist.h xlock.h xnet.h xtable.h \
				xprof.h hvfs_addr.h
MDS_H_SOURCE = mds.h cbht.h dh.h itb.h prof.h async.h bitmapc.h mds_config.h ft.h
MDSL_H_SOURCE = mdsl.h lprof.h mdsl_config.h
R2_H_SOURCE = root.h mgr.h root_config.h rprof.h
LIB_H_SOURCE = lib.h ring.h minilzo.h
API_H_SOURCE = 
BRANCH_H_SOURCE = branch.h bp.h

inc_h_depend_files = $(patsubst %.h, $(INC_PATH)/%.h, $(INC_H_SOURCE)) \
						$(LIB_PATH)/hash.c
mds_h_depend_files = $(patsubst %.h, $(MDS)/%.h, $(MDS_H_SOURCE))
mdsl_h_depend_fils = $(patsubst %.h, $(MDSL)/%.h, $(MDSL_H_SOURCE))
lib_h_depend_files = $(patsubst %.h, $(LIB_PATH)/%.h, $(LIB_H_SOURCE))
r2_h_depend_files = $(patsubst %.h, $(R2)/%.h, $(R2_H_SOURCE))
api_h_depend_files = $(patsubst %.h, $(API)/%.h, $(API_H_SOURCE))
branch_h_depend_files = $(patsubst %.h, $(BRANCH)/%.h, $(BRANCH_H_SOURCE))
header_depend_files = $(inc_h_depend_files) $(mds_h_depend_files) \
						$(lib_h_depend_files) $(mdsl_h_depend_files) \
						$(r2_h_depend_files) $(api_h_depend_files)

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
api_depend_files = $(patsubst %.c, $(API)/%.c, $(API_AR_SOURCE)) \
					$(header_depend_files)
branch_depend_files = $(patsubst %.c, $(BRANCH)/%.c, $(BRANCH_AR_SOURCE)) \
					$(header_depend_files)
triggers_depend_files = $(patsubst %.c, $(TRIGGERS)/%.c, $(TRIGGERS_SOURCE)) \
					$(header_depend_files)
triggers_target_files = $(patsubst %.c, $(TRIGGERS)/%.so, $(TRIGGERS_SOURCE))

# shared libs
LIB_SO = $(LIB_PATH)/libhvfs.so.1.0
XNET_SO = $(XNET)/libxnet.so.1.0
MDS_SO = $(MDS)/libmds.so.1.0
MDSL_SO = $(MDSL)/libmdsl.so.1.0
R2_SO = $(R2)/libr2.so.1.0
API_SO = $(API)/libapi.so.1.0
BRANCH_SO = $(BRANCH)/libbranch.so.1.0

HVFS_LIB = $(LIB_PATH)/libhvfs.a
MDS_LIB = $(MDS)/libmds.a
MDSL_LIB = $(MDSL)/libmdsl.a
R2_LIB = $(R2)/libr2.a
XNET_LIB = $(XNET)/libxnet.a
API_LIB = $(API)/libapi.a
BRANCH_LIB = $(BRANCH)/libbranch.a