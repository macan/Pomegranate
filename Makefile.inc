##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-07 15:37:14 macan>
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
XNET = $(HOME_PATH)/xnet

COMPILE_DATE = `date`
COMPILE_HOST = `hostname`

CFLAGS += -g -O2 -Wall -pg -DCDATE="\"$(COMPILE_DATE)\"" \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) -lpthread \
			-I$(LIB_PATH) \
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY
LFLAGS +=

