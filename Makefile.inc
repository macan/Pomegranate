##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-14 09:06:00 macan>
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
TEST = $(HOME_PATH)/test

COMPILE_DATE = `date`
COMPILE_HOST = `hostname`

# Debuging the memory and locks
CFLAGS += -g -O2 -Wall -pg -DCDATE="\"$(COMPILE_DATE)\"" -rdynamic \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) -lpthread \
			-I$(LIB_PATH) -I$(MDS)\
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY -DHVFS_DEBUG_LOCK_
LFLAGS +=

