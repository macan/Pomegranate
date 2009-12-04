##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-04 10:37:26 macan>
#
# This is the makefile for HVFS project.
#
# Armed by EMACS.

CC = gcc
LD = gcc

COMPILE_DATE = `date`
COMPILE_HOST = `hostname`

HOME_PATH = $(shell pwd)
INC_PATH = $(HOME_PATH)/include
LIB_PATH = $(HOME_PATH)/lib
MDS = $(HOME_PATH)/mds

CFLAGS += -g -O2 -Wall -pg -DCDATE="\"$(COMPILE_DATE)\"" \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) -lpthread \
			-I$(LIB_PATH) \
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY
LFLAGS +=

UNIT_TARGETS = $(LIB_PATH)/ring $(MDS)/cbht
UNIT_OBJS = $(LIB_PATH)/lib.o $(LIB_PATH)/ring.o

all : unit_test

$(LIB_PATH)/ring : $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

$(MDS)/cbht : $(MDS)/itb.c $(MDS)/cbht.c $(MDS)/mds.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

unit_test: $(UNIT_TARGETS)
	@echo "Targets [$(UNIT_TARGETS)] for unit test are ready."

unit_test_clean:
	@rm -rf $(UNIT_TARGETS)

clean: unit_test_clean