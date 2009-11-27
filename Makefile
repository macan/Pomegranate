##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-11-27 09:50:09 macan>
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

CFLAGS += -g -O2 -Wall -pg -DCDATE="\"$(COMPILE_DATE)\"" \
			-DCHOST="\"$(COMPILE_HOST)\"" -I$(INC_PATH) -lpthread \
			-DHVFS_TRACING -DHVFS_DEBUG_MEMORY
LFLAGS +=

UNIT_TARGETS = $(LIB_PATH)/ring
UNIT_OBJS = $(LIB_PATH)/lib.o $(LIB_PATH)/ring.o

all : unit_test

$(LIB_PATH)/ring : $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

unit_test: $(UNIT_TARGETS)
	@echo "Targets for unit test are ready."
	@echo "Executing 'ring' now ..."
	@$(LIB_PATH)/ring

unit_test_clean:
	@rm -rf $(UNIT_TARGETS)

clean: unit_test_clean