##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-14 20:22:09 macan>
#
# This is the makefile for HVFS project.
#
# Armed by EMACS.

HOME_PATH = $(shell pwd)

include Makefile.inc

UNIT_TARGETS = $(LIB_PATH)/ring $(TEST)/mds/cbht $(MDS)/tx
UNIT_OBJS = $(LIB_PATH)/lib.o $(LIB_PATH)/ring.o
RING_SOURCES = $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c $(LIB_PATH)/hash.c \
				$(LIB_PATH)/xlock.c

all : hvfs_lib unit_test

hvfs_lib : 
	@echo -e " " CD"\t" $(LIB_PATH)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)"

clean: unit_test_clean
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)" clean

# Note: the following region is only for UNIT TESTing
# region for unit test
$(LIB_PATH)/ring : $(RING_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

CBHT_SOURCES = $(MDS)/itb.c $(MDS)/mds.c $(MDS)/txg.c $(XNET)/xnet.c $(MDS)/cbht.c \
				$(TEST)/mds/cbht.c
TX_SOURCES = $(MDS)/mds.c $(MDS)/txg.c $(MDS)/tx.c $(XNET)/xnet.c

$(TEST)/mds/cbht : $(CBHT_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST -L$(LIB_PATH) -lhvfs 

$(MDS)/tx : $(TX_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST -L$(LIB_PATH) -lhvfs 

unit_test: $(UNIT_TARGETS)
	@echo "Targets [$(UNIT_TARGETS)] for unit test are ready."

install: hvfs_lib unit_test
	@scp $(TEST)/mds/cbht syssw@glnode08:~/cbht
	@lagent -d glnode08 -u syssw -sc "time ~/cbht $(CBHT_ARGS)"
	@scp $(MDS)/tx syssw@glnode08:~/tx
	@lagent -d glnode08 -u syssw -sc "time ~/tx $(CBHT_ARGS)"

rut:
	@lagent -d glnode08 -u syssw -sc "time ~/cbht $(CBHT_ARGS)"
	@lagent -d glnode08 -u syssw -sc "gprof ~/cbht"

unit_test_clean:
	@rm -rf $(UNIT_TARGETS)

