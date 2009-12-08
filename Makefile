##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-08 15:46:42 macan>
#
# This is the makefile for HVFS project.
#
# Armed by EMACS.

HOME_PATH = $(shell pwd)

include Makefile.inc

UNIT_TARGETS = $(LIB_PATH)/ring $(MDS)/cbht
UNIT_OBJS = $(LIB_PATH)/lib.o $(LIB_PATH)/ring.o

all : hvfs_lib unit_test

hvfs_lib : 
	@echo -e " " CD"\t" $(LIB_PATH)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)"

clean: unit_test_clean
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)" clean

# Note: the following region is only for UNIT TESTing
# region for unit test
$(LIB_PATH)/ring : $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

CBHT_SOURCES = $(MDS)/itb.c $(MDS)/cbht.c $(MDS)/mds.c $(MDS)/txg.c $(XNET)/xnet.c

$(MDS)/cbht : $(CBHT_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST -L$(LIB_PATH) -lhvfs 

unit_test: $(UNIT_TARGETS)
	@echo "Targets [$(UNIT_TARGETS)] for unit test are ready."
	@$(MDS)/cbht

install: $(UNIT_TARGETS)
	@scp $(MDS)/cbht syssw@glnode08:~/cbht
	@lagent -d glnode08 -u syssw -sc "~/cbht"

rut:
	@lagent -d glnode08 -u syssw -sc "~/cbht"

unit_test_clean:
	@rm -rf $(UNIT_TARGETS)

