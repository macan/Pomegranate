##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-29 17:08:34 macan>
#
# This is the makefile for HVFS project.
#
# Armed by EMACS.

HOME_PATH = $(shell pwd)

include Makefile.inc

RING_SOURCES = $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c $(LIB_PATH)/hash.c \
				$(LIB_PATH)/xlock.c

all : unit_test

$(HVFS_LIB) : $(lib_depend_files)
	@echo -e " " CD"\t" $(LIB_PATH)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)"

$(MDS_LIB) : $(mds_depend_files)
	@echo -e " " CD"\t" $(MDS)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(MDS) -e "HOME_PATH=$(HOME_PATH)"

$(XNET_LIB) : $(xnet_depend_files)
	@echo -e " " CD"\t" $(XNET)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(XNET) -e "HOME_PATH=$(HOME_PATH)"

clean :
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(MDS) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(XNET) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TEST)/mds -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TEST)/xnet -e "HOME_PATH=$(HOME_PATH)" clean
	-@rm -rf $(LIB_PATH)/ring

# Note: the following region is only for UNIT TESTing
# region for unit test
$(LIB_PATH)/ring : $(RING_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

unit_test : $(ut_depend_files) $(HVFS_LIB) $(MDS_LIB) $(XNET_LIB)
	@echo -e " " CD"\t" $(TEST)/mds
	@$(MAKE) --no-print-directory -C $(TEST)/mds -e "HOME_PATH=$(HOME_PATH)"
	@echo -e " " CD"\t" $(TEST)/xnet
	@$(MAKE) --no-print-directory -C $(TEST)/xnet -e "HOME_PATH=$(HOME_PATH)"
	@echo "Targets for unit test are ready."

install: unit_test
	@scp $(TEST)/mds/cbht.ut root@glnode09:~/cbht
	@scp $(TEST)/mds/cmd_sender.ut root@glnode09:~/cmd_sender
	@scp $(TEST)/mds/tx.ut root@glnode09:~/tx
	@scp $(TEST)/mds/dh.ut root@glnode09:~/dh
	@scp $(TEST)/xnet/xnet.ut root@glnode09:~/xnet
	@lagent -d glnode09 -u root -sc "time ~/cbht $(CBHT_ARGS)"
	@lagent -d glnode09 -u root -sc "time ~/tx $(CBHT_ARGS)"

rut:
	@lagent -d glnode09 -u root -sc "time ~/cbht $(CBHT_ARGS)"
	@lagent -d glnode09 -u root -sc "gprof ~/cbht"
