##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-24 00:08:14 macan>
#
# This is the makefile for HVFS project.
#
# Armed by EMACS.

HOME_PATH = $(shell pwd)

include Makefile.inc

RING_SOURCES = $(LIB_PATH)/ring.c $(LIB_PATH)/lib.c $(LIB_PATH)/hash.c \
				$(LIB_PATH)/xlock.c

all : unit_test lib triggers

$(HVFS_LIB) : $(lib_depend_files)
	@echo -e " " CD"\t" $(LIB_PATH)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)"

$(MDS_LIB) : $(mds_depend_files)
	@echo -e " " CD"\t" $(MDS)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(MDS) -e "HOME_PATH=$(HOME_PATH)"

$(MDSL_LIB) : $(mdsl_depend_files)
	@echo -e " " CD"\t" $(MDSL)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(MDSL) -e "HOME_PATH=$(HOME_PATH)"

$(R2_LIB) : $(r2_depend_files)
	@echo -e " " CD"\t" $(R2)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(R2) -e "HOME_PATH=$(HOME_PATH)"

$(XNET_LIB) : $(xnet_depend_files)
	@echo -e " " CD"\t" $(XNET)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(XNET) -e "HOME_PATH=$(HOME_PATH)"

$(API_LIB) : $(api_depend_files)
	@echo -e " " CD"\t" $(API)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(API) -e "HOME_PATH=$(HOME_PATH)"

$(BRANCH_LIB) : $(branch_depend_files)
	@echo -e " " CD"\t" $(BRANCH)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(BRANCH) -e "HOME_PATH=$(HOME_PATH)"

ifdef USE_FUSE
$(FUSE_LIB) : $(fuse_depend_files)
	@echo -e " " CD"\t" $(FUSE)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(FUSE) -e "HOME_PATH=$(HOME_PATH)"
else
$(FUSE_LIB) : $(fuse_depend_files)
	@echo -e " " MK"\t" $@ " (Ignored! Use 'USE_FUSE=1' to enable fuse support.)"
endif

triggers : $(triggers_depend_files) build_triggers
	@echo "Triggers' dynamic library are ready."

build_triggers : 
	@echo -e " " CD"\t" $(TRIGGERS)
	@echo -e " " MK"\t" $@
	@$(MAKE) --no-print-directory -C $(TRIGGERS) -e "HOME_PATH=$(HOME_PATH)"

clean :
	@$(MAKE) --no-print-directory -C $(LIB_PATH) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(MDS) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(MDSL) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(R2) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(API) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(BRANCH) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(XNET) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TEST)/mds -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TEST)/xnet -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TEST)/result -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(TRIGGERS) -e "HOME_PATH=$(HOME_PATH)" clean
	@$(MAKE) --no-print-directory -C $(FUSE) -e "HOME_PATH=$(HOME_PATH)" clean
	-@rm -rf $(LIB_PATH)/ring $(LIB_PATH)/a.out

# Note: the following region is only for UNIT TESTing
# region for unit test
$(LIB_PATH)/ring : $(RING_SOURCES)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $^ -o $@ -DUNIT_TEST

lib : $(HVFS_LIB) $(MDS_LIB) $(XNET_LIB) $(MDSL_LIB) $(R2_LIB) $(API_LIB) $(BRANCH_LIB) $(FUSE_LIB)
	@echo -e " " Lib is ready.

unit_test : $(ut_depend_files) $(HVFS_LIB) $(MDS_LIB) $(XNET_LIB) \
			$(MDSL_LIB) $(R2_LIB) $(API_LIB) $(BRANCH_LIB) $(FUSE_LIB)
	@echo -e " " CD"\t" $(TEST)/mds
	@$(MAKE) --no-print-directory -C $(TEST)/mds -e "HOME_PATH=$(HOME_PATH)"
	@echo -e " " CD"\t" $(TEST)/xnet
	@$(MAKE) --no-print-directory -C $(TEST)/xnet -e "HOME_PATH=$(HOME_PATH)"
	@echo -e " " CD"\t" $(TEST)/mdsl
	@$(MAKE) --no-print-directory -C $(TEST)/mdsl -e "HOME_PATH=$(HOME_PATH)"
	@echo "Targets for unit test are ready."

install: unit_test triggers
	@rsync -r $(TEST)/*.sh root@glnode09:~/hvfs/test/
	@rsync -r $(CONF) root@glnode09:~/hvfs/
	@rsync -r $(BIN) root@glnode09:~/hvfs/
	@rsync -r $(TRIGGERS) root@glnode09:~/hvfs/
	@rsync -r $(LIB_PATH)/*.so.1.0 root@glnode09:~/hvfs/lib/
	@rsync -r $(TEST)/mds/*.ut root@glnode09:~/hvfs/test/mds/
	@rsync -r $(TEST)/xnet/*.ut root@glnode09:~/hvfs/test/xnet/
	@rsync -r $(TEST)/mdsl/*.ut root@glnode09:~/hvfs/test/mdsl/
	@rsync -r $(TEST)/python/*.py root@glnode09:~/hvfs/test/python/
	@echo "Install done."

xinstall: unit_test
	@rsync -r $(TEST)/*.sh root@10.10.104.1:/home/macan/test/
	@rsync -r $(CONF) root@10.10.104.1:/home/macan/
	@rsync -r $(BIN) root@10.10.104.1:/home/macan/
	@rsync -r $(TEST)/mds/*.ut root@10.10.104.1:/home/macan/test/mds/
	@rsync -r $(TEST)/xnet/*.ut root@10.10.104.1:/home/macan/test/xnet/
	@rsync -r $(TEST)/mdsl/*.ut root@10.10.104.1:/home/macan/test/mdsl/
	@echo "Install done."

plot: 
	@echo -e "Ploting ..."
	@$(MAKE) --no-print-directory -C $(TEST)/result -e "HOME_PATH=$(HOME_PATH)" plot
	@echo -e "Done.\n"

rut:
	@lagent -d glnode09 -u root -sc "time ~/cbht $(CBHT_ARGS)"
	@lagent -d glnode09 -u root -sc "gprof ~/cbht"
