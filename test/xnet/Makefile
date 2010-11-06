##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-11-06 22:12:15 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

all : $(TEST_XNET_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUSE_XNET_SIMPLE -DUNIT_TEST -c

%.ut : %.o $(XNET_LIB) $(MDS_LIB) $(HVFS_LIB) $(MDSL_LIB) $(R2_LIB) $(API_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -o $@ $< -L$(API) -lapi \
			-L$(XNET) -lxnet -L$(MDS) -lmds \
			-L$(R2) -lr2 -L$(LIB_PATH) -lhvfs -L$(MDSL) -lmdsl \
			$(LFLAGS)

clean :
	-@rm -rf $(TEST_XNET_SOURCE:.c=.o)
	-@rm -rf $(TEST_XNET_SOURCE:.c=.ut)