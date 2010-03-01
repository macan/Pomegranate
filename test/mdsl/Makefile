##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-03-01 21:41:01 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

all : $(TEST_MDSL_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUSE_XNET_SIMPLE -DUNIT_TEST -c

%.ut : %.o $(XNET_LIB) $(MDSL_LIB) $(HVFS_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $(LFLAGS) $< -o $@ -L$(XNET) -lxnet -L$(MDSL) -lmdsl \
			-L$(LIB_PATH) -lhvfs

clean :
	-@rm -rf $(TEST_MDSL_SOURCE:.c=.o)
	-@rm -rf $(TEST_MDSL_SOURCE:.c=.ut)