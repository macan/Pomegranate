##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-07-06 16:50:32 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

all : $(TEST_MDSL_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUNIT_TEST -c

%.ut : %.o $(XNET_LIB) $(MDSL_LIB) $(HVFS_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $(LFLAGS) $< -o $@ -L$(MDSL) -lmdsl -L$(XNET) -lxnet\
			-L$(LIB_PATH) -lhvfs

clean :
	-@rm -rf $(TEST_MDSL_SOURCE:.c=.o)
	-@rm -rf $(TEST_MDSL_SOURCE:.c=.ut)