##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-05-17 18:17:18 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

all : $(TEST_FUSE_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUNIT_TEST -c

%.ut : %.o $(XNET_LIB) $(MDSL_LIB) $(HVFS_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS)  -o $@ $< -L$(LIB_PATH) -lhvfs $(LFLAGS)

clean :
	-@rm -rf $(TEST_FUSE_SOURCE:.c=.o)
	-@rm -rf $(TEST_FUSE_SOURCE:.c=.ut)