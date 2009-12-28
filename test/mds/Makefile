##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-28 20:03:30 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

TEST_MDS_DEPSRC = $(XNET)/xnet.c

all : $(TEST_MDS_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUNIT_TEST -c

%.ut : %.o $(MDS_LIB) $(HVFS_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $(TEST_MDS_DEPSRC) $< -o $@ -L$(MDS) -lmds \
			-L$(LIB_PATH) -lhvfs

clean :
	-@rm -rf $(TEST_MDS_SOURCE:.c=.o)
	-@rm -rf $(TEST_MDS_SOURCE:.c=.ut)