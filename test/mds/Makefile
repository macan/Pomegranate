##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2012-08-10 13:54:36 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

TEST_MDS_DEPSRC = $(XNET)/xnet.c

all : $(TEST_MDS_SOURCE:.c=.ut)

%.o : %.c
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUNIT_TEST -c

%.ut : %.o $(MDS_LIB) $(HVFS_LIB)
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $(TEST_MDS_DEPSRC) -o $@ $< -L$(MDS) -lmds \
			-L$(LIB_PATH) -lhvfs $(LFLAGS)

clean :
	-@rm -rf $(TEST_MDS_SOURCE:.c=.o)
	-@rm -rf $(TEST_MDS_SOURCE:.c=.ut)