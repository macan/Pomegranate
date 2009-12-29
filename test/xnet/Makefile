##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-29 15:36:08 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

all : $(TEST_XNET_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUSE_XNET_SIMPLE -DUNIT_TEST -c

%.ut : %.o $(XNET_LIB)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -o $@ -L$(XNET) -lxnet

clean :
	-@rm -rf $(TEST_XNET_SOURCE:.c=.o)
	-@rm -rf $(TEST_XNET_SOURCE:.c=.ut)