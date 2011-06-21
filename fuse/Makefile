##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-06-21 11:41:30 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : fuse_lib 

%.o : %.c $(fuse_h_depend_files)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(FUSE)/%.c, $<)

fuse_lib : $(FUSE_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libpfuse.a $(^:.c=.o)

clean : 
	-@echo "Clean FUSE client, be careful to add USE_FUSE=1 to make clean!"
	-@rm -rf $(FUSE_AR_SOURCE:.c=.o)
	-@rm -rf libpfuse.a
