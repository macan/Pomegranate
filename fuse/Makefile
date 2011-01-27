##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-24 00:12:56 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : fuse_lib

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(FUSE)/%.c, $<)

fuse_lib : $(FUSE_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libpfuse.a $(^:.c=.o)

clean : 
	-@rm -rf $(FUSE_AR_SOURCE:.c=.o)
	-@rm -rf libpfuse.a
