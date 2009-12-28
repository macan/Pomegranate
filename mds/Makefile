##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-28 20:21:36 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : mds_lib

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(MDS)/%.c, $<)

mds_lib : $(MDS_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libmds.a $(^:.c=.o)

clean : 
	-@rm -rf $(MDS_AR_SOURCE:.c=.o)
	-@rm -rf libmds.a