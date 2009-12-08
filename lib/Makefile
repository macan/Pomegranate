##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2009-12-08 10:50:10 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

LIB_AR_SOURCE = lib.c ring.c hash.c time.c bitmap.c

all : hvfs_lib

%.o : %.c 
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $<

hvfs_lib : $(LIB_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libhvfs.a $(^:.c=.o)

clean : 
	-@rm -rf $(LIB_AR_SOURCE:.c=.o)
	-@rm -rf libhvfs.a