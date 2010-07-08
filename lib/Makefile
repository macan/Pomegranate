##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-07-08 23:49:32 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : hvfs_lib

%.o : %.c 
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(LIB_PATH)/%.c, $<)

hvfs_lib : $(LIB_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libhvfs.a $(^:.c=.o)
	@echo -e " " SL"\t" $(LIB_SO)
	@$(CC) -shared -Wl,-soname,libhvfs.so.1 -o libhvfs.so.1.0 $(^:.c=.o) -lc -lrt -lpthread

clean : 
	-@rm -rf $(LIB_AR_SOURCE:.c=.o)
	-@rm -rf libhvfs.a libhvfs.so.1.0