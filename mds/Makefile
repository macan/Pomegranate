##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2012-08-10 13:59:22 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : mds_lib

%.o : %.c $(mds_h_depend_files)
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(MDS)/%.c, $<)

mds_lib : $(MDS_AR_SOURCE:.c=.o)
	@$(ECHO) -e " " AR"\t" $@
	@$(AR) rcs libmds.a $(^:.c=.o)
	@$(ECHO) -e " " SL"\t" $(MDS_SO)
	@$(CC) -shared -Wl,-soname,libmds.so.1 -o $(LIB_PATH)/libmds.so.1.0 $(^:.c=.o) -lc -lrt -lpthread

clean : 
	-@rm -rf $(MDS_AR_SOURCE:.c=.o)
	-@rm -rf libmds.a $(LIB_PATH)/libmds.so.1.0