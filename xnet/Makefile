##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2012-08-10 14:00:27 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : xnet_lib

%.o : %.c
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -DUSE_XNET_SIMPLE -c $(patsubst %.c, $(XNET)/%.c, $<)

xnet_lib : $(XNET_AR_SOURCE:.c=.o)
	@$(ECHO) -e " " AR"\t" $@
	@$(AR) rcs libxnet.a $(^:.c=.o)
	@$(ECHO) -e " " SL"\t" $(XNET_SO)
	@$(CC) -shared -Wl,-soname,libxnet.so.1 -o $(LIB_PATH)/libxnet.so.1.0 $(^:.c=.o) -lc -lrt -lpthread

clean : 
	-@rm -rf $(XNET_AR_SOURCE:.c=.o)
	-@rm -rf libxnet.a libxnet.so.1.0