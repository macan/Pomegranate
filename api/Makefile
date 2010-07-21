##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-07-21 19:07:27 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : api_so

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -DUSE_XNET_SIMPLE -c \
			$(patsubst %.c, $(API)/%.c, $<)

api_so : $(API_AR_SOURCE:.c=.o) $(XNET_LIB)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libapi.a $(^:.c=.o)
	@echo -e " " SL"\t" $(API_SO)
	@$(CC) -L$(XNET) -shared -Wl,-soname,libapi.so.1 -o $(LIB_PATH)/libapi.so.1.0 $(^:.c=.o) -lc -lrt -lpthread -lxnet

clean :
	-@rm -rf $(API_AR_SOURCE:.c=.o)
	-@rm -rf libapi.a libapi.so.1.0
