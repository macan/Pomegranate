##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2012-05-22 11:03:59 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : branch_so

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -DUSE_XNET_SIMPLE -c \
			$(patsubst %.c, $(BRANCH)/%.c, $<)

branch_so : $(BRANCH_AR_SOURCE:.c=.o) $(XNET_LIB)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libbranch.a $(^:.c=.o)
	@echo -e " " SL"\t" $(BRANCH_SO)
	@$(CC) -shared -Wl,-soname,libbranch.so.1 -o $(LIB_PATH)/libbranch.so.1.0 $(^:.c=.o) -lc -lrt -lpthread $(BDBFLAGS) -L$(XNET) -lxnet

clean :
	-@rm -rf $(BRANCH_AR_SOURCE:.c=.o)
	-@rm -rf libbranch.a libbranch.so.1.0
