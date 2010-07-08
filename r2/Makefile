##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-07-08 10:21:39 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : r2_lib

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(R2)/%.c, $<)

r2_lib : $(R2_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libr2.a $(^:.c=.o)
	@echo -e " " SL"\t" $(R2_SO)
	@$(CC) -shared -Wl,-soname,libr2.so.1 -o libr2.so.1.0 $(^:.c=.o) -lc -lrt -lpthread

clean : 
	-@rm -rf $(R2_AR_SOURCE:.c=.o)
	-@rm -rf libr2.a