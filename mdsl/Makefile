##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-03-01 21:23:40 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : mdsl_lib

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(MDSL)/%.c, $<)

mdsl_lib : $(MDSL_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libmdsl.a $(^:.c=.o)

clean : 
	-@rm -rf $(MDSL_AR_SOURCE:.c=.o)
	-@rm -rf libmdsl.a