##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-06-23 22:17:49 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : mdsl_lib

%.o : %.c $(mdsl_h_depend_files)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(MDSL)/%.c, $<)

mdsl_lib : $(MDSL_AR_SOURCE:.c=.o)
	@echo -e " " AR"\t" $@
	@$(AR) rcs libmdsl.a $(^:.c=.o)
	@echo -e " " SL"\t" $(MDSL_SO)
	@$(CC) -shared -Wl,-soname,libmdsl.so.1 -o $(LIB_PATH)/libmdsl.so.1.0 $(^:.c=.o) -lc -lrt -lpthread

clean : 
	-@rm -rf $(MDSL_AR_SOURCE:.c=.o)
	-@rm -rf libmdsl.a libmdsl.so.1.0