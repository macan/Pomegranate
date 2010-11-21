##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-11-22 00:21:43 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../Makefile.inc

all : triggers

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -c $(patsubst %.c, $(TRIGGERS)/%.c, $<)

triggers : $(TRIGGERS_SOURCE:.c=.so)
	@echo "Build triggers done."

%.so : %.o
	@echo -e " " SL"\t" $@
	@$(CC) -shared -Wl,-soname,lib.so.1 -o $(TRIGGERS)/$@ $^ -lc -lrt

clean :
	-@rm -rf $(TRIGGERS_SOURCE:.c=.o)
	-@rm -rf $(TRIGGERS_SOURCE:.c=.so)
	-@rm -rf *.so
