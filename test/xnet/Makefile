##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-26 15:36:38 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

ifdef USE_FUSE
DEPEND_LIBS = $(XNET_LIB) $(MDS_LIB) $(HVFS_LIB) $(MDSL_LIB) $(R2_LIB) \
				$(API_LIB) $(FUSE_LIB)
EX_LFLAGS = -lpfuse
else
DEPEND_LIBS = $(XNET_LIB) $(MDS_LIB) $(HVFS_LIB) $(MDSL_LIB) $(R2_LIB) \
				$(API_LIB)
endif

all : $(TEST_XNET_SOURCE:.c=.ut)

%.o : %.c
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUSE_XNET_SIMPLE -DUNIT_TEST -c

%.ut : %.o $(DEPEND_LIBS)
	@echo -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -o $@ $< -L$(API) -lapi \
			-L$(XNET) -lxnet -L$(MDS) -lmds \
			-L$(R2) -lr2 -L$(LIB_PATH) -lhvfs -L$(MDSL) -lmdsl \
			-L$(BRANCH) -lbranch -L$(API) -lapi -L$(R2) -lr2 \
			-L$(FUSE) $(EX_LFLAGS) $(LFLAGS)

clean :
	-@rm -rf $(TEST_XNET_SOURCE:.c=.o)
	-@rm -rf $(TEST_XNET_SOURCE:.c=.ut)