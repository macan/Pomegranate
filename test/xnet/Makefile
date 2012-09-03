##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2012-08-10 13:54:21 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

include ../../Makefile.inc

ifdef USE_FUSE
DEPEND_LIBS = $(XNET_LIB) $(MDS_LIB) $(HVFS_LIB) $(MDSL_LIB) $(R2_LIB) \
				$(API_LIB) $(FUSE_LIB) $(BRANCH_LIB) $(OSD_LIB)
EX_LFLAGS = -lpfuse
else
DEPEND_LIBS = $(XNET_LIB) $(MDS_LIB) $(HVFS_LIB) $(MDSL_LIB) $(R2_LIB) \
				$(API_LIB) $(BRANCH_LIB) $(OSD_LIB)
endif

all : $(TEST_XNET_SOURCE:.c=.ut)

%.o : %.c $(mds_h_depend_files)
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) $< -DUSE_XNET_SIMPLE -DUNIT_TEST -c

%.ut : %.o $(DEPEND_LIBS)
	@$(ECHO) -e " " CC"\t" $@
	@$(CC) $(CFLAGS) -o $@ $< -L$(API) -lapi \
			-L$(XNET) -lxnet -L$(MDS) -lmds \
			-L$(R2) -lr2 -L$(MDSL) -lmdsl -L$(OSD) -losd \
			-L$(FUSE) $(EX_LFLAGS) -L$(API) -lapi -L$(R2) -lr2 \
			-L$(BRANCH) -lbranch $(LFLAGS) -L$(LIB_PATH) -lhvfs $(LFLAGS)

clean :
	-@rm -rf $(TEST_XNET_SOURCE:.c=.o)
	-@rm -rf $(TEST_XNET_SOURCE:.c=.ut)