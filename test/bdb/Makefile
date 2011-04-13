##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-04-06 16:33:25 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

BDB_TEST = bdb_test.c

ifdef BDB_HOME
BDB_MAIN = $(BDB_HOME)
else
BDB_MAIN = /usr
endif

BDB_INC_PATH = $(BDB_MAIN)/include
BDB_LIB_PATH = $(BDB_MAIN)/lib

all : bdb_test
	@echo "BDB test targets are ready."

bdb_test : $(BDB_TEST)
	@echo -e " " CC"\t" bdb_test.c
	@gcc bdb_test.c -o bdb_test.ut -I$(BDB_INC_PATH) -L$(BDB_LIB_PATH) -ldb

clean :
	-@rm -rf bdb_test.ut base_db db_* db_type __db.* log.*
