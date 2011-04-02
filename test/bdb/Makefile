##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-04-03 00:02:34 macan>
#
# This is the makefile for HVFS project.
#
# Armed with EMACS.

BDB_TEST = bdb_test.c

all : bdb_test
	@echo "BDB test targets are ready."

bdb_test : $(BDB_TEST)
	@echo -e " " CC"\t" bdb_test.c
	@gcc bdb_test.c -o bdb_test -ldb

clean :
	-@rm -rf bdb_test base_db tag_* type_db __db.* log.*
