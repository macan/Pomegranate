#
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-11-06 19:15:43 macan>
#
# Armed with EMACS.

DIR_TRIG_NONE         = 0
DIR_TRIG_PRE_FORCE    = 1
DIR_TRIG_POST_FORCE   = 2
DIR_TRIG_PRE_CREATE   = 3
DIR_TRIG_POST_CREATE  = 4
DIR_TRIG_PRE_LOOKUP   = 5
DIR_TRIG_POST_LOOKUP  = 6
DIR_TRIG_PRE_UNLINK   = 7
DIR_TRIG_POST_UNLINK  = 8
DIR_TRIG_PRE_LINKADD  = 9
DIR_TRIG_POST_LINKADD = 10
DIR_TRIG_PRE_UPDATE   = 11
DIR_TRIG_POST_UPDATE  = 12
DIR_TRIG_PRE_LIST     = 13
DIR_TRIG_POST_LIST    = 14

TRIG_CONTINUE = 0
TRIG_ABORT = 1

class column():
    stored_itbid = None
    len = None
    offset = None

    def __init__(self, stored_itbid, len, offset):
        self.stored_itbid = stored_itbid
        self.len = len
        self.offset = offset

class DT():
    dt = None
    def __init__(self, dict):
        self.dt = dict
        if self.dt == None:
            print "Init leaves a empty DT object."
