##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-11-08 22:58:21 macan>
#
# Armed with EMACS.

def dtdefault(dt):
    if dt == None:
        return TRIG_CONTINUE
    print "DT @ %s status %d" % (dt.dt['where'], dt.dt['status'])
    print dt.dt['itb_puuid']
    print dt.dt['itb_itbid']
    print dt.dt['mdu_ctime']
    dt.dt['mdu_version'] = 9000
    return TRIG_CONTINUE
