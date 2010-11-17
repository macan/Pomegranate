##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-11-16 01:01:14 macan>
#
# Armed with EMACS.

def dttest(dt):
    print "DT @ %s status %d" % (dt.dt['where'], dt.dt['status'])
    print dt.dt['itb_puuid']
    print dt.dt['itb_itbid']
    print dt.dt['mdu_ctime']
    dt.dt['mdu_version'] = 9000

def dtlist(dt):
    line = str(dt.dt['itb_itbid']) + " " + str(dt.dt['itb_entries']) + "\n"
    fname = "/tmp/hvfs-dir-list-%lx" % (dt.dt['itb_puuid'])
    file = open(fname, "a")
    file.write(line)
    file.close()
    return TRIG_CONTINUE

def dtdefault(dt):
    if dt == None:
        return TRIG_CONTINUE
    return dttest(dt)
