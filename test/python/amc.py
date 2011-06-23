#!/bin/env python
#
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-06-23 22:32:52 macan>
#
# Armed with EMACS.

import os, time, sys
import getopt
import signal
import cmd
import shlex
import string
import random
import threading
from ctypes import *

try:
    libc = CDLL("libc.so.6")
    lib = CDLL("../../lib/libhvfs.so.1.0", mode=RTLD_GLOBAL)
    xnet = CDLL("../../lib/libxnet.so.1.0", mode=RTLD_GLOBAL)
    mds = CDLL("../../lib/libmds.so.1.0", mode=RTLD_GLOBAL)
    root = CDLL("../../lib/libr2.so.1.0", mode=RTLD_GLOBAL)
    api = CDLL("../../lib/libapi.so.1.0", mode=RTLD_GLOBAL)
except OSError, oe:
    print "Can not load shared library: %s" % oe
    sys.exit()

class bcolors:
    HEADER = '\033[36m'
    OKPINK = '\033[35m'
    OKBLUE = '\033[34m'
    OKGREEN = '\033[32m'
    WARNING = '\033[33m'
    FAIL = '\033[41m'
    ENDC = '\033[0m'
    mode = True

    def flip(self):
        if self.mode == True:
            self.mode = False
        else:
            self.mode = True

    def print_warn(self, string):
        if self.mode:
            print bcolors.WARNING + str(string) + bcolors.ENDC
        else:
            print str(string)

    def print_err(self, string):
        if self.mode:
            print bcolors.FAIL + str(string) + bcolors.ENDC
        else:
            print str(string)

    def print_ok(self, string):
        if self.mode:
            print bcolors.OKGREEN + str(string) + bcolors.ENDC
        else:
            print str(string)

    def print_pink(self, string):
        if self.mode:
            print bcolors.OKPINK + str(string) + bcolors.ENDC
        else:
            print str(string)

class test_put(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        genvalue = "".join([random.choice(string.letters + 
                                          string.digits) for x in range(self.bytes)])
        for i in self.array:
            try:
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                value = c_char_p(genvalue)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_put(self.table, key, value, column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_put() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_get(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                value = c_char_p(None)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_get(self.table, key, byref(value), column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_get() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
                api.hvfs_free(value)
            except ValueError, ve:
                print "ValueError %s" % ve

class test_del(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                self.xstart = time.time()
                err = api.hvfs_del(self.table, key, 0)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_get() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_put_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        genvalue = "".join([random.choice(string.letters + 
                                          string.digits) for x in range(self.bytes)])
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                value = c_char_p(genvalue)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_put_v2(ptid, psalt, key, value, column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_put_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_get_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                value = c_char_p(None)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_get_v2(ptid, psalt, key, byref(value), column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_get_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
                api.hvfs_free(value)
            except ValueError, ve:
                print "ValueError %s" % ve

class test_del_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_ulonglong((long(i) << self.shift) + 
                                  int(self.id))
                self.xstart = time.time()
                err = api.hvfs_del_v2(ptid, psalt, key, 0)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_del_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sput(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        genvalue = "".join([random.choice(string.letters + 
                                          string.digits) for x in range(self.bytes)])
        for i in self.array:
            try:
                key = c_char_p(str(self.id) + "." + str(i))
                value = c_char_p(genvalue)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_sput(self.table, key, value, column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sput() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sget(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                key = c_char_p(str(self.id) + "." + str(i))
                value = c_char_p(None)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_sget(self.table, key, byref(value), column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sget() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
                api.hvfs_free(value)
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sdel(threading.Thread):
    def __init__(self, table, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.table = table
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                key = c_char_p(str(self.id) + "." + str(i))
                self.xstart = time.time()
                err = api.hvfs_sdel(self.table, key, 0)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sdel() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sput_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        genvalue = "".join([random.choice(string.letters + 
                                          string.digits) for x in range(self.bytes)])
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_char_p(str(self.id) + "." + str(i))
                value = c_char_p(genvalue)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_sput_v2(ptid, psalt, key, value, 
                                       column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sput_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sget_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_char_p(str(self.id) + "." + str(i))
                value = c_char_p(None)
                column = c_int(self.column[i])
                self.xstart = time.time()
                err = api.hvfs_sget_v2(ptid, psalt, key, 
                                       byref(value), column)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sget_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
                api.hvfs_free(value)
            except ValueError, ve:
                print "ValueError %s" % ve

class test_sdel_v2(threading.Thread):
    def __init__(self, ptid, psalt, id, loops, bytes, shift, 
                 column, array):
        threading.Thread.__init__(self)
        self.ptid = ptid
        self.psalt = psalt
        self.shift = shift
        self.id = id
        self.loops = loops
        self.bytes = bytes
        self.column = column
        self.array = array
        self.xstart = 0.0
        self.stop = 0.0
        self.total = 0.0

    def run(self):
        for i in self.array:
            try:
                ptid = c_ulonglong(self.ptid)
                psalt = c_ulonglong(self.psalt)
                key = c_char_p(str(self.id) + "." + str(i))
                self.xstart = time.time()
                err = api.hvfs_sdel_v2(ptid, psalt, key, 0)
                self.stop = time.time()
                if err != 0:
                    print "api.hvfs_sdel_v2() failed w/ %d" % err
                    return
                self.total += self.stop - self.xstart
            except ValueError, ve:
                print "ValueError %s" % ve

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hdt:i:r:x:",
                                   ["help", "thread=", "id=", 
                                    "ring=", "debug", "test="])
    except getopt.GetoptError:
        sys.exit()

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    thread = 1
    id = 0
    port = 9001
    ring = "127.0.0.1"
    debug = False
    dotest = False
    loops = 0

    try:
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_help()
                sys.exit()
            elif opt in ("-t", "--thread"):
                thread = int(arg)
            elif opt in ("-i", "--id"):
                id = int(arg)
            elif opt in ("-r", "--ring"):
                ring = arg
            elif opt in ("-d", "--debug"):
                debug = True
            elif opt in ("-x", "--test"):
                dotest = True
                loops = arg
    except ValueError, ve:
        print "Value error: %s" % ve
        sys.exit()

    print "AMC Client %d Running w/ (%d threads)..." % (id, thread)

    # init the AMC client
    CSTR_ARRAY = c_char_p * 7
    argv = CSTR_ARRAY("pyAMC", "-d", str(id), "-r", ring, "-p", 
                      str(port + id))
    err = api.__core_main(7, argv)
    if err != 0:
        print "api.__core_main() failed w/ %d" % err
        return

    # create the root entry
    err = api.hvfs_create_root(None)
    if err != 0:
        print "api.hvfs_create_root() failed /w %d" % err
        return

    if dotest == True:
        #do_test(loops, thread)
        do_test_v2(loops, thread)
        api.__core_exit(None)
        return
    elif debug == True:
        # create the table
        table = c_char_p("table_x")
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

        uuid = c_long(0)
        salt = c_long(0)
        err = api.hvfs_find_table(table, byref(uuid), byref(salt))
        if err != 0:
            print "api.hvfs_find_table() failed w/ %d" % err

        print "table %s uuid %lx salt %lx" % (table.value, 
                                              uuid.value,
                                              salt.value)

        # k/v accesses
        key = c_long(10)
        value = c_char_p("hello, world!")
        ov = c_char_p()

        # put the entry
        err = api.hvfs_put(table, key, value, 1)
        if err != 0:
            print "api.hvfs_put() failed w/ %d" % err
        else:
            # get the entry
            err = api.hvfs_get(table, key, byref(ov), 1)
            if err != 0:
                print "api.hvfs_get() failed w/ %d" % err
            else:
                print "get value '%s'" % ov.value
                # delete the entry
                err = api.hvfs_del(table, key, 1)
                if err != 0:
                    print "api.hvfs_del() failed w/ %d" % err

        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ %d" % err

    pamc_shell().cmdloop("Welcome to Python AMC Client Shell, " + 
                         "for help please input ? or help")

    api.__core_exit(None)

def do_test(loops, thread_nr = 1):
    '''Do a strandard test for Pomegranate KV store'''
    start = 0.0
    stop = 0.0
    total = 0.0
    one_table = True

    try:
        if int(loops) <= 0:
            print "Invalid or zero loops, do nothing ..."
            return
    except Exception:
        print "Invalid loops value, do nothing ..."
        return

    if thread_nr == 1:
        print ("\033[41mThis is a SINGLE thread test!.\033[0m")
    print ("\033[41mPomegranate K/V API(v1) need 2+ RPCs " +
           "and several malloc()s for " + 
           "each OP, we will fix it in API(v2).\033[0m")
    print ("\033[41mPerformance of K/V API(v1) is only ~30% of xTable API.\033[0m")

    shift = 0
    _tmp = thread_nr
    while _tmp > 0:
        _tmp = _tmp >> 1
        shift += 1

    # Step 1: test put/get interface
    table = c_char_p("test_table_1")
    err = api.hvfs_create_table(table)
    if err != 0:
        print "api.hvfs_create_table() failed w/ %d" % err
        return

    random.seed(1079)
    column = [random.choice(range(1)) for x in range(int(loops))]
    array = random.sample(range(int(loops)), int(loops))

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_put(table, id, loops, 100, shift, column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  PUT is: %f" % (thread_nr * int(loops) / total)

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_get(table, id, loops, 100, shift, column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  GET is: %f" % (thread_nr * int(loops) / total)

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_del(table, id, loops, 100, shift, column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  DEL is: %f" % (thread_nr * int(loops) / total)

    if not one_table:
        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                              err)
            return

    # Step 2: test sput/sget interface
    if not one_table:
        table = c_char_p("test_table_2")
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sput(table, id, loops, 100, shift, column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SPUT is: %f" % (thread_nr * int(loops) / total)

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sget(table, id, loops, 100, shift, column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SGET is: %f" % (thread_nr * int(loops) / total)

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sdel(table, id, loops, 100, shift, column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SDEL is: %f" % (thread_nr * int(loops) / total)

    if not one_table:
        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                              err)
            return

    # Step 3: test put/get with random column 
    if not one_table:
        table = c_char_p("test_table_3")
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

    random.seed(1079)
    column = [random.choice(range(4000)) for x in range(int(loops))]
    array = random.sample(range(int(loops)), int(loops))

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_put(table, id, loops, 100, shift, column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  PUT is: %f" % (thread_nr * int(loops) / total)

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_get(table, id, loops, 100, shift, column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  GET is: %f" % (thread_nr * int(loops) / total)

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_del(table, id, loops, 100, shift, column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  DEL is: %f" % (thread_nr * int(loops) / total)

    err = api.hvfs_drop_table(table)
    if err != 0:
        print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                          err)
        return

    # Step 4: test sput/sget with random column

def do_test_v2(loops, thread_nr = 1):
    '''Do a strandard test for Pomegranate KV store'''
    start = 0.0
    stop = 0.0
    total = 0.0
    one_table = True

    try:
        if int(loops) <= 0:
            print "Invalid or zero loops, do nothing ..."
            return
    except Exception:
        print "Invalid loops value, do nothing ..."
        return

    if thread_nr == 1:
        print ("\033[41mThis is a SINGLE thread test!.\033[0m")
    print ("\033[41mPomegranate K/V API(v2) is a little optimized"
           + ".\033[0m")
    print ("\033[41mPerformance of K/V API(v2) is about ~60% of xTable API.\033[0m")

    shift = 0
    _tmp = thread_nr
    while _tmp > 0:
        _tmp = _tmp >> 1
        shift += 1

    # Step 1: test put/get interface
    table = c_char_p("test_table_1")
    err = api.hvfs_create_table(table)
    if err != 0:
        print "api.hvfs_create_table() failed w/ %d" % err
        return

    # open the table
    ptid = c_long(0)
    psalt = c_long(0)
    err = api.hvfs_open_table(table, byref(ptid), byref(psalt))
    if err != 0:
        print "api.hvfs_create_table() failed w/ %d" % err
        return
    ptid = ptid.value
    psalt = psalt.value

    random.seed(1079)
    column = [random.choice(range(1)) for x in range(int(loops))]
    array = random.sample(range(int(loops)), int(loops))

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_put_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  PUT is: %f" % (thread_nr * int(loops) / total)

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_get_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  GET is: %f" % (thread_nr * int(loops) / total)

    s1list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_del_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s1list.append(ct)
        ct.start()

    for s1 in s1list:
        s1.join()
    stop = time.time()
    total = stop - start

    print "RPS of  DEL is: %f" % (thread_nr * int(loops) / total)

    if not one_table:
        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                              err)
            return

    # Step 2: test sput/sget interface
    if not one_table:
        table = c_char_p("test_table_2")
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

        ptid = c_long(0)
        psalt = c_long(0)
        err = api.hvfs_open_table(table, byref(ptid), byref(psalt))
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return
        ptid = ptid.value
        psalt = psalt.value

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sput_v2(ptid, psalt, id, loops, 100, shift, 
                          column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SPUT is: %f" % (thread_nr * int(loops) / total)

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sget_v2(ptid, psalt, id, loops, 100, shift, 
                          column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SGET is: %f" % (thread_nr * int(loops) / total)

    s2list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_sdel_v2(ptid, psalt, id, loops, 100, shift, 
                          column, array)
        s2list.append(ct)
        ct.start()

    for s2 in s2list:
        s2.join()
    stop = time.time()
    total = stop - start

    print "RPS of SDEL is: %f" % (thread_nr * int(loops) / total)

    if not one_table:
        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                              err)
            return

    # Step 3: test put/get with random column 
    if not one_table:
        table = c_char_p("test_table_3")
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

        ptid = c_long(0)
        psalt = c_long(0)
        err = api.hvfs_open_table(table, byref(ptid), byref(psalt))
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return
        ptid = ptid.value
        psalt = psalt.value

    random.seed(1079)
    column = [random.choice(range(4000)) for x in range(int(loops))]
    array = random.sample(range(int(loops)), int(loops))

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_put_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  PUT is: %f" % (thread_nr * int(loops) / total)

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_get_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  GET is: %f" % (thread_nr * int(loops) / total)

    s3list = []
    start = time.time()
    for id in range(thread_nr):
        ct = test_del_v2(ptid, psalt, id, loops, 100, shift, 
                         column, array)
        s3list.append(ct)
        ct.start()

    for s3 in s3list:
        s3.join()
    stop = time.time()
    total = stop - start

    print "RPS of  DEL is: %f" % (thread_nr * int(loops) / total)

    err = api.hvfs_drop_table(table)
    if err != 0:
        print "api.hvfs_drop_table() failed w/ %s(%d)" % (os.strerror(-err), 
                                                          err)
        return

    # Step 4: test sput/sget with random column

class pamc_shell(cmd.Cmd):
    bc = None
    table = None
    clock_start = 0.0
    clock_stop = 0.0
    keywords = ["EOF", "create", "drop", "put", "get", "del", "update",
                "quit", "list", "ls", "set", "commit", "getcluster",
                "getactivesite", "online", "offline", "sput", 
                "sget", "supdate", "addsite", "rmvsite", "shutdown",
                "pst", "getinfo"]

    def __init__(self):
        cmd.Cmd.__init__(self)
        # Same issue as client.py, change use_rawinput always to true
        cmd.Cmd.use_rawinput = True
        self.bc = bcolors()

    def emptyline(self):
        return

    def start_clock(self):
        self.clock_start = time.time()
        return

    def stop_clock(self):
        self.clock_stop = time.time()

    def echo_clock(self, str):
        if self.bc.mode:
            print self.bc.OKGREEN + "%s %fs" % (str, 
                                                self.clock_stop 
                                                - self.clock_start) + self.bc.ENDC
        else:
            print "%s %fs" % (str, self.clock_stop - self.clock_start)
        return

    def do_create(self, line):
        '''Create a new table in the KV store.
        Usage: create table <table_name>'''
        l = shlex.split(line)
        if len(l) < 2:
            print "Usage: create table <table_name>"
            return
        if l[0] != "table":
            print "Usage: create table <table_name>"
            return
        if l[1] == "" or l[1] == None:
            print "Usage: create table <table_name>"
            return

        # ok, l[1] is the table_name
        table = c_char_p(l[1])
        err = api.hvfs_create_table(table)
        if err != 0:
            print "api.hvfs_create_table() failed w/ %d" % err
            return

    def do_drop(self, line):
        '''Drop a table in the KV store.
        Usage: drop table <table_name>'''
        l = shlex.split(line)
        if len(l) < 2:
            print "Usage: drop table <table_name>"
            return
        if l[0] != "table":
            print "Usage: drop table <table_name>"
            return
        if l[1] == "" or l[1] == None:
            print "Usage: drop table <table_name>"
            return

        # ok, l[1] is the table_name
        table = c_char_p(l[1])
        err = api.hvfs_drop_table(table)
        if err != 0:
            print "api.hvfs_drop_table() failed w/ (%d) %s" % (err, 
                                                               os.strerror(-err))
            return

    def do_list(self, line):
        '''List the tables in the KV store.
        Usage: list'''
        table = c_char_p(None)
        arg = c_char_p(None)
        op = c_int(0)
        err = api.hvfs_list(table, op, arg)
        if err != 0:
            print "api.hvfs_list() failed w/ %d" % err
            return
    
    def do_ls(self, line):
        '''List the table in the KV store.
        Usage: ls'''
        return self.do_list(line)

    def do_select(self, line):
        '''Select * from the table.
        select * from <table_name>'''
        l = shlex.split(line)
        if len(l) < 3:
            print "Usage: select <*> from <table_name>"
            return
        if l[0] != "*" and l[0] != "count(1)":
            print "Usage: select <*> from <table_name>"
            return
        if l[1] != "from":
            print "Usage: select <*> from <table_name>"
            return
        if len(l) >= 5 and l[3] != None:
            if l[3] == "where" and l[4] != None:
                self.bc.print_ok("Gramma OK.")
            else:
                print "Usage: select <*> from <table_name> where <str>"
                return
        
        table = c_char_p(l[2])
        if l[0] == "*":
            op = c_int(0)
        elif l[0] == "count(1)":
            op = c_int(1)
        if len(l) >= 5 and l[4] != None:
            op.value += 2
            arg = c_char_p(l[4])
        else:
            arg = c_char_p(None)
        err = api.hvfs_list(table, op, arg)
        if err != 0:
            print "api.hvfs_list() failed w/ %d" % err
            return

    def do_set(self, line):
        '''Set the working table.
        set table <table_name>'''
        l = shlex.split(line)
        if len(l) < 2:
            print "Usage: set table <table_name>"
            return
        if l[0] != "table":
            print "Usage: set table <table_name>"
            return
        if l[1] == "" or l[1] == None:
            print "Usage: set table <table_name>"
            return

        # ok, l[1] is the table_name
        self.table = c_char_p(l[1])

    def do_put(self, line):
        '''Put a Key/Value pair to the KV store.
        Usage: put key value [column]'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 2:
            print "Usage: put key value"
            return
        # ok, transfer the key to int
        try:
            key = c_ulonglong(long(l[0]))
            value = c_char_p(l[1])
            if len(l) == 3:
                column = c_int(int(l[2]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_put(self.table, key, value, column)
            if err != 0:
                print "api.hvfs_put() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_get(self, line):
        '''Get the value of the key from the KV store.
        Usage: get key [column]'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 1:
            print "Usage: get key"
            return
        # ok, transform the key to long
        try:
            key = c_ulonglong(long(l[0]))
            value = c_char_p("")
            if len(l) == 2:
                column = c_int(int(l[1]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_get(self.table, key, byref(value), column)
            if err != 0:
                print "api.hvfs_get() failed w/ %d" % err
                return
            self.stop_clock()
            if value.value == "":
                print >> sys.stderr, "Key: %ld Column: %d => Value: NONE" % (key.value, column.value)
            else:
                print >> sys.stderr, "Key: %ld Column: %d => Value: %s" % (key.value, column.value, value.value)
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_del(self, line):
        '''Delete the key/value pair in the KV store.
        Usage: del key'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 1:
            print "Usage: del key"
            return
        # ok, transform the key to long
        try:
            key = c_ulonglong(long(l[0]))
            self.start_clock()
            err = api.hvfs_del(self.table, key, 0)
            if err != 0:
                print "api.hvfs_del() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_update(self, line):
        '''Update the key/value pair in the KV store.
        Usage: update key value [column]'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 2:
            print "Invalid argument."
            return
        # ok, transform the key to long
        try:
            key = c_ulonglong(long(l[0]))
            value = c_char_p(l[1])
            if len(l) == 3:
                column = c_int(int(l[2]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_update(self.table, key, value, column)
            if err != 0:
                print "api.hvfs_update() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_sput(self, line):
        '''Put a Key/Value pair to the KV store.
        Usage: put key value [column]'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 2:
            print "Usage: put key value"
            return
        # ok, transfer the key to int
        try:
            key = c_char_p(l[0])
            value = c_char_p(l[1])
            if len(l) == 3:
                column = c_int(int(l[2]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_sput(self.table, key, value, column)
            if err != 0:
                print "api.hvfs_put() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_sget(self, line):
        '''Get the value of the key from the KV store.
        Usage: get key [column]'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 1:
            print "Usage: get key"
            return
        # ok, transform the key to long
        try:
            key = c_char_p(l[0])
            value = c_char_p("")
            if len(l) == 2:
                column = c_int(int(l[1]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_sget(self.table, key, byref(value), column)
            if err != 0:
                print "api.hvfs_sget() failed w/ (%d) %s" % (err, 
                                                             os.strerror(-err))
                return
            self.stop_clock()
            if value.value == "":
                print >> sys.stderr, "Key: %s => Value: NONE" % (key.value)
            else:
                print >> sys.stderr, "Key: %s => Value: %s" % (key.value, 
                                                               value.value)
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_sdel(self, line):
        '''Delete the key/value pair in the KV store.
        Usage: del key'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 1:
            print "Usage: del key"
            return
        # ok, transform the key to long
        try:
            key = c_char_p(l[0])
            self.start_clock()
            err = api.hvfs_sdel(self.table, key, 0)
            if err != 0:
                print "api.hvfs_del() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_supdate(self, line):
        '''Update the key/value pair in the KV store.
        Usage: update key value'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 2:
            print "Invalid argument."
            return
        # ok, transform the key to long
        try:
            key = c_char_p(l[0])
            value = c_char_p(l[1])
            if len(l) == 3:
                column = c_int(int(l[2]))
                if column.value >= 0x1000:
                    print "Invalid column id %ld" % (column.value)
            else:
                column = c_int(0)
            self.start_clock()
            err = api.hvfs_supdate(self.table, key, value, column)
            if err != 0:
                print "api.hvfs_update() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_commit(self, line):
        '''Trigger a memory snapshot on the remote MDS.
        Usage: commit #MDS'''
        l = shlex.split(line)
        if len(l) < 1:
            print "Invalid argument."
            return
        # ok, transform the id to int
        if l[0] == "all":
            try:
                api.hvfs_active_site.restype = c_char_p
                asites = api.hvfs_active_site("mds")
                lx = shlex.split(asites)
                for x in lx:
                    if x != "" and x != None:
                        id = c_int(int(x))
                        err = api.hvfs_commit(id)
                        if err != 0:
                            print "api.hvfs_commit() failed w/ %d" % err
                            return
            except ValueError, ve:
                print "ValueError %s" % ve
        else:
            try:
                id = c_int(int(l[0]))
                err = api.hvfs_commit(id)
                if err != 0:
                    print "api.hvfs_commit() failed w/ %d" % err
                    return
            except ValueError, ve:
                print "ValueError %s" % ve

    def do_getcluster(self, line):
        '''Get the MDS/MDSL cluster status.
        Usage: getcluster 'mds/mdsl' '''
        l = shlex.split(line)
        if len(l) < 1:
            print "Invalid argument."
            return
        # ok
        try:
            err = api.hvfs_get_cluster(l[0])
            if err != 0:
                print "api.hvfs_get_cluster() failed w/ %d" % err
                return
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_getactivesite(self, line):
        '''Get the active sites.
        Usage: getactivesite 'mds/mdsl' '''
        l = shlex.split(line)
        if len(l) < 1:
            print "Invalid argument. See help getactivesite!"
            return
        # ok
        try:
            err = api.hvfs_active_site(l[0])
            if err == None:
                print "api.hvfs_active_site() failed w/ %s" % err
                return
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_offline(self, line):
        '''Offline a site or a group of sites.
        Usage: offline 'mds/mdsl' id force'''
        force = 0
        l = shlex.split(line)
        if len(l) < 2:
            print "Invalid argument. See help offline!"
            return
        elif len(l) > 2:
            force = l[2]

        # ok
        try:
            self.start_clock()
            err = api.hvfs_offline(l[0], int(l[1]), int(force))
            if err != 0:
                print "api.hvfs_offline() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except TypeError, te:
            print "TypeError %s" % te
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_online(self, line):
        '''Online a site or a group sites.
        Usage: online 'mds/mdsl' id'''
        l = shlex.split(line)
        if len(l) < 2:
            print "Invalid argument. See help online!"
            return
        # ok
        try:
            self.start_clock()
            err = api.hvfs_online(l[0], int(l[1]))
            if err != 0:
                print "api.hvfs_online() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except TypeError, te:
            print "TypeError %s" % te
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_addsite(self, line):
        '''Online add a new site.
        Usage: addsite ip port type id'''
        l = shlex.split(line)
        if len(l) < 4:
            print "Invalid arguments. See help addsite!"
            return
        # ok
        try:
            self.start_clock()
            err = api.hvfs_addsite(l[0], int(l[1]), l[2], int(l[3]))
            if err != 0:
                print "api.hvfs_addsite() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except TypeError, te:
            print "TypeError %s" % te
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_rmvsite(self, line):
        '''Remove a site from the address table
        Usage: rmvsite ip port site_id'''
        l = shlex.split(line)
        if len(l) < 3:
            print "Invalid arguments. See help rmvsite!"
            return
        # ok
        try:
            self.start_clock()
            err = api.hvfs_rmvsite(l[0], int(l[1]), long(l[2]))
            if err != 0:
                print "api.hvfs_rmvsite() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except TypeError, te:
            print "TypeError %s" % te
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_shutdown(self, line):
        '''Shutdown a opened but ERROR state site entry @ R2 server
        Usage: shutdown site_id'''
        l = shlex.split(line)
        if len(l) < 1:
            print "Invalid arguments. See help shutdown!"
            return
        # ok
        try:
            self.start_clock()
            err = api.hvfs_shutdown(long(l[0]))
            if err != 0:
                print "api.hvfs_shutdown() failed w/ %d" % err
                return
            self.stop_clock()
            self.echo_clock("Time elasped:")
        except TypeError, te:
            print "TypeError %s" % te
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_pst(self, line):
        '''Print the xnet site table.
        Usage: pst
        '''

        xnet.st_print()

    def do_getinfo(self, line):
        '''Get system info from R2.
        Usage: getinfo [all|site|mds|mdsl] [all|mds|mdsl|client|bp|r2||raw|rate]
                       site [all|mds|mdsl|client|bp|r2]
                       mds  [rate|raw]
        '''
        l = shlex.split(line)
        cmd = 0
        arg = 0

        if len(l) == 0:
            cmd = 100
        elif len(l) >= 1:
            if l[0] == "all":
                cmd = 100
            elif l[0] == "site":
                cmd = 1
            elif l[0] == "mds":
                cmd = 2
            elif l[0] == "mdsl":
                cmd = 3
            else:
                cmd = 0
        if len(l) >= 2:
            if l[1] == "all":
                arg = 0
            elif l[1] == "mds":
                arg = 1
            elif l[1] == "mdsl":
                arg = 2
            elif l[1] == "client":
                arg = 3
            elif l[1] == "bp":
                arg = 4
            elif l[1] == "r2":
                arg = 5
            elif l[1] == "rate":
                arg = 0
            elif l[1] == "raw":
                arg = 1

        c_str = c_char_p(None)
        err = api.hvfs_get_info(cmd, arg, byref(c_str));
        if err != 0:
            print "api.hvfs_get_info() failed w/ %d" % err
            return
        print c_str.value
        api.hvfs_free(c_str)
        print "+OK"

    def do_quit(self, line):
        print "Quiting ..."
        return True

    def do_EOF(self, line):
        print "Quiting ..."
        return True

def print_help():
    print "AMC Client: "
    print " -h, --help          print this help document."
    print " -t, --thread        how many threads do you want to run.(IGNORED)"
    print " -i, --id            the logical id of this AMC client."
    print " -r, --ring          the R2 server ip address."

if __name__ == '__main__':
    main(sys.argv[1:])
