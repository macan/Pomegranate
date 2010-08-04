#!/bin/env python

import os, time, sys
import getopt
import signal
import cmd
import shlex
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

use_readline = True
try:
    import readline
except ImportError, ie:
    print "Warning: import failed (%s)" % ie
    use_readline = False

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

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "ht:i:r:",
                                   ["help", "thread=", "id=", 
                                    "ring="])
    except getopt.GetoptError:
        sys.exit()

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    thread = 1
    id = 0
    ring = None

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
    except ValueError, ve:
        print "Value error: %s" % ve
        sys.exit()

    print "AMC Client %d Running w/ (%d threads)..." % (id, thread)

    # init the AMC client
    CSTR_ARRAY = c_char_p * 5
    argv = CSTR_ARRAY("pyAMC", "-d", "0", "-r", "10.10.111.9")
    err = api.__core_main(5, argv)
    if err != 0:
        print "api.__core_main() failed w/ %d" % err
        return

    # create the root entry
    err = api.hvfs_create_root(None)
    if err != 0:
        print "api.hvfs_create_root() failed /w %d" % err
        return

    # create the table
    table = c_char_p("table_x")
    err = api.hvfs_create_table(table)
    if err != 0:
        print "api.hvfs_create_table() failed w/ %d" % err

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
    err = api.hvfs_put(table, key, value, 0)
    if err != 0:
        print "api.hvfs_put() failed w/ %d" % err
    else:
        # get the entry
        err = api.hvfs_get(table, key, byref(ov), 0)
        if err != 0:
            print "api.hvfs_get() failed w/ %d" % err
        else:
            print "get value '%s'" % ov.value
            # delete the entry
            err = api.hvfs_del(table, key, 0)
            if err != 0:
                print "api.hvfs_del() failed w/ %d" % err

    err = api.hvfs_drop_table(table)
    if err != 0:
        print "api.hvfs_drop_table() failed w/ %d" % err

    pamc_shell().cmdloop("Welcome to Python AMC Client Shell, " + 
                         "for help please input ? or help")

    api.__core_exit(None)

class pamc_shell(cmd.Cmd):
    bc = None
    table = None
    keywords = ["EOF", "create", "drop", "put", "get", "del", "update",
                "quit", "list", "ls", "set"]

    def __init__(self):
        cmd.Cmd.__init__(self)
        cmd.Cmd.use_rawinput = use_readline
        self.bc = bcolors()

    def emptyline(self):
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
            print "api.hvfs_drop_table() failed w/ %d" % err
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
        Usage: put key value'''
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
            err = api.hvfs_put(self.table, key, value, 0)
            if err != 0:
                print "api.hvfs_put() failed w/ %d" % err
                return
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_get(self, line):
        '''Get the value of the key from the KV store.
        Usage: get key'''
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
            err = api.hvfs_get(self.table, key, byref(value), 0)
            if err != 0:
                print "api.hvfs_get() failed w/ %d" % err
                return
            print >> sys.stderr, "Key: %ld => Value: %s" % (key.value, value.value)
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
            err = api.hvfs_del(self.table, key, 0)
            if err != 0:
                print "api.hvfs_del() failed w/ %d" % err
                return
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_update(self, line):
        '''Update the key/value pair in the KV store.
        Usage: update key value'''
        if self.table == None:
            print "Please set the table w/ 'set table <table_name>'"
            return
        l = shlex.split(line)
        if len(l) < 2:
            print "api.hvfs_update() failed w/ %d" % err
            return
        # ok, transform the key to long
        try:
            key = c_ulonglong(long(l[0]))
            value = c_char_p(l[1])
            err = api.hvfs_update(self.table, key, value, 0)
            if err != 0:
                print "api.hvfs_update() failed w/ %d" % err
                return
        except ValueError, ve:
            print "ValueError %s" % ve

    def do_quit(self, line):
        print "Quiting ..."
        return True

    def do_EOF(self, line):
        print "Quiting ..."
        return True

def print_help():
    print "AMC Client: "
    print " -h, --help          print this help document."
    print " -t, --thread        how many threads do you want to run."

if __name__ == '__main__':
    main(sys.argv[1:])
