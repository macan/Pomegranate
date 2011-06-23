##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-06-22 03:55:56 macan>
#
# Armed with EMACS.
#
# This file provide a dconf client.

import os, time, sys, socket
import getopt
import cmd
import struct

class dconfc_shell(cmd.Cmd):
    '''A shell for dconf interface'''
    dc = None
    clock_start = 0.0
    clock_stop = 0.0
    keywords = ['EOF', 'info', 'latency', 'quit']

    def __init__(self, sock = None):
        cmd.Cmd.__init__(self)
        cmd.Cmd.use_rawinput = True
        self.dc = sock
        
    def do_info(self, line):
        '''Send echo cmd to DCONF server'''
        if self.dc == None:
            print "Invalid dconf connection!"
            return

        for i in range(16):
            data = struct.pack("ll", 0, 0)
            self.dc.send(data)

        data = self.dc.recv(4)
        len = struct.unpack("i", data)
        data = self.dc.recv(int(len[0]))
        print data

    def do_latency(self, line):
        '''Send latency cmd to DCONF server'''
        if self.dc == None:
            print "Invalid dconf connection!"
            return

        for i in range(16):
            data = struct.pack("ll", 6, 0)
            self.dc.send(data)

        data = self.dc.recv(4)
        len = struct.unpack("i", data)
        data = self.dc.recv(int(len[0]))
        print data

    def do_EOF(self, line):
        print "Quiting ..."
        return True

    def do_quit(self, line):
        return self.do_EOF(line)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "p:h",
                                   ['help', 'pid='])
    except getopt.GetoptError:
        sys.exit()

    pid = 0

    try :
        for opt, arg in opts:
            if opt in ('-h', '--help'):
                print_help()
                sys.exit()
            elif opt in ('-p', '--pid'):
                pid = int(arg)
    except ValueError, ve:
        print "Value error: %s" % ve
        sys.exit()

    print "DCONF client Running ..."

    # init the DCONF client
    try:
        fname = '/tmp/.MDS.DCONF.' + str(pid)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(fname)
    except IOError, ie:
        print "IOError %s" % ie
        sys.exit()

    # init the cmd shell
    dconfc_shell(s).cmdloop("Wellcome to Python DCONF Client Shell, " + 
                            "for help please input ? or help")

    s.close()

if __name__ == '__main__':
    main(sys.argv[1:])
