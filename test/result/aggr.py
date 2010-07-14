#!/bin/env python

import sys

def aggr_mds(argv):
    f = list()
    a = list()
    ts = -5

    for x in range(100):
        try:
            f.append(open('./xnet/CP-BACK-mds.%d' % (x)))
        except IOError, ex:
            print >> sys.stderr, "IOError: %s" % ex

    while True:
        ts += 5
        r = ['PLOT', ts, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        try:
            for x in range(71):
                l = f[x].readline()
                l = l.rsplit('\n')
                a = l[0].split(' ')

                # accumulate the stats
                for y in range(2, 36):
                    r[y] = int(r[y]) + int(a[y])
        except:
            break

        s = " ".join(str(i) for i in r)
        print s

def aggr_mdsl(argv):
    f = list()
    a = list()
    ts = -5

    for x in range(100):
        try:
            f.append(open('./xnet/CP-BACK-mdsl.%d' % (x)))
        except IOError, ex:
            print >> sys.stderr, "IOError: %s" % ex

    while True:
        ts += 5
        r = ['PLOT', ts, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        try:
            for x in range(71):
                l = f[x].readline()
                l = l.rsplit('\n')
                a = l[0].split(' ')

                # accumulate the stats
                for y in range(2, 27):
                    r[y] = int(r[y]) + int(a[y])
        except:
            break

        s = " ".join(str(i) for i in r)
        print s

if __name__ == '__main__':
    if (len(sys.argv) == 1):
        print "Invalid agrument: please input the aggr target [mds|mdsl]"
        sys.exit()

    if sys.argv[1] == "mds":
        aggr_mds(sys.argv[2:])
    elif sys.argv[1] == "mdsl":
        aggr_mdsl(sys.argv[2:])
    else:
        print "Invalid agrument: please input the aggr target [mds|mdsl]"
