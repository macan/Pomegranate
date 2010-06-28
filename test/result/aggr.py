#!/bin/env python

f = list()
a = list()
ts = -5

try:
    for x in range(16):
        f.append(open('./xnet/CP-BACK-mds.%d' % (x)))
except IOError, ex:
    print ex.message

while True:
    ts += 5
    r = ['PLOT', ts, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    try:
        for x in range(16):
            l = f[x].readline()
            l = l.rsplit('\n')
            a = l[0].split(' ')

            # accumulate the stats
            for y in range(2, 31):
                r[y] = int(r[y]) + int(a[y])
    except:
        break

    s = " ".join(str(i) for i in r)
    print s
