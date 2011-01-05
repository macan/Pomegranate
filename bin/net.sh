#!/bin/bash
##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-05 16:16:28 macan>
#
# This is a simple network usage displayer for Pomegranate users
#
# Armed with EMACS.

if [ "x$1" == "x" ]; then
    DEV="eth0"
else
    DEV=$1
fi

OUTFILE="/tmp/netstat.out.$$"
> $OUTFILE

while true;
do
    cat /proc/net/dev | grep $DEV | sed "s/$DEV://g" | awk '{print $1, $9}' >> $OUTFILE
    sleep 5
done &

trap "rm -rf $OUTFILE; kill $!;" EXIT

echo "RX(MB/s) TX(MB/s)"
sleep 5
tail -f $OUTFILE | awk 'BEGIN{tx=0; rx=0; banner=0;} {banner++; if (banner % 15 == 0) {print "RX(MB/s) TX(MB/s)"} if (tx != 0) {print ($1 - rx)/1024/1024/5, ($2 - tx)/1024/1024/5;} rx = $1; tx = $2;}'
