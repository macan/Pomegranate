#!/bin/bash
##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-03-18 10:27:17 macan>
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
    cat /proc/net/dev | grep $DEV | sed "s/$DEV://g" | awk '{print $1, $2, $9, $10}' >> $OUTFILE
    sleep 5
done &

trap "rm -rf $OUTFILE; kill $!;" EXIT

echo "RX(MiB/s) avgRXunit(B) TX(MiB/s) avgTXunit(B)"
sleep 5
tail -f $OUTFILE | awk 'BEGIN{tx=0; rx=0; txp=0; rxp=0; txpd=0; rxpd=0; banner=0;} {banner++; if (banner % 15 == 0) {print "RX(MiB/s) avgRXunit(B) TX(MiB/s) avgTXunit(B)"} rxpd = $2 - rxp; if (rxpd == 0) {rxpd = 1;} txpd = $4 - txp; if (txpd == 0) {txpd = 1;} if (tx != 0) {printf "%8.2f %12.2f %9.2f %12.2f\n", ($1 - rx)/1024/1024/5, ($1 - rx)/(rxpd), ($3 - tx)/1024/1024/5, ($3 - tx)/(txpd);} rx = $1; tx = $3; rxp = $2; txp = $4; flush();}'
