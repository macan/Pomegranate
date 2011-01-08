#!/bin/bash
##
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2011-01-06 10:51:34 macan>
#
# This is a simple disk usage displayer for Pomegranate users
#
# Armed with EMACS.

if [ "x$1" == "x" ]; then
    DEV="sda"
else
    DEV=$1
fi

OUTFILE="/tmp/disk.out.$$"
> $OUTFILE

while true;
do
    cat /proc/diskstats | grep "$DEV " >> $OUTFILE
    sleep 5
done &

trap "rm -rf $OUTFILE; kill $!;" EXIT

BANNER="read(#/s) rmerge(#/s) rrate(MiB/s) rlat(ms) write(#/s) wmerge(#/s) wrate(MiB/s) wlat(ms) pIO(#) alat(ms) wtlat(ms)"

echo $BANNER
sleep 5
tail -f $OUTFILE | awk 'BEGIN{read=0; rmerge=0; rrate = 0; rlat = 0; write = 0; wmerge = 0; wrate = 0; wlat = 0; pio = 0; alat = 0; wtlat = 0; banner=0;} {banner++; if (banner % 15 == 0) {print "read(#/s) rmerge(#/s) rrate(MiB/s) rlat(ms) write(#/s) wmerge(#/s) wrate(MiB/s) wlat(ms) pIO(#) alat(ms) wtlat(ms)";} xread = $4 - read; cpio = $12; xwrite = $8 - write; if (cpio == 0) {cpio = 1;} if (xread == 0) {xread = 1;} if (xwrite == 0) {xwrite = 1;} if (read != 0) {printf "%8d %11d %12.2f %8.2f %10d %11d %12.2f %8.2f %6d %8.2f %9.2f\n",($4 - read)/5, ($5 - rmerge)/5, ($6 - rrate)/2/1024/5, ($7 - rlat)/(xread), ($8 - write)/5, ($9 - wmerge)/5, ($10 - wrate)/2/1024/5, ($11 - wlat)/(xwrite), ($12), ($13 - alat)/cpio, ($14 - wtlat)/cpio;} read = $4; rmerge = $5; rrate = $6; rlat = $7; write = $8; wmerge = $9; wrate = $10; wlat = $11; pio = $12; alat = $13; wtlat = $14;}'