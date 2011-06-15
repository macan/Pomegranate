# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 10,3
set terminal png transparent size 1000,300
#set output "cn.paper.largeio.eps"
set output "cn.paper.largeio.png"

set multiplot layout 1,2

set style data histogram
set style histogram cluster gap 1
set style fill solid 1.00 border -1
set boxwidth 0.9

set ylabel "I/O Bandwidth (MB/s)"
set xtics ("Sequential Read" 0, "Sequential Write" 1)
set yrange [0:125]

plot 'paper/cn/largeio' using ($1/1024) ti "Ext3", '' u ($2/1024) ti "HVFS Kernel", '' u ($3/1024) ti "HVFS FUSE"

set yrange [0:900]
plot 'paper/cn/largeio.skyfs' using ($1/1024) ti "SkyFS", '' u ($2/1024) ti "HVFS Kernel", '' u ($3/1024) ti "HVFS FUSE"
