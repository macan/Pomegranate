# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 10,3
set terminal png transparent size 1000,300
set origin 0.0, 0.0
set size 1, 1
#set grid
#set output "cn.paper.ioscale.eps"
set output "cn.paper.ioscale.png"
set auto x
set xtics out
set auto y

set multiplot layout 1,2
# set size 1, 1
# set origin 2, 0
set xlabel "Client Cluster Size (#)"
set ylabel "File Writen (#/s)
set logscale x 2
set logscale y 2
set key bottom right

plot "paper/cn/ioscale.client2server" using 1:2 t "#Server=1" w linesp ls 1,\
     '' u 1:3 t "#Server=2" w linesp ls 2,\
     '' u 1:4 t "#Server=4" w linesp ls 3,\
     '' u 1:5 t "#Server=8" w linesp ls 4,\
     '' u 1:6 t "#Server=16" w linesp ls 5,\
     '' u 1:7 t "#Server=32" w linesp ls 6

set xlabel "Server Cluster Size (#)"
set ylabel "Write Bandwidth (KB/s)"
set yrange [64:16384]

plot "paper/cn/ioscale.server2client" using 1:3 t "#Client=1" w linesp ls 1,\
     '' u 1:4 t "#Client=2" w linesp ls 2,\
     '' u 1:5 t "#Client=4" w linesp ls 3,\
     '' u 1:6 t "#Client=8" w linesp ls 4,\
     '' u 1:7 t "#Client=16" w linesp ls 5,\
     '' u 1:8 t "#Client=32" w linesp ls 6

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset