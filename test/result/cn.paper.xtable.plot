# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 10,3
set terminal png transparent size 500,300
#set output "cn.paper.smallio.eps"
set output "cn.paper.xtable.png"

set style data histogram
set style histogram cluster gap 1
set style fill solid 1.00 pattern border -1
set boxwidth 0.9
set logscale y 10
set key bottom center out horizontal
set yrange [1:1000000]

set xtics ("create" 0, "lookup" 1, "write" 2, "read" 3, "delete" 4)

plot 'paper/cn/xtable' using 1 ti "Request/Second", \
     '' u 2 ti "Latency(us)"

