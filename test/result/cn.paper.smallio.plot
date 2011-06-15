# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 10,3
set terminal png transparent size 1000,300
#set output "cn.paper.smallio.eps"
set output "cn.paper.smallio.png"

set multiplot layout 1,2

set style data histogram
set style histogram cluster gap 1
set style fill solid 1.00 border -1
set boxwidth 0.9
set logscale y 10
set xlabel "File Size Range (Bytes)"

set ylabel "Postmark Runtime (s)"
set xtics ("[1,1000]" 0, "[1K,10K]" 1, "[10K,100K]" 2, "[100K,1M]" 3)
set label "Lower is better" at 0.5,10000

plot 'paper/cn/smallio.runtime' using 1 ti "HVFS FUSE", '' u 2 ti "ReiserFS", '' u 3 ti "Ext3"

set ylabel "Transaction Rate (#/s)"
unset label
set label "Higher is better" at 1,1000

plot 'paper/cn/smallio.tx' using 1 ti "HVFS FUSE", '' u 2 ti "ReiserFS", '' u 3 ti "Ext3"
