# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 10,3
set terminal png transparent size 600,300
#set output "en.paper.smallio.eps"
set output "en.paper.smallio.png"

set auto x
set auto y
set logscale y 10
set logscale x 2
set xlabel "Small File Size (KB)"
set ylabel "Write Bandwidth (MB/s)"
set key top left

plot 'paper/fast/orangefs.ioscale' using 1:($4/1024) ti "OrangeFS" w linesp ls 2, \
     '' u 1:($8/1024) ti "HVFS" w linesp ls 3


