# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color size 6,3
set terminal png transparent size 600,300
set origin 0.0, 0.0
set size 1, 1
set grid
#set output "cn.paper.mdscale.eps"
set output "cn.paper.mdscale.png"
set auto x
set xtics out offset -1,0
set auto y

set xlabel "Server Cluster Size (#)"
set ylabel "File Creation per Second (#/s)"
set key top left
set logscale x 2

plot "paper/cn/mdscale.mdtest" using 1:2 t "HVFS" w linesp ls 2, \
     '' u 1:3 t "GIGA+" w linesp ls 3, \
     '' u 1:4 t "HBase" w linesp ls 4, \
     '' u 1:5 t "Ceph" w linesp ls 5
