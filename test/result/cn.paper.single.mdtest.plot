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
#set output "cn.paper.single.mdtest.eps"
set output "cn.paper.single.mdtest.png"
set logscale y 10
set logscale x 10
set format x "%.0f"
set auto x
set xtics out offset -2,0
set auto y

set xlabel "Directory Size (# of entires)"
set ylabel "Request per Second (#/s)"
set key top right

plot "paper/cn/single.mdtest" using 1:2 t "HVFS File Creation" w linesp ls 2, \
     "paper/cn/single.mdtest" using 1:3 t "HVFS File Removal" w linesp ls 3, \
     "paper/cn/single.mdtest" using 1:5 t "Ext3 File Creation" w linesp ls 4, \
     "paper/cn/single.mdtest" using 1:6 t "Ext3 File Removal" w linesp ls 5
