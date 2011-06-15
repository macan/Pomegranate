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
set grid
#set output "cn.paper.create.eps"
set output "cn.paper.create.png"
set auto x
set xtics out
set auto y

set xrange [0:180]

set multiplot layout 1,2
#set origin 0.0, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)"
set ytics nomirror
set format y "%gK"
set y2label "# of Table Slices (#)"
set y2tics
set key right top

plot "< awk '{if (ts == 0) {ts = $2; modify = $5;} \
              {print ($2 - ts)\" \"(($5 - modify)/5.0/1000);} \
              modify = $5;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Create RPS" w linesp ls 2 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; sp_local = $13;} \
              {print ($2 - ts)\" \"($13 - sp_local);} \
              sp_local = $13;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Split Slices" w linesp ls 5 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; sp_send = $14;} \
              {print ($2 - ts)\" \"($14 - sp_send);} \
              sp_send = $14;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Split Sent" w linesp ls 3 axes x1y2

# set origin .25, 0
unset format
unset y2label
unset y2tics
set xlabel "TimeStamp (s)"
set ylabel "# of Requests (#)"
set ytics
set format y "%gK"
set key top right

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"(($15 - fwds)/1000);} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Requests Routed" w linesp ls 1 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; loop_fwds = $24;} \
              {print ($2 - ts)\" \"(($24 - loop_fwds)/1000);} \
              loop_fwds = $24;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Looped Routes" w linesp ls 2 axes x1y2

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset