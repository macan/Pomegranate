# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
#set terminal postscript eps enhanced color
set terminal png transparent size 600,300
set origin 0.0, 0.0
set size 1, 1
#set grid
#set output "paper.create.eps"
set output "paper.create.split.png"
set auto x
#set xtics out
set auto y

set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)"
set ytics nomirror
set format y "%gK"
set y2label "# of Table Slices (#)"
set y2tics
set key center below

# set xrange [0:180]
# plot "< awk '{if (ts == 0) {ts = $2; modify = $5;} \
#               {print ($2 - ts)\" \"(($5 - modify)/5.0/1000);} \
#               modify = $5;}' xnet/CP-BACK-mds.aggr" \
#      using 1:2 t "Creates/Second" w linesp ls 2 axes x1y1, \
#      "< awk '{if (ts == 0) {ts = $2; sp_local = $13;} \
#               {print ($2 - ts)\" \"($13 - sp_local);} \
#               sp_local = $13;}' xnet/CP-BACK-mds.aggr"\
#      using 1:2 t "Local Splits" w linesp ls 5 axes x1y2, \
#      "< awk '{if (ts == 0) {ts = $2; sp_send = $14;} \
#               {print ($2 - ts)\" \"($14 - sp_send);} \
#               sp_send = $14;}' xnet/CP-BACK-mds.aggr"\
#      using 1:2 t "Remote Splits" w linesp ls 3 axes x1y2

set xrange [0:170]
plot "< awk '{if (ts == 0) {ts = $1; modify = $5;} \
              {print ($1 - ts)\" \"(($5 - modify)/5.0/1000);} \
              modify = $5;}' xnet/CP-BACK-root.mds" \
     using 1:2 t "Creates/Second" w linesp ls 2 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $1; sp_local = $13;} \
              {print ($1 - ts)\" \"($13 - sp_local);} \
              sp_local = $13;}' xnet/CP-BACK-root.mds"\
     using 1:2 t "Local Splits" w linesp ls 5 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $1; sp_send = $14;} \
              {print ($1 - ts)\" \"($14 - sp_send);} \
              sp_send = $14;}' xnet/CP-BACK-root.mds"\
     using 1:2 t "Remote Splits" w linesp ls 3 axes x1y2

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset