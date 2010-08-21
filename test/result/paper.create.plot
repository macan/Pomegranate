# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
set terminal postscript eps enhanced color
#set terminal png transparent
set origin 0.0, 0.0
set size 1, 1
set grid
set output "paper.create.eps"
#set output "paper.create.png"
set auto x
set xtics out
set auto y

set xrange [0:180]

set multiplot layout 2,1
#set origin 0.0, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)"
set ytics nomirror
set format y "%gK"
set y2label "# of Table Slices (#)"
set y2tics
set key center bottom box

plot "< awk '{if (ts == 0) {ts = $2; modify = $5;} \
              {print ($2 - ts)\" \"(($5 - modify)/5.0/1000);} \
              modify = $5;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Create RPS" w linesp ls 2 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; cowed = $10;} \
              {print ($2 - ts)\" \"($10 - cowed);} \
              cowed = $10;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "COWed Slices" w linesp ls 4 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; sp_local = $13;} \
              {print ($2 - ts)\" \"($13 - sp_local);} \
              sp_local = $13;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Split Slices" w linesp ls 5 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; sp_send = $14;} \
              {print ($2 - ts)\" \"($14 - sp_send);} \
              sp_send = $14;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Split Sent" w linesp ls 6 axes x1y2

# set origin .25, 0
unset format
set xlabel "TimeStamp (s)"
set ylabel "Throughput (MB/s)"
set ytics nomirror
set y2label "# of Requests (#)"
set y2tics
set key top box

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"($15 - fwds);} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Forward Requests" w linesp ls 1 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2;} \
              {print ($2 - ts)\" \"($9);} \
             }' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Active Table Slices" w linesp ls 3 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; loop_fwds = $24;} \
              {print ($2 - ts)\" \"($24 - loop_fwds);} \
              loop_fwds = $24;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Looped Forwards" w linesp ls 2 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; inBW = $21;} \
              {print ($2 - ts)\" \"(($21 - inBW)/5/1024/1024);} \
              inBW = $21;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net in BW" w linesp ls 8 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; outBW = $22;} \
              {print ($2 - ts)\" \"(($22 - outBW)/5/1024/1024);} \
              outBW = $22;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net out BW" w linesp ls 9 axes x1y1

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset