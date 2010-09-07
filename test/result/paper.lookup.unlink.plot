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
set output "paper.lookup.unlink.eps"
#set output "paper.lookup.unlink.png"
set auto x
set xtics out
set auto y

set multiplot layout 2,1
# set size 1, 1
# set origin 2, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)
set format y "%gK"
set ytics nomirror
set y2label "Net Bandwidth (MB/s)\n or # of Requests"
set y2tics
set key center bottom box
set xrange [420:650]

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"(($15 - fwds));} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Forward Requests" w linesp ls 3 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; lookup = $4;} \
              {print ($2 - ts)\" \"(($4 - lookup)/5.0/1000);} \
              lookup = $4;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Lookup RPS" w linesp ls 1 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; inBW = $21;} \
              {print ($2 - ts)\" \"(($21 - inBW)/5/1024/1024);} \
              inBW = $21;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net in BW" w linesp ls 8 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; outBW = $22;} \
              {print ($2 - ts)\" \"(($22 - outBW)/5/1024/1024);} \
              outBW = $22;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net out BW" w linesp ls 9 axes x1y2

# set size 1, 1
# set origin 3, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)
set format y "%gK"
set ytics nomirror
set y2label "Net Bandwidth (MB/s)\n or # of Requests"
set y2tics
set key center bottom box
set xrange [3770:4000]

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"(($15 - fwds));} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Forward Requests" w linesp ls 3 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; modify = $5;} \
              {print ($2 - ts)\" \"(($5 - modify)/5.0/1000);} \
              modify = $5;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Delete RPS" w linesp ls 2 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; inBW = $21;} \
              {print ($2 - ts)\" \"(($21 - inBW)/5/1024/1024);} \
              inBW = $21;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net in BW" w linesp ls 8 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; outBW = $22;} \
              {print ($2 - ts)\" \"(($22 - outBW)/5/1024/1024);} \
              outBW = $22;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Net out BW" w linesp ls 9 axes x1y2

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset