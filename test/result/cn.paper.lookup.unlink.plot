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
#set output "cn.paper.lookup.unlink.eps"
set output "cn.paper.lookup.unlink.png"
set auto x
set xtics out
set auto y

set multiplot layout 1,2
# set size 1, 1
# set origin 2, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)
set format y "%gK"
set ytics nomirror
set y2label "# of Requests"
set y2tics
set key top right

set xrange [420:650]

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"(($15 - fwds));} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Requests Routed" w linesp ls 3 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; lookup = $4;} \
              {print ($2 - ts)\" \"(($4 - lookup)/5.0/1000);} \
              lookup = $4;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Lookup RPS" w linesp ls 1 axes x1y1

# set size 1, 1
# set origin 3, 0
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)
set format y "%gK"
set ytics nomirror
set y2label "# of Requests"
set y2tics
set key top right
set y2range [0:10]

set xrange [3770:4000]

plot "< awk '{if (ts == 0) {ts = $2; fwds = $15;} \
              {print ($2 - ts)\" \"(($15 - fwds));} \
              fwds = $15;}' xnet/CP-BACK-mds.aggr"\
     using 1:2 t "Requests Routed" w linesp ls 3 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; modify = $5;} \
              {print ($2 - ts)\" \"(($5 - modify)/5.0/1000);} \
              modify = $5;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Delete RPS" w linesp ls 2 axes x1y1

unset multiplot
unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
reset