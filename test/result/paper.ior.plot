# Template for plot mds pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
set terminal postscript eps enhanced color
#set terminal png transparent
set size 1,1
set origin 0.0, 0.0
set grid
set output "paper.ior.eps"
#set output "paper.ior.png"
set auto x
set xtics out
set auto y

set xrange [1720:3390]

set multiplot layout 2,1
set xlabel "TimeStamp (s)"
set ylabel "Request per Second (#/s)"
set ytics nomirro
set format y "%gK"
set y2label "# of Table Slices (#)"
set y2tics
set key center top box

plot "< awk '{if (ts == 0) {ts = $2; lookup = $4;} \
              {print ($2 - ts)\" \"(($4 - lookup)/5.0/1000);} \
              lookup = $4;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "Read RPS" w linesp ls 1 axes x1y1, \
     "< awk '{if (ts == 0) {ts = $2; cowed = $10;} \
              {print ($2 - ts)\" \"($10 - cowed);} \
              cowed = $10;}' xnet/CP-BACK-mds.aggr" \
     using 1:2 t "COWed Slices" w linesp ls 4 axes x1y2

unset format
set xlabel "TimeStamp (s)"
set ylabel "IO BW (MB/s)"
set ytics nomirror
set y2label "Net BW (MB/s)"
set y2tics
set key center top box

plot "< awk '{if (ts == 0) {ts = $2; inBW = $16;} \
              {print ($2 - ts)\" \"(($16 - inBW)/5/1024/1024);} \
              inBW = $16;}' xnet/CP-BACK-mdsl.aggr"\
     using 1:2 t "Net in BW" w linesp ls 8 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; outBW = $17;} \
              {print ($2 - ts)\" \"(($17 - outBW)/5/1024/1024);} \
              outBW = $17;}' xnet/CP-BACK-mdsl.aggr"\
     using 1:2 t "Net out BW" w linesp ls 9 axes x1y2, \
     "< awk '{if (ts == 0) {ts = $2; A = $20;} \
             {print ($2 - ts)\" \"(($20 - A)/5/1024/1024);} \
             A = $20;}' xnet/CP-BACK-mdsl.aggr" \
     using 1:2 t "Read BW" w linesp ls 4 axes x1y1
