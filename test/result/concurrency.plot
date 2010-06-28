# Template for plot concurrency pictures
#
# Copyright (c) Ma Can <ml.macana@gmail.com>
#                      <macan@ncic.ac.cn>
#
reset
set terminal png transparent size 800 600
set size 1,1
set origin 0.0, 0.0
set grid
set output "concurrency.png"
set title "Create/Lookup/Unlink/Lookup on 100M entries"
set auto x
set xtics out
set auto y

set xlabel "# of Threads"
set logscale x 2
set ylabel "IOPS (#)"
set ytics nomirror
set y2label "Latency (us)"
set y2tics
set key top left box

plot "itbsplit.log" using 1:7 t "Create IOPS" w linesp ls 6 axes x1y1,\
     "itbsplit.log" using 1:8 t "Lookup(hit) IOPS" w linesp ls 7 axes x1y1,\
     "itbsplit.log" using 1:9 t "Unlink IOPS" w linesp ls 8 axes x1y1,\
     "itbsplit.log" using 1:10 t "Lookup(miss) IOPS" w linesp ls 9 axes x1y1,\
     "itbsplit.log" using 1:3 t "Create" w linesp ls 2 axes x1y2, \
     "itbsplit.log" using 1:4 t "Lookup(hit)" w linesp ls 3 axes x1y2, \
     "itbsplit.log" using 1:5 t "Unlink" w linesp ls 4 axes x1y2, \
     "itbsplit.log" using 1:6 t "Lookup(miss)" w linesp ls 5 axes x1y2

unset yrange
unset xtic
unset boxwidth
unset style
unset key
unset xrange
