#!/bin/bash

if [ "x$1" == "x" ]; then
    echo "Usage: $0 client_lat-logfile"
    exit
fi

cat $1 | sed -n '/real test/, $ {/<=/ {p}}' | awk '{print $2, $4, $6, $7}' > $1.uld

MAX=`cat $1.uld | awk 'BEGIN{max=0}{if (max < $3) max = $3;}END{print max}'`

cat <<EOF | gnuplot 
reset
set terminal png transparent 
set origin 0, 0
set size 1, 1
set grid
set output '$1.png'
set auto x
set auto y

set xlabel 'Latency (ms)'
set ylabel 'Percentage (%)'
set ytics nomirror
set y2label 'Frequency (%)'
set y2tics
set key right bottom

plot '$1.uld' u 2:1 t 'CDF' w linesp axes x1y1, \
     '' u 2:(100*\$4/$MAX) t 'Frequency' smooth frequency w histeps axes x1y2 
EOF

rm -rf $1.uld