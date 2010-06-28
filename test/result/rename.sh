#!/bin/bash

# $1 is the log HEADER
# $2 is the output HEADER

# rename the system logs
cat xnet/$1-node60-*.tab | sed -e '$d' > xnet/$2-node0.tab
cat xnet/$1-node61-*.tab | sed -e '$d' > xnet/$2-node1.tab
cat xnet/$1-node62-*.tab | sed -e '$d' > xnet/$2-node2.tab
cat xnet/$1-node63-*.tab | sed -e '$d' > xnet/$2-node3.tab
cat xnet/$1-node64-*.tab | sed -e '$d' > xnet/$2-node4.tab
cat xnet/$1-node65-*.tab | sed -e '$d' > xnet/$2-node5.tab
cat xnet/$1-node70-*.tab | sed -e '$d' > xnet/$2-node6.tab
cat xnet/$1-gnode71-*.tab | sed -e '$d' > xnet/$2-node7.tab
cat xnet/$1-gnode72-*.tab | sed -e '$d' > xnet/$2-node8.tab
cat xnet/$1-gnode73-*.tab | sed -e '$d' > xnet/$2-node9.tab
cat xnet/$1-gnode74-*.tab | sed -e '$d' > xnet/$2-node10.tab
cat xnet/$1-gnode75-*.tab | sed -e '$d' > xnet/$2-node11.tab
cat xnet/$1-gnode76-*.tab | sed -e '$d' > xnet/$2-node12.tab
cat xnet/$1-gnode77-*.tab | sed -e '$d' > xnet/$2-node13.tab
cat xnet/$1-node78-*.tab | sed -e '$d' > xnet/$2-node14.tab
cat xnet/$1-node79-*.tab | sed -e '$d' > xnet/$2-node15.tab
