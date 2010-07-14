#!/bin/bash

function plot_mds() {
    total=`ls xnet/CP-BACK-mds.* | wc -l`
    let nr=total/2;
    step=0
    echo "Begin plotting the MDS pngs, total $total, output $nr..."

    while [ $step -lt $nr ]; do
        let first=$step*2
        let second=first+1
        sed "s/mds.gXXX.png/mds.g$step.png/g; s/CP-BACK-mds.FIRST/CP-BACK-mds.$first/g; s/CP-BACK-mds.SECOND/CP-BACK-mds.$second/g" mds.plot.template | gnuplot
        let step+=1
    done
}

function plot_mds_aggr() {
    sed "s/mds.gXXX.png/mds.aggr.png/g; s/CP-BACK-mds.FIRST/CP-BACK-mds.aggr/g; s/CP-BACK-mds.SECOND/CP-BACK-mds.aggr/g" mds.plot.aggr.template | gnuplot
}

function plot_mdsl_aggr() {
    sed "s/mdsl.gXXX.png/mdsl.aggr.png/g; s/CP-BACK-mdsl.FIRST/CP-BACK-mdsl.aggr/g; s/CP-BACK-mdsl.SECOND/CP-BACK-mdsl.aggr/g" mdsl.plot.aggr.template | gnuplot
}

function plot_mdsl() {
    total=`ls xnet/CP-BACK-mdsl.* | wc -l`
    let nr=total/2;
    step=0
    echo "Begin plotting the MDSL pngs, total $total, output $nr..."

    while [ $step -lt $nr ]; do
        let first=$step*2
        let second=first+1
        sed "s/mdsl.gXXX.png/mdsl.g$step.png/g; s/CP-BACK-mdsl.FIRST/CP-BACK-mdsl.$first/g; s/CP-BACK-mdsl.SECOND/CP-BACK-mdsl.$second/g" mdsl.plot.template | gnuplot
        let step+=1
    done
}

function plot_sys() {
    total=`ls xnet/CP-BACK-*node* | wc -l`
    step=0
    echo "Begin plotting the node pngs, total $total, output $total..."

    while [ $step -lt $total ]; do
        let first=$step
        sed "s/system.NODE.png/system.n$step.png/g; s/CP-BACK-NODE.tab/CP-BACK-node$first.tab/g" system.plot.template | gnuplot
        let step+=1
    done
}

function plot_sys_disk_mm() {
    total=`ls xnet/CP-BACK-*node* | wc -l`
    step=0
    echo "Begin plotting the node pngs, total $total, output $total..."

    while [ $step -lt $total ]; do
        let first=$step
        sed "s/system_detail.NODE.png/system_detail.n$step.png/g; s/CP-BACK-NODE.tab/CP-BACK-node$first.tab/g" system.plot.disk.mm.template | gnuplot
        let step+=1
    done
}

#plot_mds
plot_mds_aggr
plot_mdsl_aggr
#plot_mdsl

exit
# transform the log names
./rename.sh collect.log CP-BACK

plot_sys
plot_sys_disk_mm

for x in `ls *.png`; do
    y=`echo $x | sed -e 's/png/gif/g'`
    echo "Transform $x to $y ..."
    convert $x $y
done
