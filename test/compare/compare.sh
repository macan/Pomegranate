#!/bin/bash

TARGET=`ls *.c`

function run_test() {
    ./$1 > $1.rlt
    DIFF=`diff -Nur $1.std $1.rlt`
    if [ "x$DIFF" != "x" ]; then
        echo "This build fails test '$1', please revise your changes!"
        echo "-------------------------------------------------------"
        diff -Nur $1.std $1.rlt
        echo "-------------------------------------------------------"
    else
        rm -rf $1.rlt
    fi
}

function do_test() {
    for x in $TARGET; do
        echo -e " " CC"\t" $x
        y=`basename $x .c`
        gcc $x -o $y
        run_test $y
    done
}

function do_clean() {
    for x in $TARGET; do
        y=`basename $x .c`
        echo -e " " CL"\t" $y
        rm -rf $y
    done
}

if [ "x$1" == "xclean" ]; then
    do_clean
else
    echo "Begin compiling and regression test ..."
    do_test
    echo "OK, clean the binary targets."
    do_clean
fi