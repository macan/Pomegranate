#!/bin/bash
#
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-01-26 08:53:13 macan>
#
# This is the autotest script for HVFS project.
#
# Armed by EMACS.

PWD=`pwd`
PROJECT_HOME=`echo $PWD | sed -e 's/test//'`

echo "Starting the automate unit testing for HVFS project ..."
echo "HVFS Project Home Path: '$PROJECT_HOME'"

echo "Step 1: rebuild the whole project."
cd $PROJECT_HOME
make clean
make

LOG_PATH=`date +"%y-%m-%d-%H-%m-%s"`
mkdir -p "/tmp/HVFS-$LOG_PATH"
test_failed=0

function cbht_unit_test() {
    log_name=`echo $1 | sed -e 's/\//-/g'`
    echo -n "--> UNIT TEST m(CBHT) Start ... "
    if [ "x$2" == "x" ]; then
        total=7;
    fi
    loop=0;
    while [ $loop -lt $total ]; do
        case $loop in
            0) `$1 > /tmp/HVFS-$LOG_PATH/$log_name`;;
            1) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1000 1000 2 1000 1 0`;;
            2) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1000 1000 2 1000 2 0`;;
            3) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1000 1000 2 1000 1 1`;;
            4) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1000 1000 2 1000 2 1`;;
            5) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1400 1000 2 1000 8 0`;;
            6) `$1 >> /tmp/HVFS-$LOG_PATH/$log_name 1400 1000 2 1000 8 1`;;
        esac
        err=$?
        if [ $err -eq 0 ]; then
            echo -n "($loop/$total) done, "
        else
            echo -n "($loop/$total) failed $err, "
            let test_failed=1
        fi
        let loop+=1;
    done
    if [ $test_failed -eq 1 ]; then
        echo "some failed."
    else
        echo "all done."
    fi
}

function xnet_unit_test() {
    log_name=`echo $1 | sed -e 's/\//-/g'`
    program_name=`basename $1`
    if [ x$program_name == "xmds.ut" ]; then
        return;
    fi
    if [ x$program_name == "xfpmds.ut" ]; then
        return;
    fi
    echo -n "--> UNIT TEST s($program_name) Start ... "
    `$1 1 > /tmp/HVFS-$LOG_PATH/${log_name}-1 &`
    `$1 > /tmp/HVFS-$LOG_PATH/${log_name}-0`
    err=$?
    if [ $err -eq 0 ]; then
        echo -n "(1/2) done, "
    else
        echo -n "(1/2) failed $err, "
        let test_failed=1
    fi
    # get the jobid
    JOBLINE=`jobs | grep "$program_name"`
    JOBID=`echo $JOBLINE | awk -F "[" '{print $2}' | awk -F "]" '{print $1}'`
    JOBERR=`echo $JOBLINE | awk '{print $3}'`
    if [ x$jobid == "x" ]; then
        echo "(2/2) done."
    else
        wait %$jobid
        err=$?
        if [ $err -eq 127 ]; then
            echo "(2/2) done+."
        elif [ $err -eq 0 ]; then
            echo "(2/2) done-."
        else
            echo "(2/2) failed $err."
        fi
    fi
}

function generic_unit_test() {
    log_name=`echo $1 | sed -e 's/\//-/g'`
    program_name=`basename $1`
    echo -n "--> UNIT TEST s($program_name) Start ... "
    `$1 > /tmp/HVFS-$LOG_PATH/$log_name`
    err=$?
    if [ $err -eq 0 ]; then
        echo "done."
    else
        echo "failed $err."
        let test_failed=1
    fi
}

echo "Step 2: begin unit testing."
for i in `ls test`; do 
    if [ -d "test/$i" ]; then
        # ok, we will probe the low level directory
        for j in `ls test/$i`; do
            if [ -x "test/$i/$j" ]; then
                if [ "x$i" == "xmds" ] && [ "x$j" == "xcbht.ut" ]; then
                    cbht_unit_test "${PROJECT_HOME}/test/$i/$j"
                elif [ "x$i" == "xxnet" ]; then
                    xnet_unit_test "${PROJECT_HOME}/test/$i/$j"
                else
                    generic_unit_test "${PROJECT_HOME}/test/$i/$j"
                fi
            fi
        done
    fi
done

if [ $test_failed -eq 0 ]; then
    # test success, delete the tmp dir
    rm -rf "/tmp/HVFS-$LOG_PATH"
    echo "Summary: this build has passed the unit test."
else
    # test failed
    echo "Summary: this unit test failed, we have a regression in this build."
fi