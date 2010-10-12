#!/bin/bash

if [ "x$HVFS_HOME" == "x" ]; then
    HVFS_HOME=`pwd`
    HVFS_HOME=`dirname $HVFS_HOME`
fi

# Read the config file and start the servers 

ROOT_CMD="create=1 mode=1 hvfs_root_hb_interval=10"
MDSL_CMD="mode=1 hvfs_mdsl_prof_plot=1 hvfs_mdsl_opt_write_drop=0"
MDS_CMD="fsid=1 mode=1 hvfs_mds_opt_memlimit=0 hvfs_mds_memlimit=1072896010 hvfs_mds_txg_interval=5 hvfs_mds_opt_memonly=0 type=0 cache=0"

function start_mdsl() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do 
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$MDSL_CMD $HVFS_HOME/test/xnet/mdsl.ut $id > mdsl.$id.log" &
        done
        echo "Start MDSL server done."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:.*:$1\$" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do 
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$MDSL_CMD $HVFS_HOME/test/xnet/mdsl.ut $id > mdsl.$id.log" &
            echo "Start MDSL server $id done."
        done
    fi
}

function start_mds() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$MDS_CMD $HVFS_HOME/test/xnet/mds.ut $id > mds.$id.log" &
        done
        echo "Start MDS server done."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:.*:$1\$" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$MDS_CMD $HVFS_HOME/test/xnet/mds.ut $id > mds.$id.log" &
            echo "Start MDS server $id done."
        done
    fi
}

function start_root() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$ROOT_CMD $HVFS_HOME/test/xnet/root.ut $id $HVFS_HOME/conf/hvfs.conf 2&>1 > root.$id.log" &
        done
        echo "Start R2 server done. Waiting for 5 seconds to clean up latest instance..."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:.*:$1\$" | awk -F: '{print $2":"$4}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            ssh -x $ip "$ROOT_CMD $HVFS_HOME/test/xnet/root.ut $id $HVFS_HOME/conf/hvfs.conf 2&>1 > root.$id.log" &
            echo "Start R2 server %id done. Waiting for 5 seconds to clean up latest instance..."
        done
    fi
    sleep 5
}

function check_mdsl() {
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        R=`ssh -x $ip "cat mdsl.$id.log | grep UP"`
        if [ "x$R" == "x" ]; then
            echo "MDSL $id is not alive, please check it!"
        fi
    done
}

function check_mds() {
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        R=`ssh -x $ip "cat mds.$id.log | grep UP"`
        if [ "x$R" == "x" ]; then
            echo "MDS $id is not alive, please check it!"
        fi
    done
}

function check_root() {
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        R=`ssh -x $ip "cat root.$id.log | grep UP"`
        if [ "x$R" == "x" ]; then
            echo "R2 $id is not alive, please check it!"
        fi
    done
}

function check_all() {
    check_root
    check_mds
    check_mdsl
}

function stop_mdsl() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4}'`
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:.*:$1\$" | awk -F: '{print $2":"$4}'`
    fi

    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        PID=`ssh -x $ip "ps aux | grep \"mdsl.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -s SIGHUP $PID 2&>1 > /dev/null"
    done
    sleep 5
}

function stop_mds() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:.*:$1\$" | awk -F: '{print $2":"$4}'`
    fi

    for x in $ipnr; do
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        PID=`ssh -x $ip "ps aux | grep \"mds.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -s SIGHUP $PID 2&>1 > /dev/null"
    done
    sleep 2
}

function stop_root() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4}'`
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:.*:$1\$" | awk -F: '{print $2":"$4}'`
    fi
    sleep 2
    for x in $ipnr; do
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        PID=`ssh -x $ip "ps aux | grep \"root.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -9 $PID 2&>1 > /dev/null"
    done
}

function kill_mdsl() {
    killall -9 mdsl.ut
    sleep 5
}

function kill_mds() {
    killall -9 mds.ut
    sleep 2
}

function kill_root() {
    sleep 2
    killall -9 root.ut 2&>1 /dev/null
}

function start_all() {
    start_root
    start_mdsl
    start_mds
}

function stop_all() {
    stop_mds
    stop_mdsl
    stop_root
}

function kill_all() {
    kill_mdsl
    kill_mds
    kill_root
}

function do_clean() {
    rm -rf /tmp/hvfs/6*
    rm -rf /tmp/hvfs/*_store
    rm -rf /tmp/hvfs/txg
}

function stat_mdsl() {
    echo "----------MDSL----------"
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        NR=`ssh -x $ip "ps aux | grep \"mdsl.ut $id\" | grep -v bash | grep -v ssh | grep -v grep | wc -l"`
        if [ $NR -eq 1 ]; then
            echo "MDSL $id is running."
        else
            echo "MDSL $id is gone."
        fi
    done
}

function stat_mds() {
    echo "----------MDS----------"
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        NR=`ssh -x $ip "ps aux | grep \"mds.ut $id\" | grep -v bash | grep -v ssh | grep -v grep | wc -l"`
        if [ $NR -eq 1 ]; then
            echo "MDS  $id is running."
        else
            echo "MDS  $id is gone."
        fi
    done
}

function stat_root() {
    echo "----------R2----------"
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        NR=`ssh -x $ip "ps aux | grep \"root.ut $id\" | grep -v bash | grep -v ssh | grep -v grep | wc -l"`
        if [ $NR -eq 1 ]; then
            echo "R2   $id is running."
        else
            echo "R2   $id is gone."
        fi
    done
}

function do_status() {
    echo "Checking servers' status ..."
    stat_mdsl
    stat_mds
    stat_root
}

if [ "x$1" == "xstart" ]; then
    if [ "x$2" == "xmds" ]; then
        start_mds $3
    elif [ "x$2" == "xmdsl" ]; then
        start_mdsl $3
    elif [ "x$2" == "xr2" ]; then
        start_root $3
    else
        start_all
    fi
elif [ "x$1" == "xstop" ]; then
    if [ "x$2" == "xmds" ]; then
        stop_mds $3
    elif [ "x$2" == "xmdsl" ]; then
        stop_mdsl $3
    elif [ "x$2" == "xr2" ]; then
        stop_root $3
    else
        stop_all
    fi
elif [ "x$1" == "xkill" ]; then
    if [ "x$2" == "xmds" ]; then
        kill_mds
    elif [ "x$2" == "xmdsl" ]; then
        kill_mdsl
    elif [ "x$2" == "xr2" ]; then
        kill_root
    else
        kill_all
    fi
elif [ "x$1" == "xcheck" ]; then
    if [ "x$2" == "xmds" ]; then
        check_mds
    elif [ "x$2" == "xmdsl" ]; then
        check_mdsl
    elif [ "x$2" == "xr2" ]; then
        check_root
    else
        check_all
    fi
elif [ "x$1" == "xstat" ]; then
    do_status
elif [ "x$1" == "xclean" ]; then
    do_clean
else
    echo "Version 1.0.0b"
    echo "Author: Can Ma <ml.macana@gmail.com>"
    echo ""
    echo "Usage: hvfs.sh [start | stop | kill | check mds | mdsl | r2 | all]"
    echo "               [clean]"
fi