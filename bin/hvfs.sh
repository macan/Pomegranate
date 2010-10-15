#!/bin/bash

if [ "x$HVFS_HOME" == "x" ]; then
    HVFS_HOME=`pwd`
    TAIL=`basename $HVFS_HOME`
    if [ "x$TAIL" == 'xbin' ]; then
        HVFS_HOME=`dirname $HVFS_HOME`
    fi
fi

if [ "x$LOG_DIR" == "x" ]; then
    LOG_DIR="~"
fi

function do_conf_check() {
    if [ -d $HVFS_HOME/conf ]; then
        if [ -e $HVFS_HOME/conf/hvfs.conf ]; then
        # It is ok to continue
            return
        else
            echo "Missing config files."
            echo "Please check your home path, and make sure the config file"
            echo "'hvfs.conf' is in HVFS_HOME/conf/."
            exit
        fi
    else
        echo "Corrupt home path: $HVFS_HOME."
        echo "Please check your home path, and make sure the config file"
        echo "'hvfs.conf' is in HVFS_HOME/conf/."
        exit
    fi
}

# check if the config file exists.
do_conf_check

function do_ut_conf_check() {
    if [ -e $HVFS_HOME/conf/ut.conf ]; then
        return
    else
        echo "Missing config file: ut.config."
        echo "Please check your home path, and make sure the config file"
        echo "'ut.conf' is in HVFS_HOME/conf/."
        exit
    fi
}

# Read the config file and start the servers 

ROOT_CMD="create=1 mode=1 hvfs_root_hb_interval=10"
MDSL_CMD="mode=1 hvfs_mdsl_prof_plot=1 hvfs_mdsl_opt_write_drop=0"
if [ "x$MODE" == "xfs" ]; then
    MDS_CMD="fsid=0 mode=1 hvfs_mds_opt_memlimit=0 hvfs_mds_memlimit=1072896010 hvfs_mds_txg_interval=5 hvfs_mds_opt_memonly=0 type=0 cache=0"
else
    MDS_CMD="fsid=1 mode=1 hvfs_mds_opt_memlimit=0 hvfs_mds_memlimit=1072896010 hvfs_mds_txg_interval=5 hvfs_mds_opt_memonly=0 type=0 cache=0"
fi
CLIENT_CMD=""

ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4}'`
R2IP=`echo $ipnr | awk -F: '{print $1}'`

function start_mdsl() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do 
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$MDSL_CMD $HVFS_HOME/test/xnet/mdsl.ut $id $R2IP $port > $LOG_DIR/mdsl.$id.log" &
        done
        echo "Start MDSL server done."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:.*:$1\$" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do 
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$MDSL_CMD $HVFS_HOME/test/xnet/mdsl.ut $id $R2IP $port > $LOG_DIR/mdsl.$id.log" &
            echo "Start MDSL server $id done."
        done
    fi
}

function start_mds() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$MDS_CMD $HVFS_HOME/test/xnet/mds.ut $id $R2IP $port > $LOG_DIR/mds.$id.log" &
        done
        echo "Start MDS server done."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:.*:$1\$" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$MDS_CMD $HVFS_HOME/test/xnet/mds.ut $id $R2IP $port > $LOG_DIR/mds.$id.log" &
            echo "Start MDS server $id done."
        done
    fi
}

function start_root() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$ROOT_CMD $HVFS_HOME/test/xnet/root.ut $id $HVFS_HOME/conf/hvfs.conf $port > $LOG_DIR/root.$id.log" &
        done
        echo "Start R2 server done. Waiting for 5 seconds to clean up latest instance..."
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "r2:.*:$1\$" | awk -F: '{print $2":"$4":"$3}'`
        for x in $ipnr; do
            ip=`echo $x | awk -F: '{print $1}'`
            id=`echo $x | awk -F: '{print $2}'`
            port=`echo $x | awk -F: '{print $3}'`
            ssh -x $ip "$ROOT_CMD $HVFS_HOME/test/xnet/root.ut $id $HVFS_HOME/conf/hvfs.conf $port > $LOG_DIR/root.$id.log" &
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
        R=`ssh -x $ip "cat $LOG_DIR/mdsl.$id.log | grep UP"`
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
        R=`ssh -x $ip "cat $LOG_DIR/mds.$id.log | grep UP"`
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
        R=`ssh -x $ip "cat $LOG_DIR/root.$id.log | grep UP"`
        if [ "x$R" == "x" ]; then
            echo "R2 $id is not alive, please check it!"
        fi
    done
}

function check_all() {
    echo "'check' is not reliable, please use 'stat' instead."
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
        ssh -x $ip "kill -s SIGHUP $PID 2&>1 > /dev/null"
    done
}

function kill_mdsl() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:" | awk -F: '{print $2":"$4}'`
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mdsl:.*:$1\$" | awk -F: '{print $2":"$4}'`
    fi

    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        PID=`ssh -x $ip "ps aux | grep \"mdsl.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -9 $PID 2&>1 > /dev/null"
    done
    sleep 5
}

function kill_mds() {
    if [ "x$1" == "x" ]; then
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`
    else
        ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:.*:$1\$" | awk -F: '{print $2":"$4}'`
    fi

    for x in $ipnr; do
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        PID=`ssh -x $ip "ps aux | grep \"mds.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -9 $PID 2&>1 > /dev/null"
    done
    sleep 2
}

function kill_root() {
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
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "mds:" | awk -F: '{print $2":"$4}'`

    for x in $ipnr; do
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        ssh -x $ip "rm -rf /tmp/hvfs/6*"
        ssh -x $ip "rm -rf /tmp/hvfs/*_store"
        ssh -x $ip "rm -rf /tmp/hvfs/txg"
    done
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

function stat_client() {
    echo "----------CLIENT----------"
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "client:" | awk -F: '{print $2":"$4}'`
    for x in $ipnr; do 
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        NR=`ssh -x $ip "ps aux | grep \"client.ut $id\" | grep -v bash | grep -v ssh | grep -v grep | wc -l"`
        if [ $NR -eq 1 ]; then
            echo "CLT  $id is running."
        else
            echo "CLT  $id is gone."
        fi
    done
}

function do_status() {
    echo "Checking servers' status ..."
    stat_mdsl
    stat_mds
    stat_root
}

function do_ut() {
    echo "There are many unit test parameters, please see the config file in 'conf/ut.conf'."
    ARGS=`cat $HVFS_HOME/conf/ut.conf | grep -v "^ *#" | grep -v "^$"`
    NR=`cat $HVFS_HOME/conf/ut.conf | grep -v "^ *#" | grep -v "^$" | grep 'nr=' | sed -e 's/nr=//g'`
    TOTAL=`cat $HVFS_HOME/conf/hvfs.conf | grep "client:" | wc -l`
    if [ "x$NR" == 'x-1' ]; then
        NR=$TOTAL
    elif [ "x$NR" == "x" ]; then
        NR=0
    fi
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "client:" | awk -F: '{print $2":"$4":"$3}'`
    # prepare the client cmd environment variables
    CLIENT_CMD=`echo $ARGS | sed -e "s/nr=[-0-9]*//g"`

    # start clients now
    I=0
    for x in $ipnr; do
        if [ $I -ge $NR ]; then
            break
        fi
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        port=`echo $x | awk -F: '{print $3}'`
        ssh -x $ip "$CLIENT_CMD $HVFS_HOME/test/xnet/client.ut $id $R2IP $port > $LOG_DIR/client.$id.log" &
        let I+=1
    done
    echo "Start $NR UT client(s) done."
}

function do_kut() {
    ARGS=`cat $HVFS_HOME/conf/ut.conf | grep -v "^ *#" | grep -v "^$"`
    NR=`cat $HVFS_HOME/conf/ut.conf | grep -v "^ *#" | grep -v "^$" | grep 'nr=' | sed -e 's/nr=//g'`
    TOTAL=`cat $HVFS_HOME/conf/hvfs.conf | grep "client:" | wc -l`
    if [ "x$NR" == 'x-1' ]; then
        NR=$TOTAL
    elif [ "x$NR" == "x" ]; then
        NR=0
    fi
    ipnr=`cat $HVFS_HOME/conf/hvfs.conf | grep "client:" | awk -F: '{print $2":"$4":"$3}'`
    # kill active clients now
    I=0
    for x in $ipnr; do
        if [ $I -ge $NR ]; then
            break
        fi
        ip=`echo $x | awk -F: '{print $1}'`
        id=`echo $x | awk -F: '{print $2}'`
        port=`echo $x | awk -F: '{print $3}'`
        PID=`ssh -x $ip "ps aux | grep \"client.ut $id\" | grep -v bash | grep -v ssh | grep -v grep"`
        ssh -x $ip "kill -9 $PID 2&>1 > /dev/null"
        let I+=1
    done
}

function do_help() {
    echo "Version 1.0.0b"
    echo "Copyright (c) 2010 Can Ma <ml.macana@gmail.com>"
    echo ""
    echo "Usage: hvfs.sh [start|stop|kill|check] [mds|mdsl|r2|all] [id]"
    echo "               [clean|stat]"
    echo "               [ut|kut|sut]"
    echo ""
    echo "Commands:"
    echo "      start [t] [id]  start servers"
    echo "      stop [t] [id]   stop servers"
    echo "      kill [t] [id]   kill servers"
    echo "      check [t] [id]  check servers' status"
    echo "      clean           clean the STOREGE home"
    echo "      stat            get and print servers' status"
    echo ""
    echo "Environments:"
    echo "      HVFS_HOME       default to the current path."
    echo "                      Note that, if you boot servers on other nodes, "
    echo "                      you have to ensure that all the binaries are "
    echo "                      in the right pathname (same as this node)."
    echo "      MODE            fs: file system mode."
    echo "                      kv: key value mode."
    echo "      LOG_DIR         default to ~"
    echo ""
    echo "Examples:"
    echo "1. start all the servers in config file."
    echo "   $ hvfs.sh start"
    echo "2. start MDS 1"
    echo "   $ hvfs.sh start mds 1"
    echo "3. stop MDS 1"
    echo "   $ hvfs.sh stop mds 1"
    echo "4. stop all the servers"
    echo "   $ hvfs.sh stop"
    echo "5. get the current status"
    echo "   $ hvfs.sh stat"
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
elif [ "x$1" == "xut" ]; then
    do_ut_conf_check
    do_ut
elif [ "x$1" == "xkut" ]; then
    do_ut_conf_check
    do_kut
elif [ "x$1" == "xsut" ]; then
    do_ut_conf_check
    stat_client
elif [ "x$1" == "xstat" ]; then
    do_status
elif [ "x$1" == "xclean" ]; then
    do_clean
elif [ "x$1" == "xhelp" ]; then
    do_help
else
    do_help
fi