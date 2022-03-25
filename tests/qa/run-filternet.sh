#!/bin/sh
echo "Running minivpn with filternet"

USER=`whoami`

REMOTE_DOCKER=172.17.0.2  # can grep it from the config file instead
REMOTE=185.220.103.44
TARGET=`ip -4 addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -f 1 -d /`
FILTERNET=`which filternet`
TIMEOUT=5

#DROP_RULE="-d ${REMOTE} -p udp --dport 1194 -j DROP"
DROP_RULE="-p udp --dport 1194 -j DROP"

remote_block_all() {
    echo "Using drop rule:" $DROP_RULE
    sudo ${FILTERNET} \
        --firewall-rule "${DROP_RULE}" \
        --user $USER \
        --workdir ../.. TIMEOUT=${TIMEOUT} make test-ping
    # TODO it would be nice to store the exit code somewhere, and check for it
    if [ "$?" -ne "1" ]; then
        echo "[!] remote-block-all ==> test failed (expected exit code: 2)"
        exit 1
    else
        echo "[+] remote-block-all ==> test ok."
        exit 0
    fi
}

local_block_all() {
    echo "Using drop rule:" $DROP_RULE
    sudo ${FILTERNET} \
        --firewall-rule "${DROP_RULE}" \
        --user $USER \
        --workdir ../.. MINIVPN_HANDSHAKE_TIMEOUT=${TIMEOUT} make test-local
    echo "exit code:" $?
    [ "$?" -eq 1 ] && echo "Test OK" && exit 0
    exit 1
}

OPTION=$1
case $OPTION in
remote-block-all)
    remote_block_all
;;
local-block-all)
   local_block_all 
;;

*)
echo Unknown test scenario: $OPTION
exit 1

esac

#    --workdir ../.. make test-local
#    --workdir ../.. make qa
