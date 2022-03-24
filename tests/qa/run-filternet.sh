#!/bin/sh
echo "Running minivpn with filternet"

USER=`whoami`
REMOTE=172.17.0.2  # can grep it from the config file instead
TARGET=`ip -4 addr show docker0 | grep 'inet ' | awk '{print $2}' | cut -f 1 -d /`
FILTERNET=`which filternet`
DROP_RULE="-d ${REMOTE} -p udp --dport 1194 -j DROP"
echo "Using drop rule:" $DROP_RULE

sudo ${FILTERNET} \
    --firewall-rule "${DROP_RULE}" \
    --user $USER \
    --workdir ../.. \
    ./minivpn -c data/tests/config -t ${TARGET} -n 3 ping
