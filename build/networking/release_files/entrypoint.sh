#!/bin/bash

mkdir -p /run/sshd
/usr/sbin/sshd

## start OVS
cd /root/scripts
. p4ovs_env_setup.sh /root/p4-sde/install
cd /root 
/root/scripts/set_hugepages.sh 
/root/scripts/run_ovs.sh

function sig_handler()
{
    exit 0
}

trap "sig_handler" SIGINT SIGTERM EXIT

while true
do
	sleep 3
done
