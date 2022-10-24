#!/bin/bash

export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/usr/lib/x86_64-linux/gnu:/lib/x86_64-linux/gnu:$LD_LIBRARY_PATH
mkdir -p /run/sshd
/usr/sbin/sshd

ps aux|grep ovs|awk '{print $2}'|xargs kill
sleep 1
cd /root/scripts
. p4ovs_env_setup.sh /root/p4-sde/install
cd /root
/root/scripts/set_hugepages.sh
/root/scripts/run_ovs.sh && sleep 1
