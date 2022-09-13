#!/bin/bash

mkdir -p /run/sshd
/usr/sbin/sshd

## compile P4
export OUTPUT_DIR=/root/examples/port_forward
cd  $OUTPUT_DIR
p4c --arch psa --target dpdk --output $OUTPUT_DIR/pipe --p4runtime-files $OUTPUT_DIR/p4Info.txt --bf-rt-schema  $OUTPUT_DIR/bf-rt.json  --context  $OUTPUT_DIR/pipe/context.json $OUTPUT_DIR/port_forward.p4
ovs_pipeline_builder --p4c_conf_file=port_forward.conf --bf_pipeline_config_binary_file=port_forward.pb.bin
unset OUTPUT_DIR

## start OVS
cd /root/scripts
. p4ovs_env_setup.sh /root/p4-sde/install
cd /root 
/root/scripts/set_hugepages.sh 
/root/scripts/run_ovs.sh && sleep 1

function sig_handler()
{
    exit 0
}

trap "sig_handler" SIGINT SIGTERM EXIT

while true
do
	sleep 3
done
