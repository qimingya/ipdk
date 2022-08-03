#!/bin/bash

export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
cd /root/scrpits && . p4ovs_env_setup.sh /root/p4-sde/install
cd /root && /root/scripts/set_hugepages.sh && /root/scripts/run_ovs.sh && sleep 1

gnmi-cli set "device:virtual-device,name:TAP0,mtu:1500,port-type:TAP" && sleep 1
gnmi-cli set "device:virtual-device,name:TAP1,mtu:1500,port-type:TAP" && sleep 1
ovs-p4ctl set-pipe br0 /root/examples/vxlan/vxlan.pb.bin /root/examples/vxlan/p4Info.txt && sleep 1
ovs-p4ctl add-entry br0 ingress.vxlan "hdr.ethernet.dst_addr=aa:bb:cc:dd:00:00,action=ingress.vxlan_encap(0xa0a1a2a30000, 0xb0b1b2b30000, 0x0800, 0x45, 0, 50, 0, 0, 64, 17, 0xe928, 0xc0c10000, 0xd0d10000, 0xe000, 4789, 30, 0, 0, 0, 0, 0, 1)" && sleep 1
ip a a 2.2.2.2/24 dev TAP1
ip link set up dev TAP1
ip a a 1.1.1.1/24 dev TAP0
ip link set up dev TAP0
