#Copyright (C) 2022 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */

#include <core.p4>
#include <psa.p4>
//#include "psa-for-bmv2.p4"
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_OSPF = 89;
const bit<16> VXLAN_PORT = 4789;
const bit<16> BGP_PORT = 179;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<8>       ver_ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<16>      flags_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    bit<32>      src_ip;
    bit<32>      dst_ip;
}

header ipv6_h {
    bit<32> ver_tc_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<64> src_addr_high;
    bit<64> src_addr_low;
    bit<64> dst_addr_high;
    bit<64> dst_addr_low;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header bgp_h {
    bit<16> marker;
    bit<2>  length;
    bit<1>  type;
    bit<13> padding;
}

header ospf_h {
    bit<8>  version;
    bit<8>  type;
    bit<16> length;
    bit<32> router_id;
}

const int IPV4_HOST_SIZE =1024;

typedef bit<48> ethernet_addr_t;

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    ipv6_h       ipv6;
    tcp_h        tcp;
    udp_h        udp;
    ospf_h       ospf;
    bgp_h        bgp;
    ethernet_h   outer_ethernet;
    ipv4_h       outer_ipv4;
    ipv6_h       outer_ipv6;
    udp_h        outer_udp;
    tcp_h        outer_tcp;
    ospf_h       outer_ospf;
    vxlan_h      outer_vxlan;
    bgp_h        outer_bgp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<16> next_step;
    bit<16> bgp_ack;
    bit<16> inner_bgp_ack;
}

struct empty_metadata_t {
}

    /***********************  P A R S E R  **************************/
parser Ingress_Parser(
    packet_in pkt,
    out my_ingress_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in psa_ingress_parser_input_metadata_t ig_intr_md,
    in empty_metadata_t resub_meta, 
    in empty_metadata_t recirc_meta)
{
     state start {
        meta.next_step = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.outer_ethernet);
        transition select(hdr.outer_ethernet.ether_type){
	    ETHERTYPE_IPV4: parse_ipv4;
	    ETHERTYPE_IPV6: parse_ipv6;
	}
    }

    state parse_ipv4 {
        pkt.extract(hdr.outer_ipv4);
        transition select(hdr.outer_ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_OSPF: parse_ospf; 
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.outer_ipv6);
        transition select(hdr.outer_ipv6.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_OSPF: parse_ospf;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.outer_tcp);
        meta.bgp_ack = hdr.outer_tcp.src_port;
        transition select(hdr.outer_tcp.dst_port) {
            BGP_PORT: parse_bgp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.outer_udp);
        transition select(hdr.outer_udp.dst_port) {
            VXLAN_PORT: parse_vxlan;
            default: accept;
        }
    }

    state parse_ospf {
        meta.next_step = 1;
        pkt.extract(hdr.outer_ospf);
        transition accept;
    }

    state parse_bgp {
        meta.next_step = 1;
        pkt.extract(hdr.outer_bgp);
        transition accept;
    }

    state parse_vxlan {
        pkt.extract(hdr.outer_vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.ethernet);
	transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_inner_tcp;
            PROTO_UDP: parse_inner_udp;
            PROTO_OSPF: parse_inner_ospf;
            default: accept;
        }
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            PROTO_TCP: parse_inner_tcp;
            PROTO_UDP: parse_inner_udp;
            PROTO_OSPF: parse_inner_ospf;
            default: accept;
        }
    }

     state parse_inner_tcp {
        pkt.extract(hdr.tcp);
        meta.inner_bgp_ack = hdr.tcp.src_port;
        transition select(hdr.tcp.dst_port) {
            BGP_PORT: parse_inner_bgp;
            default: accept;
        }
    }

    state parse_inner_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_inner_ospf {
        meta.next_step = 2;
        pkt.extract(hdr.ospf);
        transition accept;
    }

    state parse_inner_bgp {
        meta.next_step = 2;
        pkt.extract(hdr.bgp);
        transition accept;
    }

/***** TODO: need to aviod loop as p4c can't support ******/
}

    /***************** M A T C H - A C T I O N  *********************/

control ingress(
    inout my_ingress_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in psa_ingress_input_metadata_t ig_intr_md,
    inout psa_ingress_output_metadata_t ostd
)
{
    InternetChecksum() csum;
    action vxlan_encap(
        bit<48> ethernet_dst_addr,
        bit<48> ethernet_src_addr,
        bit<32> ipv4_src_addr,
        bit<32> ipv4_dst_addr,
        bit<24> vxlan_vni
    ) {
	/* config inner packet  */
	hdr.ethernet = hdr.outer_ethernet;
	if(hdr.outer_ipv4.isValid()){
	    hdr.ipv4 = hdr.outer_ipv4;
	    hdr.outer_ipv4.setInvalid();
	}

	if(hdr.outer_ipv6.isValid()){
	    hdr.ipv6 = hdr.outer_ipv6;
	    hdr.outer_ipv6.setInvalid();
	}

	if(hdr.outer_ospf.isValid()) {
	    hdr.ospf = hdr.outer_ospf;
	    hdr.outer_ospf.setInvalid();
	}

	if(hdr.outer_tcp.isValid()) {
	    hdr.tcp = hdr.outer_tcp;
	    hdr.outer_tcp.setInvalid();
	}

	if(hdr.outer_bgp.isValid()) {
	    hdr.bgp = hdr.outer_bgp;
	    hdr.outer_bgp.setInvalid();
	}

        hdr.outer_ethernet.setValid();
	hdr.outer_ethernet.src_addr = ethernet_src_addr;
        hdr.outer_ethernet.dst_addr = ethernet_dst_addr;
        hdr.outer_ethernet.ether_type = 0x0800;

	hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.ver_ihl = 0x45; 
        hdr.outer_ipv4.diffserv = 0; 
        hdr.outer_ipv4.total_len = 50; 
        hdr.outer_ipv4.identification = 0x1513; 
        hdr.outer_ipv4.flags_offset = 0; 
        hdr.outer_ipv4.ttl = 64; 
        hdr.outer_ipv4.protocol = 17; 
        hdr.outer_ipv4.hdr_checksum = 0; 
        hdr.outer_ipv4.src_ip = ipv4_src_addr; 
        hdr.outer_ipv4.dst_ip = ipv4_dst_addr;
        
	hdr.outer_udp.setValid();
	hdr.outer_udp.src_port = 1522;
        hdr.outer_udp.dst_port = 4789;
        hdr.outer_udp.length = 30;
        hdr.outer_udp.checksum = 0;
        
	hdr.outer_vxlan.setValid();
	hdr.outer_vxlan.flags = 0x08;
        hdr.outer_vxlan.reserved = 0;
        hdr.outer_vxlan.vni = vxlan_vni;
        hdr.outer_vxlan.reserved2 = 0;

        hdr.outer_ipv4.total_len = hdr.outer_ipv4.total_len + hdr.ipv4.total_len;
	csum.clear();
	csum.add({hdr.outer_ipv4.ver_ihl,hdr.outer_ipv4.diffserv,hdr.outer_ipv4.total_len,
		hdr.outer_ipv4.identification, hdr.outer_ipv4.flags_offset, hdr.outer_ipv4.ttl,
		hdr.outer_ipv4.protocol, hdr.outer_ipv4.src_ip, hdr.outer_ipv4.dst_ip});
	hdr.outer_ipv4.hdr_checksum = csum.get();

        hdr.outer_udp.length = hdr.outer_udp.length + hdr.ipv4.total_len;
	hdr.outer_udp.checksum = 0;
    }

    action vxlan_decap (bit<32> port_out) {
        hdr.outer_ethernet.setInvalid();
        hdr.outer_ipv4.setInvalid();
        hdr.outer_tcp.setInvalid();
        hdr.outer_udp.setInvalid();
        hdr.outer_vxlan.setInvalid();
        ostd.egress_port = (PortId_t)port_out;
    }

    action send(bit<32> port_out) {
        ostd.egress_port = (PortId_t)port_out;
    }

    action drop() {
        ostd.egress_port = (PortId_t)0;
    }
    
    table push_vxlan_table {
        key = { ig_intr_md.ingress_port : exact; }
        actions = {
            vxlan_encap;
            @defaultonly NoAction;
        }

        const default_action = NoAction;
        size = IPV4_HOST_SIZE;
    }

    table pop_vxlan_table {
        key = { hdr.outer_vxlan.vni : exact; }
        actions = {
            vxlan_decap;
            drop;
        }

        const default_action = drop();
        size = IPV4_HOST_SIZE;
    }

    table port_forward_table {
        key = {ig_intr_md.ingress_port : exact; }
        actions = {
            send;
	    drop;
        }

        const default_action = drop();
        size = IPV4_HOST_SIZE;
    }

    apply {
        if(meta.next_step == 1 || meta.bgp_ack == 179) {
	    if(port_forward_table.apply().hit) {
        	push_vxlan_table.apply();
	    }
        } else if(meta.next_step == 2 || meta.inner_bgp_ack == 179) {
            pop_vxlan_table.apply();
	} else {
	    drop();
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control Ingress_Deparser(packet_out pkt,
    out empty_metadata_t clone_i2e_meta, 
    out empty_metadata_t resubmit_meta, 
    out empty_metadata_t normal_meta,
    inout my_ingress_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in psa_ingress_output_metadata_t istd)
{
    apply {
        pkt.emit(hdr.outer_ethernet);
        pkt.emit(hdr.outer_ipv4);
	pkt.emit(hdr.outer_ipv6);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.outer_tcp);
        pkt.emit(hdr.outer_ospf);
        pkt.emit(hdr.outer_bgp);
        pkt.emit(hdr.outer_vxlan);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
	pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.ospf);
        pkt.emit(hdr.bgp);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /***********************  P A R S E R  **************************/

parser Egress_Parser(
    packet_in pkt,
    out my_egress_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in psa_egress_parser_input_metadata_t istd, 
    in empty_metadata_t normal_meta, 
    in empty_metadata_t clone_i2e_meta, 
    in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control egress(
    inout my_egress_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in psa_egress_input_metadata_t istd, 
    inout psa_egress_output_metadata_t ostd)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control Egress_Deparser(packet_out pkt,
    out empty_metadata_t clone_e2e_meta, 
    out empty_metadata_t recirculate_meta,
    inout my_egress_headers_t hdr,
    in my_ingress_metadata_t meta,
    in psa_egress_output_metadata_t istd, 
    in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
        pkt.emit(hdr);
    }
}

#if __p4c__
bit<32> test_version = __p4c_version__;
#endif

/************ F I N A L   P A C K A G E ******************************/

IngressPipeline(Ingress_Parser(), ingress(), Ingress_Deparser()) pipe;

EgressPipeline(Egress_Parser(), egress(), Egress_Deparser()) ep;

PSA_Switch(pipe, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
