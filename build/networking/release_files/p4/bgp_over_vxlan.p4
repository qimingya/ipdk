/* -*- P4_16 -*- */

#include <core.p4>
#include <psa.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
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

/****Qiming add***/
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
    tcp_h        tcp;
    udp_h        udp;
    ospf_h       ospf;
    bgp_h        bgp;
    ethernet_h   outer_ethernet;
    ipv4_h       outer_ipv4;
    udp_h        outer_udp;
    tcp_h        outer_tcp;
    ospf_h       outer_ospf;
    vxlan_h      outer_vxlan;
    bgp_h        outer_bgp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<16> next_step;
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
        transition parse_ipv4;
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

    state parse_tcp {
        pkt.extract(hdr.outer_tcp);
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
        transition parse_inner_ipv4;
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

     state parse_inner_tcp {
        pkt.extract(hdr.tcp);
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
        bit<16> ethernet_ether_type,
        bit<8> ipv4_ver_ihl,
        bit<8> ipv4_diffserv,
        bit<16> ipv4_total_len,
        bit<16> ipv4_identification,
        bit<16> ipv4_flags_offset,
        bit<8> ipv4_ttl,
        bit<8> ipv4_protocol,
        bit<16> ipv4_hdr_checksum,
        bit<32> ipv4_src_addr,
        bit<32> ipv4_dst_addr,
        bit<16> udp_src_port,
        bit<16> udp_dst_port,
        bit<16> udp_length,
        bit<16> udp_checksum,
        bit<8> vxlan_flags,
        bit<24> vxlan_reserved,
        bit<24> vxlan_vni,
        bit<8> vxlan_reserved2
    ) {
	/* config inner packet  */
	hdr.ethernet = hdr.outer_ethernet;
	hdr.ipv4 = hdr.outer_ipv4;

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
        hdr.outer_ethernet.ether_type = ethernet_ether_type;

	hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.ver_ihl = ipv4_ver_ihl; 
        hdr.outer_ipv4.diffserv = ipv4_diffserv; 
        hdr.outer_ipv4.total_len = ipv4_total_len; 
        hdr.outer_ipv4.identification = ipv4_identification; 
        hdr.outer_ipv4.flags_offset = ipv4_flags_offset; 
        hdr.outer_ipv4.ttl = ipv4_ttl; 
        hdr.outer_ipv4.protocol = ipv4_protocol; 
        hdr.outer_ipv4.hdr_checksum = ipv4_hdr_checksum; 
        hdr.outer_ipv4.src_ip = ipv4_src_addr; 
        hdr.outer_ipv4.dst_ip = ipv4_dst_addr;
        
	hdr.outer_udp.setValid();
	hdr.outer_udp.src_port = udp_src_port;
        hdr.outer_udp.dst_port = udp_dst_port;
        hdr.outer_udp.length = udp_length;
        hdr.outer_udp.checksum = udp_checksum;
        
	hdr.outer_vxlan.setValid();
	hdr.outer_vxlan.flags = vxlan_flags;
        hdr.outer_vxlan.reserved = vxlan_reserved;
        hdr.outer_vxlan.vni = vxlan_vni;
        hdr.outer_vxlan.reserved2 = vxlan_reserved2;
        csum.add({hdr.outer_ipv4.hdr_checksum, hdr.ipv4.total_len});
        hdr.outer_ipv4.hdr_checksum = csum.get();
        hdr.outer_ipv4.total_len = hdr.outer_ipv4.total_len + hdr.ipv4.total_len;
        hdr.outer_udp.length = hdr.outer_udp.length + hdr.ipv4.total_len;
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
        ostd.egress_port = (PortId_t)1;
    }
    
    table push_vxlan_table {
        key = { hdr.outer_ipv4.dst_ip : exact; }
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
        if(meta.next_step == 1) {
	    if(port_forward_table.apply().hit) {
        	push_vxlan_table.apply();
	    }
        } else if(meta.next_step == 2) {
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
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.outer_tcp);
        pkt.emit(hdr.outer_ospf);
        pkt.emit(hdr.outer_bgp);
        pkt.emit(hdr.outer_vxlan);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
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
