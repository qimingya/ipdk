/* -*- P4_16 -*- */

#include <core.p4>
#include <psa.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

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
    bit<32>      src_addr;
    bit<32>      dst_addr;
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
/***/


const int IPV4_HOST_SIZE = 65536;

typedef bit<48> ethernet_addr_t;

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    ethernet_h   outer_ethernet;
    ipv4_h       outer_ipv4;
    udp_h        outer_udp;
    vxlan_h      outer_vxlan;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    ethernet_addr_t  dst_addr;
    ethernet_addr_t  src_addr;
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
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

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
        bit<8> vxlan_reserved2,
        bit<32> port_out
    ) {
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
        hdr.outer_ipv4.src_addr = ipv4_src_addr; 
        hdr.outer_ipv4.dst_addr = ipv4_dst_addr;
        
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
        ostd.egress_port = (PortId_t)port_out;
        csum.add({hdr.outer_ipv4.hdr_checksum, hdr.ipv4.total_len});
        hdr.outer_ipv4.hdr_checksum = csum.get();
        hdr.outer_ipv4.total_len = hdr.outer_ipv4.total_len + hdr.ipv4.total_len;
        hdr.outer_udp.length = hdr.outer_udp.length + hdr.ipv4.total_len;
    }

    action drop() {
        ostd.egress_port = (PortId_t)1;
    }
    
    table vxlan {
        key = { hdr.ethernet.dst_addr : exact; }
        actions = {
            vxlan_encap;drop;
            @defaultonly NoAction;
        }

        const default_action = drop();

        size = IPV4_HOST_SIZE;
    }


    apply {
                vxlan.apply();
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
        pkt.emit(hdr.outer_vxlan);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
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
