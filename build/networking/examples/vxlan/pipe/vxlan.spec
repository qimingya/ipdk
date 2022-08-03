

struct ethernet_h {
	bit<48> dst_addr
	bit<48> src_addr
	bit<16> ether_type
}

struct ipv4_h {
	bit<8> ver_ihl
	bit<8> diffserv
	bit<16> total_len
	bit<16> identification
	bit<16> flags_offset
	bit<8> ttl
	bit<8> protocol
	bit<16> hdr_checksum
	bit<32> src_addr
	bit<32> dst_addr
}

struct udp_h {
	bit<16> src_port
	bit<16> dst_port
	bit<16> length
	bit<16> checksum
}

struct vxlan_h {
	bit<8> flags
	bit<24> reserved
	bit<24> vni
	bit<8> reserved2
}

struct cksum_state_t {
	bit<16> state_0
}

struct psa_ingress_output_metadata_t {
	bit<8> class_of_service
	bit<8> clone
	bit<16> clone_session_id
	bit<8> drop
	bit<8> resubmit
	bit<32> multicast_group
	bit<32> egress_port
}

struct psa_egress_output_metadata_t {
	bit<8> clone
	bit<16> clone_session_id
	bit<8> drop
}

struct psa_egress_deparser_input_metadata_t {
	bit<32> egress_port
}

struct vxlan_encap_arg_t {
	bit<48> ethernet_dst_addr
	bit<48> ethernet_src_addr
	bit<16> ethernet_ether_type
	bit<8> ipv4_ver_ihl
	bit<8> ipv4_diffserv
	bit<16> ipv4_total_len
	bit<16> ipv4_identification
	bit<16> ipv4_flags_offset
	bit<8> ipv4_ttl
	bit<8> ipv4_protocol
	bit<16> ipv4_hdr_checksum
	bit<32> ipv4_src_addr
	bit<32> ipv4_dst_addr
	bit<16> udp_src_port
	bit<16> udp_dst_port
	bit<16> udp_length
	bit<16> udp_checksum
	bit<8> vxlan_flags
	bit<24> vxlan_reserved
	bit<24> vxlan_vni
	bit<8> vxlan_reserved2
	bit<32> port_out
}

header ethernet instanceof ethernet_h
header ipv4 instanceof ipv4_h
header outer_ethernet instanceof ethernet_h
header outer_ipv4 instanceof ipv4_h
header outer_udp instanceof udp_h
header outer_vxlan instanceof vxlan_h
header cksum_state instanceof cksum_state_t

struct my_ingress_metadata_t {
	bit<32> psa_ingress_input_metadata_ingress_port
	bit<8> psa_ingress_output_metadata_drop
	bit<32> psa_ingress_output_metadata_egress_port
	bit<16> Ingress_tmp
	bit<16> Ingress_tmp_0
}
metadata instanceof my_ingress_metadata_t

action NoAction args none {
	return
}

action vxlan_encap args instanceof vxlan_encap_arg_t {
	validate h.outer_ethernet
	mov h.outer_ethernet.src_addr t.ethernet_src_addr
	mov h.outer_ethernet.dst_addr t.ethernet_dst_addr
	mov h.outer_ethernet.ether_type t.ethernet_ether_type
	validate h.outer_ipv4
	mov h.outer_ipv4.ver_ihl t.ipv4_ver_ihl
	mov h.outer_ipv4.diffserv t.ipv4_diffserv
	mov h.outer_ipv4.total_len t.ipv4_total_len
	mov h.outer_ipv4.identification t.ipv4_identification
	mov h.outer_ipv4.flags_offset t.ipv4_flags_offset
	mov h.outer_ipv4.ttl t.ipv4_ttl
	mov h.outer_ipv4.protocol t.ipv4_protocol
	mov h.outer_ipv4.hdr_checksum t.ipv4_hdr_checksum
	mov h.outer_ipv4.src_addr t.ipv4_src_addr
	mov h.outer_ipv4.dst_addr t.ipv4_dst_addr
	validate h.outer_udp
	mov h.outer_udp.src_port t.udp_src_port
	mov h.outer_udp.dst_port t.udp_dst_port
	mov h.outer_udp.length t.udp_length
	mov h.outer_udp.checksum t.udp_checksum
	validate h.outer_vxlan
	mov h.outer_vxlan.flags t.vxlan_flags
	mov h.outer_vxlan.reserved t.vxlan_reserved
	mov h.outer_vxlan.vni t.vxlan_vni
	mov h.outer_vxlan.reserved2 t.vxlan_reserved2
	mov m.psa_ingress_output_metadata_egress_port t.port_out
	mov m.Ingress_tmp h.outer_ipv4.hdr_checksum
	mov m.Ingress_tmp_0 h.ipv4.total_len
	ckadd h.cksum_state.state_0 h.outer_ipv4.hdr_checksum
	ckadd h.cksum_state.state_0 h.ipv4.total_len
	mov h.outer_ipv4.hdr_checksum h.cksum_state.state_0
	mov h.outer_ipv4.total_len t.ipv4_total_len
	add h.outer_ipv4.total_len h.ipv4.total_len
	mov h.outer_udp.length t.udp_length
	add h.outer_udp.length h.ipv4.total_len
	return
}

action drop_1 args none {
	mov m.psa_ingress_output_metadata_egress_port 0x1
	return
}

table vxlan {
	key {
		h.ethernet.dst_addr exact
	}
	actions {
		vxlan_encap
		drop_1
		NoAction
	}
	default_action drop_1 args none const
	size 0x10000
}


apply {
	rx m.psa_ingress_input_metadata_ingress_port
	mov m.psa_ingress_output_metadata_drop 0x0
	extract h.ethernet
	extract h.ipv4
	table vxlan
	jmpneq LABEL_DROP m.psa_ingress_output_metadata_drop 0x0
	emit h.outer_ethernet
	emit h.outer_ipv4
	emit h.outer_udp
	emit h.outer_vxlan
	emit h.ethernet
	emit h.ipv4
	tx m.psa_ingress_output_metadata_egress_port
	LABEL_DROP :	drop
}


