

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
	bit<32> src_ip
	bit<32> dst_ip
}

struct tcp_h {
	bit<16> src_port
	bit<16> dst_port
	bit<32> seq_no
	bit<32> ack_no
	bit<16> data_offset_res_ecn_ctrl
	bit<16> window
	bit<16> checksum
	bit<16> urgent_ptr
}

struct udp_h {
	bit<16> src_port
	bit<16> dst_port
	bit<16> length
	bit<16> checksum
}

struct ospf_h {
	bit<8> version
	bit<8> type
	bit<16> length
	bit<32> router_id
}

struct bgp_h {
	bit<16> marker
	bit<16> length_type_padding
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

struct send_arg_t {
	bit<32> port_out
}

struct vxlan_decap_arg_t {
	bit<32> port_out
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
}

header ethernet instanceof ethernet_h
header ipv4 instanceof ipv4_h
header tcp instanceof tcp_h
header udp instanceof udp_h
header ospf instanceof ospf_h
header bgp instanceof bgp_h
header outer_ethernet instanceof ethernet_h
header outer_ipv4 instanceof ipv4_h
header outer_udp instanceof udp_h
header outer_tcp instanceof tcp_h
header outer_ospf instanceof ospf_h
header outer_vxlan instanceof vxlan_h
header outer_bgp instanceof bgp_h
header cksum_state instanceof cksum_state_t

struct my_ingress_metadata_t {
	bit<32> psa_ingress_input_metadata_ingress_port
	bit<8> psa_ingress_output_metadata_drop
	bit<32> psa_ingress_output_metadata_egress_port
	bit<16> local_metadata_next_step
	bit<16> Ingress_tmp
	bit<16> Ingress_tmp_0
}
metadata instanceof my_ingress_metadata_t

action NoAction args none {
	return
}

action vxlan_encap args instanceof vxlan_encap_arg_t {
	jmpnv LABEL_FALSE_2 h.outer_ethernet
	validate h.ethernet
	jmp LABEL_END_2
	LABEL_FALSE_2 :	invalidate h.ethernet
	LABEL_END_2 :	mov h.ethernet.dst_addr h.outer_ethernet.dst_addr
	mov h.ethernet.src_addr h.outer_ethernet.src_addr
	mov h.ethernet.ether_type h.outer_ethernet.ether_type
	jmpnv LABEL_FALSE_3 h.outer_ipv4
	validate h.ipv4
	jmp LABEL_END_3
	LABEL_FALSE_3 :	invalidate h.ipv4
	LABEL_END_3 :	mov h.ipv4.ver_ihl h.outer_ipv4.ver_ihl
	mov h.ipv4.diffserv h.outer_ipv4.diffserv
	mov h.ipv4.total_len h.outer_ipv4.total_len
	mov h.ipv4.identification h.outer_ipv4.identification
	mov h.ipv4.flags_offset h.outer_ipv4.flags_offset
	mov h.ipv4.ttl h.outer_ipv4.ttl
	mov h.ipv4.protocol h.outer_ipv4.protocol
	mov h.ipv4.hdr_checksum h.outer_ipv4.hdr_checksum
	mov h.ipv4.src_ip h.outer_ipv4.src_ip
	mov h.ipv4.dst_ip h.outer_ipv4.dst_ip
	jmpnv LABEL_END_4 h.outer_ospf
	jmpnv LABEL_FALSE_5 h.outer_ospf
	validate h.ospf
	jmp LABEL_END_5
	LABEL_FALSE_5 :	invalidate h.ospf
	LABEL_END_5 :	mov h.ospf.version h.outer_ospf.version
	mov h.ospf.type h.outer_ospf.type
	mov h.ospf.length h.outer_ospf.length
	mov h.ospf.router_id h.outer_ospf.router_id
	invalidate h.outer_ospf
	LABEL_END_4 :	jmpnv LABEL_END_6 h.outer_tcp
	jmpnv LABEL_FALSE_7 h.outer_tcp
	validate h.tcp
	jmp LABEL_END_7
	LABEL_FALSE_7 :	invalidate h.tcp
	LABEL_END_7 :	mov h.tcp.src_port h.outer_tcp.src_port
	mov h.tcp.dst_port h.outer_tcp.dst_port
	mov h.tcp.seq_no h.outer_tcp.seq_no
	mov h.tcp.ack_no h.outer_tcp.ack_no
	mov h.tcp.data_offset_res_ecn_ctrl h.outer_tcp.data_offset_res_ecn_ctrl
	mov h.tcp.window h.outer_tcp.window
	mov h.tcp.checksum h.outer_tcp.checksum
	mov h.tcp.urgent_ptr h.outer_tcp.urgent_ptr
	invalidate h.outer_tcp
	LABEL_END_6 :	jmpnv LABEL_END_8 h.outer_bgp
	jmpnv LABEL_FALSE_9 h.outer_bgp
	validate h.bgp
	jmp LABEL_END_9
	LABEL_FALSE_9 :	invalidate h.bgp
	LABEL_END_9 :	mov h.bgp.marker h.outer_bgp.marker
	mov h.bgp.length_type_padding h.outer_bgp.length_type_padding
	invalidate h.outer_bgp
	LABEL_END_8 :	validate h.outer_ethernet
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
	mov h.outer_ipv4.src_ip t.ipv4_src_addr
	mov h.outer_ipv4.dst_ip t.ipv4_dst_addr
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
	ckadd h.cksum_state.state_0 h.outer_ipv4.hdr_checksum
	ckadd h.cksum_state.state_0 h.ipv4.total_len
	mov h.outer_ipv4.hdr_checksum h.cksum_state.state_0
	mov h.outer_ipv4.total_len t.ipv4_total_len
	add h.outer_ipv4.total_len h.ipv4.total_len
	mov h.outer_udp.length t.udp_length
	add h.outer_udp.length h.ipv4.total_len
	return
}

action vxlan_decap args instanceof vxlan_decap_arg_t {
	invalidate h.outer_ethernet
	invalidate h.outer_ipv4
	invalidate h.outer_tcp
	invalidate h.outer_udp
	invalidate h.outer_vxlan
	mov m.psa_ingress_output_metadata_egress_port t.port_out
	return
}

action send args instanceof send_arg_t {
	mov m.psa_ingress_output_metadata_egress_port t.port_out
	return
}

action drop_1 args none {
	mov m.psa_ingress_output_metadata_egress_port 0x1
	return
}

action drop_2 args none {
	mov m.psa_ingress_output_metadata_egress_port 0x1
	return
}

table push_vxlan_table {
	key {
		h.outer_ipv4.dst_ip exact
	}
	actions {
		vxlan_encap
		NoAction
	}
	default_action NoAction args none const
	size 0x400
}


table pop_vxlan_table {
	key {
		h.outer_vxlan.vni exact
	}
	actions {
		vxlan_decap
		drop_1
	}
	default_action drop_1 args none const
	size 0x400
}


table port_forward_table {
	key {
		m.psa_ingress_input_metadata_ingress_port exact
	}
	actions {
		send
		drop_2
	}
	default_action drop_2 args none const
	size 0x400
}


apply {
	rx m.psa_ingress_input_metadata_ingress_port
	mov m.psa_ingress_output_metadata_drop 0x0
	mov m.local_metadata_next_step 0x0
	extract h.outer_ethernet
	extract h.outer_ipv4
	jmpeq INGRESS_PARSER_PARSE_TCP h.outer_ipv4.protocol 0x6
	jmpeq INGRESS_PARSER_PARSE_UDP h.outer_ipv4.protocol 0x11
	jmpeq INGRESS_PARSER_PARSE_OSPF h.outer_ipv4.protocol 0x59
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_UDP :	extract h.outer_udp
	jmpeq INGRESS_PARSER_PARSE_VXLAN h.outer_udp.dst_port 0x12b5
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_VXLAN :	extract h.outer_vxlan
	extract h.ethernet
	extract h.ipv4
	jmpeq INGRESS_PARSER_PARSE_INNER_TCP h.ipv4.protocol 0x6
	jmpeq INGRESS_PARSER_PARSE_INNER_UDP h.ipv4.protocol 0x11
	jmpeq INGRESS_PARSER_PARSE_INNER_OSPF h.ipv4.protocol 0x59
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_INNER_UDP :	extract h.udp
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_INNER_TCP :	extract h.tcp
	jmpeq INGRESS_PARSER_PARSE_INNER_BGP h.tcp.dst_port 0xb3
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_INNER_BGP :	mov m.local_metadata_next_step 0x2
	extract h.bgp
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_INNER_OSPF :	mov m.local_metadata_next_step 0x2
	extract h.ospf
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_TCP :	extract h.outer_tcp
	jmpeq INGRESS_PARSER_PARSE_BGP h.outer_tcp.dst_port 0xb3
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_BGP :	mov m.local_metadata_next_step 0x1
	extract h.outer_bgp
	jmp INGRESS_PARSER_ACCEPT
	INGRESS_PARSER_PARSE_OSPF :	mov m.local_metadata_next_step 0x1
	extract h.outer_ospf
	INGRESS_PARSER_ACCEPT :	jmpneq LABEL_FALSE m.local_metadata_next_step 0x1
	table port_forward_table
	jmpnh LABEL_END
	table push_vxlan_table
	jmp LABEL_END
	jmp LABEL_END
	LABEL_FALSE :	jmpneq LABEL_FALSE_1 m.local_metadata_next_step 0x2
	table pop_vxlan_table
	jmp LABEL_END
	LABEL_FALSE_1 :	mov m.psa_ingress_output_metadata_egress_port 0x1
	LABEL_END :	jmpneq LABEL_DROP m.psa_ingress_output_metadata_drop 0x0
	emit h.outer_ethernet
	emit h.outer_ipv4
	emit h.outer_udp
	emit h.outer_tcp
	emit h.outer_ospf
	emit h.outer_bgp
	emit h.outer_vxlan
	emit h.ethernet
	emit h.ipv4
	emit h.udp
	emit h.tcp
	emit h.ospf
	emit h.bgp
	tx m.psa_ingress_output_metadata_egress_port
	LABEL_DROP :	drop
}


