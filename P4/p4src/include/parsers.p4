/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        transition parse_ethernet;

    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_TUNNEL: parse_tunnel;
       	    default: accept;
       }
    }


    state parse_tunnel{
      packet.extract(hdr.tunnel);
      transition select(hdr.tunnel.proto_id){
      TYPE_IPV4: parse_ipv4;
      default: accept;}
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
 	transition select(hdr.ipv4.protocol){
	    TYPE_TCP: parse_tcp;
	    default: accept;
	}
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.rtt);
        packet.emit(hdr.tunnel);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}
