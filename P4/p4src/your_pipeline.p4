/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define REGISTER_SIZE 1000
#define TIMESTAMP_WIDTH 48
#define HISTOGRAM_SIZE 32


const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<16> RTT_ETHER_TYPE = 0x5678;

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //Bloom filter for existing flows, register size is 4096
    register<bit>(4096) enable_measurements;

    //Register that stores the timestamp of previous tcp packet 
    // Number of bits per value is TIMESTAMP_WIDTH, register size is 4096

    register<bit<TIMESTAMP_WIDTH>>(4096) previous_timestamp;
    // Register containing amount of how many ports belong to a specific ecmp group
    register<bit<9>>(256) ecmp_ports;

    action drop() {

        mark_to_drop(standard_metadata);
    }

    // Define the smac table and the mac_learn action

    action mac_learn(){
        meta.ingress_port = (bit<16>) standard_metadata.ingress_port;
        meta.learn_tunnel = meta.tunnel_id;
	clone3(CloneType.I2E, 100, meta);
    }

    table smac{
	actions = {
		mac_learn;
		NoAction;
	}
	key = {
		hdr.ethernet.srcAddr: exact;
		meta.customer_id: exact;
	}
	size = 1024;
	default_action = mac_learn;
    }



    action ecmp_group(bit<16> out_tunnel){
	
        ecmp_ports.read(meta.ecmp_nr_ports, (bit<32>)out_tunnel);
	
	meta.tunnel_id = out_tunnel;	

        hash(meta.ecmp_hash,
	    HashAlgorithm.crc16,
	    (bit<1>)0,
	    { hdr.ipv4.srcAddr,
	      hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              meta.customer_id},
	      meta.ecmp_nr_ports);
    }

    action forward(bit<9> out_port, bit<16> out_tunnel){
	standard_metadata.egress_spec = out_port;
    	meta.tunnel_id = out_tunnel;
    }
    action forward_ecmp(bit<9> out_port){
	standard_metadata.egress_spec = out_port;
    }
    

    table dmac{
	actions = {
		forward;
                ecmp_group;
		NoAction;
	}
	key = {
		hdr.ethernet.dstAddr: exact;
		meta.customer_id: exact;
		hdr.ipv4.protocol: ternary;
	}
	size = 1024;
	default_action = NoAction;
    }

    table ecmp_group_to_forward {
        key = {
            meta.tunnel_id: exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            forward_ecmp;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

 // Enable or disable inter-arrival time measurements is enabled
    action set_enable_interarrival_time(bit<1> value){
        enable_measurements.write((bit<32>)meta.index, value);
	    previous_timestamp.write((bit<32>)meta.index, standard_metadata.ingress_global_timestamp);
    }

    table synfin{
        actions = {
            set_enable_interarrival_time;
            NoAction;
        }
        key = {
		standard_metadata.ingress_port: exact;
	   	hdr.tcp.syn: exact;
		hdr.tcp.fin: exact;
        }
        size = 1024;
        default_action = NoAction;
    }


    // Define action for setting multicast group for packets from tunnels
    action set_mcast_grp(){
        standard_metadata.mcast_grp = meta.customer_id;
    }
    // Define action for setting multicast group for packets from directly connected hosts
    action set_mcast_grp_2(){
	standard_metadata.mcast_grp = (bit<16>) standard_metadata.ingress_port;
    }

    // Define the broadcast table
    table broadcast{
        actions = {
            set_mcast_grp;
	    set_mcast_grp_2;
        }
        key = {
	    standard_metadata.ingress_port: exact;
        }
	    size = 1024;
	    default_action = set_mcast_grp;
    }
    
    // Load a customer id into metadata
    
    // Ingress port registered in table
    action set_customer(bit<16> customer_id){
        meta.customer_id = customer_id;
    }

    // Ingress port not registered in table
    action set_from_tunnel(){
        meta.customer_id = hdr.tunnel.pw_id;
        meta.tunnel_id = hdr.tunnel.tunnel_id;
    }

    table customer_id {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_customer;
            set_from_tunnel;
        }
        size = 1024;
        default_action = set_from_tunnel;
    }

    //tunnels

    // Exit tunnel if egress point in this switch
    action tunnel_egress() {
        hdr.ethernet.etherType = hdr.tunnel.proto_id;
        hdr.tunnel.setInvalid();
    }

    // Label-switch the packet
    action tunnel_forward(bit<9> out_port){
         meta.customer_id = (bit<16>) 1;
         standard_metadata.egress_spec = out_port;
    }

    table VPLS_table{
        key = {
            hdr.tunnel.tunnel_id: exact;
        }
        actions = {
            tunnel_forward;
            tunnel_egress;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        //Perform inter-arrival time measurements only when tcp is used and on packets from directly connected hosts
        if(hdr.ipv4.protocol == TYPE_TCP && !hdr.tunnel.isValid()){
       	    //compute Hash for index in bloom filter, and reverse bloom filter
            hash(meta.index,HashAlgorithm.crc16,(bit<16>)0,
            {
              	hdr.ipv4.srcAddr,hdr.ipv4.dstAddr,hdr.tcp.srcPort,hdr.tcp.dstPort,meta.customer_id
            },
            (bit<12>)4095);
	    // get the "enable_measurements" from the correspondent register
            bit enable_meas;
            enable_measurements.read(enable_meas, (bit<32>)meta.index);
            // Apply the synfin table
            synfin.apply();
            if(enable_meas==1){
                // Compute time difference between last packet and current packet
                //read last timestamp
        	previous_timestamp.read(meta.packet_last_seen, (bit<32>)meta.index);
		//write new timestamp
        	previous_timestamp.write((bit<32>)meta.index, standard_metadata.ingress_global_timestamp);
                // Infer RTT
		bit<TIMESTAMP_WIDTH> delta = standard_metadata.ingress_global_timestamp - meta.packet_last_seen;
		// set metadata rtt value
		meta.rtt = delta;
		//clone packet to controller
		clone3(CloneType.I2E, 100, meta);
            }
        }

        customer_id.apply();
	// If the packet is encapsulated in a tunnel
        if (hdr.tunnel.isValid())
            VPLS_table.apply();
	// If the packet is not encapsulated in a tunnel
        if (!hdr.tunnel.isValid()) {
	    // If it is the first time a packet from the source is seen, learn forwarding
            smac.apply();
            switch (dmac.apply().action_run){
                ecmp_group: {
		    ecmp_group_to_forward.apply();
		}
		// If destination is not in table, flood the packet
		NoAction: {
                    broadcast.apply();
		}
            }
        }
    }
}



/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop_2(){
        mark_to_drop(standard_metadata);
    }

    action tunnel_ingress(bit<16> tunnel) {
        hdr.tunnel.setValid();
        hdr.tunnel.tunnel_id = tunnel;
        hdr.tunnel.pw_id = meta.customer_id;
        hdr.tunnel.proto_id = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_TUNNEL;
    }

    table tunnel_table{
        key = {
            meta.tunnel_id: exact;
        }
        actions = {
            tunnel_ingress;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {


        if (standard_metadata.instance_type==1){
	   if(meta.rtt != 0){
		hdr.rtt.setValid();
		hdr.rtt.pw_id = meta.customer_id;
		hdr.rtt.ip_src = hdr.ipv4.srcAddr;
		hdr.rtt.ip_dst = hdr.ipv4.dstAddr;
		hdr.rtt.rtt = meta.rtt;
		hdr.ethernet.etherType = RTT_ETHER_TYPE;
	    }
	    else{
            	hdr.cpu.setValid();
    	   	hdr.cpu.srcAddr = hdr.ethernet.srcAddr;
    	    	hdr.cpu.ingress_port = (bit<16>) meta.ingress_port;
    	    	hdr.cpu.customer_id = meta.customer_id;
            	hdr.cpu.tunnel_id = meta.learn_tunnel;
            	hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
	    }
        }
        else{
	    if(!hdr.tunnel.isValid()){
                if(standard_metadata.mcast_grp != 0)
                    meta.tunnel_id = standard_metadata.egress_rid;
                tunnel_table.apply();
            }
	}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
