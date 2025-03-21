/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


const bit<8> TYPE_TCP = 0x06;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_TUNNEL = 0x1212;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


// new header type for the tunnel id and pw
header  tunnel_t {
    bit<16> tunnel_id;
    bit<16> pw_id; //customer_id
    bit<16> proto_id;
}


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header cpu_t{
    macAddr_t srcAddr;
    bit<16> ingress_port;
    bit<16> customer_id;
    bit<16> tunnel_id;
}

header rtt_t{
    bit<16> pw_id;
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<48> rtt;
}

struct metadata {
    bit<16> customer_id;
    bit<16> ingress_port;
    bit<16> tunnel_id;
    bit<48> rtt;
    bit<16> learn_tunnel;
    bit<48> packet_last_seen;
    bit<12> index;
    bit<14> ecmp_hash;
    bit<9> ecmp_nr_ports;
}

struct headers {
    ethernet_t  ethernet;
    tunnel_t    tunnel;
    ipv4_t 	ipv4;
    cpu_t       cpu;
    rtt_t       rtt;
    tcp_t 	tcp;
}
