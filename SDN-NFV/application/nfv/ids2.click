define($idsip 100.0.0.31, $mac 00:00:00:00:00:0d)
//interfaces
from_out :: FromDevice(ids-eth1, METHOD LINUX, SNIFFER false)
from_dmz :: FromDevice(ids-eth3, METHOD LINUX, SNIFFER false) -> Queue -> ToDevice(ids-eth1, METHOD LINUX); //Passthrough all from $
to_dmz :: Queue -> ToDevice(ids-eth3, METHOD LINUX)
from_insp :: FromDevice(ids-eth2, METHOD LINUX, SNIFFER false)
to_insp :: Queue -> ToDevice(ids-eth2, METHOD LINUX)

arp :: ARPQuerier($idsip/32, $mac)

from_insp -> c_insp :: Classifier(12/0806 20/0002, -);
c_insp[0] -> [1]arp[1] -> to_insp;
c_insp[1] -> Discard;

// 37/50 = TCP PORT 80
//12/0806 All ARP passthrough
// 47/02 SYN
// 47/12 SYN, ACK
//12/0800 IP
from_out -> c_out :: Classifier(12/0806, 12/0800, -)

//ARP
c_out[0] -> Print(Pass_through_ARP_out[0], -1) -> to_dmz;

//Passthrough other than IP
c_out[2] -> Print(Other_than_IP, -1) -> to_dmz;

//IP
c_out[1] -> Strip(14) -> CheckIPHeader -> ip_out :: IPClassifier(ip proto icmp, tcp opt syn,  tcp www && tcp opt ack, tcp opt rst, -)

//Allow ICMP and TCP SYN and other ports than 80
ip_out[0] -> Print(ICMP, -1) -> to_dmz;
ip_out[1] -> Print(SYN, -1) -> to_dmz;
ip_out[3] -> Print(RST, -1) -> to_dmz;
ip_out[4] -> Print(Other_tcp_opt, -1) -> to_dmz;

//Handle TCP port 80 ACK
//POST = 504f5354 
//PUT = 505554
//OPTIONS = 4f5054494f4e53
//HEAD = 48454144
//DELETE = 44454c455445
//TRACE = 5452414345
//CONNECT = 434f4e4e454354
//GET = 474554

ip_out[2] -> StripIPHeader -> StripTCPHeader -> http_out :: Classifier(0/504f5354, 0/505554, 0/4f5054494f4e53, 0/48454144, 0/44454c455445, 0/5452414345, 0/434f4e4e454354, 0/474554, -)

//Send all other methods to inspector
http_out[2] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(OPTIONS, -1) -> IPRewriter(pattern - - 100.0.0.30 - 0 0) -> [0]arp[0] -> to_insp;
http_out[3] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(Send_to_inspector, -1) -> [0]arp[0] -> to_insp;
http_out[4] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(Send_to_inspector, -1) -> [0]arp[0] -> to_insp;
http_out[5] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(Send_to_inspector, -1) -> [0]arp[0] -> to_insp;
http_out[6] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(Send_to_inspector, -1) -> [0]arp[0] -> to_insp;
http_out[7] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> Print(Send_to_inspector, -1) -> [0]arp[0] -> to_insp;

//Pass on POST to lb1
http_out[0] -> Print(POST, -1) -> to_dmz;

//Inspect PUT
http_out[1] -> Print(PUT, -1) -> to_dmz;

//Discard other
http_out[8] -> Discard; 
