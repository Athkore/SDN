//counters
counter_in :: AverageCounter
counter_out_dmz :: AverageCounter
counter_out_insp :: AverageCounter
counter_arp_req, counter_arp_resp, counter_icmp :: AverageCounter
counter_tcp, counter_http_dmz, counter_http_insp :: AverageCounter
counter_drop :: Counter

//interfaces
from_out :: FromDevice(ids-eth1, METHOD LINUX, SNIFFER false);
from_dmz :: FromDevice(ids-eth3, METHOD LINUX, SNIFFER false) -> Queue -> ToDevice(ids-eth1, METHOD LINUX); //Passthrough from dmz to out
to_dmz :: Queue  -> counter_out_dmz -> ToDevice(ids-eth3, METHOD LINUX);
to_insp :: Queue -> counter_out_insp -> ToDevice(ids-eth2, METHOD LINUX);

//Classify ARP req, ARP resp, IP, other
from_out -> counter_in -> cl1_out :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

//Allow ARP
cl1_out[0] -> counter_arp_req -> to_dmz;
cl1_out[1] -> counter_arp_resp -> to_dmz;

//Drop other than IP
cl1_out[3] -> counter_drop -> Discard;

//Handle IP, Classify ICMP, other
cl1_out[2] -> Strip(14) -> CheckIPHeader -> cl2_out :: Classifier(9/01, -);

//Allow ICMP
cl2_out[0] -> Unstrip(14) -> counter_icmp -> to_dmz;

//Handle other, Classify TCP signaling
cl2_out[1] -> StripIPHeader -> cl3_out :: Classifier(13/02, 13/12, 13/10, 13/04, 13/11, -)

//Allow TCP signaling
cl3_out[0] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;
cl3_out[1] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;
cl3_out[2] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;
cl3_out[3] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;
cl3_out[4] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;

//PSH ACK
//cl3_out[5] -> UnstripIPHeader -> Unstrip(14) -> counter_tcp -> to_dmz;


//Handle other, Classify HTTP methods
cl3_out[5] -> StripTCPHeader -> cl4_out :: Classifier(0/474554, 0/48454144, 0/5452414345, 0/4f5054494f4e53, 0/44454c455445, 0/434f4e4e454354, 0/504f5354, 0/505554, -)

//Disallow GET, HEAD, TRACE, OPTIONS, DELETE, CONNECT and other
cl4_out[0] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[1] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[2] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[3] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[4] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[5] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl4_out[8] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;

//Allow POST
cl4_out[6] -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_dmz -> to_dmz;

//Further investigate PUT
cl4_out[7] -> Search("\r\n\r\n") -> cl5_out :: Classifier(0/636174202f6574632f706173737764, 0/636174202f7661722f6c6f67, 0/494E53455254, 0/555044415445, 0/44454C455445, -)

//Disallow HTTP PUT args "cat /etc/passwd", "cat /var/log", INSERT, UPDATE, DELETE.
cl5_out[0] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl5_out[1] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl5_out[2] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl5_out[3] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;
cl5_out[4] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_insp -> to_insp;

//Allow other HTTP PUT args
cl5_out[5] -> UnstripAnno() -> UnstripTCPHeader -> UnstripIPHeader -> Unstrip(14) -> counter_http_dmz -> to_dmz;

//Report
DriverManager(pause, print > results/ids.report "
=================== IDS Report ===================
Input  Packet  rate  (pps): $(counter_in.rate)
Output  Packet  rate (pps): $(add $(counter_out_dmz.rate) $(counter_out_insp.rate))
Total # of   input packets: $(counter_in.count)
Total # of  output packets: $(add $(counter_out_dmz.count) $(counter_out_dmz.count))
Total # of   ARP  requests: $(counter_arp_req.count)
Total # of   ARP responses: $(counter_arp_resp.count)
Total # of service packets: $(add $(counter_tcp.count) $(counter_http_dmz.count) $(counter_http_insp.count))
Total # of    ICMP packets: $(counter_icmp.count)
Total # of dropped packets: $(counter_drop.count)
==================================================
", wait 0.1s, stop);



















