define($prz_if napt-eth2, $out_if napt-eth1, $public 100.0.0.1, $private 10.0.0.1, $mac 00:00:00:00:00:0a)
//counters
from_prz, from_out, to_prz_count, to_out_count :: AverageCounter;
arp_out_request, arp_prz_request, arp_out_response, arp_prz_response :: Counter;
tcp_out, tcp_prz, icmp_out_request, icmp_prz_request :: Counter;
drop :: Counter -> Discard;

//interfaces
in_prz :: FromDevice($prz_if, METHOD PCAP, SNIFFER true) -> from_prz;
in_out :: FromDevice($out_if, METHOD PCAP, SNIFFER true) -> from_out;
to_prz :: Queue -> to_prz_count -> out_prz :: ToDevice($prz_if)
to_out :: Queue -> to_out_count -> out_out :: ToDevice($out_if)

//Internal ARP query
out_arp :: ARPQuerier($public, $mac) -> to_out; 
prz_arp :: ARPQuerier($private, $mac) -> to_prz;

//change address ip icmp
nat :: ICMPPingRewriter(pattern $public - 1-65535# 0 1, drop);
nat[0] -> out_arp;
nat[1] -> prz_arp;


//change address ip tcp udp
napt :: IPRewriter(pattern $public 1024-65535# - - 0 1, drop);
napt[0] -> out_arp;
napt[1] -> prz_arp;

//classify packet arp request, arp
from_prz ->
	prz_cl_1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
from_out -> 
	out_cl_1 :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

prz_cl_1[2] -> Strip(14) -> prz_check :: CheckIPHeader ->
        prz_cl_2 :: IPClassifier(tcp, icmp and icmp type echo, -);

out_cl_1[2] -> Strip(14) -> out_check :: CheckIPHeader ->
        out_cl_2 :: IPClassifier(tcp, icmp and icmp type echo-reply, -);

prz_check[1] -> drop;
out_check[1] -> drop;

//handle arp in prz
prz_cl_1[0] -> arp_prz_request -> ARPResponder($public/24 $mac, $private/24 $mac) -> to_prz;
prz_cl_1[1] -> arp_prz_response -> [1]prz_arp;

//handle arp outside
out_cl_1[0] -> arp_out_request -> ARPResponder($public $mac) -> to_out;
out_cl_1[1] -> arp_out_response -> [1]out_arp;

//handle tcp packets
out_cl_2[0] -> Print(tcp_to_prz,-1) -> tcp_out -> [1]napt;
// Print(From_out_tcp) -> Print(napt1To_prz_tcp) ->[0] -> Print(Output_prz0) -> to_prz;
prz_cl_2[0] -> Print(tcp_from_prz,-1) -> tcp_prz -> [0]napt;
//-> Print(From_prz_tcp) -> Print(napt0To_out_tcp) [0] -> Print(Output_out0) -> to_out;

//handle icmp echo packets
out_cl_2[1] -> Print(ping_to_prz,-1) -> icmp_out_request -> [1]nat;
prz_cl_2[1] -> Print(ping_from_prz,-1) -> icmp_prz_request -> [0]nat;

//drop other
prz_cl_1[3] -> drop;
out_cl_1[3] -> drop;
prz_cl_2[2] -> drop;
out_cl_2[2] -> drop;

//Report
DriverManager(pause, print > results/napt.report "
=================== NAPT Report ===================
Input  Packet  rate  (pps): $(add $(from_out.rate) $(from_prz.rate))
Output  Packet  rate (pps): $(add $(to_out_count.rate) $(to_prz_count.rate))
Total # of   input packets: $(add $(from_out.count) $(from_prz.count))
Total # of  output packets: $(add $(to_out_count.count) $(to_prz_count.count))
Total # of   ARP  requests: $(add $(arp_out_request.count) $(arp_prz_request.count))
Total # of   ARP responses: $(add $(arp_out_response.count) $(arp_prz_response.count))
Total # of service packets: $(add $(tcp_out.count) $(tcp_prz.count))
Total # of    ICMP packets: $(add $(icmp_out_request.count) $(icmp_prz_request.count))
Total # of dropped packets: $(drop.count)
==================================================
", wait 0.1s, stop);
