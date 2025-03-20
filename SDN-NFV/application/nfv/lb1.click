//lb will act as arp responder for webservers
define ($httpserviceip 100.0.0.45, $ws1 100.0.0.40, $ws2 100.0.0.41, $ws3 100.0.0.42, $mac 00:00:00:00:00:b1)

//counters
out_out_c, out_dmz_c, in_out, in_dmz :: AverageCounter;
arp_out_request, arp_dmz_request, arp_out_response, arp_dmz_response :: Counter;
icmp_out_request, icmp_dmz_request :: Counter;
tcp_out, tcp_dmz :: Counter;
drop :: Counter -> Discard;

//inputs and outputs
out_out :: Queue -> out_out_c -> ToDevice(lb1-eth1, METHOD LINUX);
out_dmz :: Queue -> out_dmz_c -> ToDevice(lb1-eth2, METHOD LINUX);
FromDevice(lb1-eth1, METHOD LINUX, SNIFFER false) -> in_out;
FromDevice(lb1-eth2, METHOD LINUX, SNIFFER false) -> in_dmz;

//arp queriers
arp_out :: ARPQuerier($httpserviceip/32, $mac)
arp_dmz :: ARPQuerier($httpserviceip/32, $mac)

//classifier
in_out -> c_out :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
in_dmz -> c_dmz :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

//Answer to ARP requests
c_out[0] -> arp_out_request -> ARPResponder($httpserviceip/32 $mac) -> out_out;
c_dmz[0] -> arp_dmz_request -> ARPResponder($httpserviceip/24 $mac) -> out_dmz;

//ARP replies
c_out[1] -> arp_out_response -> [1]arp_out;
c_dmz[1] -> arp_dmz_response -> [1]arp_dmz;

//Handle IP packets: Allow ping and tcp port 80 traffic to httpserviceip
c_out[2] -> Strip(14) -> CheckIPHeader -> ip_out :: IPClassifier(ip proto icmp && icmp type echo, tcp && dst host $httpserviceip && dst tcp port 80, -);
c_dmz[2] -> Strip(14) -> CheckIPHeader -> ip_dmz :: IPClassifier(ip proto icmp && icmp type echo, tcp && src host $ws1 or $ws2 or $ws3, -);
ip_out[0] -> icmp_out_request -> Unstrip(14) -> ICMPPingResponder -> EtherMirror -> out_out;
ip_dmz[0] -> drop;//icmp_dmz_request -> Unstrip(14) -> ICMPPingResponder -> EtherMirror -> out_dmz;

r :: RoundRobinIPMapper(- - $ws1 - 0 1, - - $ws2 - 0 1, - - $ws3 - 0 1)
ip_out[1] -> tcp_out -> rw_out :: IPRewriter(r, drop);
ip_dmz[1] -> tcp_dmz -> [1]rw_out;
rw_out[0] -> SetTCPChecksum -> [0]arp_dmz[0] -> out_dmz;
rw_out[1] -> SetTCPChecksum -> [0]arp_out[0] -> out_out;

ip_out[2] -> drop;
ip_dmz[2] -> drop;

//Discard non-IP, non-ARP packets
c_out[3] -> drop;
c_dmz[3] -> drop;

//Report
DriverManager(pause, print > results/lb1.report "
=================== LB1 Report ===================
Input  Packet  rate  (pps): $(add $(in_out.rate) $(in_dmz.rate))
Output  Packet  rate (pps): $(add $(out_out_c.rate) $(out_dmz_c.rate))
Total # of   input packets: $(add $(in_out.count) $(in_dmz.count))
Total # of  output packets: $(add $(out_out_c.count) $(out_dmz_c.count))
Total # of   ARP  requests: $(add $(arp_out_request.count) $(arp_dmz_request.count))
Total # of   ARP responses: $(add $(arp_out_response.count) $(arp_dmz_response.count))
Total # of service packets: $(add $(tcp_out.count) $(tcp_dmz.count))
Total # of    ICMP packets: $(add $(icmp_out_request.count) $(icmp_dmz_request.count))
Total # of dropped packets: $(drop.count)
==================================================
", wait 0.1s, stop);
