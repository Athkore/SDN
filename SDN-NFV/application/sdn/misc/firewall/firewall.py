import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from pox.forwarding.l2_learning import LearningSwitch

class Firewall (LearningSwitch):
    def __init__ (self, connection):
        LearningSwitch.__init__(self, connection, False)
        self.http_rule()
    
    def resend_packet (self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        # Action to send to specified port
        msg.actions.append(of.ofp_action_output(port = out_port))
        # Send message to firewall
        self.connection.send(msg)
        
    def http_rule (self):
        for ip in ["100.0.0.40/32","100.0.0.41/32","100.0.0.42/32"]:
            # Dissallow traffic toward servers
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_dst = ip)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            self.connection.send(msg)
        ip = "100.0.0.45/32"
        # Allow HTTP to virtual IP
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_proto = pkt.ipv4.TCP_PROTOCOL, nw_dst = ip, tp_dst = 80)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
        # Allow ICPM request to virtual IP
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_proto = pkt.ipv4.ICMP_PROTOCOL, nw_dst = ip)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
        # Dissallow other IP packets toward servers
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_dst = ip)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        self.connection.send(msg)
        # Allow all other type of traffic
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
