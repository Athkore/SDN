#from pox.misc.firewall.Firewall import Firewall
from . import Firewall
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt

class Private (Firewall):
    def __init__ (self, connection):
        Firewall.__init__(self,connection)
        self.prz_rule()
    
    def _handle_PacketIn (self,event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        packet_in = event.ofp
        ip = packet.find('ipv4')
        if ip and ip.srcip not in ["100.0.0.1"]:
            self.stateful(event, packet, packet_in)
        else:
            Firewall._handle_PacketIn(self, event)
    
    def stateful(self, event, packet, packet_in):
        if packet.type == pkt.ethernet.IP_TYPE:
            ipp = packet.find('ipv4')
            if ipp.protocol == ipp.ICMP_PROTOCOL:
                icmpp = packet.find('icmp')
                if icmpp.type == 8:
                    self.resend_packet(packet_in, of.OFPP_NONE)
                elif icmpp.type == 0:
                    self.resend_packet(packet_in,of.OFPP_ALL)
            elif ipp.protocol == ipp.TCP_PROTOCOL:
                tcpp = packet.find('tcp')
                if tcpp.SYN:
                    if tcpp.ACK:
                        self.resend_packet(packet_in, of.OFPP_ALL)
                        self.add_requested_flow(packet, ipp, tcpp)
                    else:
                        self.resend_packet(packet_in, of.OFPP_NONE)
                else:
                    self.resend_packet(packet_in, of.OFPP_ALL)
            else:
                self.resend_packet(packet_in, of.OFPP_ALL)
        else:
            self.resend_packet(packet_in, of.OFPP_NONE)

    def add_requested_flow(self, packet, ipp, tcpp):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_src = packet.src, dl_dst = packet.dst, dl_type = packet.type, nw_src = ipp.srcip, nw_dst = ipp.dstip, nw_proto = ipp.protocol, tp_src = tcpp.srcport, tp_dst = tcpp.dstport)
        msg.idle_timeout = 5
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)

    def prz_rule (self):
        ip = "100.0.0.1/32"
        # Allow outgoing
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_src = ip)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        self.connection.send(msg)
        # Send incoming IP packets to controller
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_dst = ip)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        self.connection.send(msg)
        # Drop non IP incoming packets
        msg = of.ofp_flow_mod()
        msg.priority = 2
        msg.match = of.ofp_match(dl_type = pkt.ethernet.IP_TYPE, nw_dst = ip)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
        self.connection.send(msg)
