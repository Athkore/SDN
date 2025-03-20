import os
import json
from mininet import *
from mininet.topo import *
from mininet.net import *
from mininet.node import *
from mininet.util import *


class Assignment( Topo ):
    def __init__(self, **opts):
        Topo.__init__(self,**opts)
        
        ### Hosts
        h1 = self.addHost('h1', ip='100.0.0.10/24')
        h2 = self.addHost('h2', ip='100.0.0.11/24')
        h3 = self.addHost('h3', ip='10.0.0.50/24')
        h4 = self.addHost('h4', ip='10.0.0.51/24')
        
        ### Servers
        ws1 = self.addHost('ws1', ip='100.0.0.40/24')
        ws2 = self.addHost('ws2', ip='100.0.0.41/24')
        ws3 = self.addHost('ws3', ip='100.0.0.42/24')
    
        ### Switches
        s1 = self.addSwitch('sw1')
        s2 = self.addSwitch('sw2')
        s3 = self.addSwitch('sw3')
        s4 = self.addSwitch('sw4')
        
        ### Firewalls
        fw1 = self.addSwitch('fw1', dpid='f1')
        fw2 = self.addSwitch('fw2', dpid='f2')
	
	### Load balancer
	lb1 = self.addSwitch('lb1', dpid='b1')
        
        ### Net Address Port Translator
        napt = self.addSwitch('napt', dpid='a')
        
        ### Intrusion Detection Service
        ids = self.addSwitch('ids', dpid='d')
        insp = self.addHost('insp', ip='100.0.0.30/24')
        
        ### Public Zone
        self.addLink( s1, h1 )
        self.addLink( s1, h2 )
        
        ### Private Zone
        self.addLink( s3, h3 )
        self.addLink( s3, h4 )
        
        ### Demilitarized zone
        self.addLink( s4, ws1 )
        self.addLink( s4, ws2 )
        self.addLink( s4, ws3 )
        self.addLink( s2, ids, port2=1 )
        self.addLink( ids, insp, port1=2 )
        self.addLink( ids, lb1, port1=3, port2=1 )
	self.addLink( lb1, s4, port1=2 )
        
        ### Interconnect PbZ, PrZ, and DMZ
        self.addLink( s1, fw1 )
        self.addLink( s2, fw1 )
        self.addLink( s2, napt, port2=1 )
        self.addLink( s3, napt, port2=2 )
        

topos = { 'a': (lambda: Assignment()) }
topo = Assignment()
    
if __name__ == "__main__":
    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)
    net = Mininet(
            topo            = topo,
            switch          = OVSSwitch,
            controller      = ctrl,
            autoSetMacs     = True,
            autoStaticArp   = True,
            build           = True,
            cleanup         = True
            )
    net.start()
    net['napt'].intf(intf='napt-eth1').setIP('100.0.0.1/24')
    net['napt'].intf(intf='napt-eth2').setIP('10.0.0.1/24')
    
    hostserverpid = {}
    for host in net.hosts:
        hostserverpid[host.name] = host.pid
    f = open("pid","w")
    f.write(str(hostserverpid))
    f.flush()
    f.close()
    ### Create HTTP server data
    os.system("mkdir -p www")
    os.system("touch www/page1 www/page2 www/page3 www/page4 www/page5")
    ### Assign default gateway via
    for pbz_host in ['h1','h2']:
        host = net[pbz_host]
        host.cmd('ip route add default via 100.0.0.1')
    for prz_host in ['h3','h4']:
        host = net[prz_host]
        host.cmd('ip route add default via 10.0.0.1')
    for dmz_server in ['ws1','ws2','ws3']:
        server = net[dmz_server]
        server.cmd('ip route add default via 100.0.0.45')
    ### Start HTTP servers
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 21 &')
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 22 &')
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 23 &')
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 25 &')
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 80 &')
    net['ws1'].cmd('cd www && python -m SimpleHTTPServer 443 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 21 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 22 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 23 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 25 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 80 &')
    net['ws2'].cmd('cd www && python -m SimpleHTTPServer 443 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 21 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 22 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 23 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 25 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 80 &')
    net['ws3'].cmd('cd www && python -m SimpleHTTPServer 443 &')
    ### Start capture on inspector
    net['insp'].cmd('tcpdump -U -i insp-eth0 -w IDS.pcap&')
    
    CLI( net )
    net.stop()
