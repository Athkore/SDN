import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import os
import subprocess
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.datapaths.pcap_switch import PCapSwitch
from pox.forwarding.l2_learning import LearningSwitch
from pox.misc.firewall import *

log = core.getLogger()

class App (object):
    def __init__ (self, **opts):
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp (self, event):
        #log.debug("Connection %s" % (event.connection,))
        if event.dpid == 0xf1:
            print("Firewall %s has come up." % (dpid_to_str(event.dpid),))
            Firewall(event.connection)
        elif event.dpid == 0xf2:
            print("Firewall %s has come up." % (dpid_to_str(event.dpid),))
            Private(event.connection)
        elif event.dpid == 0xb1:
	    print("Load balancer %s has come up." % (dpid_to_str(event.dpid),))
            subprocess.Popen(["sudo", "click", "application/nfv/lb1.click", "mac=00:00:00:00:00:b1", "httpserviceip=100.0.0.45", "ws1=100.0.0.40", "ws2=100.0.0.41", "ws3=100.0.0.42"],stdout=subprocess.PIPE).pid
            #LearningSwitch(event.connection,False)
            #os.popen("sudo click -w application/nfv/lb1.click mac=00:00:00:00:00:b1")
            #subprocess.Popen(cmd,cwd=self.nfvdir,stdout=subprocess.PIPE).pid
            #subprocess.Popen(cmd, executable="click", cwd=self.nfvdir, stdout=subprocess.PIPE, stdin=subprocess.PIPE, ).pid
            #print(type(event.connection.ports["Ports"]))
            #print(event.connection.features)
            #subprocess.Popen("sudo /usr/local/bin/click ./click/lb1.click")
            #subprocess.call(["sudo","click", "./click/lb1.click"])
            #PCapSwitch(dpid=event.dpid, name=dpid_to_str(event.dpid))
        elif event.dpid == 0xa:
            print("NAPT %s has come up." % (dpid_to_str(event.dpid),))
            subprocess.Popen(["sudo", "click", "application/nfv/napt.click"],stdout=subprocess.PIPE).pid
            #LearningSwitch(event.connection,False)
        elif event.dpid == 0xd:
            print("IDS %s has come up." % (dpid_to_str(event.dpid),))
            subprocess.Popen(["sudo", "click", "application/nfv/ids4.click"],stdout=subprocess.PIPE).pid
            #LearningSwitch(event.connection,False)
	else:
            print("Switch %s has come up." % (dpid_to_str(event.dpid),))
            LearningSwitch(event.connection,False)
    

def launch ():
    core.registerNew(App)
