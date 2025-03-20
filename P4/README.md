# IK2217-p4
n = {1,2,3,4,5,6}
Start topology n "sudo p4run --conf 0n\*p4app.json"
Start controller for topology n "sudo python routing-controller.py 0n\*vpls.conf"

To confirm correctness of behaviour for Customer Tunnel flooding of arp requests, L2 learning, and RTT. Before running anything more, run "./test_topology_0 <n>"

ECMP functionality, and RTT for multiple flows only tested in Topology 6

After correctness of behaviour has been tested, feel free to run ./test_topology_0n.sh to test tunnels
