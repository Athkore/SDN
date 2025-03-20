NFV=$(PWD)/application/nfv

nfv:
	echo $(NFV)

topo:
	@#tmux new-session -d -s mininet "sudo python topology/topo.py"
	sudo xterm -e python topology/topo.py &
app: install
	@#tmux new-session -d -s app "/opt/ik2220/pox/pox.py misc.app"
	xterm -e /opt/ik2220/pox/pox.py misc.app &
	@# --nfvdir=$(NFV) &
test: start
	@sleep 5
	@$(MAKE) test1
	$(MAKE) stop
	@echo "Tests done"

test1:
	@rm -rf results/phase_1_report
	python results/test_phase1.py > ./results/phase_1_report 2>&1; 

start: app topo

stop:
	tmux kill-session -t mininet
	tmux kill-session -t app

install:
	sudo cp -r application/sdn/* /opt/ik2220/pox/pox/

uninstall:
	sudo rm -rf /opt/ik2220/pox/pox/misc/app.py /opt/ik2220/pox/pox/misc/firewall

clean: uninstall
	sudo rm -rf pid www IDS.pcap
