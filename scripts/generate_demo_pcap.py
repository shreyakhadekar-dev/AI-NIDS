from scapy.all import Ether,IP,TCP,wrpcap
from pathlib import Path
out=Path("uploads/demo_syn_flood.pcap")
wrpcap(str(out),[Ether()/IP(src="10.10.10.50",dst="10.10.10.10")/TCP(sport=30000+i,dport=443,flags="S") for i in range(150)])
print(out)
