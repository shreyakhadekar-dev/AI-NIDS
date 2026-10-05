import ipaddress,math,heapq
OSI=[{"layer":7,"name":"Application","examples":"HTTP, DNS, DHCP","purpose":"User-facing network services"},{"layer":6,"name":"Presentation","examples":"TLS, encoding","purpose":"Data representation and encryption"},{"layer":5,"name":"Session","examples":"Session management","purpose":"Establish/manage sessions"},{"layer":4,"name":"Transport","examples":"TCP, UDP","purpose":"End-to-end delivery, ports and reliability"},{"layer":3,"name":"Network","examples":"IPv4, IPv6, ICMP","purpose":"Logical addressing and routing"},{"layer":2,"name":"Data Link","examples":"Ethernet, ARP","purpose":"Frames and MAC addressing"},{"layer":1,"name":"Physical","examples":"Copper, fiber, radio","purpose":"Bit transmission"}]
def subnet(cidr):
 n=ipaddress.ip_network(cidr,strict=False); h=list(n.hosts()); usable=max(0,n.num_addresses-2) if n.version==4 and n.prefixlen<31 else n.num_addresses
 return {"network":str(n.network_address),"broadcast":str(n.broadcast_address),"netmask":str(n.netmask),"prefix":n.prefixlen,"total_addresses":n.num_addresses,"usable_hosts":usable,"first_host":str(h[0]) if h else None,"last_host":str(h[-1]) if h else None}
def routing_demo():
 g={"A":{"B":2,"C":5},"B":{"A":2,"C":1,"D":4},"C":{"A":5,"B":1,"D":1},"D":{"B":4,"C":1}}; dist={"A":0}; prev={}; q=[(0,"A")]
 while q:
  d,u=heapq.heappop(q)
  if d!=dist.get(u): continue
  for v,w in g[u].items():
   nd=d+w
   if nd<dist.get(v,math.inf): dist[v]=nd;prev[v]=u;heapq.heappush(q,(nd,v))
 return {"algorithm":"Dijkstra / Shortest Path","graph":g,"distances":dist,"previous":prev}
def congestion(ssthresh=16,rounds=12):
 c=1.; a=[]
 for r in range(1,rounds+1): a.append({"round":r,"cwnd":round(c,2)}); c=c*2 if c<ssthresh else c+1
 return {"algorithm":"TCP Slow Start + Congestion Avoidance","ssthresh":ssthresh,"rounds":a}
def performance(size_mb,bandwidth_mbps,rtt_ms=20):
 bits=size_mb*8*1024*1024; sec=bits/(bandwidth_mbps*1e6)
 return {"transmission_delay_sec":sec,"rtt_sec":rtt_ms/1000,"total_approx_sec":sec+rtt_ms/1000,"throughput_mbps":size_mb*8/sec/1e6 if sec else 0}
