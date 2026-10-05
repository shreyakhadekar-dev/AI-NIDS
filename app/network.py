from collections import defaultdict
from scapy.all import rdpcap,IP,IPv6,TCP,UDP,ICMP
def parse_pcap(path,limit=50000):
    packets=rdpcap(path,count=limit); groups=defaultdict(list)
    for p in packets:
        if IP in p: src,dst=p[IP].src,p[IP].dst
        elif IPv6 in p: src,dst=p[IPv6].src,p[IPv6].dst
        else: continue
        if TCP in p: proto,sport,dport="TCP",int(p[TCP].sport),int(p[TCP].dport)
        elif UDP in p: proto,sport,dport="UDP",int(p[UDP].sport),int(p[UDP].dport)
        elif ICMP in p: proto,sport,dport="ICMP",None,None
        else: proto,sport,dport="IP",None,None
        groups[(src,dst,proto,sport,dport)].append(p)
    out=[]
    for (src,dst,proto,sport,dport),ps in groups.items():
        ts=[float(p.time) for p in ps]; dur=max((max(ts)-min(ts)) if len(ts)>1 else .001,.001)
        syn=ack=rst=fin=0
        for p in ps:
            if TCP in p:
                fl=int(p[TCP].flags); syn+=bool(fl&2); ack+=bool(fl&16); rst+=bool(fl&4); fin+=bool(fl&1)
        n=len(ps); b=sum(len(p) for p in ps)
        out.append({"src_ip":src,"dst_ip":dst,"protocol":proto,"src_port":sport,"dst_port":dport,"packet_count":n,"byte_count":b,"duration":round(dur,6),"packets_per_sec":round(n/dur,3),"bytes_per_sec":round(b/dur,3),"syn_count":syn,"ack_count":ack,"rst_count":rst,"fin_count":fin})
    return out
def classify_flow(f,m):
    syn,ack=f["syn_count"],f["ack_count"]; n,pps=f["packet_count"],f["packets_per_sec"]
    if syn>=80 and ack<max(5,syn*.15): return "SYN Flood",92,"critical","High SYN volume with very low ACK completion suggests half-open TCP connections."
    if n>=120 and pps>=25 and f.get("dst_port") in {21,22,23,3389}: return "Brute Force / Service Flood",82,"high","High-rate traffic targets a commonly abused service port."
    if n>=60 and f.get("dst_port") is not None and f["protocol"]=="TCP" and syn>=25 and ack<=5: return "Port Scan",78,"high","Many connection attempts with few completed handshakes resemble scanning behavior."
    if m["label"]!="BENIGN" or m["anomaly"]:
        s=int(min(99,max(55,m["confidence"]*100))); sev="critical" if s>=90 else "high" if s>=75 else "medium"
        return m["label"],s,sev,f"ML classified the flow as {m['label']} with {m['confidence']:.1%} confidence."
    return "BENIGN",max(1,int(m["confidence"]*35)),"low","No strong malicious rule or anomaly signal was observed."
