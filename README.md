# NetSentinel AI Pro

A strong university-level Computer Networks + Cybersecurity + Machine Learning project.

## Included
- Scapy PCAP/PCAPNG analysis
- Packet-to-flow feature extraction
- TCP SYN/ACK/RST/FIN analysis
- Hybrid rule + ML NIDS
- Random Forest + Isolation Forest
- SYN Flood, Port Scan and service-flood rules
- Threat scoring, severity and incidents
- WebSocket live alerts
- PostgreSQL/SQLite persistence
- JWT register/login API
- OSI and protocol engineering lab
- ARP/DNS/DHCP/ICMP/TCP/UDP reference
- IPv4 CIDR subnet calculator
- Dijkstra routing demo
- TCP Slow Start/Congestion Avoidance simulation
- Delay/throughput calculator
- PDF security report
- Docker + Render configuration
- Automated tests
- Synthetic authorized PCAP generator

## Run
python -m venv .venv
pip install -r requirements.txt
uvicorn app.main:app --reload

Dashboard: http://127.0.0.1:8000
API docs: http://127.0.0.1:8000/docs

## Test PCAP
python scripts/generate_demo_pcap.py
Then upload uploads/demo_syn_flood.pcap.

## Docker
docker compose up --build

## Render
Push to GitHub and create a Blueprint from render.yaml. The service binds to $PORT and reads DATABASE_URL.

## Important
A cloud service cannot directly sniff your personal/college LAN. Use authorized PCAP uploads for cloud analysis; local packet capture can be a separate authorized agent.

The included model is synthetic/demo-trained so the app works without downloading a dataset. For academic benchmarking, train on a legitimate network-security dataset and report real metrics. Do not present demo metrics as real-world results.

Only analyze traffic and systems you own or are authorized to assess.
