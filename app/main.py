from pathlib import Path
import json,uuid
from fastapi import FastAPI,Depends,UploadFile,File,HTTPException,WebSocket,WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from .config import settings
from .database import Base,engine,get_db
from .models import User,Flow,Detection,Incident
from .security import hash_password,verify_password,create_token
from .ml import model
from .network import parse_pcap,classify_flow
from .cn_lab import OSI,subnet,routing_demo,congestion,performance
from .reports import build_report
BASE_DIR = Path(__file__).resolve().parent.parent
upload_path = BASE_DIR / settings.upload_dir
report_path = BASE_DIR / settings.report_dir
frontend_path = BASE_DIR / "frontend"
upload_path.mkdir(parents=True, exist_ok=True)
report_path.mkdir(parents=True, exist_ok=True)
Base.metadata.create_all(bind=engine)
app=FastAPI(title=settings.app_name,version="2.0.0"); app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])
class Hub:
 def __init__(self): self.clients=set()
 async def send(self,p):
  dead=[]
  for w in self.clients:
   try: await w.send_json(p)
   except: dead.append(w)
  for w in dead:self.clients.discard(w)
hub=Hub()
class AuthIn(BaseModel): username:str; password:str
class FlowIn(BaseModel):
 src_ip:str="10.0.0.10"; dst_ip:str="10.0.0.20"; protocol:str="TCP"; src_port:int=50000; dst_port:int=443
 packet_count:int=10; byte_count:int=12000; duration:float=1.; packets_per_sec:float=10.; bytes_per_sec:float=12000.; syn_count:int=1; ack_count:int=1; rst_count:int=0; fin_count:int=0
def persist(f,db):
 db.add(Flow(**f)); m=model.predict(f); label,score,sev,exp=classify_flow(f,m)
 if label!="BENIGN" or score>=50:
  db.add(Detection(attack_type=label,severity=sev,src_ip=f["src_ip"],dst_ip=f["dst_ip"],confidence=m["confidence"],threat_score=score,explanation=exp))
  db.add(Incident(attack_type=label,severity=sev,src_ip=f["src_ip"],dst_ip=f["dst_ip"],threat_score=score,evidence=json.dumps({"flow":f,"ml":m}),explanation=exp))
 return label,score,sev,exp,m
@app.get("/health")
def health(): return {"status":"ok","service":settings.app_name}
@app.post("/api/auth/register")
def register(x:AuthIn,db:Session=Depends(get_db)):
 if len(x.password)<8: raise HTTPException(400,"Password must be at least 8 characters")
 if db.query(User).filter_by(username=x.username).first(): raise HTTPException(409,"Username already exists")
 role="admin" if db.query(User).count()==0 else "analyst"; u=User(username=x.username,password_hash=hash_password(x.password),role=role); db.add(u);db.commit()
 return {"token":create_token(u.username,u.role),"role":u.role}
@app.post("/api/auth/login")
def login(x:AuthIn,db:Session=Depends(get_db)):
 u=db.query(User).filter_by(username=x.username).first()
 if not u or not verify_password(x.password,u.password_hash): raise HTTPException(401,"Invalid credentials")
 return {"token":create_token(u.username,u.role),"role":u.role}
@app.get("/api/dashboard")
def dashboard(db:Session=Depends(get_db)):
 return {"flows":db.query(Flow).count(),"detections":db.query(Detection).count(),"critical":db.query(Detection).filter_by(severity="critical").count(),"open_incidents":db.query(Incident).filter_by(status="open").count(),"models":["Random Forest","Isolation Forest"]}
@app.get("/api/incidents")
def incidents(db:Session=Depends(get_db)):
 return [{"id":x.id,"attack_type":x.attack_type,"severity":x.severity,"src_ip":x.src_ip,"dst_ip":x.dst_ip,"status":x.status,"threat_score":x.threat_score,"explanation":x.explanation} for x in db.query(Incident).order_by(Incident.id.desc()).limit(100)]
@app.get("/api/flows")
def flows(db:Session=Depends(get_db)):
 return [x.__dict__ | {"_sa_instance_state":None} for x in db.query(Flow).order_by(Flow.id.desc()).limit(200)]
@app.patch("/api/incidents/{iid}")
def update_incident(iid:int,status:str,db:Session=Depends(get_db)):
 x=db.get(Incident,iid)
 if not x: raise HTTPException(404,"Incident not found")
 if status not in {"open","investigating","resolved","false_positive"}: raise HTTPException(400,"Invalid status")
 x.status=status;db.commit();return {"ok":True}
@app.post("/api/analyze-flow")
async def analyze(x:FlowIn,db:Session=Depends(get_db)):
 f=x.model_dump(); label,score,sev,exp,m=persist(f,db);db.commit();await hub.send({"type":"detection","attack_type":label,"score":score,"severity":sev,"src_ip":f["src_ip"],"dst_ip":f["dst_ip"]})
 return {"classification":label,"threat_score":score,"severity":sev,"explanation":exp,"ml":m}
@app.post("/api/pcap")
async def pcap(file:UploadFile=File(...),db:Session=Depends(get_db)):
 name=(file.filename or "").lower()
 if not name.endswith((".pcap",".pcapng")): raise HTTPException(400,"Only .pcap or .pcapng files are allowed")
 data=await file.read()
 if len(data)>settings.max_upload_mb*1024*1024: raise HTTPException(413,"PCAP too large")
 path=upload_path/(uuid.uuid4().hex+"_"+Path(file.filename).name);path.write_bytes(data)
 parsed=parse_pcap(str(path)); results=[]
 for f in parsed:
  label,score,sev,exp,m=persist(f,db);results.append({"flow":f,"classification":label,"threat_score":score,"severity":sev,"explanation":exp})
 db.commit();return {"filename":file.filename,"flows_analyzed":len(results),"detections":sum(r["classification"]!="BENIGN" for r in results),"results":results[:200]}
@app.get("/api/cn/osi")
def osi(): return OSI
@app.get("/api/cn/subnet")
def subnet_api(cidr="192.168.1.0/24"):
 try:return subnet(cidr)
 except ValueError as e:raise HTTPException(400,str(e))
@app.get("/api/cn/routing")
def routing():return routing_demo()
@app.get("/api/cn/congestion")
def cong(ssthresh=16,rounds=12):return congestion(int(ssthresh),int(rounds))
@app.get("/api/cn/performance")
def perf(size_mb=10,bandwidth_mbps=100,rtt_ms=20):return performance(float(size_mb),float(bandwidth_mbps),float(rtt_ms))
@app.get("/api/cn/protocols")
def protocols():return [{"name":"TCP","layer":4,"purpose":"Reliable transport","key":"SYN/SYN-ACK/ACK/FIN/RST"},{"name":"UDP","layer":4,"purpose":"Connectionless transport","key":"Low overhead"},{"name":"IP","layer":3,"purpose":"Addressing/routing","key":"IPv4/IPv6"},{"name":"ICMP","layer":3,"purpose":"Diagnostics","key":"Echo request/reply"},{"name":"ARP","layer":2,"purpose":"IPv4-to-MAC resolution","key":"Request/reply"},{"name":"DNS","layer":7,"purpose":"Name resolution","key":"Query/response"},{"name":"DHCP","layer":7,"purpose":"Dynamic configuration","key":"Discover/Offer/Request/Ack"}]
@app.get("/api/report")
def report(db:Session=Depends(get_db)):
 d=db.query(Detection).order_by(Detection.id.desc()).limit(200).all(); path=report_path/"netsentinel-report.pdf";build_report(path,{"flows":db.query(Flow).count(),"detections":len(d),"critical":sum(x.severity=="critical" for x in d)},d);return FileResponse(path,media_type="application/pdf",filename="netsentinel-report.pdf")
@app.websocket("/ws/alerts")
async def alerts(ws:WebSocket):
 await ws.accept();hub.clients.add(ws)
 try:
  while True: await ws.receive_text()
 except WebSocketDisconnect: hub.clients.discard(ws)
app.mount("/assets",StaticFiles(directory=str(frontend_path)),name="assets")
@app.get("/")
def root():return FileResponse(str(frontend_path/"index.html"))
