import numpy as np
from sklearn.ensemble import RandomForestClassifier,IsolationForest
FEATURES=["packet_count","byte_count","duration","packets_per_sec","bytes_per_sec","syn_count","ack_count","rst_count","fin_count"]
CLASSES=["BENIGN","DoS","Port Scan","SYN Flood"]
class IDSModel:
    def __init__(self): self.rf=RandomForestClassifier(n_estimators=160,random_state=42,class_weight="balanced"); self.iso=IsolationForest(n_estimators=120,contamination=.12,random_state=42); self.trained=False
    def _train(self):
        rng=np.random.default_rng(42); X=[]; y=[]
        for label in CLASSES:
            for _ in range(180):
                if label=="BENIGN": x=[rng.integers(1,50),rng.integers(100,50000),rng.uniform(.1,30),rng.uniform(.2,20),rng.uniform(10,50000),rng.integers(0,5),rng.integers(0,5),rng.integers(0,2),rng.integers(0,3)]
                elif label=="SYN Flood":
                    s=rng.integers(120,1000); x=[s+rng.integers(0,100),rng.integers(10000,200000),rng.uniform(.1,5),rng.uniform(100,2500),rng.uniform(10000,500000),s,rng.integers(0,max(1,s//8)),rng.integers(0,20),rng.integers(0,5)]
                elif label=="Port Scan":
                    p=rng.integers(40,500); x=[p,rng.integers(1000,100000),rng.uniform(.1,20),rng.uniform(10,500),rng.uniform(1000,100000),rng.integers(0,20),rng.integers(0,20),rng.integers(0,20),rng.integers(0,10)]
                else:
                    p=rng.integers(200,5000); x=[p,rng.integers(50000,2000000),rng.uniform(.1,8),rng.uniform(50,3000),rng.uniform(50000,2000000),rng.integers(0,150),rng.integers(0,150),rng.integers(0,100),rng.integers(0,50)]
                X.append(x); y.append(label)
        X=np.asarray(X,float); self.rf.fit(X,y); self.iso.fit(X); self.trained=True
    def predict(self,f):
        if not self.trained:self._train()
        x=np.asarray([[float(f.get(k,0)) for k in FEATURES]])
        p=self.rf.predict_proba(x)[0]; i=int(np.argmax(p))
        return {"label":self.rf.classes_[i],"confidence":float(p[i]),"anomaly":int(self.iso.predict(x)[0])==-1,
                "probabilities":{str(c):round(float(v),4) for c,v in zip(self.rf.classes_,p)},"features":{k:float(f.get(k,0)) for k in FEATURES}}
model=IDSModel()
