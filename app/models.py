from datetime import datetime, timezone
from sqlalchemy import String,Integer,Float,DateTime,Text
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base
def now(): return datetime.now(timezone.utc)
class User(Base):
    __tablename__="users"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    username:Mapped[str]=mapped_column(String(80),unique=True,index=True)
    password_hash:Mapped[str]=mapped_column(String(255))
    role:Mapped[str]=mapped_column(String(30),default="analyst")
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Flow(Base):
    __tablename__="flows"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    src_ip:Mapped[str]=mapped_column(String(64)); dst_ip:Mapped[str]=mapped_column(String(64))
    protocol:Mapped[str]=mapped_column(String(16)); src_port:Mapped[int|None]=mapped_column(Integer,nullable=True); dst_port:Mapped[int|None]=mapped_column(Integer,nullable=True)
    packet_count:Mapped[int]=mapped_column(Integer,default=0); byte_count:Mapped[int]=mapped_column(Integer,default=0)
    duration:Mapped[float]=mapped_column(Float,default=0); packets_per_sec:Mapped[float]=mapped_column(Float,default=0); bytes_per_sec:Mapped[float]=mapped_column(Float,default=0)
    syn_count:Mapped[int]=mapped_column(Integer,default=0); ack_count:Mapped[int]=mapped_column(Integer,default=0); rst_count:Mapped[int]=mapped_column(Integer,default=0); fin_count:Mapped[int]=mapped_column(Integer,default=0)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Detection(Base):
    __tablename__="detections"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    attack_type:Mapped[str]=mapped_column(String(80)); severity:Mapped[str]=mapped_column(String(20))
    src_ip:Mapped[str]=mapped_column(String(64)); dst_ip:Mapped[str]=mapped_column(String(64))
    confidence:Mapped[float]=mapped_column(Float); threat_score:Mapped[float]=mapped_column(Float); explanation:Mapped[str]=mapped_column(Text)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Incident(Base):
    __tablename__="incidents"
    id:Mapped[int]=mapped_column(Integer,primary_key=True)
    attack_type:Mapped[str]=mapped_column(String(80)); severity:Mapped[str]=mapped_column(String(20))
    src_ip:Mapped[str]=mapped_column(String(64)); dst_ip:Mapped[str]=mapped_column(String(64))
    status:Mapped[str]=mapped_column(String(20),default="open"); threat_score:Mapped[float]=mapped_column(Float)
    evidence:Mapped[str]=mapped_column(Text); explanation:Mapped[str]=mapped_column(Text)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
