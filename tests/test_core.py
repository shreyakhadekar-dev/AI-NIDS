from app.cn_lab import subnet,routing_demo,congestion
from app.ml import IDSModel
def test_subnet(): assert subnet("192.168.1.0/24")["usable_hosts"]==254
def test_routing(): assert routing_demo()["distances"]["D"]==4
def test_congestion(): assert len(congestion()["rounds"])==12
def test_model():
 r=IDSModel().predict({"packet_count":10,"byte_count":1000,"duration":1,"packets_per_sec":10,"bytes_per_sec":1000,"syn_count":1,"ack_count":1,"rst_count":0,"fin_count":0})
 assert "label" in r
