from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
def build_report(path,summary,detections):
 doc=SimpleDocTemplate(str(path),pagesize=A4); s=getSampleStyleSheet()
 story=[Paragraph("NetSentinel AI Pro — Security Report",s["Title"]),Spacer(1,12),Paragraph(f"Flows: {summary['flows']} | Detections: {summary['detections']} | Critical: {summary['critical']}",s["BodyText"]),Spacer(1,12)]
 data=[["Attack","Severity","Source","Destination","Score"]]+[[d.attack_type,d.severity,d.src_ip,d.dst_ip,str(round(d.threat_score,1))] for d in detections[:50]]
 t=Table(data,repeatRows=1); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172033")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),8)])); story.append(t); doc.build(story)
