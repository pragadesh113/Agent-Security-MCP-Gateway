"""Build original vector diagrams for the IEEE manuscript (ReportLab)."""
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, black, white

OUT = Path(__file__).resolve().parent / 'figures'
OUT.mkdir(exist_ok=True)
INK = HexColor('#172a3a')
PALE = HexColor('#eef2f5')

def box(c, x, y, w, h, lines, fill=PALE, size=8):
    c.setStrokeColor(INK); c.setFillColor(fill); c.setLineWidth(.65)
    c.roundRect(x, y, w, h, 3, stroke=1, fill=1)
    c.setFillColor(black); c.setFont('Times-Roman', size)
    for i, line in enumerate(lines):
        c.drawCentredString(x+w/2, y+h/2+(len(lines)-1)*size*.57-i*size*1.14-2.3, line)

def arrow(c, x1, y1, x2, y2, dashed=False):
    import math
    c.setStrokeColor(INK); c.setFillColor(INK); c.setLineWidth(.7)
    c.setDash(3,2) if dashed else c.setDash()
    c.line(x1,y1,x2,y2); c.setDash()
    a=math.atan2(y2-y1,x2-x1); n=4
    p=c.beginPath(); p.moveTo(x2,y2)
    p.lineTo(x2-n*math.cos(a-.45),y2-n*math.sin(a-.45))
    p.lineTo(x2-n*math.cos(a+.45),y2-n*math.sin(a+.45)); p.close()
    c.drawPath(p,fill=1,stroke=0)

def label(c,x,y,s,size=7):
    c.setFillColor(black); c.setFont('Times-Roman',size); c.drawCentredString(x,y,s)

c=canvas.Canvas(str(OUT/'architecture.pdf'),pagesize=(510,164))
c.setTitle('Bidirectional MCP mediation and independent enforcement boundary')
c.setStrokeColor(INK); c.setDash(4,2); c.roundRect(88,40,327,116,5,stroke=1,fill=0); c.setDash()
label(c,250,144,'TRUSTED GATEWAY AND PERSISTENCE',8)
box(c,0,91,71,34,['Agent / MCP client','untrusted input'])
box(c,102,96,83,34,['Identity, protocol','and route checks'])
box(c,201,96,83,34,['Canonical action','and fixed policy'])
box(c,301,96,99,34,['Exact approval','and credential broker'])
box(c,436,91,74,34,['MCP server','untrusted results'])
for a,b in [(71,102),(185,201),(284,301),(400,436)]: arrow(c,a,110,b,110)
box(c,211,51,121,28,['Result provenance, schema,','redaction and egress guard'])
arrow(c,472,91,472,65); arrow(c,472,65,332,65); arrow(c,211,65,36,65); arrow(c,36,65,36,91)
label(c,392,70,'authenticated result')
label(c,129,70,'governed release')
box(c,99,4,184,25,['PostgreSQL: decisions, approvals, outcomes, audit'],size=7.5)
box(c,301,4,209,25,['Independent OS / network / IAM bypass controls'],size=7.5)
arrow(c,190,40,190,29,True); arrow(c,405,29,405,40,True)
c.save()

c=canvas.Canvas(str(OUT/'decision-flow.pdf'),pagesize=(252,181))
c.setTitle('Fail-closed authorization flow')
box(c,21,150,170,26,['Authenticate and resolve current route'])
box(c,21,110,170,26,['Canonicalize resource, effect and data flow'])
box(c,21,70,170,26,['Compose policy; validate current coverage'])
box(c,0,23,73,29,['Deny / unresolved','withhold effect'],size=7.5)
box(c,88,23,73,29,['Approval needed','exact human choice'],size=7.5)
box(c,177,23,75,29,['Allow / constrain','enforce obligations'],size=7.5)
arrow(c,106,150,106,136); arrow(c,106,110,106,96)
arrow(c,54,70,37,52); arrow(c,117,70,124,52); arrow(c,179,70,213,52)
arrow(c,161,37,177,37)
label(c,169,44,'yes',6.5)
label(c,127,6,'Before forwarding: revalidate, persist, consume once',7.5)
c.save()

c=canvas.Canvas(str(OUT/'approval-flow.pdf'),pagesize=(252,199))
c.setTitle('Approval dispatch, single-use consumption and conservative recovery')
box(c,59,166,137,26,['Human approves exact request'])
box(c,59,122,137,29,['Transaction: APPROVED','+ durable dispatch'])
box(c,59,78,137,29,['Claim; reload; revalidate','consume + create attempt'])
box(c,59,34,137,29,['Use credential; forward once','govern and persist outcome'])
for y1,y2 in [(166,151),(122,107),(78,63)]: arrow(c,128,y1,128,y2)
arrow(c,59,135,19,135,True); arrow(c,19,135,19,15,True)
arrow(c,196,90,231,90,True); arrow(c,231,90,231,15,True)
label(c,27,153,'stale before',6.7); label(c,27,145,'consumption',6.7)
label(c,224,110,'stale after',6.7); label(c,224,102,'consumption',6.7)
label(c,41,5,'REVOKED; no send',7)
label(c,206,5,'UNKNOWN; no retry',7)
c.save()
print('Built three vector figures in', OUT)
