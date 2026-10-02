"""Rebuild original report/paper figures without network access.

Requires Pillow and ReportLab. All numerical charts read retained repository evidence.
PNG is 2x (2400px); PDF and SVG retain vector geometry and selectable text.
"""
from pathlib import Path
from collections import Counter
import csv, hashlib, html, json, math, textwrap
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
W, H = 1200, 720
INK, BLUE, TEAL, RED = '#203348', '#285a86', '#237e78', '#a24143'
PALE, GRAY = '#eef3f7', '#637385'
MANIFEST, CHECKS = [], []
FONT_DIR = Path('C:/Windows/Fonts')

def font(size, bold=False):
    return ImageFont.truetype(str(FONT_DIR / ('arialbd.ttf' if bold else 'arial.ttf')), size)

class Figure:
    def __init__(self, name, title, subtitle, report, paper, caption, sources):
        self.name, self.title = name, title
        self.meta = dict(id=name, title=title, report_section=report, paper_section=paper,
                         caption=caption, sources=sources, files={f:name+'.'+f for f in ['svg','pdf','png']})
        self.im = Image.new('RGB', (W*2,H*2), 'white')
        self.draw = ImageDraw.Draw(self.im)
        self.pdf = canvas.Canvas(str(OUT/(name+'.pdf')), pagesize=(W,H))
        self.pdf.setTitle(title)
        self.svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img"><title>{html.escape(title)}</title><rect width="1200" height="720" fill="white"/>']
        self.text(38,38,title,27,bold=True)
        self.text(38,75,subtitle,16,color=GRAY)
        self.line([(38,104),(1162,104)], color='#b7c6d2')
        self.text(38,684,'Agent Security MCP Gateway | Phase 2 | Original repository figure',13,color=GRAY)
    def text(self,x,y,s,size=18,color=INK,bold=False):
        f=font(size*2,bold); bbox=self.draw.textbbox((x*2,y*2),s,font=f)
        if bbox[2]>W*2-30 or bbox[3]>H*2-20:
            raise ValueError(f'Text outside canvas: {self.name}: {s}')
        self.draw.text((x*2,y*2),s,font=f,fill=color)
        self.pdf.setFont('Helvetica-Bold' if bold else 'Helvetica',size)
        self.pdf.setFillColor(HexColor(color)); self.pdf.drawString(x,H-y-size*.83,s)
        self.svg.append(f'<text x="{x}" y="{y+size*.83}" font-family="Arial,Helvetica,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{html.escape(s)}</text>')
    def rect(self,x,y,w,h,fill=PALE,stroke='#a8bbc9'):
        self.draw.rectangle((x*2,y*2,(x+w)*2,(y+h)*2),fill=fill,outline=stroke,width=2)
        self.pdf.setStrokeColor(HexColor(stroke));self.pdf.setFillColor(HexColor(fill));self.pdf.rect(x,H-y-h,w,h,fill=1,stroke=1)
        self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}"/>')
    def box(self,x,y,w,h,label,body='',color=BLUE):
        self.rect(x,y,w,h);self.rect(x,y,5,h,color,color)
        lines=wrap(label,w-30,19,True)
        yy=y+13
        for s in lines:self.text(x+16,yy,s,19,bold=True,color=color);yy+=24
        for s in wrap(body,w-30,16):self.text(x+16,yy+8,s,16);yy+=21
        if yy+9>y+h: raise ValueError(f'Box overflow: {self.name}: {label}')
    def line(self,pts,color=BLUE,dash=False,arrow=False):
        scaled=[(x*2,y*2) for x,y in pts]
        if dash:
            for (x1,y1),(x2,y2) in zip(scaled,scaled[1:]):
                length=math.hypot(x2-x1,y2-y1)
                for start in range(0,int(length),18):
                    a=start/max(length,1);b=min(start+10,length)/max(length,1)
                    self.draw.line([(x1+(x2-x1)*a,y1+(y2-y1)*a),(x1+(x2-x1)*b,y1+(y2-y1)*b)],fill=color,width=3)
        else:self.draw.line(scaled,fill=color,width=3)
        self.pdf.setStrokeColor(HexColor(color));self.pdf.setLineWidth(1.4);self.pdf.setDash(5,4) if dash else self.pdf.setDash()
        p=self.pdf.beginPath();p.moveTo(pts[0][0],H-pts[0][1])
        for x,y in pts[1:]:p.lineTo(x,H-y)
        self.pdf.drawPath(p);self.pdf.setDash()
        self.svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in pts)}" fill="none" stroke="{color}" stroke-width="1.4"'+(' stroke-dasharray="5 4"' if dash else '')+'/>')
        if arrow:
            x,y=pts[-1];px,py=pts[-2];a=math.atan2(y-py,x-px)
            tri=[(x,y),(x-10*math.cos(a-.4),y-10*math.sin(a-.4)),(x-10*math.cos(a+.4),y-10*math.sin(a+.4))]
            self.draw.polygon([(a*2,b*2) for a,b in tri],fill=color)
            p=self.pdf.beginPath();p.moveTo(tri[0][0],H-tri[0][1])
            for a,b in tri[1:]:p.lineTo(a,H-b)
            p.close();self.pdf.setFillColor(HexColor(color));self.pdf.drawPath(p,fill=1,stroke=0)
            self.svg.append(f'<polygon points="{" ".join(f"{a},{b}" for a,b in tri)}" fill="{color}"/>')
    def arrow(self,x1,y1,x2,y2,**kw):self.line([(x1,y1),(x2,y2)],arrow=True,**kw)
    def note(self,s):
        for i,line in enumerate(wrap(s,1115,15)):self.text(40,628+i*19,line,15,color=GRAY)
    def save(self):
        self.svg.append('</svg>');(OUT/(self.name+'.svg')).write_text('\n'.join(self.svg),encoding='utf-8')
        self.im.save(OUT/(self.name+'.png'),dpi=(192,192));self.pdf.save()
        MANIFEST.append(self.meta);CHECKS.append({'id':self.name,'canvas_bounds':'pass','box_text_fit':'pass'})

def wrap(s,width,size,bold=False):
    if not s:return []
    result=[];f=font(size,bold)
    for para in s.split('\n'):
        line=''
        for word in para.split():
            trial=(line+' '+word).strip()
            if f.getlength(trial)>width and line:result.append(line);line=word
            else:line=trial
        result.append(line)
    return result

def fig(name,title,subtitle,report,paper,caption,sources=None):
    return Figure(name,title,subtitle,report,paper,caption,sources or ['docs/technical-specification.md','report.md','paper/main.tex'])

def flow(name,title,subtitle,items,report,paper,caption,note='',sources=None):
    f=fig(name,title,subtitle,report,paper,caption,sources)
    # Six steps in two rows, with serpentine path.
    pos=[(40,150),(435,150),(830,150),(830,382),(435,382),(40,382)]
    for i,(label,body) in enumerate(items):
        x,y=pos[i];f.box(x,y,330,155,f'{i+1:02d}  {label}',body)
        if i and i!=3:
            xx,yy=pos[i-1];f.arrow(xx+(330 if i<3 else 0),yy+77,x+(0 if i<3 else 330),y+77)
        elif i==3:f.arrow(995,305,995,382)
    if note:f.note(note)
    f.save()

def table(name,title,subtitle,headers,rows,widths,report,paper,caption,sources=None):
    f=fig(name,title,subtitle,report,paper,caption,sources)
    x0,y=40,140;size=16
    for i,row in enumerate([headers]+rows):
        lines=[wrap(str(v),w-24,size,bold=i==0) for v,w in zip(row,widths)]
        rh=max(48,max(map(len,lines))*22+20);x=x0
        for j,(val,w) in enumerate(zip(lines,widths)):
            f.rect(x,y,w,rh,BLUE if i==0 else ('#f2f5f8' if i%2 else '#ffffff'))
            for k,s in enumerate(val):f.text(x+12,y+12+k*22,s,size,color='#ffffff' if i==0 else INK,bold=i==0)
            x+=w
        y+=rh
    if y>620:raise ValueError('table overflow '+name)
    with (OUT/(name+'.csv')).open('w',newline='',encoding='utf-8') as handle:csv.writer(handle).writerows([headers]+rows)
    f.meta['editable_table']=name+'.csv';f.save()

def bars(name,title,subtitle,data,unit,report,paper,caption,sources,note):
    f=fig(name,title,subtitle,report,paper,caption,sources)
    left,top,plotw=350,155,690
    maxval=max(v for _,v in data); tickmax=math.ceil(maxval/5)*5
    for t in range(6):
        val=tickmax*t/5;x=left+plotw*t/5
        f.line([(x,top-8),(x,top+len(data)*75)],color='#dbe3e9');f.text(x-12,top+len(data)*75+15,str(round(val)),14,color=GRAY)
    for i,(label,v) in enumerate(data):
        yy=top+i*75;f.text(40,yy+13,label,18)
        f.rect(left,yy+4,plotw*v/tickmax,44,BLUE,BLUE);f.text(left+plotw*v/tickmax+12,yy+14,str(v),18,bold=True)
    f.text(left,top+len(data)*75+48,unit,16,color=GRAY);f.note(note)
    with (OUT/(name+'.csv')).open('w',newline='',encoding='utf-8') as handle:csv.writer(handle).writerows([['category','count']]+data)
    f.meta['editable_table']=name+'.csv';f.save()

def main():
    flow('01-gateway-architecture','Bidirectional MCP reference monitor','Requests and responses cross separate policy boundaries.',[
        ('Authenticated client','Identity is resolved outside model arguments; bind an opaque session.'),
        ('Request monitor','Resolve route and canonical effect; compose immutable policy and current coverage.'),
        ('Exact authorization','Persist decision; obtain single-use human approval where required.'),
        ('Downstream operation','Use route-scoped gateway credentials for one authorized initiation.'),
        ('Result monitor','Verify provenance, schema, bounds, secrets and data egress.'),
        ('Governed response','Return allowed content and factual awareness; persist correlated outcome.')],
        '6 Architecture','IV Reference Monitor Design','Separate request and result governance surrounds exact downstream forwarding.',
        'PostgreSQL persists decisions, approval, dispatch, outcome and audit. Independent controls must close native/direct bypasses.')
    flow('02-agent-request-result-flow','Agent request, decision and governed result','A correct final answer cannot erase an unsafe intermediate effect.',[
        ('User task','The host gives the agent a task and tool context.'),('Agent proposal','Model-controlled tool name and arguments remain untrusted.'),
        ('Gateway decision','Authorize the resolved effect, identity, route and environment.'),('Authorized execution','Only a current exact permission crosses the effect boundary.'),
        ('Result disposition','Release, redact, quarantine or deny independently of request authorization.'),('Next agent step','Treat returned material as untrusted; re-evaluate each subsequent call.')],
        '7 End-to-end call flow','I Introduction; IV Design','Every intermediate request and result requires its own boundary checks.')
    flow('03-mcp-lifecycle','MCP lifecycle and authorization checkpoints','Pinned protocol profile: MCP 2025-06-18.',[
        ('Authenticate','Resolve transport principal before accepting the MCP payload.'),('Initialize','Negotiate version and capabilities; create bound session.'),
        ('Initialized state','Only valid lifecycle transitions enable normal protocol operations.'),('Discovery','List authorized healthy routes; metadata remains untrusted.'),
        ('Call and response','Recheck current route, policy, admission, exact authority and result.'),('Termination','Cancel bounded work and close session state safely.')],
        '3.2 Simplified MCP lifecycle','II Background; V Implementation','Lifecycle negotiation permits communication; it does not grant blanket authorization.')
    flow('04-canonical-resolution','From syntax to a canonical security action','Semantic disposition and exact execution identity are distinct.',[
        ('Registered request','Validate the versioned tool contract and current schema.'),('Trusted analyzer','Use the route-selected category adapter; never execute unknown syntax.'),
        ('Resolve resources','Identify resource, effect, environment, data flow and parsing evidence.'),('Exact binding','Bind identity, session, request, route, tool, schema and argument digest.'),
        ('Canonical action','Recompute digests; preserve uncertainty and untrusted influences.'),('Policy input','Unresolved analysis cannot become a harmless Tier 0 or Tier 1 action.')],
        '8.5 Canonicalization and analyzers','III-B Semantic Equivalence; IV-A Canonicalization','Canonicalization joins trusted semantic findings with exact invocation bindings.')
    f=fig('05-representation-invariance','Equivalent effects, separate approvals','Fixture-conformance evidence; not universal semantic recognition.','8.5 Canonicalization','VI-A RQ1','Three trusted-resolver variants share destructive policy; their exact execution bindings remain separate.',['test/unit/canonical-policy-v1.test.ts','paper/main.tex'])
    for y,label in [(150,'File-removal tool'),(300,'Shell tool'),(450,'Workspace-mutation tool')]:
        f.box(40,y,290,100,label,'Distinct route and arguments');f.arrow(330,y+50,440,350)
    f.box(440,280,305,145,'Same resolved effect','Same fixture resource\nDELETE; destructive\nTrusted resolver semantics')
    f.arrow(745,350,825,350);f.box(825,280,335,145,'Same semantic policy','Tier 3; REQUIRE_APPROVAL\nFixture ENFORCED scope')
    f.note('Approval does not transfer between representations. Current route, schema and coverage restrictions may strengthen the final decision.');f.save()
    table('06-policy-precedence','Most-restrictive decision composition','An approval satisfies an approval requirement; it never cancels denial.',
          ['Priority','Decision','Operational meaning'],[['1','DENY','Withhold the operation.'],['2','REQUIRE_APPROVAL','Obtain one matching exact human authorization.'],['3','SANDBOX','Execute only within the required validated sandbox.'],['4','ALLOW_WITH_CONSTRAINTS','Enforce all compatible obligations.'],['5','ALLOW','Proceed only after all remaining boundary checks.']],
          [100,330,690],'5 Security invariants; 7.2 Decisions','III-B; IV-B Deterministic Policy','Policy joins select the most restrictive decision; conflicting enforcement resolves to denial.')
    table('07-risk-tier-table','Risk tiers and required treatment','Classification follows effect and context, not reassuring tool names.',
          ['Tier','Effect class','Default treatment'],[['0','Proven non-sensitive read; no egress or execution','Allow only with verified scope and coverage.'],['1','Bounded reversible local write','Allow or constrain within an approved isolated scope.'],['2','Executable, networked, supply-chain or meaningful state change','Sandbox, constrain or require approval.'],['3','Production, privileged, destructive, credentials or hard to reverse','One exact approval or denial; trust cannot weaken this.']],
          [85,500,535],'7.3 Risk tiers','III-B Semantic Equivalence','Four risk tiers preserve immutable high-risk approval requirements.')
    flow('08-approval-single-use','Exact human approval and atomic consumption','Human decision and downstream authority remain bound to one invocation.',[
        ('Canonical summary','Show target, effect, route, data flow, risk, expiry and coverage.'),('Human decision','Independently authenticate; Approve once or Deny.'),
        ('Durable dispatch','Commit APPROVED and dispatch together in PostgreSQL.'),('Reload and revalidate','Check stored authority, exact binding, expiry and latest scoped coverage.'),
        ('Atomic consumption','Row-lock approval; consume and create unique forwarding attempt together.'),('One initiation','Only the winning consumer obtains exact credential-use authority.')],
        '8.6 Human approval and browser UI','IV-C Single-Use Approval','Approval is consumed transactionally and permits at most one gateway initiation.',
        'Default maximum approval lifetime: five minutes. This is not exactly-once execution of a remote effect.')
    f=fig('09-approval-concurrency','Competing consumers of one approval','Durable evidence: two PostgreSQL connections.','8.6 Approval; 9 PostgreSQL','VI-B Exact Authority','The database permits one consumption and rejects its competitor.',['test/integration/postgres-persistence-v1.test.ts','paper/evidence-notes.md'])
    f.box(40,155,280,110,'Connection A','Consume same approval');f.box(40,415,280,110,'Connection B','Consume same approval')
    f.arrow(320,210,450,290);f.arrow(320,470,450,350)
    f.box(450,250,290,155,'Row-locked transaction','Check state and expiry\nConsume + unique attempt')
    f.arrow(740,288,850,210);f.arrow(740,370,850,470)
    f.box(850,155,300,110,'Winning consumer','One forwarding-attempt row',TEAL);f.box(850,415,300,110,'Competing consumer','Rejected; no credential use',RED)
    f.note('Illustrative winner assignment; either connection may win. A separate 16-way process-local fixture is not durable database evidence.');f.save()
    f=fig('10-restart-recovery','Conservative recovery after interruption','Do not retry a request whose remote effect is uncertain.','8.6 Approval; 9 PostgreSQL','IV-C Recovery','Recovery separates unconsumed authorization from consumed uncertain execution.')
    f.box(40,270,290,140,'Stale dispatch','Worker claims recovery with row locking and SKIP LOCKED.')
    f.arrow(330,310,470,205);f.arrow(330,370,470,465)
    f.box(470,150,300,125,'Not consumed','Revoke approval; no forwarding attempt',RED)
    f.box(470,410,300,125,'Consumed; no outcome','Record UNKNOWN and possible partial effects',RED)
    f.arrow(770,212,850,212);f.arrow(770,472,850,472)
    f.box(850,150,300,125,'REVOKED','No downstream initiation');f.box(850,410,300,125,'UNKNOWN','Investigate; never automatically retry')
    f.note('Gateway initiation and remote completion are different facts. Claim timeout must exceed the finite executor timeout.');f.save()
    flow('11-result-governance','A permitted request can yield a prohibited result','Result release is a separate policy decision.',[
        ('Receive result','Authenticated server response still contains untrusted data.'),('Bind provenance','Match server, request, session, action, route, schema and call chain.'),
        ('Validate structure','Check result schema, digests and observed byte bounds.'),('Check data flow','Apply sensitive-data and egress rules; redact known secrets.'),
        ('Select disposition','Release, redact, quarantine or deny; suppress raw unsafe errors.'),('Persist and return','Record remote outcome separately from content-release disposition.')],
        '8.7 Result mediation','IV-D Credential Custody and Result Governance','Authenticated provenance identifies a source; it does not make content truthful or safe.',
        'Result filtering cannot undo a remote side effect that has already executed.')
    f=fig('12-credential-custody','Credential custody and the non-exporting sink','Model-visible data must never contain downstream credential material.','8.2 Identity and credentials','IV-D Credential Custody','The broker binds gateway-only credential use to the exact authorized attempt.')
    f.box(40,220,280,170,'Agent / MCP client','Receives factual decisions and governed results. No downstream credential.',RED)
    f.box(430,140,300,135,'Vault provider','Version-pinned KV v2; audience and profile integrity')
    f.box(430,405,300,150,'Credential broker','Lease binds action, attempt, route, endpoint, session and expiry')
    f.arrow(580,275,580,405);f.arrow(320,305,430,465)
    f.box(850,220,305,170,'Non-exporting HTTP sink','Credential use inside the sink; exact endpoint; redirects refused',TEAL)
    f.arrow(730,480,1000,390)
    f.note('Diagram describes the implemented authority boundary. Disposable composition is not evidence of production credential custody.');f.save()
    table('13-coverage-state-table','Truthful coverage is scoped evidence','A functional gateway is insufficient to establish exclusive resource access.',
          ['State','Meaning','Protection claim'],[['ENFORCED','Authenticated, governed, audited, fail-safe and exclusively mediated','Exact declared path only; current trusted evidence required.'],['DEGRADED','A required guarantee or bypass control is incomplete','Block protected mutations.'],['OBSERVE_ONLY','Recorded traffic cannot reliably be blocked','No enforcement claim.'],['UNPROTECTED','No verified enforcing path exists','Current deployment state; protected forwarding disabled.']],
          [220,495,405],'8.8 Coverage','III-C Coverage; VI-C Evidence Fidelity','Coverage reports guarantees for a declared scope rather than feature-completion percentages.')
    f=fig('14-bypass-trust-boundaries','MCP mediation and native/direct bypass paths','Independent OS, network, IAM and downstream controls close the outer boundary.','4 Scope; 8.8 Coverage','III-A Threat Model','Native and direct paths are outside MCP mediation unless independently constrained.')
    f.box(40,200,255,155,'Agent runtime','Untrusted proposals and external content',RED)
    f.box(445,200,270,155,'MCP gateway','Policy + exact approval + result monitor')
    f.box(885,200,270,155,'Protected resource','Least-privilege downstream authorization')
    f.arrow(295,270,445,270);f.arrow(715,270,885,270)
    f.line([(160,355),(160,505),(1020,505),(1020,355)],color=RED,dash=True,arrow=True)
    f.text(375,462,'Native shell / browser / filesystem / direct network',19,color=RED,bold=True)
    f.note('A reachable or unverified bypass prevents an ENFORCED claim. Current production coverage remains UNPROTECTED.');f.save()
    flow('15-discovery-integrity','Integrity-checked discovery and route quarantine','Tool visibility never replaces call-time authorization.',[
        ('Administrative registration','Pin identity, audience, scope, environment and route ownership.'),('Authenticated observation','Compute protocol, capability, tool-set and schema digests.'),
        ('Integrity comparison','Reject duplicate names and ambiguity; detect drift.'),('Quarantine latch','Drifted or unhealthy routes remain unavailable.'),
        ('Explicit review','An authorized administrator reviews matching current evidence.'),('Call-time recheck','Resolve one current authorized route; re-evaluate every call.')],
        '8.3 Discovery and routing','IV-A Authenticated Discovery','Schema or capability drift latches quarantine; later matching metadata is not automatic restoration.')
    table('16-protocol-guard-table','Protocol admission and bounded execution','Limits apply to authenticated scopes and remain active during work.',
          ['Control','Scope / evidence','Failure response'],[['Replay resistance','Session-bound request identifiers, nonces and timestamp skew','Reject replay before invocation.'],['Rate and concurrency','User, agent, client, session, route, server, destination and action','Deny admission at exhausted quotas.'],['Payload and recursion','Input/result bytes, depth, fan-out and cyclic ancestry','Stop oversized or recursive work.'],['Deadline and cancellation','Bounded time, abort propagation and runtime checkpoints','Cancel; persist safe outcome classification.'],['Dependency health','Identity, route, policy, database, parser and downstream','Fail closed; circuit breaker; no memory fallback.']],
          [225,580,315],'8.4 Protocol guard','IV-B Policy and Admission','Protocol guards bound replay and resource abuse without granting authorization.')
    flow('17-audit-trajectory','The complete request-to-outcome audit trajectory','Ordinary audit rows exclude raw arguments, result content and known secrets.',[
        ('Request and action','Authenticated context + canonical effect + exact digests.'),('Policy decision','Version, tier, disposition, reasons, constraints and coverage.'),
        ('Human authority','Exact decision, expiry and binding; no exposed approval token.'),('Forwarding attempt','Durable consumption and one correlated initiation record.'),
        ('Result and outcome','Provenance, release disposition, completion or uncertainty.'),('Tamper evidence','Append-only records; SHA-256 event-chain linkage and recovery state.')],
        '9 PostgreSQL data model','IV Design; VI-B Authority','Linked state distinguishes rejected proposals, approved attempts, remote effects and returned data.',
        'Exact runtime arguments are separately AES-256-GCM encrypted; the external encryption key is not stored in PostgreSQL.')
    table('18-failure-response-table','Failure triggers and conservative behavior','Representative locally exercised conditions; not exhaustive fault coverage.',
          ['Trigger','Safe response'],[['Arguments, route or policy changed','Reject prior approval binding; require a new evaluation.'],['Approval consumed or expired','No second forwarding-attempt record or credential use.'],['Newer coverage degradation','Block mutation before credential-consuming operation.'],['Stale consumed dispatch; no outcome','Persist UNKNOWN / possible partial effects; do not retry.'],['Invalid provenance, schema or secret-bearing result','Withhold, quarantine or redact before release.'],['Required persistence unavailable','Fail closed; no runtime in-memory fallback.']],
          [510,610],'13 Testing; 16 Limitations','VI-B Failure Cases','Failure handling preserves authority and uncertainty across request and result boundaries.')
    flow('19-trust-supervisor-boundaries','Shadow trust and advisory supervision','Neither behavioral reputation nor an LLM verdict is authorization.',[
        ('Deterministic decision','Hard policy, Tier 3 approval and coverage are authoritative.'),('Eligible evidence','Only verified outcomes can count positively; unknown outcomes cannot.'),
        ('Shadow computation','Calculate trust or counterfactual output without changing policy.'),('Anomaly freeze','Identity change, route drift, audit gaps and missing outcomes stop positive trust.'),
        ('Advisory supervisor','Minimized redacted context; structured recommendation can add restriction.'),('Promotion gate','Future bounded influence requires independent repeated-trial evidence.')],
        '8.9 Dynamic trust and supervisor','V Implementation; VII Limitations','Trust stays observational; supervisor output cannot weaken immutable decisions.')
    flow('20-research-evaluation-design','Planned paired security and utility study','Research protocol; comparative effectiveness has not been established.',[
        ('Freeze contracts','Pin tool schemas, grammar, resources, versions and platform.'),('Independent labels','Review candidate effects without resolver predictions; retain disagreements.'),
        ('Family-level split','Create new untouched held-out families; do not relabel exposed cases.'),('Paired conditions','Native MCP, deterministic policy, awareness, ablations and relevant baselines.'),
        ('Observe trajectories','Capture intermediate effects, sink receipts, faults and legitimate completion.'),('Report denominators','Attack success, utility, false decisions, latency and approval burden separately.')],
        '13 Testing; 16 Current limitations','VII-B Next Experiments','Independent semantic labels and paired trajectories are needed beyond local conformance.',
        'This is a study design, not an experiment result. No fabricated attack-success or latency bars are provided.', ['docs/research-protocol.md','research/resolver/README.md'])
    bars('21-historical-validation-counts','Historical local verification counts','September 25, 2026 manuscript verification snapshot.',
         [('Unit tests',295),('Integration tests',66),('Browser workflows',4)],'Number of checks (different test granularities)',
         '13.1 Test layers','VI Local Verification','Dated verification counts describe test inventory, not a security effectiveness rate.',
         ['paper/evidence-notes.md','paper/main.tex'],'Counts have different granularities and shared fixtures. Do not infer attack prevention, statistical confidence or production coverage.')
    upstream=json.loads((ROOT/'artifacts/open-source-mcp-smoke.json').read_text())
    bars('22-retained-mcp-tool-counts','Retained local MCP discovery observations','Artifact dated September 20, 2026; selected upstream versions only.',
         [('Everything MCP',upstream['servers'][0]['advertisedToolCount']),('Playwright MCP',upstream['servers'][1]['advertisedToolCount'])],
         'Advertised tools in retained discovery response','14 Release evidence','VI-C Interoperability','Pinned local servers advertise 13 and 26 tools; harmless selected calls succeed and unknown tools are rejected.',
         ['artifacts/open-source-mcp-smoke.json'],'These are locally launched servers, not independently operated hosts. Tool counts are not protection or compatibility percentages.')
    corpus=json.loads((ROOT/'research/resolver/corpus-v1.json').read_text()); counts=Counter(c['intent'] for c in corpus['cases'])
    bars('23-candidate-corpus-inventory','Candidate resolver development corpus','CANDIDATE_UNREVIEWED labels; every family is DEVELOPMENT.',
         [('Benign-intent calls',counts['BENIGN']),('Adversarial-intent calls',counts['ADVERSARIAL'])],
         'Number of author-labelled candidate calls','8.5 Analyzers; 16 Research limits','VII-B Next Experiments','Candidate corpus composition is an inventory, not independently reviewed resolver accuracy.',
         ['research/resolver/corpus-v1.json','research/resolver/README.md'],
         f"{len(corpus['cases'])} calls across {len(set(c['familyId'] for c in corpus['cases']))} families; no held-out cases. Intent labels are not resolver verdicts or observed attack outcomes.")
    table('24-release-assurance-table','Local engineering completion and production assurance','Separate evidence questions prevent a misleading protection claim.',
          ['Evidence boundary','Recorded state','What remains outside the claim'],[['Phase 2 implementation','21 locally complete feature records','Independent production security review.'],['Regression / workflows','295 unit; 66 integration; 4 browser (historical)','Adaptive comparative security/utility experiments.'],['Upstream interoperability','Two version-pinned locally launched servers','Independently administered host operation.'],['Local packaging','Unsigned and unpublished non-production artifacts','Signing, publication and operational ownership.'],['Deployment coverage','UNPROTECTED; protected forwarding disabled','Exclusive mediation and production credential custody.']],
          [280,420,420],'14 Release; 15 Status; 16 Limitations','VI-C; VII Discussion','Local implementation completion does not satisfy deferred production assurance.', ['docs/featurelist.json','paper/evidence-notes.md','artifacts/open-source-mcp-smoke.json'])
    # Retain hashes so readers can identify the evidence actually used at generation.
    sources=sorted({p for m in MANIFEST for p in m['sources']})
    evidence={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources}
    (OUT/'manifest.json').write_text(json.dumps({'schemaVersion':'1.0.0','prepared':'2026-10-01','original_artwork':True,'evidence_sha256':evidence,'figures':MANIFEST},indent=2),encoding='utf-8')
    (OUT/'visual-qa.json').write_text(json.dumps({'checks':CHECKS,'count':len(CHECKS),'method':'Pillow text bounds; per-box wrapped-line height; table bottom bounds; SVG XML and image dimensions verified separately.'},indent=2),encoding='utf-8')
    cards=[]
    for m in MANIFEST:
        cards.append(f'<article><h2>{html.escape(m["title"])}</h2><img src="{m["id"]}.svg" alt="{html.escape(m["caption"],quote=True)}"><p>{html.escape(m["caption"])}</p><p class="meta">Report: {html.escape(m["report_section"])}<br>Paper: {html.escape(m["paper_section"])}</p><p>'+ ' | '.join(f'<a href="{m["id"]}.{ext}">{ext.upper()}</a>' for ext in ['png','svg','pdf'])+'</p></article>')
    (OUT/'gallery.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Report and paper visual atlas</title><style>body{max-width:1250px;margin:auto;padding:32px;font:17px Arial;color:#203348;background:#eef3f7}h1{font-size:32px}article{background:white;padding:24px;margin:24px 0;border:1px solid #cad7df}img{width:100%;height:auto}.meta{font-size:15px;color:#637385}a{color:#285a86}</style><h1>Report and paper visual atlas</h1><p>24 original, evidence-scoped figures. Numerical charts use dated retained evidence or explicit candidate-corpus inventories. Comparative security and performance data have not been invented.</p>'+''.join(cards)+'</html>',encoding='utf-8')
    sheet=Image.new('RGB',(1800,3040),'#edf2f5');sd=ImageDraw.Draw(sheet)
    for i,m in enumerate(MANIFEST):
        tile=Image.open(OUT/(m['id']+'.png'));tile.thumbnail((580,348))
        x=(i%3)*600+10;y=(i//3)*380+8
        sheet.paste(tile,(x,y));sd.text((x,y+352),m['id'],font=font(14),fill=INK)
    sheet.save(OUT/'contact-sheet.png')
    import xml.etree.ElementTree as ET
    for m in MANIFEST:
        ET.parse(OUT/(m['id']+'.svg'))
        assert Image.open(OUT/(m['id']+'.png')).size==(W*2,H*2)
    print(f'Generated {len(MANIFEST)} figures: PNG, SVG and PDF; tables/charts also have CSV sources.')

if __name__=='__main__':main()
