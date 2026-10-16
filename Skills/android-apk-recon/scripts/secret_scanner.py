#!/usr/bin/env python3
"""Module 8: Quick secret detection with entropy + allowlist filtering."""
import argparse,json,math,os,re,sys
from collections import defaultdict
PATTERNS=[
    ("AWS Access Key",r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',"critical"),
    ("Google API Key",r'\bAIza[0-9A-Za-z_-]{35}\b',"medium"),
    ("GitHub Token",r'\bgh[pousr]_[A-Za-z0-9_]{20,255}\b',"high"),
    ("Stripe Secret",r'\bsk_live_[A-Za-z0-9]{20,}\b',"critical"),
    ("OpenAI Key",r'\bsk-proj-[A-Za-z0-9_-]{20,}\b',"high"),
    ("Private Key",r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',"critical"),
    ("JWT",r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b',"high"),
    ("Generic Secret",r'(?i)(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*["\x27][A-Za-z0-9_/+=.-]{8,}["\x27]',"medium"),
    ("Firebase URL",r'https://[a-z0-9_-]+\.firebaseio\.com',"medium"),
    ("Slack Token",r'\bxox[bpras]-[A-Za-z0-9-]{10,}\b',"high"),
    ("SendGrid Key",r'\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b',"high"),
    ("MongoDB URI",r'mongodb(?:\+srv)?://[^\s"]{10,}',"critical"),
]
ALLOW={"AKIAIOSFODNN7EXAMPLE","your-api-key-here","INSERT_YOUR_API_KEY","TODO","CHANGEME","xxxxxxxx"}
EXT={".java",".kt",".xml",".json",".properties",".js",".smali"}
def entropy(s):
    if not s:return 0
    f=defaultdict(int)
    for c in s:f[c]+=1
    l=len(s);return -sum((v/l)*math.log2(v/l) for v in f.values())
def scan(d):
    findings=[]
    for root,dirs,files in os.walk(d):
        dirs[:]=[x for x in dirs if x not in{"node_modules",".git","META-INF"}]
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in EXT:continue
            fp=os.path.join(root,fn)
            try:c=open(fp,errors="ignore").read()
            except:continue
            rel=os.path.relpath(fp,d)
            if any(s in rel for s in["/com/google/","/androidx/","/kotlin/","/okhttp3/internal/"]):continue
            for name,pat,sev in PATTERNS:
                for m in re.finditer(pat,c):
                    txt=m.group(0)
                    if any(a.lower() in txt.lower() for a in ALLOW):continue
                    masked=txt[:8]+"***"+txt[-4:] if len(txt)>16 else txt[:4]+"***"
                    findings.append({"rule":name,"severity":sev,"match":masked,"file":rel,
                        "line":c[:m.start()].count("\n")+1,"entropy":round(entropy(txt),2)})
    seen=set();u=[]
    for f in findings:
        k=(f["rule"],f["file"],f["line"])
        if k not in seen:seen.add(k);u.append(f)
    return u
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("-o","--output",default="potential_secrets.json")
    a=p.parse_args();r=scan(a.dir)
    by_sev=defaultdict(int)
    for f in r:by_sev[f["severity"]]+=1
    json.dump({"total":len(r),"by_severity":dict(by_sev),"findings":r},open(a.output,"w"),indent=2)
    print(f"[+] {len(r)} potential secrets (C:{by_sev.get('critical',0)} H:{by_sev.get('high',0)} M:{by_sev.get('medium',0)})")
if __name__=="__main__":main()
