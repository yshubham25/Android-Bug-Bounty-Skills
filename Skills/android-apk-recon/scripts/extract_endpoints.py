#!/usr/bin/env python3
"""Extract URLs, API endpoints, domains, IPs from decompiled source."""
import argparse,json,os,re,sys
URL_PAT=re.compile(r'https?://[^\s"\'<>\)\]\}\\]{5,}')
IP_PAT=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b')
API_PAT=re.compile(r'["\']/(api|v[0-9]|graphql|rest|auth|login|user|admin|oauth|token|webhook|callback|internal|staging|dev)[/\w.-]*["\']')
RETRO_PAT=re.compile(r'@(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"')
SKIP={"schemas.android.com","www.w3.org","ns.adobe.com","xmlpull.org","apache.org"}
EXT={".java",".kt",".xml",".json",".js",".properties",".smali"}
def extract(d):
    urls=[];ips=[];apis=[];retro=[];domains=set()
    for root,_,files in os.walk(d):
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in EXT:continue
            fp=os.path.join(root,fn)
            try:c=open(fp,errors="ignore").read()
            except:continue
            rel=os.path.relpath(fp,d)
            for m in URL_PAT.finditer(c):
                u=m.group(0).rstrip(".,;:)")
                if any(s in u for s in SKIP):continue
                urls.append({"url":u,"file":rel,"line":c[:m.start()].count("\n")+1})
                try:
                    from urllib.parse import urlparse
                    h=urlparse(u).hostname
                    if h:domains.add(h)
                except:pass
            for m in IP_PAT.finditer(c):
                ip=m.group(0)
                if not ip.startswith("0.") and ip!="127.0.0.1":ips.append({"ip":ip,"file":rel})
            for m in API_PAT.finditer(c):apis.append({"path":m.group(0).strip("\"'"),"file":rel})
            for m in RETRO_PAT.finditer(c):retro.append({"path":m.group(1),"file":rel})
    su=list({u["url"]:u for u in urls}.values());sa=list({a["path"]:a for a in apis}.values())
    return {"urls":su,"ips":list({i["ip"]:i for i in ips}.values()),"api_paths":sa,"retrofit":retro,
            "domains":sorted(domains),"summary":{"urls":len(su),"ips":len(set(i["ip"] for i in ips)),"api_paths":len(sa),"domains":len(domains)}}
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("-o","--output",default="endpoints.json")
    a=p.parse_args();r=extract(a.dir)
    json.dump(r,open(a.output,"w"),indent=2)
    open(a.output.replace(".json","")+"_domains.txt","w").write("\n".join(r["domains"]))
    print(f"[+] {r['summary']['urls']} URLs | {r['summary']['api_paths']} APIs | {r['summary']['domains']} domains")
if __name__=="__main__":main()
