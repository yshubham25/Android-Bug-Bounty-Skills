#!/usr/bin/env python3
"""Extract Firebase configuration from Android APK.
Usage: python3 firebase_extract.py target.apk -o /tmp/fb_out"""
import argparse,json,os,re,subprocess,sys,zipfile
PATTERNS={"database_url":re.compile(r'https://[a-z0-9_-]+\.firebaseio\.com'),"database_v2":re.compile(r'https://[a-z0-9_-]+\.firebasedatabase\.app'),"storage":re.compile(r'[a-z0-9_-]+\.appspot\.com'),"functions":re.compile(r'https://[a-z0-9-]+-[a-z0-9_-]+\.cloudfunctions\.net/[a-zA-Z0-9_-]+'),"project_id":re.compile(r'"project_id"\s*:\s*"([a-z0-9_-]+)"'),"api_key_json":re.compile(r'"current_key"\s*:\s*"([^"]+)"'),}
def scan_dir(d):
    found=[]
    for r,_,fs in os.walk(d):
        for fn in fs:
            if not fn.endswith(('.java','.kt','.xml','.json','.properties')):continue
            fp=os.path.join(r,fn)
            try:c=open(fp,errors='ignore').read()
            except:continue
            rel=os.path.relpath(fp,d)
            for n,p in PATTERNS.items():
                for m in p.finditer(c):
                    found.append({"type":n,"value":m.group(0),"file":rel,"line":c[:m.start()].count('\n')+1})
    seen=set();u=[]
    for f in found:
        k=(f["type"],f["value"])
        if k not in seen:seen.add(k);u.append(f)
    return u
def main():
    p=argparse.ArgumentParser();p.add_argument("apk");p.add_argument("-o","--output",default=None)
    a=p.parse_args();out=a.output or a.apk.replace(".apk","_firebase");os.makedirs(out,exist_ok=True)
    jd=os.path.join(out,"jadx");ad=os.path.join(out,"apktool")
    subprocess.run(["jadx","-d",jd,"--deobf",a.apk],capture_output=True)
    subprocess.run(["apktool","d",a.apk,"-o",ad,"-f"],capture_output=True)
    refs=scan_dir(jd)
    cfg={"code_references":refs,"summary":{"database_urls":list(set(f["value"] for f in refs if "database" in f["type"])),"storage_buckets":list(set(f["value"] for f in refs if f["type"]=="storage")),"functions_urls":list(set(f["value"] for f in refs if f["type"]=="functions")),"project_ids":list(set(f["value"] for f in refs if f["type"]=="project_id"))}}
    # Check strings.xml
    sx=os.path.join(ad,"res","values","strings.xml")
    if os.path.exists(sx):
        c=open(sx).read();st={}
        for k in ["firebase_database_url","google_api_key","google_storage_bucket","project_id","google_app_id"]:
            m=re.search(rf'name="{k}"[^>]*>([^<]+)<',c)
            if m:st[k]=m.group(1)
        cfg["strings_xml"]=st
    of=os.path.join(out,"firebase_config.json")
    json.dump(cfg,open(of,"w"),indent=2)
    print(f"[+] Firebase config → {of}")
    for k,v in cfg["summary"].items():
        if v:print(f"  {k}: {v}")
if __name__=="__main__":main()
