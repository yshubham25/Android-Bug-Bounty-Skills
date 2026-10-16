#!/usr/bin/env python3
"""Analyze obfuscation level of decompiled APK source."""
import argparse,json,os,re,sys
def analyze(jadx_dir):
    total=0;short_names=0;long_names=0;has_proguard=False
    for root,_,files in os.walk(jadx_dir):
        for fn in files:
            if not fn.endswith((".java",".kt")):continue
            total+=1
            name=os.path.splitext(fn)[0]
            if len(name)<=2:short_names+=1
            else:long_names+=1
    # Check ProGuard
    meta=os.path.join(jadx_dir,"..","apktool","original","META-INF")
    if os.path.exists(meta):
        for f in os.listdir(meta):
            if "proguard" in f.lower():has_proguard=True
    ratio=short_names/max(total,1)
    if ratio>0.7:level="heavy"
    elif ratio>0.3:level="moderate"
    elif ratio>0.1:level="light"
    else:level="none"
    # String encryption
    string_encrypt=0
    for root,_,files in os.walk(jadx_dir):
        for fn in files:
            if not fn.endswith(".java"):continue
            try:c=open(os.path.join(root,fn),errors="ignore").read()
            except:continue
            string_encrypt+=len(re.findall(r'decrypt|deobfuscate|xor.*string|decode.*key',c,re.I))
    return {"total_classes":total,"short_names":short_names,"long_names":long_names,
            "obfuscation_ratio":round(ratio,2),"level":level,"proguard_detected":has_proguard,
            "string_encryption_indicators":string_encrypt}
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("-o","--output",default="obfuscation.json")
    a=p.parse_args();r=analyze(a.dir)
    json.dump(r,open(a.output,"w"),indent=2)
    print(f"[+] Obfuscation: {r['level'].upper()} ({r['obfuscation_ratio']:.0%} short names, ProGuard={'yes' if r['proguard_detected'] else 'no'})")
if __name__=="__main__":main()
