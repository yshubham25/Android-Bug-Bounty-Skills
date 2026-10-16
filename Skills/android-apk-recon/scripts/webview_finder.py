#!/usr/bin/env python3
"""Find WebView instances, settings, bridges, cookie ops."""
import argparse,json,os,re,sys
PATS={"webview_create":[r'new WebView\b',r'WebView\s+\w+\s*='],"js_enabled":[r'setJavaScriptEnabled\s*\(\s*true'],
    "js_bridge":[r'addJavascriptInterface\s*\('],"load_url":[r'\.loadUrl\s*\(',r'\.evaluateJavascript\s*\('],
    "file_access":[r'AllowUniversalAccessFromFileURLs\s*\(\s*true',r'AllowFileAccessFromFileURLs\s*\(\s*true'],
    "cookie_mgr":[r'setCookie\s*\('],"debug":[r'setWebContentsDebuggingEnabled\s*\(\s*true']}
def scan(d):
    findings=[]
    for root,_,files in os.walk(d):
        for fn in files:
            if not fn.endswith((".java",".kt")):continue
            fp=os.path.join(root,fn)
            try:c=open(fp,errors="ignore").read()
            except:continue
            rel=os.path.relpath(fp,d)
            if any(s in rel for s in ["/com/google/","/androidx/","/kotlin/"]):continue
            for cat,pats in PATS.items():
                for pat in pats:
                    for m in re.finditer(pat,c):
                        findings.append({"category":cat,"match":m.group(0)[:80],"file":rel,"line":c[:m.start()].count("\n")+1})
    seen=set();u=[]
    for f in findings:
        k=(f["category"],f["file"],f["line"])
        if k not in seen:seen.add(k);u.append(f)
    return u
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("-o","--output",default="webviews.json")
    a=p.parse_args();r=scan(a.dir)
    json.dump({"total":len(r),"findings":r},open(a.output,"w"),indent=2)
    print(f"[+] {len(r)} WebView findings")
if __name__=="__main__":main()
