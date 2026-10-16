#!/usr/bin/env python3
"""Generate Markdown report from Firebase validation results."""
import argparse,json
from datetime import datetime
def main():
    p=argparse.ArgumentParser();p.add_argument("input");p.add_argument("-o","--output",default="report.md");p.add_argument("--target",default="Target APK")
    a=p.parse_args();data=json.load(open(a.input))
    vulns=[f for f in data.get("findings",[]) if f.get("status")=="vulnerable"]
    lines=[f"# Firebase Misconfiguration Report\n",f"**Target:** {a.target}",f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",f"**Findings:** {len(vulns)}\n","---\n"]
    for i,f in enumerate(vulns,1):
        lines+=[f"## {i}. [{f.get('severity','?').upper()}] {f['type']}\n",f"**Target:** `{f['target']}`",f"**Command:** `{f['command']}`",f"**Response:** `{f.get('response_preview','')[:150]}`",f"**Remediation:** Lock Firebase Security Rules.\n---\n"]
    open(a.output,"w").write("\n".join(lines))
    print(f"[+] Report: {a.output} ({len(vulns)} findings)")
if __name__=="__main__":main()
