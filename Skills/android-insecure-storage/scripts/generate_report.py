#!/usr/bin/env python3
"""Generate HackerOne report from storage scan results."""
import argparse, json
from datetime import datetime
def main():
    p = argparse.ArgumentParser()
    p.add_argument("input"); p.add_argument("-o","--output",default="storage_report.md"); p.add_argument("--target",default="Target APK")
    a = p.parse_args(); data = json.load(open(a.input))
    vulns = data.get("vulnerabilities", [])
    manifest = data.get("manifest_issues", [])
    secure = data.get("secure_practices", [])
    lines = [f"# Insecure Data Storage Audit Report\n",f"**Target:** {a.target}",f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
             f"**Vulnerabilities:** {len(vulns)} | **Manifest issues:** {len(manifest)} | **Secure practices:** {len(secure)}\n","---\n"]
    if manifest:
        lines.append("## Manifest Issues\n")
        for m in manifest:
            lines += [f"- [{m['risk'].upper()}] {m['description']}\n"]
        lines.append("---\n")
    lines.append("## Vulnerabilities\n")
    i = 1
    for v in vulns:
        lines += [f"### {i}. [{v.get('risk','?').upper()}] {v['description']}\n",f"**File:** `{v['file']}` line {v.get('line','?')}",
                  f"**Category:** {v['category']}",f"**Remediation:** Use EncryptedSharedPreferences, SQLCipher, or Android Keystore.\n---\n"]
        i += 1
    if secure:
        lines.append("## Secure Practices Found\n")
        for s in secure:
            lines.append(f"- {s['description']} (`{s['file']}`)\n")
    open(a.output, "w").write("\n".join(lines))
    print(f"[+] Report: {a.output}")
if __name__ == "__main__": main()
