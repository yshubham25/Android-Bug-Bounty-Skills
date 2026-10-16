#!/usr/bin/env python3
"""Generate HackerOne-style report from auth analysis findings."""
import argparse, json
from datetime import datetime

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input");p.add_argument("-o","--output",default="auth_report.md");p.add_argument("--target",default="Target APK")
    args = p.parse_args()
    data = json.load(open(args.input))
    findings = data.get("findings", [])

    lines = [f"# Authentication Bypass Report\n",f"**Target:** {args.target}",f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
             f"**Findings:** {len(findings)}\n","---\n"]

    for i, f in enumerate(findings, 1):
        lines += [
            f"## {i}. [{f.get('severity','?').upper()}] {f['type'].replace('_',' ').title()}\n",
            f"**Status:** {f.get('status','potential')}",
            f"**Description:** {f['description']}",
        ]
        if f.get("file"): lines.append(f"**File:** `{f['file']}` line {f.get('line','?')}")
        if f.get("adb_test"): lines.append(f"**ADB Test:** `{f['adb_test']}`")
        if f.get("validation"): lines.append(f"**Validation:** {f['validation']}")
        lines.append(f"\n**Remediation:** Set exported=false, enforce server-side auth, use CryptoObject for biometrics.\n---\n")

    open(args.output, "w").write("\n".join(lines))
    print(f"[+] Report: {args.output} ({len(findings)} findings)")

if __name__ == "__main__":
    main()
