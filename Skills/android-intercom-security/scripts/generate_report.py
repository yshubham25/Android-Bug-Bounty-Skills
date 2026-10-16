#!/usr/bin/env python3
"""Generate Intercom security assessment report."""
import argparse,json,os
from datetime import datetime
def load(p):
    try:return json.load(open(p))
    except:return {}
def main():
    p=argparse.ArgumentParser();p.add_argument("results_dir");p.add_argument("-o","--output",default="intercom_report.md")
    a=p.parse_args();d=a.results_dir
    det=load(os.path.join(d,"intercom_detection.json"))
    auth=load(os.path.join(d,"auth_analysis.json")) if os.path.exists(os.path.join(d,"auth_analysis.json")) else {}
    cfg=det.get("config",{})
    lines=[f"# Intercom Security Assessment Report\n",f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
           f"**Intercom detected:** {'Yes' if cfg.get('intercom_detected') else 'No'}\n","---\n"]
    if not cfg.get("intercom_detected"):
        lines.append("No Intercom SDK integration found. Assessment not applicable.\n")
        open(a.output,"w").write("\n".join(lines));return
    lines+=[f"## Configuration\n",
            f"| Setting | Value |",f"|---------|-------|",
            f"| App ID found | {cfg.get('app_id_found','?')} |",
            f"| SDK credential found | {cfg.get('sdk_credential_found','?')} |",
            f"| Identity verification | {cfg.get('identity_verification_status','?')} |",
            f"| Risk level | {cfg.get('risk','?').upper()} |",
            f"| User hash present | {cfg.get('user_hash_found','?')} |",
            f"| HMAC present | {cfg.get('hmac_found','?')} |\n","---\n"]
    if cfg.get("risk_reason"):lines.append(f"**Risk reason:** {cfg['risk_reason']}\n")
    # Findings
    findings=det.get("findings",{})
    if findings:
        lines.append("## Detection evidence\n")
        for ind,matches in findings.items():
            lines.append(f"**{ind}** ({len(matches)} hits)")
            for m in matches[:3]:lines.append(f"- `{m['file']}:{m['line']}` — `{m['match'][:60]}`")
            lines.append("")
    # Tests to run
    tests=auth.get("vulnerabilities_to_test",[])
    if tests:
        lines+=["---\n","## Recommended tests\n"]
        for t in tests:lines.append(f"- [{t['severity'].upper()}] **{t['test']}**: {t['description']} ({t['cwe']})")
    lines+=["\n---\n","## Remediation\n",
            "1. Enable Intercom identity verification for authenticated users",
            "2. Generate user_hash server-side using HMAC-SHA256",
            "3. Never expose identity verification secret in client code",
            "4. Bind Intercom sessions to authenticated app sessions",
            "5. Enforce conversation-level authorization server-side\n"]
    open(a.output,"w").write("\n".join(lines))
    print(f"[+] Report → {a.output}")
if __name__=="__main__":main()
