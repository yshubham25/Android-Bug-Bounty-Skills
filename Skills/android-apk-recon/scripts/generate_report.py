#!/usr/bin/env python3
"""Generate consolidated recon report from all JSON outputs including Intercom."""
import argparse,json,os
from datetime import datetime
def load(p):
    try:return json.load(open(p))
    except:return {}
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("-o","--output",default="recon_report.md")
    a=p.parse_args();d=a.dir
    apk=load(os.path.join(d,"apk_info.json"));manifest=load(os.path.join(d,"manifest_analysis.json"))
    endpoints=load(os.path.join(d,"endpoints.json"));webviews=load(os.path.join(d,"webviews.json"))
    sdks=load(os.path.join(d,"third_party_sdks.json"));intercom=load(os.path.join(d,"intercom_analysis.json"))
    secrets=load(os.path.join(d,"potential_secrets.json"))
    dls=manifest.get("deeplinks",[]) if isinstance(manifest,dict) else []
    ic=intercom.get("config",{})
    lines=[f"# APK Reconnaissance Report v2\n",f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
           f"**Package:** `{apk.get('package','?')}`",f"**Version:** {apk.get('version_name','?')} ({apk.get('version_code','?')})",
           f"**Framework:** {apk.get('framework','?')}",f"**SDK:** min={apk.get('min_sdk','?')} target={apk.get('target_sdk','?')}",
           f"**SHA-256:** `{apk.get('sha256','?')[:32]}...`\n","---\n",
           "## Attack surface\n","| Category | Count |","|----------|-------|",
           f"| Exported components | {manifest.get('exported_count',0)} |",
           f"| Deep links | {len(dls)} |",
           f"| URLs | {endpoints.get('summary',{}).get('urls',0)} |",
           f"| API paths | {endpoints.get('summary',{}).get('api_paths',0)} |",
           f"| Domains | {endpoints.get('summary',{}).get('domains',0)} |",
           f"| WebView findings | {webviews.get('total',0)} |",
           f"| Third-party SDKs | {len(sdks)} |",
           f"| Potential secrets | {secrets.get('total',0)} |",
           f"| Permissions | {len(apk.get('permissions',[]))} |\n","---\n"]
    # Config warnings
    cfg=manifest.get("app_config",{})
    warns=[]
    if cfg.get("allowBackup") in("true","unset"):warns.append("allowBackup=true")
    if cfg.get("debuggable")=="true":warns.append("debuggable=true (CRITICAL)")
    if cfg.get("usesCleartextTraffic")=="true":warns.append("cleartext traffic allowed")
    if warns:lines+=["## Config warnings\n"]+[f"- {w}" for w in warns]+["\n---\n"]
    # Intercom section
    lines.append("## Intercom SDK analysis\n")
    if ic.get("intercom_detected"):
        lines+=[f"**Status:** DETECTED",f"**Identity verification:** {ic.get('identity_verification','?')}",
                f"**Risk:** {ic.get('risk','?').upper()}"]
        if ic.get("risk_reason"):lines.append(f"**Reason:** {ic['risk_reason']}")
        tests=ic.get("recommended_tests",[])
        if tests:
            lines.append("\n**Recommended tests:**")
            for t in tests:lines.append(f"- [{t['severity'].upper()}] {t['test']}: {t['description']}")
    else:
        lines.append("**Status:** Not detected — Intercom-specific testing not applicable")
    lines.append("\n---\n")
    # Deep links
    if dls:
        lines+=["## Deep links\n"]
        for dl in dls[:15]:lines.append(f"- `{dl['uri']}` → {dl['activity'].split('.')[-1]}")
        if len(dls)>15:lines.append(f"- ... and {len(dls)-15} more")
        lines.append("\n---\n")
    # Secrets
    if secrets.get("total",0):
        lines+=["## Potential secrets\n"]
        for s in secrets.get("findings",[])[:10]:
            lines.append(f"- [{s['severity'].upper()}] {s['rule']}: `{s['match']}` in `{s['file']}:{s['line']}`")
        lines.append("\n---\n")
    # SDKs
    if sdks:
        lines+=["## Third-party SDKs\n"]
        for name in sorted(sdks.keys()):lines.append(f"- {name}")
        lines.append("\n---\n")
    # Next steps
    lines+=["## Recommended next steps\n",
            "1. Run `android-authentication-bypass` on exported activities",
            "2. Run `android-deeplink-pentest` on discovered deep links",
            "3. Run `android-webview-pentest` on WebView instances",
            "4. Run `android-sensitive-data-leakage` for full secret scan",
            "5. Run `android-firebase-misconfiguration` on Firebase config",
            "6. Run `android-ipc-exploitation` on providers/receivers",
            "7. Run `android-insecure-storage` for credential storage audit",
            "8. Run `android-network-security` for SSL/TLS analysis"]
    if ic.get("intercom_detected"):
        lines.append("9. Run `android-intercom-security` for identity verification testing")
    with open(a.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Report → {a.output}")
if __name__=="__main__":main()
