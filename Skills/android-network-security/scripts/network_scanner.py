#!/usr/bin/env python3
"""
network_scanner.py — Static analysis for network security issues in Android APKs.
Detects cleartext traffic, trust-all TrustManagers, missing pinning, weak TLS,
HTTP URLs, and framework-specific networking patterns.

Usage: python3 network_scanner.py target.apk -o scan.json
"""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict

NETWORK_PATTERNS = {
    "trust_all": {
        "patterns": [
            r'trustAllCerts|ALLOW_ALL_HOSTNAME|AllowAllHostnameVerifier|ACCEPT_ALL_CERTS',
            r'checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}',
            r'checkClientTrusted\s*\([^)]*\)\s*\{[\s\n]*\}',
            r'verify\s*\([^)]*\)\s*\{\s*return\s+true',
            r'setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL',
        ],
        "risk": "critical", "category": "trust_all",
        "description": "Trust-all TrustManager or HostnameVerifier — accepts ANY certificate",
    },
    "cleartext_http": {
        "patterns": [r'http://(?!schemas|www\.w3\.org|ns\.adobe|localhost|127\.0\.0\.1|10\.)[\w.-]+'],
        "risk": "high", "category": "cleartext",
        "description": "HTTP URL found — data transmitted in cleartext",
    },
    "weak_tls": {
        "patterns": [r'SSLv3|TLSv1"[^.]|TLSv1\.0|SSL_OP_NO_TLSv1_3'],
        "risk": "medium", "category": "weak_tls",
        "description": "Weak TLS version (SSLv3 / TLS 1.0) — vulnerable to downgrade",
    },
    "pinning_okhttp": {
        "patterns": [r'CertificatePinner\.Builder|\.certificatePinner\(|sha256/'],
        "risk": "secure", "category": "pinning",
        "description": "OkHttp CertificatePinner configured (good practice)",
    },
    "pinning_config": {
        "patterns": [r'<pin-set|<pin\s+digest'],
        "risk": "secure", "category": "pinning",
        "description": "Network security config pinning (good practice)",
    },
    "custom_trust_manager": {
        "patterns": [r'implements\s+X509TrustManager|new\s+X509TrustManager|TrustManagerFactory'],
        "risk": "medium", "category": "custom_tm",
        "description": "Custom TrustManager — verify it's not trust-all",
    },
    "token_in_url": {
        "patterns": [r'(?:token|key|session|auth|password|secret)=[^&\s"]{8,}'],
        "risk": "medium", "category": "token_url",
        "description": "Possible token/credential in URL query parameter",
    },
    "webview_ssl_error": {
        "patterns": [r'onReceivedSslError.*proceed\(\)'],
        "risk": "high", "category": "webview_ssl",
        "description": "WebView SSL errors ignored — MitM via WebView",
    },
}

SCAN_EXTENSIONS = {".java", ".kt", ".xml", ".json", ".smali"}
SKIP_DIRS = {"node_modules", ".git", "META-INF"}


def check_manifest(manifest_path):
    issues = []
    if not os.path.exists(manifest_path): return issues
    c = open(manifest_path).read()
    if 'usesCleartextTraffic="true"' in c:
        issues.append({"type": "cleartext_allowed", "risk": "high", "category": "cleartext",
                        "description": "android:usesCleartextTraffic=true — HTTP traffic allowed"})
    if 'networkSecurityConfig' not in c:
        issues.append({"type": "no_net_sec_config", "risk": "medium", "category": "missing_config",
                        "description": "No networkSecurityConfig — using default trust anchors"})
    return issues


def check_net_security_config(apktool_dir):
    issues = []
    config_path = os.path.join(apktool_dir, "res", "xml", "network_security_config.xml")
    if not os.path.exists(config_path):
        return issues
    c = open(config_path).read()
    if 'cleartextTrafficPermitted="true"' in c:
        issues.append({"type": "cleartext_in_config", "risk": "high", "category": "cleartext",
                        "description": "Network security config allows cleartext traffic"})
    if '<certificates src="user"/>' in c:
        issues.append({"type": "user_certs_trusted", "risk": "medium", "category": "trust_config",
                        "description": "User-installed certificates trusted (debug config?)"})
    if '<pin-set' in c:
        issues.append({"type": "pinning_configured", "risk": "secure", "category": "pinning",
                        "description": "Certificate pinning configured in network security config"})
    return issues


def scan_source(jadx_dir):
    findings = []
    for dirpath, dirnames, filenames in os.walk(jadx_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if os.path.splitext(fname)[1].lower() not in SCAN_EXTENSIONS: continue
            fpath = os.path.join(dirpath, fname)
            try: content = open(fpath, encoding="utf-8", errors="ignore").read()
            except: continue
            rel = os.path.relpath(fpath, jadx_dir)
            if any(sdk in rel for sdk in ["/com/google/", "/androidx/", "/kotlin/", "/okhttp3/internal/"]): continue

            for gname, group in NETWORK_PATTERNS.items():
                for pat_str in group["patterns"]:
                    for m in re.finditer(pat_str, content, re.IGNORECASE):
                        line = content[:m.start()].count("\n") + 1
                        lines = content.split("\n")
                        ctx = "\n".join(lines[max(0,line-3):min(len(lines),line+2)])
                        findings.append({
                            "group": gname, "category": group["category"],
                            "risk": group["risk"], "description": group["description"],
                            "match": m.group(0)[:100], "file": rel, "line": line,
                            "context": ctx[:400],
                        })
    seen = set()
    unique = []
    for f in findings:
        key = (f["group"], f["file"], f["line"])
        if key not in seen: seen.add(key); unique.append(f)
    return unique


def main():
    p = argparse.ArgumentParser(description="Scan APK for network security issues")
    p.add_argument("target"); p.add_argument("-o", "--output", default="network_scan.json")
    args = p.parse_args()
    target = args.target; jadx_dir = target; apktool_dir = None

    if target.endswith(".apk"):
        jadx_dir = target.replace(".apk", "_jadx"); apktool_dir = target.replace(".apk", "_apktool")
        subprocess.run(["jadx", "-d", jadx_dir, "--deobf", target], capture_output=True)
        subprocess.run(["apktool", "d", target, "-o", apktool_dir, "-f"], capture_output=True)

    # Framework detection
    from identify_framework import identify
    fw_result = identify(target) if target.endswith(".apk") else {"framework": "unknown"}

    manifest_issues = check_manifest(os.path.join(apktool_dir or "", "AndroidManifest.xml"))
    config_issues = check_net_security_config(apktool_dir or "")
    code_findings = scan_source(jadx_dir)

    vulns = [f for f in code_findings if f["risk"] not in ("secure", "info")]
    secure = [f for f in code_findings if f["risk"] == "secure"]

    by_cat = defaultdict(int)
    for f in vulns: by_cat[f["category"]] += 1

    result = {
        "framework": fw_result, "manifest_issues": manifest_issues,
        "config_issues": config_issues, "vulnerabilities": vulns,
        "secure_practices": secure,
        "summary": {"total_vulns": len(vulns), "by_category": dict(by_cat)},
    }
    json.dump(result, open(args.output, "w"), indent=2)

    print(f"\n{'='*55}")
    print(f" Network Security Scan Complete")
    print(f"{'='*55}")
    print(f" Framework: {fw_result.get('framework','unknown').upper()}")
    print(f" Vulnerabilities: {len(vulns)}")
    for cat, count in sorted(by_cat.items()): print(f"   {cat:20s} {count}")
    print(f" Manifest issues: {len(manifest_issues)}")
    print(f" Config issues: {len(config_issues)}")
    print(f" Secure practices: {len(secure)}")
    print(f" Results → {args.output}")
    print(f"{'='*55}")

if __name__ == "__main__": main()
