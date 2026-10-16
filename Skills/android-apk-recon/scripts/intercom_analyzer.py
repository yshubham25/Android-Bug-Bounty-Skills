#!/usr/bin/env python3
"""
intercom_analyzer.py — Module 7: Detect and analyze Intercom SDK integration.
Part of the recon pipeline. Outputs intercom_analysis.json.

Detects: SDK presence, App ID, credentials, identity verification status,
login methods, user binding, conversation API references, risk level.

Usage: python3 intercom_analyzer.py jadx_out/ -o intercom_analysis.json
"""
import argparse, json, os, re, sys
from collections import defaultdict

INDICATORS = {
    "sdk_package": re.compile(r'io\.intercom\.android'),
    "api_host": re.compile(r'mobile-messenger\.intercom\.com'),
    "sdk_credential": re.compile(r'android_sdk-[A-Za-z0-9_-]{20,}'),
    "app_id_ref": re.compile(r'(?:app_id|appId|INTERCOM_APP_ID)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    "initialize": re.compile(r'Intercom\.initialize|Intercom\.client|IntercomSDK', re.I),
    "user_hash": re.compile(r'user_hash|userHash|identity_verification', re.I),
    "hmac": re.compile(r'HMAC|HmacSHA256|Mac\.getInstance.*HmacSHA', re.I),
    "login_identified": re.compile(r'loginIdentifiedUser|registerIdentifiedUser', re.I),
    "login_unidentified": re.compile(r'loginUnidentifiedUser|registerUnidentifiedUser', re.I),
    "email_binding": re.compile(r'withEmail|setEmail|\.email\s*=', re.I),
    "userid_binding": re.compile(r'withUserId|setUserId|\.userId\s*=', re.I),
    "conversation_api": re.compile(r'/messenger/mobile/conversations|/conversations/unread', re.I),
    "set_user_attribute": re.compile(r'setUserAttribute|updateUser|setCustomAttribute', re.I),
    "intercom_config": re.compile(r'IntercomSettings|IntercomConfig', re.I),
}

SCAN_EXT = {".java", ".kt", ".xml", ".json", ".smali", ".properties", ".js"}


def scan(jadx_dir):
    findings = defaultdict(list)
    files_scanned = 0

    for root, dirs, files in os.walk(jadx_dir):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "META-INF"}]
        for fname in files:
            if os.path.splitext(fname)[1].lower() not in SCAN_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
            except:
                continue
            files_scanned += 1
            rel = os.path.relpath(fpath, jadx_dir)

            for name, pattern in INDICATORS.items():
                for m in pattern.finditer(content):
                    line = content[:m.start()].count("\n") + 1
                    match_text = m.group(0)[:120]
                    # Mask credentials
                    if name == "sdk_credential":
                        match_text = match_text[:15] + "***MASKED***"
                    findings[name].append({"match": match_text, "file": rel, "line": line})

    return dict(findings), files_scanned


def classify(findings):
    detected = bool(findings) and any(
        k in findings for k in ["sdk_package", "api_host", "sdk_credential", "initialize"]
    )

    config = {
        "intercom_detected": detected,
        "app_id_found": "app_id_ref" in findings,
        "sdk_credential_found": "sdk_credential" in findings,
        "api_host_found": "api_host" in findings,
        "user_hash_found": "user_hash" in findings,
        "hmac_found": "hmac" in findings,
        "login_identified": "login_identified" in findings,
        "login_unidentified": "login_unidentified" in findings,
        "email_binding": "email_binding" in findings,
        "userid_binding": "userid_binding" in findings,
        "conversation_api_refs": "conversation_api" in findings,
        "user_attributes": "set_user_attribute" in findings,
    }

    # Identity verification status
    if config["user_hash_found"] and config["hmac_found"]:
        config["identity_verification"] = "likely_enabled"
    elif config["user_hash_found"]:
        config["identity_verification"] = "references_found_unconfirmed"
    elif config["login_identified"] and not config["user_hash_found"]:
        config["identity_verification"] = "potentially_disabled"
    elif not detected:
        config["identity_verification"] = "not_applicable"
    else:
        config["identity_verification"] = "unknown"

    # Risk
    if not detected:
        config["risk"] = "not_applicable"
        config["risk_reason"] = "No Intercom integration found"
    elif config["identity_verification"] == "potentially_disabled":
        config["risk"] = "medium"
        config["risk_reason"] = "loginIdentifiedUser without user_hash — identity verification may be disabled, test for impersonation"
    elif config["identity_verification"] == "likely_enabled":
        config["risk"] = "low"
        config["risk_reason"] = "Identity verification appears implemented — confirm at runtime"
    else:
        config["risk"] = "unknown"
        config["risk_reason"] = "Cannot determine identity verification from static analysis alone"

    # Recommended tests
    tests = []
    if detected:
        if config["identity_verification"] == "potentially_disabled":
            tests.append({
                "test": "identity_impersonation",
                "severity": "high",
                "description": "Test if arbitrary email/userId can access other users' conversations",
                "cwe": "CWE-639",
            })
        tests.append({
            "test": "cross_account_idor",
            "severity": "high",
            "description": "Test if Account A can access Account B's conversation via conversation_id swap",
            "cwe": "CWE-639",
        })
        tests.append({
            "test": "conversation_creation",
            "severity": "medium",
            "description": "Test if conversations can be created under arbitrary identity",
            "cwe": "CWE-287",
        })
    config["recommended_tests"] = tests

    return config


def main():
    p = argparse.ArgumentParser(description="Analyze Intercom SDK integration")
    p.add_argument("jadx_dir", help="JADX output directory")
    p.add_argument("-o", "--output", default="intercom_analysis.json")
    args = p.parse_args()

    findings, files_scanned = scan(args.jadx_dir)
    config = classify(findings)

    result = {
        "config": config,
        "findings": findings,
        "files_scanned": files_scanned,
        "total_indicators": sum(len(v) for v in findings.values()),
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    if not config["intercom_detected"]:
        print(f"[+] Intercom: NOT DETECTED (scanned {files_scanned} files)")
    else:
        print(f"[+] Intercom: DETECTED | verification={config['identity_verification']} | risk={config['risk'].upper()}")
        if config.get("risk_reason"):
            print(f"    {config['risk_reason']}")
        print(f"    Indicators: {sum(len(v) for v in findings.values())} hits across {len(findings)} categories")
        for test in config.get("recommended_tests", []):
            print(f"    [{test['severity'].upper()}] {test['test']}: {test['description'][:60]}")


if __name__ == "__main__":
    main()
