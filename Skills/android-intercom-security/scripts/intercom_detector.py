#!/usr/bin/env python3
"""
intercom_detector.py — Detect Intercom SDK in Android APK and extract configuration.
Phase 1+2: Detection + credential/config extraction.

Usage:
    python3 intercom_detector.py target.apk -o intercom_results/
    python3 intercom_detector.py jadx_out/ -o intercom_results/
"""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict

INTERCOM_INDICATORS = {
    "sdk_package": re.compile(r'io\.intercom\.android', re.IGNORECASE),
    "api_host": re.compile(r'mobile-messenger\.intercom\.com', re.IGNORECASE),
    "sdk_credential": re.compile(r'android_sdk-[A-Za-z0-9_-]{20,}'),
    "app_id": re.compile(r'(?:app_id|appId|INTERCOM_APP_ID)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
    "initialize": re.compile(r'Intercom\.initialize|Intercom\.client|IntercomSDK', re.IGNORECASE),
    "user_hash": re.compile(r'user_hash|userHash|identity_verification', re.IGNORECASE),
    "hmac": re.compile(r'HMAC|HmacSHA256|Mac\.getInstance.*HmacSHA', re.IGNORECASE),
    "login_identified": re.compile(r'loginIdentifiedUser|registerIdentifiedUser', re.IGNORECASE),
    "login_unidentified": re.compile(r'loginUnidentifiedUser|registerUnidentifiedUser', re.IGNORECASE),
    "email_binding": re.compile(r'withEmail|setEmail|\.email\s*=', re.IGNORECASE),
    "userid_binding": re.compile(r'withUserId|setUserId|\.userId\s*=', re.IGNORECASE),
    "conversation_api": re.compile(r'/messenger/mobile/conversations|/conversations/unread', re.IGNORECASE),
}

SCAN_EXT = {".java", ".kt", ".xml", ".json", ".smali", ".properties", ".js"}


def scan_source(source_dir):
    findings = defaultdict(list)
    total_files = 0

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "META-INF"}]
        for fname in files:
            if os.path.splitext(fname)[1].lower() not in SCAN_EXT:
                continue
            fpath = os.path.join(root, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
            except:
                continue
            total_files += 1
            rel = os.path.relpath(fpath, source_dir)

            for indicator_name, pattern in INTERCOM_INDICATORS.items():
                for m in pattern.finditer(content):
                    line = content[:m.start()].count("\n") + 1
                    match_text = m.group(0)[:120]

                    # Mask credentials
                    if indicator_name == "sdk_credential":
                        match_text = match_text[:15] + "***REDACTED***"

                    findings[indicator_name].append({
                        "match": match_text,
                        "file": rel,
                        "line": line,
                    })

    return dict(findings), total_files


def analyze_findings(findings):
    detected = len(findings) > 0 and any(
        k in findings for k in ["sdk_package", "api_host", "sdk_credential", "initialize"]
    )

    config = {
        "intercom_detected": detected,
        "app_id_found": "app_id" in findings,
        "sdk_credential_found": "sdk_credential" in findings,
        "api_host_found": "api_host" in findings,
        "user_hash_found": "user_hash" in findings,
        "hmac_found": "hmac" in findings,
        "login_identified": "login_identified" in findings,
        "login_unidentified": "login_unidentified" in findings,
        "email_binding": "email_binding" in findings,
        "userid_binding": "userid_binding" in findings,
    }

    # Identity verification status
    if config["user_hash_found"] and config["hmac_found"]:
        config["identity_verification_status"] = "likely_enabled"
    elif config["user_hash_found"]:
        config["identity_verification_status"] = "references_found_unconfirmed"
    elif config["login_identified"] and not config["user_hash_found"]:
        config["identity_verification_status"] = "potentially_disabled"
    else:
        config["identity_verification_status"] = "unknown"

    # Risk assessment
    if not detected:
        config["risk"] = "not_applicable"
    elif config["identity_verification_status"] == "potentially_disabled":
        config["risk"] = "medium"
        config["risk_reason"] = "Identified user login without user_hash — identity verification may be disabled"
    elif config["identity_verification_status"] == "likely_enabled":
        config["risk"] = "low"
        config["risk_reason"] = "Identity verification appears implemented — test at runtime to confirm"
    else:
        config["risk"] = "unknown"
        config["risk_reason"] = "Cannot determine identity verification status from static analysis"

    return config


def main():
    p = argparse.ArgumentParser(description="Detect Intercom SDK in Android APK")
    p.add_argument("target", help="APK file or JADX output directory")
    p.add_argument("-o", "--output", default="intercom_results")
    args = p.parse_args()

    target = args.target
    jadx_dir = target
    os.makedirs(args.output, exist_ok=True)

    if target.endswith(".apk"):
        jadx_dir = os.path.join(args.output, "jadx")
        print("[*] Decompiling APK...")
        subprocess.run(["jadx", "-d", jadx_dir, "--deobf", target], capture_output=True)

    print("[*] Scanning for Intercom indicators...")
    findings, total_files = scan_source(jadx_dir)
    config = analyze_findings(findings)

    result = {
        "config": config,
        "findings": findings,
        "files_scanned": total_files,
        "total_indicators": sum(len(v) for v in findings.values()),
    }

    out_file = os.path.join(args.output, "intercom_detection.json")
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*50}")
    print(f" Intercom Detection Results")
    print(f"{'='*50}")
    print(f" Files scanned: {total_files}")
    print(f" Intercom detected: {'YES' if config['intercom_detected'] else 'NO'}")

    if not config["intercom_detected"]:
        print(f" Status: NOT APPLICABLE — no Intercom integration found")
        print(f" Action: STOP — do not proceed with Intercom-specific testing")
    else:
        print(f" App ID found: {config['app_id_found']}")
        print(f" SDK credential found: {config['sdk_credential_found']}")
        print(f" Identity verification: {config['identity_verification_status']}")
        print(f" Risk: {config['risk'].upper()}")
        if config.get("risk_reason"):
            print(f" Reason: {config['risk_reason']}")
        print(f"\n Indicator breakdown:")
        for ind_name, matches in findings.items():
            print(f"   {ind_name:25s} {len(matches)} hit(s)")
            for m in matches[:2]:
                print(f"     → {m['file']}:{m['line']}")

    print(f"\n Results → {out_file}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
