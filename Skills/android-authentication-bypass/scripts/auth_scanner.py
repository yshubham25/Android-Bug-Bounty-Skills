#!/usr/bin/env python3
"""
auth_scanner.py — Scan Android APK for authentication bypass vulnerabilities.
Decompiles APK, parses manifest, scans source for auth patterns.

Usage:
    python3 auth_scanner.py target.apk -o scan.json
    python3 auth_scanner.py jadx_out/ -o scan.json
"""
import argparse, json, math, os, re, subprocess, sys
from collections import defaultdict
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Auth-related code patterns with risk classification
AUTH_PATTERNS = {
    # Client-side auth checks
    "client_auth_flag": {
        "patterns": [
            r'getBoolean\s*\(\s*"[^"]*(?:logged|auth|verified|premium)[^"]*"',
            r'(?:isLoggedIn|isAuthenticated|isVerified|isAuthorized|isPremium)\s*[=\(]',
            r'putBoolean\s*\(\s*"[^"]*(?:login|auth|verified)[^"]*"',
            r'(?:loginRequired|skipLogin|bypassAuth)\s*[=\(]',
        ],
        "risk": "high",
        "category": "client_side_auth",
        "description": "Client-side authentication flag — may be manipulable",
    },
    # Biometric auth
    "biometric": {
        "patterns": [
            r'BiometricPrompt',
            r'FingerprintManager',
            r'onAuthenticationSucceeded',
            r'onAuthenticationFailed',
            r'onAuthenticationError',
        ],
        "risk": "medium",
        "category": "biometric_auth",
        "description": "Biometric authentication — check for CryptoObject usage",
    },
    "crypto_object": {
        "patterns": [r'CryptoObject', r'BiometricPrompt\.CryptoObject'],
        "risk": "info",
        "category": "biometric_auth",
        "description": "CryptoObject usage (good sign — biometric tied to crypto)",
    },
    # Token handling
    "token_handling": {
        "patterns": [
            r'(?:access_token|refresh_token|id_token|auth_token|session_token)\s*[=:]',
            r'Bearer\s+[A-Za-z0-9_.-]+',
            r'Authorization.*Bearer',
            r'jwt\s*[=:]|JsonWebToken|JWTDecoder',
        ],
        "risk": "medium",
        "category": "token_session",
        "description": "Token/JWT handling — check validation and storage",
    },
    # Intent auth control
    "intent_auth": {
        "patterns": [
            r'getBooleanExtra\s*\(\s*"[^"]*(?:auth|skip|login|verified)[^"]*"',
            r'getStringExtra\s*\(\s*"[^"]*(?:token|session|auth)[^"]*"',
            r'getBooleanExtra\s*\(\s*"[^"]*(?:premium|admin|bypass)[^"]*"',
        ],
        "risk": "high",
        "category": "intent_auth_control",
        "description": "Intent extras controlling auth decisions — likely exploitable",
    },
    # OAuth/SSO
    "oauth": {
        "patterns": [
            r'redirect_uri\s*[=:]',
            r'authorization_code|code_verifier|code_challenge',
            r'state\s*=\s*["\'][^"\']+["\']',
            r'handleAuthCallback|handleRedirect|onLoginResult',
        ],
        "risk": "medium",
        "category": "oauth_sso",
        "description": "OAuth/SSO flow — check state validation and PKCE",
    },
    # PIN/OTP
    "pin_otp": {
        "patterns": [
            r'verifyPin|checkOtp|validateMfa|pinCorrect|otpMatch',
            r'MAX_RETRY|attempt.*count|lockout.*time',
            r'pinCode\s*==\s*|otp\s*\.equals\(',
        ],
        "risk": "high",
        "category": "pin_otp_mfa",
        "description": "Local PIN/OTP verification — check for server enforcement",
    },
    # Password reset
    "password_reset": {
        "patterns": [
            r'resetPassword|magicLink|passwordReset|forgotPassword',
            r'oobCode|resetToken|verifyEmail|recoveryLink',
        ],
        "risk": "medium",
        "category": "password_reset",
        "description": "Password reset flow — check token replay and expiry",
    },
    # WebView auth bridges
    "webview_auth": {
        "patterns": [
            r'addJavascriptInterface.*(?:auth|login|session|token)',
            r'@JavascriptInterface.*(?:get.*[Tt]oken|get.*[Ss]ession|login|auth)',
        ],
        "risk": "high",
        "category": "webview_auth",
        "description": "WebView JS bridge exposing auth methods",
    },
}

SCAN_EXTENSIONS = {".java", ".kt", ".xml", ".json", ".smali"}


def parse_manifest(apktool_dir):
    manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return {"exported_activities": [], "deep_links": []}

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    package = root.attrib.get("package", "")
    exported = []
    deep_links = []

    for activity in root.iter("activity"):
        name = activity.attrib.get(f"{ANDROID_NS}name", "")
        exp = activity.attrib.get(f"{ANDROID_NS}exported", "unset")
        has_intent_filter = len(activity.findall("intent-filter")) > 0

        # Exported if explicitly true OR has intent-filter (implicit export)
        is_exported = exp == "true" or (exp == "unset" and has_intent_filter)

        if is_exported:
            entry = {"name": name, "exported": exp, "has_intent_filter": has_intent_filter}
            # Check for auth-related names
            lower = name.lower()
            if any(k in lower for k in ["login", "auth", "splash", "main", "launcher"]):
                entry["likely_role"] = "entry_point"
            elif any(k in lower for k in ["dashboard", "home", "profile", "settings", "payment", "admin", "account"]):
                entry["likely_role"] = "protected_screen"
                entry["risk"] = "high"
            else:
                entry["likely_role"] = "unknown"
            exported.append(entry)

        # Extract deep links
        for intent_filter in activity.findall("intent-filter"):
            for data in intent_filter.findall("data"):
                scheme = data.attrib.get(f"{ANDROID_NS}scheme", "")
                host = data.attrib.get(f"{ANDROID_NS}host", "")
                path = data.attrib.get(f"{ANDROID_NS}pathPrefix", "") or data.attrib.get(f"{ANDROID_NS}path", "")
                if scheme:
                    deep_links.append({
                        "activity": name, "scheme": scheme, "host": host, "path": path,
                        "uri": f"{scheme}://{host}{path}" if host else f"{scheme}://"
                    })

    return {"package": package, "exported_activities": exported, "deep_links": deep_links}


def scan_source(jadx_dir):
    findings = []
    for dirpath, dirnames, filenames in os.walk(jadx_dir):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "META-INF"}]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
            except:
                continue
            rel = os.path.relpath(fpath, jadx_dir)
            for group_name, group in AUTH_PATTERNS.items():
                for pat_str in group["patterns"]:
                    pat = re.compile(pat_str, re.IGNORECASE)
                    for m in pat.finditer(content):
                        line = content[:m.start()].count("\n") + 1
                        # Context
                        lines = content.split("\n")
                        start = max(0, line - 3)
                        end = min(len(lines), line + 2)
                        context = "\n".join(lines[start:end])

                        findings.append({
                            "group": group_name,
                            "category": group["category"],
                            "risk": group["risk"],
                            "description": group["description"],
                            "match": m.group(0)[:100],
                            "file": rel,
                            "line": line,
                            "context": context[:400],
                        })
    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["group"], f["match"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def check_biometric_security(findings):
    """Check if BiometricPrompt uses CryptoObject."""
    has_biometric = any(f["group"] == "biometric" for f in findings)
    has_crypto = any(f["group"] == "crypto_object" for f in findings)
    if has_biometric and not has_crypto:
        return {"vulnerable": True, "issue": "BiometricPrompt used WITHOUT CryptoObject — callback-only auth, bypassable via Frida"}
    elif has_biometric and has_crypto:
        return {"vulnerable": False, "note": "BiometricPrompt uses CryptoObject (good)"}
    return {"vulnerable": False, "note": "No biometric auth found"}


def main():
    p = argparse.ArgumentParser(description="Scan APK for auth bypass vulnerabilities")
    p.add_argument("target", help="APK file or JADX output directory")
    p.add_argument("-o", "--output", default="auth_scan.json")
    args = p.parse_args()

    target = args.target
    jadx_dir = target
    apktool_dir = None

    if target.endswith(".apk"):
        jadx_dir = target.replace(".apk", "_jadx")
        apktool_dir = target.replace(".apk", "_apktool")
        print("[*] Decompiling with JADX...")
        subprocess.run(["jadx", "-d", jadx_dir, "--deobf", target], capture_output=True)
        print("[*] Decompiling with APKTool...")
        subprocess.run(["apktool", "d", target, "-o", apktool_dir, "-f"], capture_output=True)
    else:
        # Try to find apktool output
        parent = os.path.dirname(target)
        for d in os.listdir(parent) if parent else []:
            if "apktool" in d:
                apktool_dir = os.path.join(parent, d)
                break

    # Parse manifest
    manifest_data = {}
    if apktool_dir:
        manifest_data = parse_manifest(apktool_dir)
        print(f"[+] Exported activities: {len(manifest_data.get('exported_activities', []))}")
        print(f"[+] Deep links: {len(manifest_data.get('deep_links', []))}")

    # Scan source
    print(f"[*] Scanning source for auth patterns...")
    code_findings = scan_source(jadx_dir)

    # Biometric analysis
    biometric_check = check_biometric_security(code_findings)

    # Summary
    by_category = defaultdict(int)
    by_risk = defaultdict(int)
    for f in code_findings:
        by_category[f["category"]] += 1
        by_risk[f["risk"]] += 1

    result = {
        "manifest": manifest_data,
        "code_findings": code_findings,
        "biometric_analysis": biometric_check,
        "summary": {
            "total_findings": len(code_findings),
            "by_category": dict(by_category),
            "by_risk": dict(by_risk),
            "exported_activities": len(manifest_data.get("exported_activities", [])),
            "protected_screens_exported": len([a for a in manifest_data.get("exported_activities", []) if a.get("likely_role") == "protected_screen"]),
            "deep_links": len(manifest_data.get("deep_links", [])),
        },
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*50}")
    print(f" Auth Bypass Scan Complete")
    print(f"{'='*50}")
    print(f" Code findings:              {len(code_findings)}")
    for cat, count in sorted(by_category.items()):
        print(f"   {cat:30s} {count}")
    print(f" Exported activities:         {result['summary']['exported_activities']}")
    print(f" Protected screens exported:  {result['summary']['protected_screens_exported']}")
    print(f" Biometric: {biometric_check.get('issue') or biometric_check.get('note')}")
    print(f" Results → {args.output}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
