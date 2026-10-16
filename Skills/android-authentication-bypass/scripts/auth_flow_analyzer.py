#!/usr/bin/env python3
"""
auth_flow_analyzer.py — Analyze auth scan results, classify findings,
generate validation plan with ADB commands and Frida hooks.

Usage: python3 auth_flow_analyzer.py auth_scan.json -o analysis.json
"""
import argparse, json, sys

SEVERITY_MAP = {
    "protected_screen_exported": "high",
    "biometric_no_crypto": "high",
    "intent_auth_control": "high",
    "client_auth_flag_in_prefs": "high",
    "pin_otp_local_only": "medium",
    "deep_link_to_protected": "medium",
    "oauth_missing_state": "medium",
    "webview_auth_bridge": "high",
}


def analyze_exported_activities(manifest):
    findings = []
    for act in manifest.get("exported_activities", []):
        if act.get("likely_role") == "protected_screen":
            pkg = manifest.get("package", "com.target.app")
            name = act["name"]
            full = f"{pkg}/{name}" if not name.startswith(pkg) else name
            findings.append({
                "type": "protected_screen_exported",
                "severity": "high",
                "activity": name,
                "description": f"Protected screen '{name}' is exported — may be accessible without auth",
                "adb_test": f'adb shell am start -n {pkg}/{name}',
                "validation": "Check if activity shows user data or allows actions without login",
                "status": "potential",
            })
    return findings


def analyze_deep_link_auth(manifest, code_findings):
    findings = []
    auth_activities = set()
    for f in code_findings:
        if f["category"] in ("client_side_auth", "biometric_auth"):
            auth_activities.add(f["file"].split("/")[-1].replace(".java", ""))

    for dl in manifest.get("deep_links", []):
        act_name = dl["activity"].split(".")[-1]
        findings.append({
            "type": "deep_link_to_protected",
            "severity": "medium",
            "activity": dl["activity"],
            "uri": dl["uri"],
            "description": f"Deep link routes to {act_name} — test if auth check runs",
            "adb_test": f'adb shell am start -d "{dl["uri"]}" {manifest.get("package", "")}',
            "status": "potential",
        })
    return findings


def analyze_biometric(biometric_check, code_findings):
    if not biometric_check.get("vulnerable"):
        return []
    bio_files = [f for f in code_findings if f["group"] == "biometric"]
    return [{
        "type": "biometric_no_crypto",
        "severity": "high",
        "description": biometric_check["issue"],
        "files": [f["file"] for f in bio_files[:3]],
        "frida_bypass": 'Java.perform(function(){var B=Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");B.onAuthenticationSucceeded.implementation=function(r){console.log("[*] Biometric bypassed");this.onAuthenticationSucceeded(r)};});',
        "validation": "Hook onAuthenticationSucceeded with Frida, check if app grants access",
        "status": "potential",
    }]


def analyze_intent_auth(code_findings, manifest):
    findings = []
    pkg = manifest.get("package", "com.target.app")
    for f in code_findings:
        if f["category"] == "intent_auth_control":
            # Extract the extra name from the match
            extra_match = f["match"]
            findings.append({
                "type": "intent_auth_control",
                "severity": "high",
                "description": f"Intent extra controls auth: {extra_match}",
                "file": f["file"],
                "line": f["line"],
                "adb_test": f'adb shell am start -n {pkg}/.MainActivity --ez "skip_auth" true --ez "is_authenticated" true',
                "status": "potential",
            })
    return findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="Auth scan JSON")
    p.add_argument("-o", "--output", default="auth_analysis.json")
    args = p.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    manifest = data.get("manifest", {})
    code = data.get("code_findings", [])
    bio = data.get("biometric_analysis", {})

    all_findings = []
    all_findings += analyze_exported_activities(manifest)
    all_findings += analyze_deep_link_auth(manifest, code)
    all_findings += analyze_biometric(bio, code)
    all_findings += analyze_intent_auth(code, manifest)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "medium"), 9))

    result = {
        "total_findings": len(all_findings),
        "by_severity": {},
        "findings": all_findings,
    }
    for f in all_findings:
        s = f.get("severity", "medium")
        result["by_severity"][s] = result["by_severity"].get(s, 0) + 1

    with open(args.output, "w") as out:
        json.dump(result, out, indent=2)

    print(f"[+] Analysis: {len(all_findings)} potential auth bypass findings → {args.output}")
    for f in all_findings:
        print(f"  [{f['severity'].upper():8s}] {f['type']}: {f['description'][:80]}")


if __name__ == "__main__":
    main()
