#!/usr/bin/env python3
"""
protection_detector.py — Detect root detection, Frida detection, emulator detection,
tamper checks, and commercial RASP SDKs in Android APKs.

Usage: python3 protection_detector.py target.apk -o protections.json
"""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict

PROTECTIONS = {
    "root_rootbeer": {"patterns": [r"com\.scottyab\.rootbeer|RootBeer|isRooted\b|isRootedWithBusyBox"],
        "category": "root_detection", "name": "RootBeer library", "bypass": "Frida RootBeer hooks or Magisk DenyList"},
    "root_su_binary": {"patterns": [r"which su|/system/xbin/su|/sbin/su|/system/bin/su|canExecSu"],
        "category": "root_detection", "name": "su binary check", "bypass": "Frida File.exists + Runtime.exec hooks"},
    "root_packages": {"patterns": [r"com\.topjohnwu\.magisk|eu\.chainfire\.supersu|com\.koushikdutta\.superuser|com\.noshufou\.android\.su"],
        "category": "root_detection", "name": "Root app package check", "bypass": "Magisk DenyList or Frida PM hook"},
    "root_build_tags": {"patterns": [r"Build\.TAGS|test-keys"],
        "category": "root_detection", "name": "Build.TAGS check", "bypass": "Frida Build.TAGS.value override"},
    "root_mount": {"patterns": [r"/proc/mounts.*rw|/system.*remount"],
        "category": "root_detection", "name": "Mount check", "bypass": "Frida fopen hook on /proc/mounts"},
    "safetynet": {"patterns": [r"SafetyNet|SafetyNetClient|safetynet\.googleapis|attest\b"],
        "category": "attestation", "name": "SafetyNet attestation", "bypass": "Magisk + custom module (difficult)"},
    "play_integrity": {"patterns": [r"PlayIntegrity|integrity.*verdict|MEET_DEVICE_INTEGRITY|IntegrityManager"],
        "category": "attestation", "name": "Play Integrity API", "bypass": "Very difficult — server-side verified"},
    "frida_port": {"patterns": [r"27042|27043"],
        "category": "frida_detection", "name": "Frida port check", "bypass": "Frida Socket hook or custom port"},
    "frida_library": {"patterns": [r"frida-agent|frida-gadget|libfrida|LIBFRIDA"],
        "category": "frida_detection", "name": "Frida library check", "bypass": "Frida /proc/self/maps hook"},
    "frida_process": {"patterns": [r"/proc/self/maps.*frida|frida-server|frida.*detect"],
        "category": "frida_detection", "name": "Frida process/maps check", "bypass": "Rename frida-server binary"},
    "ptrace": {"patterns": [r"ptrace|PTRACE_ATTACH|PTRACE_TRACEME|TracerPid"],
        "category": "debugger_detection", "name": "ptrace anti-debug", "bypass": "Frida native ptrace hook"},
    "debugger": {"patterns": [r"isDebuggerConnected|Debug\.isDebuggerConnected|waitForDebugger"],
        "category": "debugger_detection", "name": "Java debugger check", "bypass": "Frida Debug class hook"},
    "emulator": {"patterns": [r"generic.*Build|sdk_gphone|goldfish|ranchu|QEMU|qemu|nox|bluestacks|genymotion"],
        "category": "emulator_detection", "name": "Emulator detection", "bypass": "Frida Build field overrides"},
    "signature": {"patterns": [r"GET_SIGNING_CERTIFICATES|getPackageInfo.*GET_SIGNATURES|checkSignatures|signingInfo"],
        "category": "tamper_detection", "name": "Signature verification", "bypass": "Frida PackageManager hook"},
    "installer": {"patterns": [r"getInstallingPackageName|getInstallSourceInfo|com\.android\.vending"],
        "category": "tamper_detection", "name": "Installer verification", "bypass": "Frida PM installer hook"},
    "promon": {"patterns": [r"promon|com\.promon"],
        "category": "commercial_rasp", "name": "Promon SHIELD", "bypass": "Difficult — multi-layered native protection"},
    "guardsquare": {"patterns": [r"dexguard|guardsquare|ixguard"],
        "category": "commercial_rasp", "name": "Guardsquare DexGuard", "bypass": "Difficult — control flow obfuscation"},
    "freerasp": {"patterns": [r"freerasp|talsec|com\.aheaditec"],
        "category": "commercial_rasp", "name": "Talsec freeRASP", "bypass": "Frida hooks on callback methods"},
}

SCAN_EXT = {".java", ".kt", ".smali", ".xml"}

def scan(jadx_dir):
    findings = defaultdict(list)
    for root, dirs, files in os.walk(jadx_dir):
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "META-INF"}]
        for fname in files:
            if os.path.splitext(fname)[1].lower() not in SCAN_EXT: continue
            fpath = os.path.join(root, fname)
            try: content = open(fpath, errors="ignore").read()
            except: continue
            rel = os.path.relpath(fpath, jadx_dir)
            for prot_name, prot in PROTECTIONS.items():
                for pat in prot["patterns"]:
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        findings[prot_name].append({
                            "match": m.group(0)[:80], "file": rel,
                            "line": content[:m.start()].count("\n") + 1,
                        })
    return dict(findings)

def classify(findings):
    detected = {}
    for prot_name, matches in findings.items():
        prot = PROTECTIONS[prot_name]
        detected[prot_name] = {
            "name": prot["name"], "category": prot["category"],
            "bypass": prot["bypass"], "hits": len(matches),
            "locations": [{"file": m["file"], "line": m["line"]} for m in matches[:5]],
        }
    by_cat = defaultdict(list)
    for name, info in detected.items():
        by_cat[info["category"]].append(info["name"])
    return detected, dict(by_cat)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target"); p.add_argument("-o", "--output", default="protections.json")
    args = p.parse_args()
    jadx_dir = args.target
    if args.target.endswith(".apk"):
        jadx_dir = args.target.replace(".apk", "_jadx")
        subprocess.run(["jadx", "-d", jadx_dir, "--deobf", args.target], capture_output=True)

    findings = scan(jadx_dir)
    detected, by_cat = classify(findings)

    result = {"protections_detected": detected, "by_category": by_cat,
              "total_protections": len(detected), "protection_level": "none"}
    if len(detected) >= 8: result["protection_level"] = "heavy"
    elif len(detected) >= 4: result["protection_level"] = "moderate"
    elif len(detected) >= 1: result["protection_level"] = "light"

    json.dump(result, open(args.output, "w"), indent=2)

    print(f"\n{'='*50}")
    print(f" Protection Detection Results")
    print(f"{'='*50}")
    print(f" Protection level: {result['protection_level'].upper()}")
    print(f" Protections found: {len(detected)}")
    for cat, names in sorted(by_cat.items()):
        print(f"\n  {cat}:")
        for n in names: print(f"    - {n}")
    print(f"\n Results → {args.output}")
    print(f"{'='*50}")

if __name__ == "__main__": main()
