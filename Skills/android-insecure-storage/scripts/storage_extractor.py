#!/usr/bin/env python3
"""
storage_extractor.py — Extract and analyze app storage from a connected Android device.
Requires ADB and a rooted device or debuggable app.

Usage:
    python3 storage_extractor.py com.target.app -o extracted/
    python3 storage_extractor.py com.target.app --backup -o extracted/
"""
import argparse, json, os, re, subprocess, sys

SENSITIVE_PATTERNS = [
    (r'(?i)password|passwd|pwd', "password"),
    (r'(?i)token|access_token|refresh_token|auth_token|session_token|id_token', "token"),
    (r'(?i)session|session_id|sid', "session"),
    (r'(?i)secret|api_secret|client_secret', "secret"),
    (r'(?i)credit.?card|card.?number|cvv|ccnum', "credit_card"),
    (r'(?i)ssn|social.?security', "ssn"),
    (r'(?i)pin|otp|mfa.?code', "pin_otp"),
    (r'(?i)bearer|jwt|eyJ[A-Za-z0-9]', "bearer_jwt"),
    (r'(?i)private.?key|-----BEGIN', "private_key"),
    (r'(?i)api.?key|apikey', "api_key"),
]

def adb(cmd, as_root=False):
    prefix = "adb shell su -c" if as_root else "adb shell"
    full = f'{prefix} "{cmd}"' if as_root else f'{prefix} {cmd}'
    r = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=15)
    return r.stdout.strip(), r.returncode == 0

def extract_prefs(pkg, out_dir):
    prefs_dir = os.path.join(out_dir, "shared_prefs")
    os.makedirs(prefs_dir, exist_ok=True)

    files, ok = adb(f"ls /data/data/{pkg}/shared_prefs/", as_root=True)
    if not ok:
        files, ok = adb(f"run-as {pkg} ls shared_prefs/")
    if not ok:
        print("  [!] Cannot access SharedPreferences (need root or debuggable app)")
        return []

    extracted = []
    for f in files.split("\n"):
        f = f.strip()
        if not f.endswith(".xml"):
            continue
        content, ok = adb(f"cat /data/data/{pkg}/shared_prefs/{f}", as_root=True)
        if not ok:
            content, ok = adb(f"run-as {pkg} cat shared_prefs/{f}")
        if ok and content:
            out_path = os.path.join(prefs_dir, f)
            open(out_path, "w").write(content)
            extracted.append({"file": f"shared_prefs/{f}", "content": content})

    return extracted

def extract_databases(pkg, out_dir):
    db_dir = os.path.join(out_dir, "databases")
    os.makedirs(db_dir, exist_ok=True)

    files, ok = adb(f"ls /data/data/{pkg}/databases/", as_root=True)
    if not ok:
        files, ok = adb(f"run-as {pkg} ls databases/")
    if not ok:
        return []

    extracted = []
    for f in files.split("\n"):
        f = f.strip()
        if not f or f.endswith("-journal") or f.endswith("-wal") or f.endswith("-shm"):
            continue
        # Copy to sdcard then pull
        adb(f"cp /data/data/{pkg}/databases/{f} /sdcard/_pentest_{f}", as_root=True)
        pull = subprocess.run(f"adb pull /sdcard/_pentest_{f} {os.path.join(db_dir, f)}", shell=True, capture_output=True)
        adb(f"rm /sdcard/_pentest_{f}", as_root=True)
        if pull.returncode == 0:
            extracted.append({"file": f"databases/{f}", "path": os.path.join(db_dir, f)})

    return extracted

def analyze_for_secrets(files):
    findings = []
    for f in files:
        content = f.get("content", "")
        if not content and f.get("path"):
            try:
                content = open(f["path"], errors="ignore").read()
            except:
                continue
        for pat, category in SENSITIVE_PATTERNS:
            for m in re.finditer(pat, content):
                # Get surrounding context
                start = max(0, m.start() - 50)
                end = min(len(content), m.end() + 100)
                context = content[start:end].strip()
                findings.append({
                    "file": f["file"], "category": category,
                    "match_context": context[:200],
                    "severity": "critical" if category in ("password", "credit_card", "ssn", "private_key") else "high",
                })
    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["category"], f["match_context"][:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def extract_backup(pkg, out_dir):
    backup_dir = os.path.join(out_dir, "backup")
    os.makedirs(backup_dir, exist_ok=True)
    ab_file = os.path.join(backup_dir, "backup.ab")

    print("  [*] Creating ADB backup (approve on device)...")
    subprocess.run(f"adb backup -f {ab_file} -apk {pkg}", shell=True, timeout=60)

    if os.path.exists(ab_file) and os.path.getsize(ab_file) > 100:
        print(f"  [+] Backup saved: {ab_file}")
        print("  [*] Convert with: java -jar abe.jar unpack backup.ab backup.tar")
        return [{"file": "backup.ab", "path": ab_file}]
    return []

def main():
    p = argparse.ArgumentParser(description="Extract app storage from device")
    p.add_argument("package", help="App package name")
    p.add_argument("-o", "--output", default="extracted")
    p.add_argument("--backup", action="store_true", help="Also create ADB backup")
    args = p.parse_args()

    os.makedirs(args.output, exist_ok=True)
    pkg = args.package
    all_files = []

    print(f"[*] Extracting storage for {pkg}...")

    print("[*] SharedPreferences...")
    prefs = extract_prefs(pkg, args.output)
    all_files += prefs
    print(f"  [+] {len(prefs)} preference files extracted")

    print("[*] Databases...")
    dbs = extract_databases(pkg, args.output)
    all_files += dbs
    print(f"  [+] {len(dbs)} database files extracted")

    if args.backup:
        print("[*] ADB Backup...")
        backups = extract_backup(pkg, args.output)
        all_files += backups

    print("[*] Analyzing for sensitive data...")
    secrets = analyze_for_secrets(all_files)

    result = {
        "package": pkg,
        "files_extracted": len(all_files),
        "sensitive_findings": secrets,
        "files": [{"file": f["file"]} for f in all_files],
    }

    out_file = os.path.join(args.output, "extraction_results.json")
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*50}")
    print(f" Extraction Complete: {pkg}")
    print(f"{'='*50}")
    print(f" Files extracted: {len(all_files)}")
    print(f" Sensitive findings: {len(secrets)}")
    for s in secrets[:10]:
        print(f"   [{s['severity'].upper():8s}] {s['category']:15s} in {s['file']}")
    print(f" Results → {out_file}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
