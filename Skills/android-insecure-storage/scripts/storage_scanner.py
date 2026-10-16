#!/usr/bin/env python3
"""
storage_scanner.py — Static analysis for insecure data storage patterns in Android APKs.
Scans decompiled source for plaintext credential storage, unencrypted databases,
external storage writes, logging leaks, clipboard usage, and backup exposure.

Usage:
    python3 storage_scanner.py target.apk -o scan.json
    python3 storage_scanner.py jadx_out/ --manifest apktool_out/AndroidManifest.xml -o scan.json
"""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict

STORAGE_PATTERNS = {
    "prefs_plaintext_cred": {
        "patterns": [
            r'putString\s*\(\s*"[^"]*(?:password|passwd|pwd|secret|token|session|pin|otp|auth_token|access_token|refresh_token|api_key|private_key)[^"]*"',
            r'edit\(\)\.putString\s*\(\s*"[^"]*(?:password|token|session|secret)[^"]*"',
        ],
        "risk": "critical", "category": "shared_preferences",
        "description": "Plaintext credentials stored in SharedPreferences",
    },
    "prefs_world_readable": {
        "patterns": [r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'],
        "risk": "critical", "category": "shared_preferences",
        "description": "World-readable SharedPreferences — any app can read",
    },
    "prefs_usage": {
        "patterns": [r'getSharedPreferences\s*\(|PreferenceManager\.getDefault'],
        "risk": "info", "category": "shared_preferences",
        "description": "SharedPreferences usage — verify no sensitive data",
    },
    "encrypted_prefs": {
        "patterns": [r'EncryptedSharedPreferences|MasterKey|MasterKeys'],
        "risk": "secure", "category": "shared_preferences",
        "description": "EncryptedSharedPreferences used (good practice)",
    },
    "sqlite_unencrypted": {
        "patterns": [
            r'SQLiteDatabase\.openOrCreateDatabase|getWritableDatabase|getReadableDatabase|SQLiteOpenHelper',
            r'Room\.databaseBuilder|RoomDatabase',
        ],
        "risk": "medium", "category": "sqlite_database",
        "description": "SQLite database — check if encrypted with SQLCipher",
    },
    "sqlite_sensitive_insert": {
        "patterns": [
            r'(?:INSERT|insert)\s+(?:INTO|into)\s+\w+.*(?:password|token|credit|ssn|pin|secret)',
            r'ContentValues.*put.*(?:password|token|credit_card|ssn|session)',
        ],
        "risk": "high", "category": "sqlite_database",
        "description": "Sensitive data inserted into SQLite — check encryption",
    },
    "sqlcipher": {
        "patterns": [r'SQLCipher|net\.sqlcipher|import.*sqlcipher'],
        "risk": "secure", "category": "sqlite_database",
        "description": "SQLCipher encryption used (good practice)",
    },
    "external_storage_write": {
        "patterns": [
            r'getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir',
            r'Environment\.getExternalStorage|DIRECTORY_DOWNLOADS|DIRECTORY_DOCUMENTS',
        ],
        "risk": "high", "category": "external_storage",
        "description": "External storage write — files are world-readable",
    },
    "log_sensitive": {
        "patterns": [
            r'Log\.\w+\s*\([^)]*(?:password|token|session|credit|pin|otp|secret|bearer|auth|key|jwt)[^)]*\)',
            r'System\.out\.print.*(?:password|token|key|session)',
            r'println\s*\(.*(?:password|token|secret)',
        ],
        "risk": "high", "category": "logging",
        "description": "Sensitive data in log output — readable via logcat",
    },
    "clipboard_sensitive": {
        "patterns": [
            r'ClipboardManager.*(?:password|token|otp|pin|secret|credit)',
            r'setPrimaryClip.*(?:password|token|otp)',
            r'ClipData\.newPlainText.*(?:password|token)',
        ],
        "risk": "medium", "category": "clipboard",
        "description": "Sensitive data copied to clipboard — accessible by other apps",
    },
    "webview_cache": {
        "patterns": [
            r'setCacheMode\s*\(\s*WebSettings\.LOAD_DEFAULT',
            r'setDomStorageEnabled\s*\(\s*true',
        ],
        "risk": "low", "category": "webview_cache",
        "description": "WebView caching enabled — may cache auth data",
    },
    "realm_unencrypted": {
        "patterns": [r'RealmConfiguration\.Builder\(\)(?!.*encryptionKey)'],
        "risk": "medium", "category": "realm_database",
        "description": "Realm database without encryption key",
    },
    "file_write_sensitive": {
        "patterns": [
            r'FileOutputStream|FileWriter|OutputStreamWriter.*(?:password|token|secret|credential|auth)',
            r'write\s*\(.*(?:password|token|session|secret).*getBytes',
        ],
        "risk": "high", "category": "file_storage",
        "description": "Sensitive data written to file — check location and permissions",
    },
    "keystore_usage": {
        "patterns": [r'KeyStore\.getInstance\s*\(\s*"AndroidKeyStore"|AndroidKeyStore|KeyGenParameterSpec'],
        "risk": "secure", "category": "keystore",
        "description": "Android Keystore used (good practice for crypto keys)",
    },
}

SCAN_EXTENSIONS = {".java", ".kt", ".smali", ".xml"}
SKIP_DIRS = {"node_modules", ".git", "META-INF", "__pycache__"}


def check_manifest(manifest_path):
    issues = []
    if not os.path.exists(manifest_path):
        return issues
    content = open(manifest_path).read()

    if 'android:allowBackup="true"' in content or ('allowBackup' not in content and 'android:' in content):
        issues.append({
            "type": "backup_enabled", "risk": "high", "category": "backup",
            "description": "android:allowBackup is true (or not set, defaults to true) — app data extractable via ADB backup",
            "file": "AndroidManifest.xml",
        })

    if 'android:debuggable="true"' in content:
        issues.append({
            "type": "debuggable", "risk": "critical", "category": "debug",
            "description": "android:debuggable=true — full app data accessible via run-as",
            "file": "AndroidManifest.xml",
        })

    if 'android:usesCleartextTraffic="true"' in content:
        issues.append({
            "type": "cleartext_traffic", "risk": "medium", "category": "network",
            "description": "Cleartext HTTP traffic allowed — tokens may leak over network",
            "file": "AndroidManifest.xml",
        })

    if 'WRITE_EXTERNAL_STORAGE' in content:
        issues.append({
            "type": "external_storage_perm", "risk": "medium", "category": "external_storage",
            "description": "WRITE_EXTERNAL_STORAGE permission — app writes to world-readable location",
            "file": "AndroidManifest.xml",
        })

    return issues


def scan_source(jadx_dir):
    findings = []
    for dirpath, dirnames, filenames in os.walk(jadx_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if os.path.splitext(fname)[1].lower() not in SCAN_EXTENSIONS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
            except:
                continue
            rel = os.path.relpath(fpath, jadx_dir)

            # Skip SDK/library code for noise reduction
            if any(sdk in rel for sdk in ["/com/google/", "/androidx/", "/kotlin/", "/okhttp/", "/retrofit/", "/com/facebook/", "/com/crashlytics/"]):
                continue

            for group_name, group in STORAGE_PATTERNS.items():
                for pat_str in group["patterns"]:
                    for m in re.finditer(pat_str, content, re.IGNORECASE):
                        line = content[:m.start()].count("\n") + 1
                        lines = content.split("\n")
                        ctx_s = max(0, line - 3)
                        ctx_e = min(len(lines), line + 2)
                        findings.append({
                            "group": group_name, "category": group["category"],
                            "risk": group["risk"], "description": group["description"],
                            "match": m.group(0)[:100], "file": rel, "line": line,
                            "context": "\n".join(lines[ctx_s:ctx_e])[:400],
                        })

    seen = set()
    unique = []
    for f in findings:
        key = (f["group"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def main():
    p = argparse.ArgumentParser(description="Scan APK for insecure data storage")
    p.add_argument("target", help="APK file or JADX output directory")
    p.add_argument("--manifest", help="Path to AndroidManifest.xml")
    p.add_argument("-o", "--output", default="storage_scan.json")
    args = p.parse_args()

    target = args.target
    jadx_dir = target
    manifest_path = args.manifest

    if target.endswith(".apk"):
        jadx_dir = target.replace(".apk", "_jadx")
        apktool_dir = target.replace(".apk", "_apktool")
        print("[*] Decompiling...")
        subprocess.run(["jadx", "-d", jadx_dir, "--deobf", target], capture_output=True)
        subprocess.run(["apktool", "d", target, "-o", apktool_dir, "-f"], capture_output=True)
        manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")

    manifest_issues = check_manifest(manifest_path) if manifest_path else []
    code_findings = scan_source(jadx_dir)

    # Separate secure practices from vulnerabilities
    secure = [f for f in code_findings if f["risk"] == "secure"]
    vulns = [f for f in code_findings if f["risk"] not in ("secure", "info")]

    by_cat = defaultdict(int)
    by_risk = defaultdict(int)
    for f in vulns:
        by_cat[f["category"]] += 1
        by_risk[f["risk"]] += 1

    result = {
        "manifest_issues": manifest_issues,
        "vulnerabilities": vulns,
        "secure_practices": secure,
        "info_findings": [f for f in code_findings if f["risk"] == "info"],
        "summary": {
            "total_vulns": len(vulns),
            "manifest_issues": len(manifest_issues),
            "secure_practices": len(secure),
            "by_category": dict(by_cat),
            "by_risk": dict(by_risk),
        },
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*50}")
    print(f" Insecure Storage Scan Complete")
    print(f"{'='*50}")
    print(f" Vulnerabilities: {len(vulns)}")
    for cat, count in sorted(by_cat.items()):
        print(f"   {cat:25s} {count}")
    print(f" Manifest issues: {len(manifest_issues)}")
    for mi in manifest_issues:
        print(f"   [{mi['risk'].upper():8s}] {mi['description'][:60]}")
    print(f" Secure practices found: {len(secure)}")
    for sp in secure:
        print(f"   [GOOD] {sp['description']}")
    print(f" Results → {args.output}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
