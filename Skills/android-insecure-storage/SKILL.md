---
name: android-insecure-storage
description: Audit Android insecure data storage — SharedPreferences, SQLite, external storage, logs, clipboard, backups, credential leakage, PoC extraction, HackerOne reporting.
---

# Android Insecure Data Storage Audit

Systematic discovery of sensitive data stored insecurely in Android apps —
the #1 most common Android bug bounty finding (OWASP Mobile Top 10 M9).

> **Authorization required.** Static analysis is safe. Runtime extraction
> via ADB/Frida requires explicit permission and a rooted test device.

## Quick Start

```bash
python3 scripts/storage_scanner.py target.apk -o scan.json
python3 scripts/storage_extractor.py com.target.app -o extracted/    # runtime, needs ADB
python3 scripts/generate_report.py scan.json -o report.md
```

---

## Phase 1 — Static Analysis: Find Storage Patterns in Code

### 1.1 Decompile
```bash
jadx -d jadx_out/ --deobf --show-bad-code target.apk
apktool d target.apk -o apktool_out/
```

### 1.2 SharedPreferences — plaintext credentials
```bash
# Find all SharedPreferences usage
grep -rn "getSharedPreferences\|PreferenceManager\|SharedPreferences" jadx_out/

# Plaintext credential storage
grep -rn "putString.*password\|putString.*token\|putString.*session\|putString.*secret\|putString.*key\|putString.*pin" jadx_out/

# World-readable modes (deprecated but still found)
grep -rn "MODE_WORLD_READABLE\|MODE_WORLD_WRITEABLE" jadx_out/

# Check for EncryptedSharedPreferences (secure)
grep -rn "EncryptedSharedPreferences\|MasterKey\|MasterKeys" jadx_out/
```

### 1.3 SQLite — unencrypted databases
```bash
# Database operations
grep -rn "SQLiteDatabase\|openOrCreateDatabase\|getWritableDatabase\|getReadableDatabase" jadx_out/

# Sensitive data in SQL
grep -rn "INSERT.*password\|INSERT.*token\|INSERT.*credit\|INSERT.*ssn" jadx_out/

# Check for SQLCipher (encrypted — good)
grep -rn "SQLCipher\|net.sqlcipher\|sqlcipher" jadx_out/
```

### 1.4 External storage — world-readable
```bash
# External storage writes
grep -rn "getExternalStorageDirectory\|getExternalFilesDir\|Environment.DIRECTORY" jadx_out/
grep -rn "WRITE_EXTERNAL_STORAGE\|READ_EXTERNAL_STORAGE" apktool_out/AndroidManifest.xml

# File output streams
grep -rn "FileOutputStream\|FileWriter\|OutputStreamWriter" jadx_out/ | grep -i "sdcard\|external"
```

### 1.5 Logging — sensitive data in logcat
```bash
# Log statements with sensitive data
grep -rn "Log\.\(d\|i\|v\|w\|e\)\s*(" jadx_out/ | grep -i "password\|token\|session\|credit\|pin\|otp\|secret\|key\|auth\|bearer"

# println statements
grep -rn "System.out.println\|System.err.println" jadx_out/ | grep -i "password\|token\|key"
```

### 1.6 Clipboard — sensitive copy
```bash
grep -rn "ClipboardManager\|setPrimaryClip\|ClipData" jadx_out/
# Check: is password/token/OTP copied to clipboard?
```

### 1.7 Backup exposure
```bash
# Check allowBackup flag
grep "allowBackup" apktool_out/AndroidManifest.xml
# android:allowBackup="true" → app data extractable via adb backup

# Check fullBackupContent rules
grep -rn "fullBackupContent\|dataExtractionRules" apktool_out/AndroidManifest.xml
```

### 1.8 WebView cache and cookies
```bash
grep -rn "setCacheMode\|setDomStorageEnabled\|CookieManager" jadx_out/
# WebView may cache auth tokens in app_webview/Cookies database
```

### 1.9 Realm / Room databases
```bash
grep -rn "RealmConfiguration\|Realm.getInstance\|RoomDatabase\|@Database" jadx_out/
# Check if Realm encryption key is set
grep -rn "encryptionKey\|RealmConfiguration.Builder.*encryptionKey" jadx_out/
```

---

## Phase 2 — Runtime Extraction (Authorized, Rooted Device)

### 2.1 Extract SharedPreferences
```bash
adb shell run-as com.target.app cat shared_prefs/*.xml
# OR on rooted device:
adb shell su -c "cat /data/data/com.target.app/shared_prefs/*.xml"

# Pull all prefs
adb shell su -c "ls /data/data/com.target.app/shared_prefs/"
for f in $(adb shell su -c "ls /data/data/com.target.app/shared_prefs/"); do
  adb shell su -c "cat /data/data/com.target.app/shared_prefs/$f" > "prefs_$f"
done
```

### 2.2 Extract SQLite databases
```bash
adb shell su -c "ls /data/data/com.target.app/databases/"
adb shell su -c "cp /data/data/com.target.app/databases/*.db /sdcard/"
adb pull /sdcard/*.db .

# Query database
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"
sqlite3 app.db ".schema"
```

### 2.3 Extract via backup
```bash
# Create backup (device prompts user)
adb backup -f backup.ab -apk com.target.app

# Convert to tar (needs android-backup-extractor)
java -jar abe.jar unpack backup.ab backup.tar ""

# Extract and search
tar xf backup.tar
grep -r "password\|token\|session\|secret" apps/com.target.app/
```

### 2.4 Monitor logcat for leaks
```bash
# Start app, perform login, monitor logs
adb logcat | grep -i "password\|token\|session\|auth\|key\|otp\|bearer\|secret"

# Filter by app
adb logcat --pid=$(adb shell pidof com.target.app) | grep -i "token\|password"
```

### 2.5 Check external storage
```bash
adb shell ls -laR /sdcard/Android/data/com.target.app/
adb shell ls -laR /sdcard/ | grep -i "com.target"
adb shell find /sdcard/ -name "*.db" -o -name "*.json" -o -name "*.xml" -o -name "*.log" -o -name "*.txt" 2>/dev/null
```

### 2.6 Check clipboard
```bash
# Frida hook to monitor clipboard
frida -U -f com.target.app -l scripts/clipboard_monitor.js --no-pause
```

### 2.7 Objection extraction
```bash
objection -g com.target.app explore

# List and download files
env
ls
file download /data/data/com.target.app/shared_prefs/auth.xml ./auth.xml
sqlite connect /data/data/com.target.app/databases/app.db
```

---

## Phase 3 — What to Look For in Extracted Data

### Sensitive data categories (by severity)

**CRITICAL — Credentials & tokens:**
- Plaintext passwords, PINs
- OAuth access/refresh tokens
- Session tokens, JWT
- API keys with write access
- Private keys, certificates

**HIGH — PII:**
- Full names + email + phone
- Credit card numbers
- SSN / national ID
- Health/medical data
- Addresses, DOB

**MEDIUM — App-sensitive data:**
- User preferences revealing behavior
- Chat messages, transaction history
- Location history
- Internal API endpoints
- Debug flags, feature toggles

**LOW — Not typically impactful:**
- Public user IDs
- App version, device info
- Non-sensitive preferences
- Cached UI state

---

## Phase 4 — Severity Classification

| Finding | Data Accessible | Severity |
|---------|----------------|----------|
| Plaintext password in SharedPrefs | Credential | Critical |
| Session token in unencrypted DB | Session hijack | Critical |
| Backup extraction → credentials | Credential | High |
| PII in plaintext SQLite | Privacy | High |
| Token in logcat | Session hijack | High |
| Credit card in external storage | Financial | Critical |
| Password copied to clipboard | Credential | Medium |
| Internal URLs in preferences | Recon | Low-Medium |
| allowBackup=true (no sensitive data) | Depends | Low |

---

## Phase 5 — Remediation

1. **Use EncryptedSharedPreferences** for all sensitive key-value data
2. **Use SQLCipher** for databases containing PII or credentials
3. **Never store passwords** — store server-issued tokens with expiry
4. **Set `android:allowBackup="false"`** or use `dataExtractionRules` to exclude sensitive files
5. **Never log sensitive data** — strip all credential logging before release
6. **Avoid external storage** for sensitive files — use internal only
7. **Clear clipboard** after timeout for OTP/password fields
8. **Use Android Keystore** for cryptographic key material
9. **Implement certificate pinning** to protect tokens in transit
10. **Use `FLAG_SECURE`** on windows showing sensitive data (prevents screenshots)

---

## References

- OWASP Mobile Top 10 M9: Insecure Data Storage
- OWASP MASTG: Testing Data Storage (0x05d)
- OWASP MASVS-STORAGE requirements
- Appknox: Hidden Risks of Android Local Storage
- Corellium: Exploiting Android Local Storage
- HackerOne #44727 — Steal files via insecure storage
- HackerOne #57918 — Insecure local data storage → file theft
- HackerOne #753868 — Insecure storage + overly permissive keys
- B3nac Android Reports & Resources — insecure-data-storage tag
