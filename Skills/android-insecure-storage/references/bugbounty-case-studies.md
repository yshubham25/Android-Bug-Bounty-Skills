# Bug Bounty Case Studies — Insecure Data Storage

## HackerOne #44727 — Steal Files via Insecure Storage
- App stored sensitive data in world-readable location
- Any app on device could read credentials
- Severity: High

## HackerOne #57918 — Insecure Local Data Storage
- Plaintext credentials in SharedPreferences
- No encryption, MODE_WORLD_READABLE on older versions
- Easy file theft on rooted devices

## HackerOne #753868 — Insecure Storage + Permissive Keys
- API keys stored in plaintext SharedPreferences
- Combined with overly permissive key scopes
- Full backend access via extracted keys

## HackerOne #283058 / #283063 — Data Leakage
- Sensitive user data written to external storage
- Any app with READ_EXTERNAL_STORAGE could access
- PII exposure for all app users

## Common Patterns in Accepted Reports
1. Plaintext password/token in SharedPreferences → always accepted
2. Session token in unencrypted SQLite → High severity
3. PII in external storage → High (privacy impact)
4. Credentials in logcat → Medium-High
5. allowBackup=true + extractable credentials → High
6. Password in clipboard → Medium
7. Internal URLs in preferences → Low (recon value)

## What Programs Reject
- allowBackup=true alone (without demonstrating sensitive data extraction)
- SharedPreferences usage without proving sensitive data is stored
- "Theoretical" storage issues without PoC extraction
- Cached non-sensitive UI data
