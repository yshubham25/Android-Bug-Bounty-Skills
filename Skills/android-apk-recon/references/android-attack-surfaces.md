# Android Attack Surface Reference

## Component-level
- Exported activities → auth bypass, direct launch
- Exported services → data access, privileged actions
- Exported receivers → broadcast injection, OTP intercept
- Exported providers → SQLi, path traversal, data leak

## Communication-level
- Deep links → URL validation bypass, auth skip, scheme hijack
- WebViews → JS bridge abuse, file access, UXSS, cookie theft
- Intents → implicit intent leak, pending intent hijack

## Data-level
- SharedPreferences → plaintext credentials
- SQLite → unencrypted databases
- External storage → world-readable files
- Backups → adb backup extraction
- Logs → credential leakage in logcat

## Network-level
- TrustManagers → trust-all in production
- Cleartext → HTTP for auth/API
- Certificate pinning → bypassable, framework-dependent

## Third-party SDK level
- Firebase → database/storage misconfiguration
- Intercom → identity verification bypass, IDOR
- Analytics → PII leakage to third parties
- Payment SDKs → credential handling

## Cloud/backend level
- API endpoints → IDOR, broken access control
- Firebase → public database/storage
- Hardcoded secrets → cloud API access
