# Bug Bounty Case Studies — Authentication Bypass

## HackerOne #202425 — 2FA Bypass via Vulnerable Endpoint
Endpoint accepted auth without 2FA challenge. Direct API call bypassed MFA.

## HackerOne #205000 — Auth Bypass via Endpoint
Alternative API endpoint didn't enforce authentication.

## HackerOne #331489 — PIN/Fingerprint Lock Bypass
App-level biometric lock bypassed. No CryptoObject, callback-only auth.

## HackerOne #490946 — Lock Protection Bypass
Screen lock feature could be circumvented via task switching.

## HackerOne #637194 — Biometrics Security Bypass
Biometric check skippable via activity lifecycle manipulation.

## CVE-2026-44964/47363/44965 — Datadog Exported Activities
Multiple exported activities accepting attacker-controlled intents.
No permission guards, no caller verification.

## CVE-2026-44279 — FortiToken Component Export
Exported components leaked OTP material used for MFA.

## Key Patterns
1. Exported activities without permission guards
2. Callback-only biometric auth (no CryptoObject)
3. Client-side auth flags in SharedPreferences
4. Intent extras controlling auth decisions
5. Missing server-side auth enforcement
