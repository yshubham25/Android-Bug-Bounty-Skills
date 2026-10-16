# OWASP MASVS / MASTG Quick Reference

Map your skills to OWASP categories for program compliance.

## MASVS-STORAGE (Data Storage)
**Skill:** `android-insecure-storage` + `android-sensitive-data-leakage`
- MASTG-TEST-0001: Testing Local Storage for Sensitive Data
- MASTG-TEST-0002: Testing Local Storage for Input Validation
- MASTG-TEST-0011: Testing Backups for Sensitive Data
- MASTG-TEST-0012: Testing Logs for Sensitive Data
- SharedPreferences, SQLite, external storage, clipboard, backup

## MASVS-CRYPTO (Cryptography)
**Skill:** covered partially in `android-sensitive-data-leakage`
- MASTG-TEST-0013: Testing Symmetric Cryptography
- MASTG-TEST-0014: Testing Random Number Generation
- Hardcoded keys, weak algorithms, insecure modes

## MASVS-AUTH (Authentication)
**Skill:** `android-authentication-bypass`
- MASTG-TEST-0016: Testing Biometric Authentication
- MASTG-TEST-0017: Testing Confirm Credentials
- Biometric, PIN, client-side flags, OAuth

## MASVS-NETWORK (Network Communication)
**Skill:** `android-network-security`
- MASTG-TEST-0019: Testing Endpoint Identity Verification
- MASTG-TEST-0020: Testing Custom Certificate Stores
- MASTG-TEST-0021: Testing the Security Provider
- TLS config, pinning, cleartext, TrustManagers

## MASVS-PLATFORM (Platform Interaction)
**Skills:** `android-deeplink-pentest` + `android-webview-pentest` + `android-ipc-exploitation`
- MASTG-TEST-0024: Testing Deep Links
- MASTG-TEST-0025: Testing for Sensitive Functionality Exposure Through IPC
- MASTG-TEST-0026: Testing JavaScript Execution in WebViews
- MASTG-TEST-0027: Testing WebView Protocol Handlers
- MASTG-TEST-0028: Testing for Overlay Attacks
- MASTG-TEST-0364: Testing Exported Activities

## MASVS-CODE (Code Quality)
**Skill:** `android-apk-recon` + `android-sensitive-data-leakage`
- MASTG-TEST-0034: Testing for Debugging Symbols
- MASTG-TEST-0035: Testing for Debugging Code
- MASTG-TEST-0036: Testing for Third-Party Libraries
- Obfuscation, debug flags, SDK versions

## MASVS-RESILIENCE (Resilience)
**Skill:** not yet covered (reverse engineering / anti-tamper skill needed)
- MASTG-TEST-0038: Testing Root Detection
- MASTG-TEST-0039: Testing Anti-Debugging Detection
- MASTG-TEST-0040: Testing File Integrity Checks
