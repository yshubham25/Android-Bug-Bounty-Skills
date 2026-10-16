# HackerOne / Bugcrowd Report Format Guide

## Structure every report like this

### Title
`[Vuln Type] in [Component] of [App Name] allows [Impact]`

Examples:
- SQL Injection in UserContentProvider of ExampleApp allows full database extraction
- One-Click ATO via Deep Link Session Cookie Binding in ShopApp
- Biometric Authentication Bypass in BankApp due to missing CryptoObject

### Severity
Include CVSS 3.1 score with vector string.
Use the calculator: https://www.first.org/cvss/calculator/3.1

### Weakness (CWE)
Pick the most specific one:
- CWE-89: SQL Injection
- CWE-22: Path Traversal
- CWE-287: Improper Authentication
- CWE-639: IDOR
- CWE-312: Cleartext Storage
- CWE-295: Improper Certificate Validation
- CWE-749: Exposed Dangerous Method
- CWE-798: Hardcoded Credentials
- CWE-926: Improper Export of Android Components

### Summary
2-3 sentences. What the bug is, where it is, what an attacker can do.

### Steps to reproduce
Numbered list. Exact commands. Anyone should be able to reproduce.
```
1. Install [App] v[X.Y.Z] on Android [version]
2. Decompile: jadx -d out/ app.apk
3. Observe [vulnerable code] at [file:line]
4. Run: [exact ADB/curl/Frida command]
5. Result: [what happens — data returned, access granted, etc.]
```

### Impact
What can an attacker actually do? Be specific:
- "Read any user's private messages" not "data leak"
- "Take over any account with one tap" not "authentication issue"
- "Extract all credit card numbers from the database" not "SQL injection"

### Evidence
- Screen recording (poc.mp4)
- Burp Collaborator screenshot
- Code snippet showing the vulnerability
- curl command + response (masked)

### Remediation
Specific fix, not generic advice:
- "Use parameterized queries in UserContentProvider.query()" not "fix SQL injection"
- "Set android:exported=false on DashboardActivity" not "restrict access"
- "Add CryptoObject to BiometricPrompt.authenticate()" not "fix biometrics"

## What gets triaged faster
- Clear title with impact
- Minimal but complete reproduction steps
- Video PoC showing the full chain
- Evidence of actual data access, not just theoretical
- Remediation that names the specific file/method to fix

## What gets rejected
- "I found an API key in the APK" without demonstrating impact
- "allowBackup is true" without extracting sensitive data
- Missing certificate pinning without demonstrating MitM impact
- UI-only auth bypass claimed as account takeover
- Theoretical chains without any validation
- Duplicate of a known SDK behavior (not app-specific)
