---
name: android-intercom-security
description: Test Android Intercom SDK integration for identity verification bypass, IDOR, BOLA, conversation hijack, cross-account access. Use for Intercom, messenger SDK, chat widget pentest.
---

# Android Intercom Security Testing

Detect and validate Intercom Messenger SDK vulnerabilities in Android apps —
identity verification bypass, cross-account conversation access, IDOR/BOLA
on conversation endpoints, and impersonation via SDK credentials.

> **Authorization required.** APK analysis is safe. Active API testing
> requires explicit scope authorization and researcher-owned test accounts only.
> Never access or modify real users' conversations.

## Quick Start

```bash
# Phase 1: Detect Intercom in APK (safe, static)
python3 scripts/intercom_detector.py target.apk -o intercom_results/

# Phase 2: Analyze auth configuration (static)
python3 scripts/intercom_auth_analyzer.py intercom_results/ -o auth_analysis.json

# Phase 3: Generate validation plan (no requests sent)
python3 scripts/intercom_test_planner.py auth_analysis.json -o test_plan.json

# Phase 4: Generate report
python3 scripts/generate_report.py intercom_results/ -o report.md
```

---

## Phase 1 — Intercom Detection (Mandatory First Step)

### 1.1 Decompile and search
```bash
jadx -d jadx_out/ --deobf target.apk

# Search for Intercom indicators
rg -ni 'intercom|mobile-messenger|android_sdk-|user_hash|io\.intercom' jadx_out/

# Manifest check
grep -i "intercom" apktool_out/AndroidManifest.xml

# Resources
grep -rni "intercom" apktool_out/res/values/strings.xml
```

### 1.2 Key indicators to find
```bash
# SDK package
grep -rn "io.intercom.android" jadx_out/

# API hostname
grep -rn "mobile-messenger.intercom.com" jadx_out/

# App ID and SDK credential
grep -rn "android_sdk-\|app_id.*intercom\|intercom.*app_id" jadx_out/

# Identity verification
grep -rn "user_hash\|identity_verification\|loginIdentifiedUser\|loginUnidentifiedUser" jadx_out/

# Initialization
grep -rn "Intercom.initialize\|Intercom.client\|IntercomSDK" jadx_out/
```

### Decision gate
If NO Intercom evidence found → **STOP**. Skill does not apply.
If Intercom detected → proceed to Phase 2.

---

## Phase 2 — Extract Intercom Configuration

### 2.1 Extract credentials and config
```bash
# App ID (format: varies)
grep -rn "app_id\|appId\|INTERCOM_APP_ID" jadx_out/

# Android SDK key (format: android_sdk-XXXXX)
grep -rn "android_sdk-" jadx_out/

# API hostname
grep -rn "mobile-messenger" jadx_out/

# SDK version
grep -rn "intercom.*version\|sdk.*version" jadx_out/ | grep -i intercom
```

### 2.2 Identity verification analysis
```bash
# HMAC / user_hash usage
grep -rn "user_hash\|userHash\|hmac\|HMAC" jadx_out/

# How users are registered with Intercom
grep -rn "loginIdentifiedUser\|loginUnidentifiedUser\|Registration" jadx_out/ | grep -i intercom

# Email vs userId identification
grep -rn "withEmail\|withUserId\|setEmail\|setUserId" jadx_out/ | grep -i intercom
```

### 2.3 What to record
```
Intercom App ID:         [found/not found] → [file:line]
Android SDK Credential:  [found/not found] → [file:line]
API Hostname:            [found/not found]
SDK Version:             [found/unknown]
Identity Verification:
  - user_hash reference: [yes/no/unknown]
  - HMAC implementation: [yes/no/unknown]
  - Verification status: [confirmed/potentially disabled/unknown]
User Type:               [identified/unidentified/both]
```

**Note:** Embedded App ID and SDK credential alone are NOT vulnerabilities.
They are required for the client SDK to function.

---

## Phase 3 — Authentication Flow Analysis

### 3.1 How the app initializes Intercom
```bash
# Initialization pattern
grep -B5 -A10 "Intercom.initialize\|Intercom.client" jadx_out/

# User registration flow
grep -B5 -A10 "loginIdentifiedUser\|loginUnidentifiedUser" jadx_out/

# Token/session binding
grep -rn "setUserAttribute\|updateUser\|setCustomAttribute" jadx_out/ | grep -i intercom
```

### 3.2 Classify the auth model

**A — Identity verification enabled (HMAC):**
Server generates `user_hash = HMAC-SHA256(identity_secret, user_id_or_email)`
and passes it to the SDK. Intercom server validates the hash.

**B — Identity verification potentially disabled:**
App calls `loginIdentifiedUser` with email/userId but no `user_hash`.
Any caller with the SDK credentials could impersonate any user.

**C — Unknown:**
Cannot determine from static analysis alone. Requires runtime validation.

### 3.3 SDK authorization format
```bash
# The SDK uses HTTP Basic Auth: Base64(APP_ID:SDK_KEY)
# Check if this is constructed in code
grep -rn "Basic\|Authorization\|base64.*intercom\|intercom.*base64" jadx_out/
```

---

## Phase 4 — Controlled Validation (Authorized Only)

### Prerequisites
- Written authorization to test the target app's Intercom integration
- Two researcher-owned test accounts (Account A, Account B)
- Burp Suite or mitmproxy configured for traffic interception
- SSL pinning bypassed (use your network-security skill)

### 4.1 Establish baselines
```
1. Log in as Account A → open Intercom messenger → send test message:
   "INTERCOM-TEST-ACCOUNT-A-[timestamp]"
2. Log in as Account B → open Intercom messenger → send test message:
   "INTERCOM-TEST-ACCOUNT-B-[timestamp]"
3. Record conversation IDs for both accounts from intercepted traffic
```

### 4.2 API endpoints to monitor
```
GET/POST /messenger/mobile/conversations/unread
GET/POST /messenger/mobile/conversations
GET/POST /messenger/mobile/conversations/{conversation_id}
```

### 4.3 Identity boundary test
```
Test: Can Account A's session access Account B's conversation?

1. Capture Account A's authenticated request to /conversations
2. Note the authentication headers and identity fields
3. Replace conversation_id with Account B's conversation_id
4. Send the modified request
5. Check: does the response contain Account B's messages?

Expected secure behavior:
- 403 Forbidden or empty response
- No cross-account data disclosed

Potential vulnerability:
- Account B's conversation transcript returned to Account A
- This is IDOR (CWE-639) / BOLA (OWASP API1:2023)
```

### 4.4 Impersonation test (if identity verification is disabled)
```
Test: Can a request with arbitrary email/userId access that user's conversations?

1. Construct a request using SDK credentials from the APK
2. Set the identity field to Account B's email
3. Query conversations
4. Check: do you receive Account B's private conversations?

This is only a vulnerability if:
- The conversations are private authenticated conversations
- Not public visitor/support chat that anyone can create
```

---

## Phase 5 — False Positive Elimination

Before reporting, verify ALL of these:

1. Is visitor messaging intentionally public? (Not a vuln)
2. Did you reuse the same session between accounts? (Invalidates test)
3. Was the response a NEW visitor conversation, not an existing user's? (Not IDOR)
4. Is creating a support conversation expected behavior? (Not a vuln)
5. Can you reproduce after fully clearing sessions/cookies?
6. Is the issue in the target app's integration, or in Intercom SDK itself?
7. Did you actually access ANOTHER USER's private data, or just your own?

**A successful support message creation is NOT evidence of IDOR.**
**An embedded SDK credential is NOT a vulnerability by itself.**

The finding requires demonstrated cross-account data access.

---

## Phase 6 — Severity Classification

| Finding | Severity |
|---------|----------|
| SDK credentials in APK (expected) | Informational |
| Identity verification disabled, no demonstrated impact | Low |
| Can create conversations as arbitrary email (no private data) | Low-Medium |
| Cross-account conversation access (private messages) | High |
| Full user impersonation with message read/write | Critical |
| Missing user_hash without behavioral confirmation | Informational |

### CWE mapping
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-287: Improper Authentication

### Confidence levels
```
CONFIRMED    — reproduced cross-account access with controlled accounts
LIKELY       — identity verification absent + no HMAC, untested dynamically
INCONCLUSIVE — cannot determine without runtime testing
NOT VULN     — identity verification properly enforced
N/A          — no Intercom integration found
```

---

## Phase 7 — Remediation

1. **Enable Intercom identity verification** for all authenticated users
2. **Generate user_hash server-side** using HMAC-SHA256 with identity secret
3. **Never expose the identity verification secret** in client code
4. **Bind Intercom sessions** to authenticated app sessions
5. **Enforce conversation ownership** — server-side validation of conversation access
6. **Separate visitor and authenticated flows** — different identity contexts
7. **Rotate SDK credentials** if exposed alongside identity verification secret

---

## References

- Intercom Identity Verification docs
- OWASP API1:2023 — Broken Object Level Authorization
- CWE-639 — Authorization Bypass Through User-Controlled Key
- HackerOne reports on third-party SDK identity verification bypass
