---
name: android-authentication-bypass
description: Find Android authentication bypasses — exported activities, biometric flaws, client-side auth, OAuth/JWT/session bugs, deep link auth skip, PoC generation, HackerOne reporting.
---

# Android Authentication Bypass Skill

Systematic discovery of authentication bypass vulnerabilities in Android apps
via static analysis, with controlled runtime validation on authorized targets.

> **Authorization required.** Static analysis is safe. Runtime testing
> (ADB, Frida) requires explicit permission. Use researcher-owned test accounts.

## Quick Start

```bash
python3 scripts/auth_scanner.py target.apk -o scan.json
python3 scripts/auth_flow_analyzer.py scan.json -o analysis.json
python3 scripts/generate_poc.py analysis.json -o pocs/
python3 scripts/generate_report.py analysis.json -o report.md
```

---

## Phase 1 — Recon: Map Authentication Surface

### 1.1 Decompile
```bash
jadx -d jadx_out/ --deobf --show-bad-code target.apk
apktool d target.apk -o apktool_out/
```

### 1.2 Map exported components
```bash
# All exported activities (potential auth bypass entry points)
grep -B2 -A10 'exported="true"' apktool_out/AndroidManifest.xml

# Via Drozer
run app.activity.info -a com.target.app
run app.package.attacksurface com.target.app
```

### 1.3 Find authentication code
```bash
# Auth state checks
grep -rn "isAuthenticated\|isLoggedIn\|isVerified\|isAuthorized\|isPremium\|loginRequired" jadx_out/

# Auth managers
grep -rn "AuthManager\|SessionManager\|TokenManager\|LoginManager\|AccountManager" jadx_out/

# Biometric auth
grep -rn "BiometricPrompt\|FingerprintManager\|CryptoObject\|onAuthenticationSucceeded" jadx_out/

# Token handling
grep -rn "access_token\|refresh_token\|id_token\|Bearer\|Authorization\|JWT" jadx_out/

# SharedPreferences auth flags
grep -rn "getBoolean.*logged\|getBoolean.*auth\|putBoolean.*login\|is_logged_in" jadx_out/

# Intent extras controlling auth
grep -rn "getBooleanExtra.*auth\|getStringExtra.*token\|getBooleanExtra.*skip" jadx_out/
```

---

## Phase 2 — Ten Attack Patterns

### Pattern 1: Exported Activity Bypass
**What:** Protected screens directly launchable without authentication.

**Test:**
```bash
# List all activities, try launching post-login screens
adb shell am start -n com.target.app/.DashboardActivity
adb shell am start -n com.target.app/.ProfileActivity
adb shell am start -n com.target.app/.SettingsActivity
adb shell am start -n com.target.app/.PaymentActivity
```

**What to look for:** Activity opens without login prompt, shows user data,
or allows actions. Recent CVEs: Datadog CVE-2026-44964, CVE-2026-47363
(exported activities accepting attacker-controlled session data).

**Severity:** High-Critical if data/actions are accessible. Medium if UI-only.

### Pattern 2: Deep Link Auth Skip
**What:** Deep links route directly to authenticated screens.

```bash
adb shell am start -d "myapp://dashboard" com.target.app
adb shell am start -d "myapp://profile/settings" com.target.app
adb shell am start -d "myapp://payment/add-card" com.target.app
```

**Check:** Does the app verify auth state in `onCreate()` of the target
activity, or only in the login flow?

### Pattern 3: Client-Side Auth Flag Manipulation
**What:** Auth decisions rely on SharedPreferences booleans.

**Grep:**
```bash
grep -rn "getBoolean.*isLoggedIn\|getBoolean.*authenticated\|putBoolean.*login" jadx_out/
```

**Frida bypass (authorized only):**
```javascript
Java.perform(function() {
    var SP = Java.use("android.app.SharedPreferencesImpl");
    SP.getBoolean.implementation = function(key, def) {
        if (key.match(/login|auth|verified|premium/i)) {
            console.log("[*] Bypassing: " + key);
            return true;
        }
        return this.getBoolean(key, def);
    };
});
```

### Pattern 4: Biometric Bypass
**What:** App uses `BiometricPrompt` callback without `CryptoObject`.

**Vulnerable pattern:**
```java
// No CryptoObject — callback-only auth
biometricPrompt.authenticate(promptInfo);
// onAuthenticationSucceeded grants access without crypto proof
```

**Secure pattern:**
```java
// CryptoObject ties auth to actual key operation
biometricPrompt.authenticate(promptInfo, new CryptoObject(cipher));
// onAuthenticationSucceeded: cipher is now unlocked
```

**Grep:**
```bash
grep -rn "BiometricPrompt\|authenticate(" jadx_out/
grep -rn "CryptoObject" jadx_out/
# If BiometricPrompt exists but CryptoObject doesn't → likely vulnerable
```

**HackerOne references:** #331489, #490946, #637194

### Pattern 5: PIN/OTP/MFA Local Bypass
**What:** PIN/OTP verified client-side without backend enforcement.

**Grep:**
```bash
grep -rn "verifyPin\|checkOtp\|validateMfa\|pinCorrect\|otpMatch" jadx_out/
grep -rn "MAX_RETRY\|attempt.*count\|lockout" jadx_out/
```

**Red flags:** PIN comparison in Java code, no server round-trip,
retry counter stored in SharedPreferences (resettable by clearing app data).

### Pattern 6: OAuth/SSO Bypass
**What:** Missing state parameter, weak PKCE, redirect URI hijacking.

**Grep:**
```bash
grep -rn "state=\|code_verifier\|code_challenge\|redirect_uri\|authorization_code" jadx_out/
grep -rn "onActivityResult.*LOGIN\|handleAuthCallback\|handleRedirect" jadx_out/
```

**Check:** Is `state` validated on callback? Is PKCE used? Can redirect_uri
be overridden via intent extras?

### Pattern 7: JWT/Session Bypass
**What:** Token not validated properly, no expiry check, client-side trust.

**Grep:**
```bash
grep -rn "jwt\|JsonWebToken\|decode.*token\|verify.*token\|exp.*claim" jadx_out/
grep -rn "setHeader.*alg.*none\|Algorithm.none" jadx_out/
```

**Check:** Does app decode JWT without verifying signature? Does it check
`exp` claim? Does it accept `alg: none`?

### Pattern 8: Intent Extra Auth Control
**What:** Intent extras control authentication decisions.

**Grep:**
```bash
grep -rn "getBooleanExtra.*auth\|getBooleanExtra.*skip\|getBooleanExtra.*verified" jadx_out/
grep -rn "getStringExtra.*token\|getStringExtra.*session" jadx_out/
```

**Test:**
```bash
adb shell am start -n com.target.app/.MainActivity --ez "skip_auth" true
adb shell am start -n com.target.app/.MainActivity --ez "is_authenticated" true
adb shell am start -n com.target.app/.Dashboard --es "session_token" "crafted_value"
```

**Recent CVE:** Datadog CVE-2026-47363 — exported activity accepting OAuth
token material via intent extras.

### Pattern 9: WebView Auth Bypass
**What:** WebView JS bridge exposes auth methods, or session cookies are
accessible to attacker-controlled pages.

**Grep:**
```bash
grep -rn "addJavascriptInterface" jadx_out/ | grep -i "auth\|login\|session\|token"
grep -rn "@JavascriptInterface" jadx_out/
```

Cross-reference with the WebView pentest skill.

### Pattern 10: Password Reset / Magic Link Bypass
**What:** Reset link callback doesn't validate origin, token is replayable.

**Grep:**
```bash
grep -rn "resetPassword\|magicLink\|passwordReset\|recovery" jadx_out/
grep -rn "oobCode\|resetToken\|verifyEmail" jadx_out/
```

**Check:** Is the reset deep link handler exported? Can the token be used
multiple times? Is there an expiry?

---

## Phase 3 — Severity Classification

| Finding | Backend data accessible? | Severity |
|---------|------------------------|----------|
| Exported activity shows real user data | Yes | Critical |
| Exported activity shows UI but no data | No | Medium |
| Biometric bypass + data access | Yes | Critical |
| Biometric callback-only (no CryptoObject) | Depends | High |
| Client-side auth flag bypass + API access | Yes | Critical |
| Client-side flag, no backend impact | No | Low-Medium |
| JWT alg:none accepted by backend | Yes | Critical |
| OAuth state missing + token theft | Yes | High-Critical |
| Deep link skips login screen | Depends | Medium-High |
| PIN verified locally only | Depends | Medium-High |

**Key rule:** UI-only bypass without backend data = Medium at best.
Backend data/action access = High-Critical.

---

## Phase 4 — Report Writing

Use `templates/vulnerability-report.md`. Always include:
- Exact ADB/Frida command or deep link
- What data/action was accessed without authentication
- Whether backend enforces auth independently
- Screen recording or screenshot evidence

---

## Phase 5 — Remediation

1. **Set `exported=false`** on all activities unless required
2. **Check auth state in every Activity's `onCreate()`**, not just login flow
3. **Use CryptoObject** with BiometricPrompt — never callback-only
4. **Server-side auth enforcement** — never trust client-side flags
5. **Validate OAuth state parameter** on every callback
6. **Implement PKCE** for all mobile OAuth flows
7. **Verify JWT signature server-side** — reject `alg:none`
8. **Never pass auth decisions via intent extras**
9. **Rate-limit and server-verify** PIN/OTP attempts
10. **Expire and single-use** password reset tokens

---

## References

- OWASP MASTG: Testing Local Authentication
- OWASP MASTG: Exported Activity Auth Bypass (MASTG-TEST-0364)
- HackerOne #331489, #490946, #637194 — Biometric bypass
- HackerOne #202425 — 2FA bypass via vulnerable endpoint
- HackerOne #205000 — Auth bypass via endpoint
- CVE-2026-44964/47363/44965 — Datadog exported activity auth bypass
- CVE-2026-44279 — FortiToken exported component bypass
- B3nac/Android-Reports-and-Resources — HackerOne Android report collection
