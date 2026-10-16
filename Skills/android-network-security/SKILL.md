---
name: android-network-security
description: Audit Android network security and bypass SSL pinning — Java/Kotlin, Flutter, React Native, Xamarin, OkHttp, Conscrypt, Frida, Objection, MitM, cleartext detection.
---

# Android Network Security & SSL Pinning Bypass

Complete methodology for auditing network security and bypassing SSL/TLS
pinning across ALL Android app frameworks during authorized pentests.

> **Authorization required.** Static analysis is safe. MitM interception
> and Frida bypass require explicit permission.

## Quick Start

```bash
python3 scripts/network_scanner.py target.apk -o scan.json        # static analysis
python3 scripts/identify_framework.py target.apk                   # detect app framework
python3 scripts/pinning_bypass.py --framework auto --package com.target.app  # generate bypass
```

---

## Phase 1 — Identify the App Framework

The bypass technique depends entirely on the framework. Get this right first.

### 1.1 Automatic detection
```bash
python3 scripts/identify_framework.py target.apk
```

### 1.2 Manual detection
```bash
# Flutter — has libflutter.so + libapp.so
unzip -l target.apk | grep -i "libflutter\|libapp.so"

# React Native — has libreactnativejni.so or index.android.bundle
unzip -l target.apk | grep -i "reactnative\|index.android.bundle\|libreact"

# Xamarin — has libmonodroid.so or Mono assemblies
unzip -l target.apk | grep -i "xamarin\|monodroid\|assemblies"

# Cordova/Ionic — has www/ folder with index.html
unzip -l target.apk | grep "assets/www/"

# Native Java/Kotlin — none of the above
```

| Framework | Networking Stack | Pinning Location |
|-----------|-----------------|-----------------|
| Java/Kotlin | OkHttp, HttpURLConnection, Volley | Java layer (hookable) |
| Flutter | BoringSSL in libflutter.so | Native C++ (requires binary analysis) |
| React Native | OkHttp (Android), fetch API | Java layer + JS bridge |
| Xamarin | Mono HttpClient, AndroidClientHandler | Mono/.NET layer |
| Cordova/Ionic | WebView → system network stack | Network security config |

---

## Phase 2 — Static Analysis

### 2.1 Network security config
```bash
# Check if custom config exists
grep "networkSecurityConfig" apktool_out/AndroidManifest.xml

# Read the config
cat apktool_out/res/xml/network_security_config.xml

# What to look for:
# <domain-config cleartextTrafficPermitted="true">  → cleartext allowed
# <pin-set>  → certificate pinning configured
# <trust-anchors> <certificates src="user"/> → user certs trusted (good for testing)
```

### 2.2 Cleartext traffic
```bash
# Manifest check
grep "usesCleartextTraffic" apktool_out/AndroidManifest.xml
# true = HTTP allowed (bad), false = HTTPS only (good)

# Find HTTP URLs in code
grep -rn "http://" jadx_out/ | grep -v "https://" | grep -v "http://schemas\|http://www.w3.org\|http://ns.adobe"
```

### 2.3 TrustManager implementations
```bash
# Custom TrustManagers (often trust-all for dev/debug)
grep -rn "X509TrustManager\|TrustManager\|checkServerTrusted\|checkClientTrusted" jadx_out/

# Trust-all patterns (CRITICAL vuln)
grep -rn "trustAllCerts\|ALLOW_ALL_HOSTNAME\|AllowAllHostnameVerifier\|ACCEPT_ALL" jadx_out/

# HostnameVerifier bypass
grep -rn "HostnameVerifier\|verify.*return true\|setHostnameVerifier" jadx_out/
```

### 2.4 Pinning implementation
```bash
# OkHttp CertificatePinner
grep -rn "CertificatePinner\|certificatePinner\|sha256/" jadx_out/

# Network security config pins
grep -rn "<pin-set\|<pin " apktool_out/res/xml/

# TrustKit
grep -rn "TrustKit\|trustkit" jadx_out/

# Custom pinning
grep -rn "X509Certificate\|getPublicKey\|getEncoded\|MessageDigest.*SHA" jadx_out/
```

### 2.5 SSL/TLS configuration
```bash
# SSLContext creation
grep -rn "SSLContext\.getInstance\|TLSv1\|SSLv3\|TLS " jadx_out/

# Conscrypt usage
grep -rn "Conscrypt\|conscrypt" jadx_out/
```

---

## Phase 3 — SSL Pinning Bypass by Framework

### 3A: Java/Kotlin Native Apps

**Method 1 — Objection (quickest):**
```bash
objection -g com.target.app explore --startup-command "android sslpinning disable"
```

**Method 2 — Frida universal bypass:**
```bash
frida -U -f com.target.app -l scripts/ssl_bypass_universal.js --no-pause
```

**Method 3 — Network security config patching:**
```bash
# 1. Decompile
apktool d target.apk -o patched/

# 2. Create/modify res/xml/network_security_config.xml
cat > patched/res/xml/network_security_config.xml << 'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>
XML

# 3. Add to manifest if not present
# android:networkSecurityConfig="@xml/network_security_config"

# 4. Rebuild and sign
apktool b patched/ -o patched.apk
keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -validity 10000
jarsigner -keystore debug.keystore patched.apk debug
```

**Method 4 — Magisk module (persistent):**
```bash
# Install MagiskTrustUserCerts module
# Moves user-installed CA certs to system trust store
```

### 3B: Flutter Apps

Flutter bundles BoringSSL inside `libflutter.so` — Java-layer bypasses don't work.

**Method 1 — kill_flutter (works on any Flutter version):**
```bash
pip install frida-tools
git clone https://github.com/f3rb123/kill_flutter
cd kill_flutter
python3 kill_flutter.py target.apk
# Outputs Frida script with correct offset
frida -U -f com.target.app -l flutter_bypass.js --no-pause
```

**Method 2 — reFlutter (binary patching):**
```bash
pip install reflutter
reflutter target.apk
# Generates release.RE.apk with patched libflutter.so
# Re-sign: jarsigner -keystore debug.keystore release.RE.apk debug
adb install release.RE.apk
# Set proxy to 8083 (reFlutter default)
```

**Method 3 — Frida codeshare:**
```bash
frida -U -f com.target.app \
  --codeshare TheDauntless/disable-flutter-tls-v1 --no-pause
```

**Method 4 — Manual offset (when tools fail):**
```bash
# 1. Extract libflutter.so
unzip -j target.apk "lib/arm64-v8a/libflutter.so" -d libs/

# 2. Find ssl_crypto_x509_session_verify_cert_chain
# Search for "ssl_client" and "ssl_server" strings in .rodata
python3 -c "
import struct
data = open('libs/libflutter.so','rb').read()
idx = data.find(b'ssl_client')
print(f'ssl_client at offset: 0x{idx:x}')
"

# 3. Use the offset in a Frida script to force return 1
```

### 3C: React Native Apps

React Native on Android uses OkHttp — Java-layer bypasses usually work.

**Method 1 — Objection:**
```bash
objection -g com.target.app explore --startup-command "android sslpinning disable"
```

**Method 2 — Frida (OkHttp + TrustManager):**
```bash
frida -U -f com.target.app -l scripts/ssl_bypass_universal.js --no-pause
```

**Method 3 — If react-native-ssl-pinning is used:**
```bash
# Hook the native module
grep -rn "ssl-pinning\|RNSslPinning" jadx_out/
# The pinning happens via OkHttp CertificatePinner — standard bypass works
```

### 3D: Xamarin Apps

**Method 1 — Frida Mono hooks:**
```bash
# Hook ServicePointManager.ServerCertificateValidationCallback
frida -U -f com.target.app -l scripts/ssl_bypass_xamarin.js --no-pause
```

**Method 2 — DLL patching:**
```bash
# Extract assemblies
unzip target.apk "assemblies/*" -d extracted/
# Patch ServerCertificateValidationCallback in the DLL using dnSpy
```

### 3E: Cordova/Ionic Apps

Traffic goes through system WebView — network security config bypass works.
```bash
# Patch network_security_config.xml (Method 3 from section 3A)
# Or install Burp CA as system cert via Magisk
```

---

## Phase 4 — MitM Proxy Setup

### Burp Suite
```bash
# 1. Set proxy listener: 0.0.0.0:8080
# 2. Export CA cert (DER format)
# 3. Push to device
adb push cacert.der /sdcard/cacert.cer
# 4. Install: Settings → Security → Install certificates
# 5. Set device Wi-Fi proxy to <host-ip>:8080

# For Flutter with reFlutter, use port 8083
```

### mitmproxy
```bash
mitmproxy --listen-port 8080 --set block_global=false
# CA cert at ~/.mitmproxy/mitmproxy-ca-cert.cer
```

### Verify interception
```bash
# Check if traffic is flowing through proxy
# Look for API calls with auth headers
# Search for: Authorization, Bearer, Cookie, X-Session
```

---

## Phase 5 — What to Test After Bypassing

Once you can see traffic:
1. **Authentication tokens** — are they sent securely? Expiry?
2. **API endpoints** — IDOR, broken access control, mass assignment
3. **Sensitive data in transit** — PII, financial data, health data
4. **Certificate validation** — does app accept invalid certs without pinning?
5. **Cleartext fallback** — does app fall back to HTTP on TLS failure?
6. **Token in URL** — tokens in query parameters (logged by proxies/CDN)

---

## Phase 6 — Severity Classification

| Finding | Severity |
|---------|----------|
| Trust-all TrustManager in production | Critical |
| Cleartext HTTP for auth/API traffic | High |
| No certificate pinning (when handling sensitive data) | Medium |
| Pinning bypassable via Frida (requires rooted device) | Low-Medium |
| Weak TLS version (TLS 1.0/1.1) | Medium |
| Token in URL query parameter | Medium |
| Missing HSTS equivalent | Low |

---

## Phase 7 — Remediation

1. **Implement certificate pinning** via network security config or OkHttp CertificatePinner
2. **Set `android:usesCleartextTraffic="false"`** in manifest
3. **Use TLS 1.2+ only** — disable TLS 1.0/1.1
4. **Never implement trust-all TrustManager** — even for debug
5. **Pin backup keys** — include a backup pin hash for rotation
6. **Use `CertificateTransparency`** library for CT enforcement
7. **Implement root/tamper detection** to complement pinning
8. **Rotate pins** — plan for certificate renewal
9. **Flutter:** Use custom `SecurityContext` with pinned certificates
10. **React Native:** Use `react-native-ssl-pinning` with SHA-256 pins

---

## References

- OWASP MASTG: Testing Network Communication
- SecurityCafe: Root Detection & SSL Pinning Bypass
- Minded Security: Flutter SSL Pinning Bypass via BoringSSL
- kill_flutter: Universal Flutter bypass — https://github.com/f3rb123/kill_flutter
- reFlutter: Flutter binary patching — https://github.com/AlirezaGhanmo/reFlutter
- NVISO: disable-flutter-tls-verification
- VICHHKA: 30+ SSL Pinning Bypass Frida script
- HackerOne Android Reports — SSL/TLS findings
