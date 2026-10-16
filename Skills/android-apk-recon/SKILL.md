---
name: android-apk-recon
description: Full APK recon — framework detection, manifest, endpoints, components, WebViews, Firebase, secrets, Intercom SDK, attack surface map, prioritized targets. Run first.
---

# Android APK Recon — Foundation Skill (v2)

Comprehensive static reconnaissance that runs FIRST and feeds all other
Android pentest skills. Decompiles once, maps the entire attack surface
including third-party SDK analysis (Intercom, Firebase, analytics),
saves structured JSON for downstream skills to reuse.

> **No live attacks.** Pure static analysis and OSINT.

## Quick Start

```bash
# Full recon (all modules including Intercom + external tools)
python3 scripts/recon_orchestrator.py target.apk --full -o recon_results/

# Quick recon (manifest + endpoints only)
python3 scripts/recon_orchestrator.py target.apk --quick -o recon_results/

# Reuse cached results (skip if APK SHA-256 unchanged)
python3 scripts/recon_orchestrator.py target.apk --reuse -o recon_results/
```

---

## Recon Pipeline (9 Modules)

```
APK → [1] Info → [2] Decompile → [3] Manifest → [4] Endpoints
    → [5] WebViews → [6] Components/SDKs → [7] Intercom
    → [8] Secrets → [9] Prioritize → Report
```

### Module 1 — APK Identification
Package, version, SDK levels, permissions, signing cert, SHA-256,
framework (Flutter/React Native/Xamarin/Cordova/Unity/native),
architectures, obfuscation level.

### Module 2 — Decompilation
JADX (Java/Kotlin source) + APKTool (manifest, resources, assets, smali)
+ DEX strings + native library strings. One-time, cached by hash.

### Module 3 — Manifest Analysis
Exported activities/services/receivers/providers, deep links (schemes,
hosts, paths), App Links verification, app config flags (allowBackup,
debuggable, cleartext, networkSecurityConfig).

### Module 4 — Endpoint Extraction
URLs, API paths (/api/, /v1/, /graphql/), Retrofit annotations,
OkHttp base URLs, IP addresses, unique domains. Filters XML schema noise.
Outputs `endpoints.json` + `domains.txt` for subdomain enum.

### Module 5 — WebView Mapping
WebView instances, `setJavaScriptEnabled`, `addJavascriptInterface`,
`loadUrl`/`evaluateJavascript`, file access flags, cookie operations,
debug enabled. Cross-references with manifest for exported WebView activities.

### Module 6 — Component & SDK Mapping
Detects 25+ third-party SDKs by package path (Firebase, Stripe, Facebook,
Twilio, OkHttp, Retrofit, analytics, ads). Finds interesting files in
assets/raw (databases, keys, configs, env files, PEM/P12 certs).

### Module 7 — Intercom Analysis (NEW)
Detects Intercom SDK integration. If found, extracts:
- App ID and SDK credential locations (masked)
- API hostname references
- Identity verification status (user_hash, HMAC presence)
- Login method (identified vs unidentified users)
- Email/userId binding pattern
- Conversation API endpoint references
- Risk classification for identity verification bypass

If Intercom NOT detected → marks as N/A, skips Intercom-specific testing.

### Module 8 — Secret Detection
Scans for hardcoded API keys, tokens, passwords, private keys, database
URLs using provider-specific regex patterns. Entropy analysis + allowlist
filtering to reduce false positives. Outputs masked findings.

### Module 9 — Prioritization Engine
Ranks attack chains by exploitability:

**P1 Critical:** Deep link → WebView → JS bridge → token theft |
Exported provider → no permissions → SQLi | Hardcoded secret → cloud access |
Intercom identity verification disabled → cross-account IDOR

**P2 High:** Exported activity → client-side auth bypass |
Firebase URL → public read/write | Weak URL validation → open redirect |
Intercom user_hash absent → impersonation risk

**P3 Medium:** WebView file access + needs URL load vector |
Token in SharedPrefs + needs device access | Debug activity + needs extras

**P4 Low:** allowBackup=true (unconfirmed sensitive data) |
Outdated SDK (no known exploit) | Cleartext allowed (no sensitive endpoint)

---

## Output Structure

```
recon_results/
├── apk_info.json                # package, version, framework, hash
├── manifest_analysis.json       # full parsed manifest
├── exported_components.json     # activities, services, receivers, providers
├── content_providers.json       # providers with permissions, authorities
├── deeplinks.json               # schemes, hosts, paths, target activities
├── endpoints.json               # URLs, API paths, domains, IPs
├── domains.txt                  # unique domains for subdomain enum
├── webviews.json                # WebView instances, settings, bridges
├── third_party_sdks.json        # detected SDKs with versions
├── intercom_analysis.json       # Intercom config, identity verification, risk
├── potential_secrets.json       # hardcoded keys/tokens (masked)
├── interesting_files.json       # configs, DBs, keys in assets
├── network_config.json          # cleartext, pinning, TrustManagers
├── attack_surface.json          # unified surface map
├── prioritized_targets.json     # ranked attack chains
├── recon_report.md              # human-readable summary
└── decompiled/
    ├── jadx/
    └── apktool/
```

### Reuse contract for downstream skills
```python
import os, json
RECON = "recon_results"
if os.path.exists(f"{RECON}/apk_info.json"):
    info = json.load(open(f"{RECON}/apk_info.json"))
    jadx = f"{RECON}/decompiled/jadx"  # skip decompilation
```

---

## Individual Module Usage

```bash
python3 scripts/apk_info.py target.apk -o apk_info.json
python3 scripts/manifest_analyzer.py apktool_out/AndroidManifest.xml -o results/
python3 scripts/extract_endpoints.py jadx_out/ -o endpoints.json
python3 scripts/webview_finder.py jadx_out/ -o webviews.json
python3 scripts/component_mapper.py jadx_out/ --manifest apktool_out/AndroidManifest.xml -o results/
python3 scripts/intercom_analyzer.py jadx_out/ -o intercom_analysis.json
python3 scripts/secret_scanner.py jadx_out/ -o potential_secrets.json
python3 scripts/generate_report.py recon_results/ -o recon_report.md
```

---

## Tools Reference

| Tool | Purpose | Install |
|------|---------|---------|
| JADX | Java/Kotlin decompiler | `brew install jadx` |
| APKTool | Manifest/resource extractor | `brew install apktool` |
| apk2url | URL/IP endpoint extractor | github.com/n0mi1k/apk2url |
| APKLeaks | Endpoint + secret scanner | `pip3 install apkleaks` |
| get_schemas | Deep link scheme extractor | github.com/teknogeek/get_schemas |
| aapt2 | APK info dump | Android SDK |
| MobSF | Full static analysis | github.com/MobSF |
| Androguard | Python APK analysis | `pip3 install androguard` |

---

## References

- YesWeHack: Android Recon for Bug Bounty Hunters
- OWASP MASTG: Static Analysis guidance
- Intercom Identity Verification documentation
- B3nac: Android Reports and Resources
