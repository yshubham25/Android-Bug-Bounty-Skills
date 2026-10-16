# APK Recon Methodology v2

## Pipeline order (9 modules)
1. APK info (aapt2, framework detection, SHA-256 hash)
2. Decompile (JADX + APKTool + DEX strings, one-time)
3. Manifest analysis (components, deep links, app config)
4. Endpoint extraction (URLs, APIs, domains, IPs, Retrofit)
5. WebView mapping (instances, settings, bridges)
6. Component/SDK mapping (25+ SDKs, interesting files)
7. **Intercom analysis** (SDK detection, identity verification, risk)
8. Secret detection (regex + entropy + allowlist filtering)
9. Report generation (consolidated, prioritized)

## Caching
SHA-256 hash stored in apk_info.json. --reuse skips if hash matches.

## External tools (--full mode)
- apk2url: endpoint extraction
- APKLeaks: endpoint + secret scan
- MobSF: automated static analysis (run separately)

## Downstream skill integration
All skills check for recon_results/apk_info.json before decompiling.
Structured JSON contracts: each module outputs a standard JSON file.
