# Bug Bounty Case Studies — Network Security

## Trust-All TrustManager in Production
- Custom TrustManager with empty checkServerTrusted()
- Left over from development/testing
- Any MitM attacker can intercept all app traffic
- Severity: Critical — no root/Frida needed

## Missing Certificate Pinning + Token Theft
- App sends Bearer token over HTTPS without pinning
- Attacker on same network with Burp CA installed
- Intercepted and replayed session token → ATO
- Severity: Medium (requires MitM position + user cert install)

## Cleartext HTTP for Login API
- Login endpoint used HTTP instead of HTTPS
- Password sent in plaintext on the network
- Severity: Critical

## WebView SSL Error Bypass
- onReceivedSslError calls handler.proceed()
- WebView loads any page ignoring certificate errors
- Phishing or MitM via WebView
- Severity: High

## Token in URL Query Parameter
- OAuth token passed as ?access_token= in URL
- Logged by proxies, CDN, server access logs, browser history
- Severity: Medium
