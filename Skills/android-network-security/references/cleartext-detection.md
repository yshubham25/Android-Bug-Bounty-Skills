# Cleartext Traffic Detection

## Manifest check
```bash
grep "usesCleartextTraffic" AndroidManifest.xml
# true or absent (default true below API 28) = HTTP allowed
```

## Network security config
```bash
cat res/xml/network_security_config.xml
# <base-config cleartextTrafficPermitted="true"> = bad
```

## Find HTTP URLs in source
```bash
grep -rn "http://" jadx_out/ | grep -v "https\|schemas\|w3.org\|xmlns\|localhost\|127.0.0.1"
```

## Runtime detection
```bash
# Monitor all HTTP (non-HTTPS) traffic
adb shell tcpdump -i any -n port 80 -A 2>/dev/null | grep -i "password\|token\|auth"
```

## Severity
- Auth credentials over HTTP → Critical
- PII over HTTP → High
- Non-sensitive API over HTTP → Medium
- HTTP for static assets only → Low
