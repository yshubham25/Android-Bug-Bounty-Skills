# Exported Activity Authentication Bypass

## The Pattern
Protected activities (dashboard, profile, payment, admin) declared as
exported in AndroidManifest.xml can be launched directly via ADB or a
malicious app, skipping the login flow entirely.

## Why It Happens
- `android:exported="true"` set explicitly
- Intent filter present (implicit export on API < 31)
- Developer assumes the login activity gates all access

## Test Methodology
```bash
# List exported activities
adb shell dumpsys package com.target | grep -A2 "Activity.*exported=true"
# Launch each protected screen directly
adb shell am start -n com.target/.DashboardActivity
adb shell am start -n com.target/.ProfileActivity
adb shell am start -n com.target/.AdminPanelActivity
```

## Real CVEs (2026)
- CVE-2026-44964: Datadog OnCallNotificationActivity — no permission guard
- CVE-2026-47363: Datadog AppActivity — accepted OAuth tokens from any caller
- CVE-2026-44965: Datadog widget activities — brute-force widget IDs
- CVE-2026-44279: FortiToken — exported components leak OTP material

## Severity
- Shows real user data/actions → Critical
- UI renders but no data accessible → Medium
- Only shows generic app UI → Low/Informational
