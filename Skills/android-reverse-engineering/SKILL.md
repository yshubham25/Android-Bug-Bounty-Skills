---
name: android-reverse-engineering
description: Bypass Android root detection, Frida detection, SSL pinning guards, obfuscation analysis, native lib reversing, anti-tamper evasion. Force multiplier for all other pentest skills.
---

# Android Reverse Engineering & Anti-Tamper Bypass

The force multiplier skill — when apps detect root, block Frida, or use
heavy obfuscation, your other pentest skills can't run. This skill finds
those protections statically and generates bypasses.

> **Authorization required for runtime bypass.** Static detection is safe.

## Quick Start

```bash
# Detect all protections in an APK
python3 scripts/protection_detector.py target.apk -o protections.json

# Generate Frida bypass scripts for detected protections
python3 scripts/bypass_generator.py protections.json -o bypasses/

# Analyze obfuscation level
python3 scripts/obfuscation_analyzer.py jadx_out/ -o obfuscation.json
```

---

## Phase 1 — Detect Protections

### 1.1 Root detection libraries
```bash
# RootBeer (most common)
grep -rn "RootBeer\|com.scottyab.rootbeer\|isRooted\|isRootedWithBusyBox" jadx_out/

# SafetyNet / Play Integrity
grep -rn "SafetyNet\|PlayIntegrity\|safetynet\|integrity.*verdict\|MEET_DEVICE_INTEGRITY" jadx_out/

# Custom root checks
grep -rn "which su\|/system/app/Superuser\|/system/xbin/su\|test-keys\|/sbin/su" jadx_out/
grep -rn "com.topjohnwu.magisk\|eu.chainfire.supersu\|com.koushikdutta.superuser" jadx_out/

# Runtime checks
grep -rn "Runtime.getRuntime.*exec.*su\|ProcessBuilder.*su\|canExecSu" jadx_out/

# Build.TAGS check
grep -rn "Build.TAGS\|test-keys\|release-keys" jadx_out/

# Mounting check
grep -rn "/proc/mounts\|/system.*rw" jadx_out/
```

### 1.2 Frida detection
```bash
# Frida port/process
grep -rn "27042\|frida\|frida-server\|frida-gadget\|LIBFRIDA" jadx_out/

# Frida library detection
grep -rn "frida-agent\|frida-gadget\|libfrida\|/proc/self/maps.*frida" jadx_out/

# D-Bus detection (Frida uses D-Bus)
grep -rn "DBUS\|dbus\|d-bus" jadx_out/

# Memory scanning for Frida strings
grep -rn "/proc/self/maps\|/proc/self/status\|/proc/self/task" jadx_out/

# Native Frida detection
grep -rn "ptrace\|PTRACE_ATTACH\|TracerPid" jadx_out/
```

### 1.3 Emulator detection
```bash
grep -rn "generic.*Build\|sdk_gphone\|google_sdk\|Emulator\|goldfish\|ranchu" jadx_out/
grep -rn "Build.FINGERPRINT.*generic\|Build.MODEL.*SDK\|Build.HARDWARE.*goldfish" jadx_out/
grep -rn "QEMU\|qemu\|/dev/qemu\|init.svc.qemu" jadx_out/
grep -rn "nox\|bluestacks\|genymotion\|Andy\|Droid4X" jadx_out/
```

### 1.4 Debugger detection
```bash
grep -rn "isDebuggerConnected\|Debug.isDebuggerConnected\|waitForDebugger" jadx_out/
grep -rn "android:debuggable\|ApplicationInfo.*FLAG_DEBUGGABLE" jadx_out/
grep -rn "ptrace\|PTRACE\|TracerPid" jadx_out/
```

### 1.5 Tampering / integrity detection
```bash
# Signature verification
grep -rn "PackageManager.*signatures\|GET_SIGNING_CERTIFICATES\|checkSignatures" jadx_out/
grep -rn "getPackageInfo.*GET_SIGNATURES\|signingInfo" jadx_out/

# Installer verification
grep -rn "getInstallingPackageName\|getInstallSourceInfo\|com.android.vending" jadx_out/

# Hash/checksum verification
grep -rn "MessageDigest.*SHA\|checksum\|integrity.*check\|verify.*hash" jadx_out/
grep -rn "classes.dex.*hash\|resources.arsc.*crc" jadx_out/
```

### 1.6 Commercial protection SDKs
```bash
# Promon SHIELD
grep -rn "promon\|shield" jadx_out/ | grep -iv "copyright\|license"

# Guardsquare (DexGuard/iXGuard)
grep -rn "dexguard\|guardsquare\|ixguard" jadx_out/

# Appdome
grep -rn "appdome" jadx_out/

# Arxan / Digital.ai
grep -rn "arxan\|digital.ai\|whitecryption" jadx_out/

# Talsec freeRASP
grep -rn "freerasp\|talsec" jadx_out/
```

---

## Phase 2 — Bypass Techniques

### 2.1 Root detection bypass — Frida

```javascript
// Universal root detection bypass
Java.perform(function() {
    // RootBeer bypass
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithBusyBox.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        RootBeer.detectRootManagementApps.implementation = function() { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
        RootBeer.detectTestKeys.implementation = function() { return false; };
        RootBeer.checkForBinary.overload("java.lang.String").implementation = function(s) { return false; };
        RootBeer.checkForDangerousProps.implementation = function() { return false; };
        RootBeer.checkForRWPaths.implementation = function() { return false; };
        RootBeer.checkSuExists.implementation = function() { return false; };
        RootBeer.checkForRootNative.implementation = function() { return false; };
        RootBeer.checkForMagiskBinary.implementation = function() { return false; };
        console.log("[+] RootBeer bypassed");
    } catch(e) {}

    // Generic root check bypass
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var origExec = Runtime.exec.overload("java.lang.String");
        origExec.implementation = function(cmd) {
            if (cmd.indexOf("su") !== -1) {
                throw new java.io.IOException("not found");
            }
            return origExec.call(this, cmd);
        };
        console.log("[+] Runtime.exec su bypass");
    } catch(e) {}

    // Build.TAGS bypass
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[+] Build.TAGS set to release-keys");
    } catch(e) {}

    // File existence bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1 ||
                path.indexOf("Superuser") !== -1 || path.indexOf("busybox") !== -1) {
                return false;
            }
            return this.exists();
        };
        console.log("[+] File.exists su/magisk bypass");
    } catch(e) {}
});
```

### 2.2 Root detection bypass — Objection
```bash
objection -g com.target.app explore --startup-command "android root disable"
```

### 2.3 Root detection bypass — Magisk
```bash
# MagiskHide / Zygisk DenyList
# Settings → Zygisk → Enable
# Settings → DenyList → Add target app
# The app process runs without Magisk footprint
```

### 2.4 Frida detection bypass
```javascript
// Anti-Frida bypass — hide Frida artifacts
Java.perform(function() {
    // Port check bypass
    try {
        var Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
            if (port === 27042 || port === 27043) {
                throw new java.net.ConnectException("Connection refused");
            }
            return this.$init(host, port);
        };
        console.log("[+] Socket port 27042 bypass");
    } catch(e) {}

    // /proc/self/maps bypass — hide frida from memory maps
    try {
        var fopen = Module.findExportByName("libc.so", "fopen");
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("/proc/self/maps") !== -1) {
                    // Return a sanitized version
                }
            }
        });
    } catch(e) {}

    // Named pipe check bypass
    try {
        var File = Java.use("java.io.File");
        var origExists = File.exists;
        File.exists.implementation = function() {
            var name = this.getName();
            if (name.indexOf("frida") !== -1 || name.indexOf("linjector") !== -1) {
                return false;
            }
            return origExists.call(this);
        };
        console.log("[+] Frida file detection bypass");
    } catch(e) {}
});
```

### 2.5 Frida gadget injection (no root needed)
```bash
# 1. Decompile
apktool d target.apk -o patched/

# 2. Download matching Frida gadget
wget https://github.com/frida/frida/releases/download/16.x.x/frida-gadget-16.x.x-android-arm64.so.xz
xz -d frida-gadget-*.so.xz
cp frida-gadget-*.so patched/lib/arm64-v8a/libfrida-gadget.so

# 3. Inject load in smali (add to main activity's onCreate)
# Add: const-string v0, "frida-gadget"
#      invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

# 4. Rebuild and sign
apktool b patched/ -o patched.apk
jarsigner -keystore debug.keystore patched.apk debug
```

### 2.6 Emulator detection bypass
```javascript
Java.perform(function() {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/walleye/walleye:8.1.0/OPM1.171019.011:user/release-keys";
    Build.MODEL.value = "Pixel 2";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "walleye";
    Build.PRODUCT.value = "walleye";
    Build.HARDWARE.value = "walleye";
    Build.BOARD.value = "walleye";
    console.log("[+] Emulator detection bypassed");
});
```

### 2.7 Signature verification bypass
```javascript
Java.perform(function() {
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getPackageInfo.overload("java.lang.String", "int").implementation = function(pkg, flags) {
            // Remove GET_SIGNATURES flag
            var result = this.getPackageInfo(pkg, flags & ~0x40);
            return result;
        };
        console.log("[+] Signature check bypassed");
    } catch(e) {}
});
```

---

## Phase 3 — Obfuscation Analysis

### 3.1 Detect obfuscation level
```bash
# ProGuard/R8 indicators
ls apktool_out/original/META-INF/ | grep -i proguard
cat apktool_out/original/META-INF/proguard/* 2>/dev/null

# Class naming analysis
find jadx_out/sources/ -name "*.java" | head -30
# Single letters (a.java, b.java) = obfuscated
# Full names (MainActivity.java) = not obfuscated

# Method naming
grep -rn "public.*\b[a-z]\b(" jadx_out/ | head -20
```

### 3.2 String deobfuscation
```bash
# Find string decryption methods
grep -rn "decrypt\|deobfuscate\|decode.*string\|xor.*string" jadx_out/

# Base64 encoded strings
grep -rn "Base64.decode\|android.util.Base64" jadx_out/

# XOR encrypted strings
grep -rn "\^ 0x\|xor\|XOR" jadx_out/
```

---

## Phase 4 — Severity & Reporting

| Protection | Bypass Impact | Bounty Relevance |
|-----------|---------------|------------------|
| Root detection only | Enables device testing | Not a vuln itself |
| Frida detection | Enables dynamic analysis | Not a vuln itself |
| Missing root detection (sensitive app) | Enables local attacks | Medium (banking/finance) |
| Weak signature verification | Enables APK modification | Medium |
| Bypassable integrity checks | Enables code injection | Medium |
| Client-only protection (no server check) | Full bypass | High if sensitive data |

**Key:** Bypassing protections is an enabler, not a finding. The finding
is what you discover AFTER the bypass — use your other 10 skills.

---

## Phase 5 — Remediation

1. Use Play Integrity API instead of client-only checks
2. Implement server-side attestation verification
3. Use native (C/C++) checks alongside Java checks
4. Implement multiple layered detection (not just one check)
5. Use commercial RASP solutions (Promon, Guardsquare)
6. Never make security decisions purely on client-side root/tamper status
7. Combine with SSL pinning and certificate transparency
