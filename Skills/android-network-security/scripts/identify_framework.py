#!/usr/bin/env python3
"""
identify_framework.py — Detect which framework an Android APK uses.
Determines the correct SSL pinning bypass strategy.

Usage: python3 identify_framework.py target.apk
"""
import argparse, os, sys, zipfile

FRAMEWORK_SIGNATURES = {
    "flutter": {
        "files": ["lib/arm64-v8a/libflutter.so", "lib/armeabi-v7a/libflutter.so",
                   "lib/x86_64/libflutter.so", "lib/arm64-v8a/libapp.so"],
        "description": "Flutter (Dart + BoringSSL in libflutter.so)",
        "bypass": "kill_flutter, reFlutter, or manual Frida offset hook on libflutter.so",
        "difficulty": "HARD — Java-layer bypasses won't work",
    },
    "react_native": {
        "files": ["assets/index.android.bundle", "lib/arm64-v8a/libreactnativejni.so",
                   "lib/armeabi-v7a/libreactnativejni.so", "lib/arm64-v8a/libjsi.so"],
        "description": "React Native (JS + OkHttp on Android)",
        "bypass": "Objection or Frida universal script — uses OkHttp under the hood",
        "difficulty": "EASY — standard OkHttp/TrustManager bypass works",
    },
    "xamarin": {
        "files": ["assemblies/", "lib/arm64-v8a/libmonodroid.so",
                   "lib/armeabi-v7a/libmonodroid.so", "lib/arm64-v8a/libxamarin-app.so"],
        "description": "Xamarin (.NET/Mono + AndroidClientHandler)",
        "bypass": "Frida Mono hooks on ServicePointManager or patch DLL",
        "difficulty": "MEDIUM — need Mono-specific hooks",
    },
    "cordova": {
        "files": ["assets/www/index.html", "assets/www/cordova.js",
                   "assets/www/plugins/"],
        "description": "Cordova/Ionic (WebView + system network stack)",
        "bypass": "Network security config patch — system WebView, no custom pinning",
        "difficulty": "EASY — patch network_security_config.xml",
    },
    "unity": {
        "files": ["lib/arm64-v8a/libunity.so", "lib/arm64-v8a/libil2cpp.so",
                   "assets/bin/Data/"],
        "description": "Unity (C# via IL2CPP or Mono)",
        "bypass": "Frida IL2CPP hooks or Mono hooks depending on backend",
        "difficulty": "MEDIUM-HARD",
    },
}

NATIVE_NETWORKING = {
    "okhttp": ["okhttp3/", "com/squareup/okhttp/"],
    "volley": ["com/android/volley/"],
    "retrofit": ["retrofit2/"],
    "conscrypt": ["org/conscrypt/"],
    "trustkit": ["com/datatheorem/android/trustkit/"],
    "apache_http": ["org/apache/http/"],
}


def identify(apk_path):
    results = {"framework": "native_java_kotlin", "networking": [], "details": {}}

    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()

            # Check frameworks
            for fw_name, fw in FRAMEWORK_SIGNATURES.items():
                for sig_file in fw["files"]:
                    if any(sig_file in n for n in names):
                        results["framework"] = fw_name
                        results["details"] = fw
                        break

            # Check networking libraries (for native apps)
            for lib_name, paths in NATIVE_NETWORKING.items():
                for path in paths:
                    if any(path in n for n in names):
                        results["networking"].append(lib_name)
                        break

            # Check for network security config
            if any("network_security_config" in n for n in names):
                results["has_network_security_config"] = True
            else:
                results["has_network_security_config"] = False

            # Architecture
            arches = set()
            for n in names:
                if n.startswith("lib/"):
                    parts = n.split("/")
                    if len(parts) >= 2:
                        arches.add(parts[1])
            results["architectures"] = list(arches)

    except Exception as e:
        print(f"[!] Error: {e}")
        return results

    return results


def main():
    p = argparse.ArgumentParser(description="Identify Android app framework")
    p.add_argument("apk", help="Path to APK")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    result = identify(args.apk)

    if args.json:
        import json
        print(json.dumps(result, indent=2))
        return

    fw = result["framework"]
    details = result.get("details", {})

    print(f"\n{'='*55}")
    print(f" Framework Detection: {os.path.basename(args.apk)}")
    print(f"{'='*55}")
    print(f" Framework:    {fw.upper()}")
    print(f" Description:  {details.get('description', 'Native Java/Kotlin app')}")
    print(f" Bypass:       {details.get('bypass', 'Objection / Frida universal / network_security_config patch')}")
    print(f" Difficulty:   {details.get('difficulty', 'EASY — standard TrustManager/OkHttp bypass')}")
    print(f" Architectures: {', '.join(result.get('architectures', ['unknown']))}")
    print(f" Net sec config: {'Yes' if result.get('has_network_security_config') else 'No'}")

    if result["networking"]:
        print(f" Networking libs: {', '.join(result['networking'])}")

    print(f"\n Recommended bypass order:")
    if fw == "flutter":
        print("   1. kill_flutter (auto-offset Frida)")
        print("   2. reFlutter (binary patch)")
        print("   3. Frida codeshare: TheDauntless/disable-flutter-tls-v1")
        print("   4. Manual libflutter.so offset analysis")
    elif fw == "react_native":
        print("   1. objection --startup-command 'android sslpinning disable'")
        print("   2. frida -l ssl_bypass_universal.js")
        print("   3. Network security config patch")
    elif fw == "xamarin":
        print("   1. frida -l ssl_bypass_xamarin.js")
        print("   2. Patch Mono DLL via dnSpy")
        print("   3. Network security config patch")
    elif fw == "cordova":
        print("   1. Network security config patch")
        print("   2. Install Burp CA as system cert (Magisk)")
    else:
        print("   1. objection --startup-command 'android sslpinning disable'")
        print("   2. frida -l ssl_bypass_universal.js")
        print("   3. Network security config patch + rebuild")
        print("   4. Magisk MagiskTrustUserCerts module")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
