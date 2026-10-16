#!/usr/bin/env python3
"""Generate framework-specific SSL pinning bypass commands.
Usage: python3 pinning_bypass.py --framework flutter --package com.target.app"""
import argparse,json
BYPASSES={"native":{"methods":[
{"name":"Objection","cmd":'objection -g {pkg} explore --startup-command "android sslpinning disable"',"difficulty":"easy"},
{"name":"Frida universal","cmd":"frida -U -f {pkg} -l scripts/ssl_bypass_universal.js --no-pause","difficulty":"easy"},
{"name":"Network config patch","cmd":"apktool d {apk} → patch res/xml/network_security_config.xml → rebuild","difficulty":"medium"},
{"name":"Magisk module","cmd":"Install MagiskTrustUserCerts + Burp CA as user cert","difficulty":"easy"},
]},"flutter":{"methods":[
{"name":"kill_flutter","cmd":"python3 kill_flutter.py {apk} → frida -U -f {pkg} -l flutter_bypass.js --no-pause","difficulty":"medium"},
{"name":"reFlutter","cmd":"reflutter {apk} → jarsigner → adb install → proxy port 8083","difficulty":"medium"},
{"name":"Frida codeshare","cmd":"frida -U -f {pkg} --codeshare TheDauntless/disable-flutter-tls-v1 --no-pause","difficulty":"easy"},
{"name":"Manual offset","cmd":"Extract libflutter.so → find ssl_client/ssl_server → Frida hook at offset","difficulty":"hard"},
]},"react_native":{"methods":[
{"name":"Objection","cmd":'objection -g {pkg} explore --startup-command "android sslpinning disable"',"difficulty":"easy"},
{"name":"Frida universal","cmd":"frida -U -f {pkg} -l scripts/ssl_bypass_universal.js --no-pause","difficulty":"easy"},
]},"xamarin":{"methods":[
{"name":"Frida Mono","cmd":"frida -U -f {pkg} -l scripts/ssl_bypass_xamarin.js --no-pause","difficulty":"medium"},
{"name":"DLL patch","cmd":"Extract assemblies/ → patch with dnSpy → repackage","difficulty":"hard"},
]},"cordova":{"methods":[
{"name":"Config patch","cmd":"apktool d → add user cert trust → rebuild","difficulty":"easy"},
{"name":"Magisk","cmd":"Install MagiskTrustUserCerts module","difficulty":"easy"},
]}}
def main():
    p=argparse.ArgumentParser();p.add_argument("--framework",default="auto");p.add_argument("--package",default="com.target.app");p.add_argument("--apk",default="target.apk")
    a=p.parse_args();fw=a.framework
    if fw=="auto":fw="native"
    methods=BYPASSES.get(fw,BYPASSES["native"])["methods"]
    print(f"\n{'='*55}\n SSL Pinning Bypass — {fw.upper()}\n{'='*55}")
    for i,m in enumerate(methods,1):
        cmd=m["cmd"].format(pkg=a.package,apk=a.apk)
        print(f"\n [{i}] {m['name']} ({m['difficulty']})")
        print(f"     {cmd}")
    print(f"\n{'='*55}\n")
if __name__=="__main__":main()
