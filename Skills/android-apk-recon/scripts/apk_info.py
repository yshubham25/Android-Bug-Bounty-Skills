#!/usr/bin/env python3
"""Extract APK metadata: package, version, SDK, framework, permissions, hash."""
import argparse,hashlib,json,os,re,subprocess,sys,zipfile
FRAMEWORK_SIGS={"flutter":["libflutter.so","libapp.so"],"react_native":["libreactnativejni.so","index.android.bundle"],"xamarin":["libmonodroid.so","assemblies/"],"cordova":["assets/www/index.html","assets/www/cordova.js"],"unity":["libunity.so","libil2cpp.so"]}
def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(8192),b""):h.update(c)
    return h.hexdigest()
def detect_framework(apk):
    try:
        with zipfile.ZipFile(apk) as z:
            names=z.namelist()
            for fw,sigs in FRAMEWORK_SIGS.items():
                if any(any(s in n for n in names) for s in sigs):return fw
    except:pass
    return "native_java_kotlin"
def get_aapt_info(apk):
    info={"package":"","version_name":"","version_code":"","min_sdk":"","target_sdk":"","permissions":[]}
    try:
        r=subprocess.run(["aapt2","dump","badging",apk],capture_output=True,text=True,timeout=30)
        for pat,key in [(r"package: name='([^']+)'","package"),(r"versionName='([^']+)'","version_name"),
            (r"versionCode='([^']+)'","version_code"),(r"sdkVersion:'(\d+)'","min_sdk"),(r"targetSdkVersion:'(\d+)'","target_sdk")]:
            m=re.search(pat,r.stdout)
            if m:info[key]=m.group(1)
        info["permissions"]=[m.group(1) for m in re.finditer(r"uses-permission: name='([^']+)'",r.stdout)]
    except:pass
    return info
def main():
    p=argparse.ArgumentParser();p.add_argument("apk");p.add_argument("-o","--output",default="apk_info.json")
    a=p.parse_args();info=get_aapt_info(a.apk)
    info["sha256"]=sha256(a.apk);info["file_size"]=os.path.getsize(a.apk);info["framework"]=detect_framework(a.apk)
    try:
        with zipfile.ZipFile(a.apk) as z:
            info["architectures"]=list(set(n.split("/")[1] for n in z.namelist() if n.startswith("lib/") and "/" in n[4:]))
    except:info["architectures"]=[]
    json.dump(info,open(a.output,"w"),indent=2)
    print(f"[+] {info['package']} v{info['version_name']} | {info['framework']} | {len(info['permissions'])} perms")
if __name__=="__main__":main()
