#!/usr/bin/env python3
"""Detect third-party SDKs and interesting files."""
import argparse,json,os,sys
SDKS={"com.google.firebase":"Firebase","com.facebook":"Facebook","com.stripe":"Stripe","com.razorpay":"Razorpay",
    "io.sentry":"Sentry","com.crashlytics":"Crashlytics","com.appsflyer":"AppsFlyer","com.adjust":"Adjust",
    "com.mixpanel":"Mixpanel","com.segment":"Segment","com.twilio":"Twilio","com.sendgrid":"SendGrid",
    "com.amazonaws":"AWS SDK","io.intercom":"Intercom SDK","com.google.android.gms":"Play Services",
    "com.google.ads":"Google Ads","com.squareup.okhttp":"OkHttp","com.squareup.retrofit":"Retrofit",
    "io.reactivex":"RxJava","com.bumptech.glide":"Glide","com.squareup.picasso":"Picasso",
    "com.zendesk":"Zendesk","com.freshchat":"Freshchat","io.branch":"Branch","com.airbnb.lottie":"Lottie"}
INT_EXT={".json",".xml",".db",".sqlite",".pem",".key",".p12",".env",".conf",".properties",".yml",".sql",".bak"}
def detect_sdks(d):
    found={}
    for pkg,name in SDKS.items():
        if os.path.exists(os.path.join(d,"sources",pkg.replace(".",os.sep))):found[name]=pkg
    return found
def find_files(ad):
    files=[]
    for base in ["assets","res/raw"]:
        bd=os.path.join(ad,base)
        if not os.path.exists(bd):continue
        for root,_,fnames in os.walk(bd):
            for fn in fnames:
                if os.path.splitext(fn)[1].lower() in INT_EXT:
                    files.append({"file":os.path.relpath(os.path.join(root,fn),ad),"type":os.path.splitext(fn)[1]})
    return files
def main():
    p=argparse.ArgumentParser();p.add_argument("dir");p.add_argument("--manifest",default="");p.add_argument("-o","--output",default=".")
    a=p.parse_args();os.makedirs(a.output,exist_ok=True)
    sdks=detect_sdks(a.dir);json.dump(sdks,open(os.path.join(a.output,"third_party_sdks.json"),"w"),indent=2)
    print(f"[+] {len(sdks)} SDKs: {', '.join(sorted(sdks.keys())[:8])}")
    ad=os.path.dirname(a.manifest) if a.manifest else ""
    if ad:
        files=find_files(ad);json.dump(files,open(os.path.join(a.output,"interesting_files.json"),"w"),indent=2)
        print(f"[+] {len(files)} interesting files")
if __name__=="__main__":main()
