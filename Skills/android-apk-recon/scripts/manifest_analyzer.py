#!/usr/bin/env python3
"""Parse AndroidManifest.xml — components, deep links, permissions, configs."""
import argparse,json,os,sys
import xml.etree.ElementTree as ET
NS="{http://schemas.android.com/apk/res/android}"
def parse(mp):
    tree=ET.parse(mp);root=tree.getroot();pkg=root.attrib.get("package","")
    app=root.find("application");app_attrs={}
    if app is not None:
        app_attrs={k:app.attrib.get(f"{NS}{k}","unset") for k in ["allowBackup","debuggable","usesCleartextTraffic","networkSecurityConfig"]}
    comps={"activities":[],"services":[],"receivers":[],"providers":[]};dls=[]
    for tag,key in [("activity","activities"),("service","services"),("receiver","receivers"),("provider","providers")]:
        for elem in root.iter(tag):
            name=elem.attrib.get(f"{NS}name","");exp=elem.attrib.get(f"{NS}exported","unset")
            perm=elem.attrib.get(f"{NS}permission","");hf=len(elem.findall("intent-filter"))>0
            is_exp=exp=="true" or (exp=="unset" and hf)
            entry={"name":name,"exported":is_exp,"permission":perm}
            if tag=="provider":
                entry.update({"authorities":elem.attrib.get(f"{NS}authorities",""),
                    "readPermission":elem.attrib.get(f"{NS}readPermission",""),
                    "writePermission":elem.attrib.get(f"{NS}writePermission",""),
                    "grantUriPermissions":elem.attrib.get(f"{NS}grantUriPermissions","false")})
            for ifilter in elem.findall("intent-filter"):
                acts=[a.attrib.get(f"{NS}name","") for a in ifilter.findall("action")]
                if "android.intent.action.VIEW" not in acts:continue
                for data in ifilter.findall("data"):
                    sc=data.attrib.get(f"{NS}scheme","");ho=data.attrib.get(f"{NS}host","")
                    pa=data.attrib.get(f"{NS}pathPrefix","") or data.attrib.get(f"{NS}path","")
                    if sc:dls.append({"activity":name,"scheme":sc,"host":ho,"path":pa,"uri":f"{sc}://{ho}{pa}" if ho else f"{sc}://"})
            comps[key].append(entry)
    perms=[p.attrib.get(f"{NS}name","") for p in root.iter("uses-permission")]
    return {"package":pkg,"app_config":app_attrs,"components":comps,"deeplinks":dls,"permissions":perms,
            "exported_count":sum(1 for cat in comps.values() for c in cat if c.get("exported"))}
def main():
    p=argparse.ArgumentParser();p.add_argument("manifest");p.add_argument("-o","--output",default=".")
    a=p.parse_args();r=parse(a.manifest);os.makedirs(a.output,exist_ok=True)
    json.dump(r,open(os.path.join(a.output,"manifest_analysis.json"),"w"),indent=2)
    json.dump(r["deeplinks"],open(os.path.join(a.output,"deeplinks.json"),"w"),indent=2)
    json.dump([c for cat in r["components"].values() for c in cat if c.get("exported")],open(os.path.join(a.output,"exported_components.json"),"w"),indent=2)
    json.dump(r["components"]["providers"],open(os.path.join(a.output,"content_providers.json"),"w"),indent=2)
    print(f"[+] {r['package']} | {r['exported_count']} exported | {len(r['deeplinks'])} deep links | {len(r['permissions'])} perms")
if __name__=="__main__":main()
