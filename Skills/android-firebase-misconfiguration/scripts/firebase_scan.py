#!/usr/bin/env python3
"""Generate Firebase misconfiguration test cases from extracted config.
Usage: python3 firebase_scan.py /tmp/fb_extracted -o scan.json"""
import argparse,json,os
def load(p):
    f=os.path.join(p,"firebase_config.json") if os.path.isdir(p) else p
    return json.load(open(f))
def gen(cfg):
    tests=[];s=cfg.get("summary",{})
    for u in s.get("database_urls",[]):
        u=u.rstrip("/")
        tests.append({"id":f"rtdb_read","type":"realtime_database_read","target":u,"command":f'curl -s "{u}/.json" | head -c 500',"severity_if_vulnerable":"critical","description":"Unauthorized database read"})
        tests.append({"id":f"rtdb_write","type":"realtime_database_write","target":u,"command":f'curl -s -X PUT -d \'{{\"_pentest\":\"test\"}}\' "{u}/_pentest.json"',"cleanup":f'curl -s -X DELETE "{u}/_pentest.json"',"severity_if_vulnerable":"critical","requires_authorization":True,"description":"Unauthorized database write"})
    for b in s.get("storage_buckets",[]):
        tests.append({"id":"storage_list","type":"storage_list","target":b,"command":f'curl -s "https://firebasestorage.googleapis.com/v0/b/{b}/o" | head -c 500',"severity_if_vulnerable":"high","description":"Public storage file listing"})
    for pid in s.get("project_ids",[]):
        pid=pid.strip('"').split(":")[-1].strip().strip('"') if ":" in str(pid) else str(pid).strip('"')
        tests.append({"id":"firestore","type":"firestore_read","target":pid,"command":f'curl -s "https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents/" | head -c 500',"severity_if_vulnerable":"high","description":"Unauthorized Firestore access"})
    ak=cfg.get("strings_xml",{}).get("google_api_key","")
    if ak:
        tests.append({"id":"anon_auth","type":"anonymous_auth","target":"API key","command":f'curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={ak}" -H "Content-Type: application/json" -d \'{{\"returnSecureToken\":true}}\'',"severity_if_vulnerable":"medium","description":"Anonymous auth enabled"})
    for fu in s.get("functions_urls",[]):
        tests.append({"id":"function","type":"cloud_function","target":fu,"command":f'curl -s -o /dev/null -w "%{{http_code}}" "{fu}"',"severity_if_vulnerable":"high","description":"Unauthenticated Cloud Function"})
    return tests
def main():
    p=argparse.ArgumentParser();p.add_argument("input");p.add_argument("-o","--output",default="firebase_scan.json")
    a=p.parse_args();cfg=load(a.input);tests=gen(cfg)
    json.dump({"total":len(tests),"tests":tests},open(a.output,"w"),indent=2)
    print(f"[+] {len(tests)} tests → {a.output}")
    for t in tests:
        auth=" [AUTH]" if t.get("requires_authorization") else ""
        print(f"  [{t['severity_if_vulnerable'].upper():8s}] {t['type']}{auth}")
if __name__=="__main__":main()
