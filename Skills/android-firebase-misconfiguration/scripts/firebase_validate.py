#!/usr/bin/env python3
"""Execute Firebase tests. Read-only by default. --authorized enables writes.
Usage: python3 firebase_validate.py scan.json --authorized -o results.json"""
import argparse,json,subprocess,sys
def run(t,auth=False):
    if t.get("requires_authorization") and not auth:
        return {**t,"status":"skipped","reason":"needs --authorized"}
    try:
        r=subprocess.run(t["command"],shell=True,capture_output=True,text=True,timeout=15)
        resp=r.stdout.strip();v=False
        if t["type"]=="realtime_database_read":v=resp and resp not in['null',''] and "Permission denied" not in resp and "error" not in resp.lower()
        elif t["type"]=="realtime_database_write":
            v=resp and "Permission denied" not in resp and "error" not in resp.lower()
            if v and t.get("cleanup"):subprocess.run(t["cleanup"],shell=True,capture_output=True,timeout=10)
        elif t["type"]=="storage_list":v='"items"' in resp or '"name"' in resp
        elif t["type"]=="firestore_read":v='"documents"' in resp or '"fields"' in resp
        elif t["type"]=="anonymous_auth":v='"idToken"' in resp
        elif t["type"]=="cloud_function":v=resp in["200","301","302"]
        return {**t,"status":"vulnerable" if v else "secure","response_preview":resp[:200],"severity":t["severity_if_vulnerable"] if v else "none"}
    except:return {**t,"status":"error"}
def main():
    p=argparse.ArgumentParser();p.add_argument("input");p.add_argument("--authorized",action="store_true");p.add_argument("-o","--output",default="validated.json")
    a=p.parse_args();data=json.load(open(a.input));tests=data.get("tests",[])
    print(f"[*] Running {len(tests)} tests...")
    results=[run(t,a.authorized) for t in tests]
    vulns=[r for r in results if r["status"]=="vulnerable"]
    json.dump({"vulnerable":len(vulns),"total":len(results),"findings":results},open(a.output,"w"),indent=2)
    print(f"[+] {len(vulns)} vulnerable / {len(results)} tested → {a.output}")
if __name__=="__main__":main()
