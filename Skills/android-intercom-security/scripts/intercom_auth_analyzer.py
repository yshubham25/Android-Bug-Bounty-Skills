#!/usr/bin/env python3
"""Analyze Intercom auth configuration from detection results.
Usage: python3 intercom_auth_analyzer.py intercom_results/ -o auth_analysis.json"""
import argparse,json,os,sys
def main():
    p=argparse.ArgumentParser();p.add_argument("results_dir");p.add_argument("-o","--output",default="auth_analysis.json")
    a=p.parse_args()
    det=json.load(open(os.path.join(a.results_dir,"intercom_detection.json")))
    cfg=det["config"];findings=det["findings"]
    analysis={"intercom_detected":cfg["intercom_detected"],"identity_verification":cfg["identity_verification_status"],
              "auth_model":{},"vulnerabilities_to_test":[],"test_prerequisites":[]}
    if not cfg["intercom_detected"]:
        analysis["status"]="NOT_APPLICABLE"
        json.dump(analysis,open(a.output,"w"),indent=2)
        print("[!] No Intercom — nothing to analyze");return
    # Auth model
    if cfg.get("login_identified"):analysis["auth_model"]["user_type"]="identified"
    elif cfg.get("login_unidentified"):analysis["auth_model"]["user_type"]="unidentified"
    else:analysis["auth_model"]["user_type"]="unknown"
    analysis["auth_model"]["identity_binding"]="email" if cfg.get("email_binding") else ("userId" if cfg.get("userid_binding") else "unknown")
    analysis["auth_model"]["hmac_present"]=cfg.get("hmac_found",False)
    analysis["auth_model"]["user_hash_present"]=cfg.get("user_hash_found",False)
    # Vulnerabilities to test
    if cfg["identity_verification_status"]=="potentially_disabled":
        analysis["vulnerabilities_to_test"].append({"test":"identity_impersonation","severity":"high",
            "description":"loginIdentifiedUser without user_hash — test if arbitrary email/userId can access conversations",
            "cwe":"CWE-639"})
    analysis["vulnerabilities_to_test"].append({"test":"cross_account_idor","severity":"high",
        "description":"Test if Account A can access Account B's conversation by swapping conversation_id",
        "cwe":"CWE-639"})
    analysis["vulnerabilities_to_test"].append({"test":"conversation_creation_impersonation","severity":"medium",
        "description":"Test if conversations can be created under arbitrary identity","cwe":"CWE-287"})
    # Prerequisites
    analysis["test_prerequisites"]=["Written authorization for target app","Two researcher-owned test accounts",
        "Burp Suite / mitmproxy configured","SSL pinning bypassed","Test messages created in both accounts"]
    analysis["status"]="READY_FOR_TESTING"
    json.dump(analysis,open(a.output,"w"),indent=2)
    print(f"[+] Auth analysis → {a.output}")
    print(f"  Identity verification: {cfg['identity_verification_status']}")
    print(f"  Tests to run: {len(analysis['vulnerabilities_to_test'])}")
    for t in analysis["vulnerabilities_to_test"]:
        print(f"    [{t['severity'].upper():6s}] {t['test']}: {t['description'][:60]}")
if __name__=="__main__":main()
