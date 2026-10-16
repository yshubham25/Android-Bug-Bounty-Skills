#!/usr/bin/env python3
"""Generate step-by-step validation plan for Intercom security testing.
Usage: python3 intercom_test_planner.py auth_analysis.json -o test_plan.json"""
import argparse,json,sys
def main():
    p=argparse.ArgumentParser();p.add_argument("input");p.add_argument("-o","--output",default="test_plan.json")
    a=p.parse_args();analysis=json.load(open(a.input))
    if analysis.get("status")=="NOT_APPLICABLE":
        print("[!] Not applicable");return
    plan={"prerequisites":analysis.get("test_prerequisites",[]),"steps":[
        {"step":1,"name":"Setup test accounts","action":"Create Account A (researcher-a@test.com) and Account B (researcher-b@test.com)",
         "validation":"Both accounts can access Intercom messenger in the app"},
        {"step":2,"name":"Create test markers","action":"Account A sends: INTERCOM-TEST-A-[timestamp], Account B sends: INTERCOM-TEST-B-[timestamp]",
         "validation":"Both test messages visible in respective accounts"},
        {"step":3,"name":"Intercept baseline traffic","action":"Capture Burp requests for /messenger/mobile/conversations for both accounts",
         "validation":"Record conversation IDs, auth headers, identity fields for each account"},
        {"step":4,"name":"Test IDOR on conversations","action":"Using Account A's session, request Account B's conversation_id",
         "expected_secure":"403 or empty response","vulnerability_if":"Account B's messages returned to Account A"},
        {"step":5,"name":"Test identity impersonation","action":"Using SDK credentials, send request with Account B's email/userId from Account A's context",
         "expected_secure":"Rejected or returns only Account A's data","vulnerability_if":"Account B's conversations returned"},
        {"step":6,"name":"Test conversation creation","action":"Create conversation with harmless marker using arbitrary identity",
         "expected_secure":"Requires valid identity proof","vulnerability_if":"Can create conversations as any user"},
        {"step":7,"name":"False positive check","action":"Verify findings per Phase 5 checklist (visitor vs authenticated, session reuse, etc.)",
         "validation":"Finding survives all false-positive elimination checks"},
    ],"false_positive_checks":["Is visitor messaging intentionally public?","Did you reuse sessions between accounts?",
        "Was the response a NEW visitor conversation?","Can you reproduce after clearing all sessions?",
        "Is the issue in the app's integration or Intercom SDK itself?"]}
    json.dump(plan,open(a.output,"w"),indent=2)
    print(f"[+] Test plan → {a.output} ({len(plan['steps'])} steps)")
    for s in plan["steps"]:print(f"  Step {s['step']}: {s['name']}")
if __name__=="__main__":main()
