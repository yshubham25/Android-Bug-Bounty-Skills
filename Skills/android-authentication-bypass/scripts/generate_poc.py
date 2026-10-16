#!/usr/bin/env python3
"""
generate_poc.py — Generate PoC scripts (ADB, Frida, HTML) for auth bypass findings.
Usage: python3 generate_poc.py auth_analysis.json -o pocs/
"""
import argparse, json, os

def gen_adb_poc(finding, out_dir):
    if not finding.get("adb_test"):
        return
    fname = f"poc_{finding['type']}_{finding.get('activity','unknown').split('.')[-1]}.sh"
    path = os.path.join(out_dir, fname)
    with open(path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# PoC: {finding['type']}\n")
        f.write(f"# Description: {finding['description']}\n")
        f.write(f"# Severity: {finding.get('severity','?')}\n\n")
        f.write("# Record screen for evidence\n")
        f.write("adb shell screenrecord /sdcard/poc.mp4 --time-limit 15 &\n")
        f.write("sleep 1\n\n")
        f.write(f"# Trigger auth bypass\n{finding['adb_test']}\n\n")
        f.write("sleep 5\n")
        f.write("kill %1 2>/dev/null\n")
        f.write("adb pull /sdcard/poc.mp4 ./poc_evidence.mp4\n")
        f.write('echo "[+] PoC complete. Check poc_evidence.mp4"\n')
    os.chmod(path, 0o755)
    return path

def gen_frida_poc(finding, out_dir):
    if not finding.get("frida_bypass"):
        return
    fname = f"frida_{finding['type']}.js"
    path = os.path.join(out_dir, fname)
    with open(path, "w") as f:
        f.write(f"// Frida PoC: {finding['type']}\n")
        f.write(f"// {finding['description']}\n")
        f.write(f"// Usage: frida -U -f com.target.app -l {fname} --no-pause\n\n")
        f.write(finding["frida_bypass"])
        f.write("\n")
    return path

def gen_deeplink_poc(finding, out_dir):
    if not finding.get("uri"):
        return
    fname = f"poc_deeplink_{finding.get('activity','').split('.')[-1]}.html"
    path = os.path.join(out_dir, fname)
    with open(path, "w") as f:
        f.write(f'<!DOCTYPE html>\n<html><body>\n')
        f.write(f'<h2>Auth Bypass PoC: {finding["type"]}</h2>\n')
        f.write(f'<p>{finding["description"]}</p>\n')
        f.write(f'<a href="{finding["uri"]}" style="font-size:20px;padding:10px 20px;background:#e74c3c;color:white;text-decoration:none;border-radius:5px;">Tap to test</a>\n')
        f.write(f'</body></html>\n')
    return path

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input");p.add_argument("-o","--output",default="pocs")
    args = p.parse_args()
    os.makedirs(args.output, exist_ok=True)

    with open(args.input) as f:
        data = json.load(f)

    generated = []
    for finding in data.get("findings", []):
        r = gen_adb_poc(finding, args.output)
        if r: generated.append(r)
        r = gen_frida_poc(finding, args.output)
        if r: generated.append(r)
        r = gen_deeplink_poc(finding, args.output)
        if r: generated.append(r)

    print(f"[+] Generated {len(generated)} PoC files in {args.output}/")
    for g in generated:
        print(f"  {g}")

if __name__ == "__main__":
    main()
