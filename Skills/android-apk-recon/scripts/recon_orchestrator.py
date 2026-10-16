#!/usr/bin/env python3
"""
recon_orchestrator.py — Full APK recon pipeline with 9 modules.
Decompiles once, runs all modules including Intercom analysis,
saves structured JSON, generates prioritized attack surface report.

Usage:
    python3 recon_orchestrator.py target.apk --full -o recon_results/
    python3 recon_orchestrator.py target.apk --quick -o recon_results/
    python3 recon_orchestrator.py target.apk --reuse -o recon_results/
"""
import argparse, hashlib, json, os, subprocess, sys, time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run_module(name, cmd):
    print(f"  [{name}]...", end=" ", flush=True)
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        print("done" if r.returncode == 0 else f"warning")
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print("timeout")
        return False
    except Exception as e:
        print(f"error: {str(e)[:50]}")
        return False


def check_cache(apk, out_dir):
    cache_file = os.path.join(out_dir, "apk_info.json")
    if not os.path.exists(cache_file):
        return False
    try:
        return json.load(open(cache_file)).get("sha256") == sha256(apk)
    except:
        return False


def decompile(apk, out_dir):
    jadx_dir = os.path.join(out_dir, "decompiled", "jadx")
    apktool_dir = os.path.join(out_dir, "decompiled", "apktool")
    os.makedirs(jadx_dir, exist_ok=True)
    os.makedirs(apktool_dir, exist_ok=True)
    run_module("JADX", f'jadx -d "{jadx_dir}" --deobf --show-bad-code "{apk}"')
    run_module("APKTool", f'apktool d "{apk}" -o "{apktool_dir}" -f')
    # DEX strings
    dex_dir = os.path.join(out_dir, "decompiled", "dex")
    os.makedirs(dex_dir, exist_ok=True)
    run_module("DEX strings", f'cd "{dex_dir}" && unzip -o "{os.path.abspath(apk)}" "classes*.dex" 2>/dev/null; for f in classes*.dex; do strings "$f" 2>/dev/null; done > "{out_dir}/dex_strings.txt" 2>/dev/null')
    return jadx_dir, apktool_dir


def s(script):
    return os.path.join(SCRIPT_DIR, script)


def main():
    p = argparse.ArgumentParser(description="Full APK reconnaissance")
    p.add_argument("apk", help="Path to APK file")
    p.add_argument("-o", "--output", default="recon_results")
    p.add_argument("--full", action="store_true", help="All modules + external tools")
    p.add_argument("--quick", action="store_true", help="Manifest + endpoints only")
    p.add_argument("--reuse", action="store_true", help="Skip if APK unchanged")
    args = p.parse_args()

    apk = os.path.abspath(args.apk)
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)

    print(f"\n{'='*55}")
    print(f" Android APK Recon v2 (with Intercom)")
    print(f"{'='*55}")
    print(f" Target: {os.path.basename(apk)}")
    print(f" Mode:   {'full' if args.full else 'quick' if args.quick else 'standard'}")
    start = time.time()

    if args.reuse and check_cache(apk, out):
        print(" Cache hit — reusing results")
        print(f"{'='*55}\n")
        return

    # === Module 1: APK Info ===
    print("\n[1/9] APK identification")
    run_module("apk_info", f'python3 "{s("apk_info.py")}" "{apk}" -o "{out}/apk_info.json"')

    # === Module 2: Decompile ===
    print("\n[2/9] Decompilation")
    jadx_dir, apktool_dir = decompile(apk, out)
    manifest = os.path.join(apktool_dir, "AndroidManifest.xml")

    # === Module 3: Manifest ===
    print("\n[3/9] Manifest analysis")
    run_module("manifest", f'python3 "{s("manifest_analyzer.py")}" "{manifest}" -o "{out}"')

    # === Module 4: Endpoints ===
    print("\n[4/9] Endpoint extraction")
    run_module("endpoints", f'python3 "{s("extract_endpoints.py")}" "{jadx_dir}" -o "{out}/endpoints.json"')

    if args.quick:
        print("\n[Quick mode] Skipping modules 5-8")
    else:
        # === Module 5: WebViews ===
        print("\n[5/9] WebView mapping")
        run_module("webviews", f'python3 "{s("webview_finder.py")}" "{jadx_dir}" -o "{out}/webviews.json"')

        # === Module 6: Components & SDKs ===
        print("\n[6/9] Component & SDK mapping")
        run_module("components", f'python3 "{s("component_mapper.py")}" "{jadx_dir}" --manifest "{manifest}" -o "{out}"')

        # === Module 7: Intercom Analysis ===
        print("\n[7/9] Intercom SDK analysis")
        run_module("intercom", f'python3 "{s("intercom_analyzer.py")}" "{jadx_dir}" -o "{out}/intercom_analysis.json"')

        # === Module 8: Secret Detection ===
        print("\n[8/9] Secret detection")
        run_module("secrets", f'python3 "{s("secret_scanner.py")}" "{jadx_dir}" -o "{out}/potential_secrets.json"')

    # === External tools (full mode) ===
    if args.full:
        print("\n[Extra] External tools")
        run_module("apk2url", f'which apk2url >/dev/null 2>&1 && apk2url "{apk}" 2>/dev/null || true')
        run_module("apkleaks", f'which apkleaks >/dev/null 2>&1 && apkleaks -f "{apk}" --json -o "{out}/apkleaks.json" 2>/dev/null || true')

    # === Module 9: Report ===
    print("\n[9/9] Report generation")
    run_module("report", f'python3 "{s("generate_report.py")}" "{out}" -o "{out}/recon_report.md"')

    elapsed = time.time() - start
    print(f"\n{'='*55}")
    print(f" Recon complete in {elapsed:.0f}s")
    print(f" Results: {out}/")
    print(f" Report:  {out}/recon_report.md")

    # Quick summary
    for jf in ["apk_info.json", "intercom_analysis.json"]:
        fp = os.path.join(out, jf)
        if os.path.exists(fp):
            d = json.load(open(fp))
            if jf == "apk_info.json":
                print(f" Framework: {d.get('framework', '?')}")
            elif jf == "intercom_analysis.json":
                print(f" Intercom: {'DETECTED' if d.get('config',{}).get('intercom_detected') else 'not found'}")

    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
