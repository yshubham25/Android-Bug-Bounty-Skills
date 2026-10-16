#!/usr/bin/env python3
"""Android MCP server for bug-bounty work against a rooted (Magisk) emulator.

Binary discovery: ANDROID_MCP_ADB / ANDROID_MCP_EMULATOR env vars, then PATH,
then ANDROID_HOME / ANDROID_SDK_ROOT / %LOCALAPPDATA%\\Android\\Sdk / ~/android-sdk.

Device targeting: ANDROID_MCP_DEVICE env var (serial), else the only online
device, else the only online emulator. Every tool also takes device_id.
"""

import base64
import os
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from mcp.server.mcpserver import MCPServer, Image

mcp = MCPServer("android-bb")

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
DEFAULT_AVD = os.environ.get("ANDROID_MCP_AVD") or "Magisk API 34"
_DEVICE_ENV = os.environ.get("ANDROID_MCP_DEVICE") or None


# ---------------------------------------------------------------- binaries

def _env(name):
    return os.environ.get(name) or None


def _is_file(p):
    return bool(p) and Path(str(p)).is_file()


def _sdk_dirs():
    dirs = []
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = _env(var)
        if v:
            dirs.append(Path(v))
    for la_key in ("LOCALAPPDATA",):
        v = _env(la_key)
        if v:
            dirs.append(Path(v) / "Android" / "Sdk")
    home = Path.home()
    dirs.append(home / "AppData" / "Local" / "Android" / "Sdk")
    dirs.append(home / "android-sdk")
    dirs.append(home / "Android" / "Sdk")
    return dirs


SDK_DIRS = _sdk_dirs()


def _find_binary(env_var, name, rels):
    v = _env(env_var)
    if v and _is_file(v):
        return v
    w = shutil.which(name)
    if w:
        return w
    for d in SDK_DIRS:
        for r in rels:
            c = d / r
            if _is_file(c):
                return str(c)
    return None


ADB = _find_binary(
    "ANDROID_MCP_ADB", "adb",
    ["platform-tools/adb.exe", "platform-tools/adb", "adb.exe"],
)
EMULATOR = _find_binary(
    "ANDROID_MCP_EMULATOR", "emulator",
    ["emulator/emulator.exe", "emulator/emulator"],
)


def _require_adb():
    if not ADB:
        raise RuntimeError(
            "adb not found. Set ANDROID_MCP_ADB or install platform-tools "
            "(searched PATH, ANDROID_HOME, ANDROID_SDK_ROOT, %LOCALAPPDATA%\\Android\\Sdk, ~/android-sdk)."
        )
    return ADB


def _require_emulator():
    if not EMULATOR:
        raise RuntimeError(
            "emulator binary not found. Set ANDROID_MCP_EMULATOR "
            "(usually %LOCALAPPDATA%\\Android\\Sdk\\emulator\\emulator.exe)."
        )
    return EMULATOR


def _run(cmd, timeout=120, binary=False):
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = r.stdout if binary else r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    return out, err, r.returncode


def _adb(*args, device=None, timeout=120, binary=False):
    cmd = [_require_adb()]
    if device:
        cmd += ["-s", str(device)]
    cmd += [str(a) for a in args]
    return _run(cmd, timeout=timeout, binary=binary)


def _shq(s):
    """Single-quote a string for the device's POSIX shell."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def _shell(command, device=None, root=False, timeout=120, binary=False):
    dev = _resolve_device(device)
    if root:
        command = "su -c " + _shq(command)
    return _adb("shell", command, device=dev, timeout=timeout, binary=binary)


def _shell_ok(command, device=None, root=False, timeout=120):
    out, err, rc = _shell(command, device=device, root=root, timeout=timeout)
    text = (out or "").strip()
    if err.strip():
        text += ("\n" if text else "") + "[stderr] " + err.strip()
    if rc != 0 and not text:
        text = f"[exit {rc}]"
    return text


# ---------------------------------------------------------------- devices

def _devices():
    out, _, _ = _adb("devices", "-l", timeout=30)
    devs = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        d = {"serial": parts[0], "state": parts[1]}
        for kv in parts[2:]:
            if ":" in kv:
                k, v = kv.split(":", 1)
                if k in ("model", "product", "device", "transport_id"):
                    d[k] = v
        devs.append(d)
    return devs


def _avd_name(serial):
    out, _, _ = _adb("emu", "avd", "name", device=serial, timeout=15)
    for line in (out or "").splitlines():
        s = line.strip()
        if s and s != "OK":
            return s
    out, _, _ = _adb("shell", "getprop ro.boot.qemu.avd_name", device=serial, timeout=15)
    return (out or "").strip() or None


def _resolve_device(explicit=None):
    if explicit:
        return explicit
    if _DEVICE_ENV:
        return _DEVICE_ENV
    devs = [d for d in _devices() if d["state"] == "device"]
    if not devs:
        raise RuntimeError(
            "no online device. Boot the 'Magisk API 34' AVD (start_emulator) or pass device_id."
        )
    if len(devs) == 1:
        return devs[0]["serial"]
    emus = [d for d in devs if d["serial"].startswith("emulator-")]
    if len(emus) == 1:
        return emus[0]["serial"]
    raise RuntimeError(
        "multiple devices online (" + ", ".join(d["serial"] for d in devs) + "); pass device_id."
    )


# ---------------------------------------------------------------- device mgmt

@mcp.tool()
def list_devices():
    """List adb devices (serial, state, model, AVD name for emulators) and show which one is the default target."""
    devs = _devices()
    for d in devs:
        if d["serial"].startswith("emulator-"):
            try:
                d["avd"] = _avd_name(d["serial"])
            except Exception:
                d["avd"] = None
    try:
        target = _resolve_device()
    except Exception:
        target = None
    return {"adb": ADB, "emulator": EMULATOR, "default_target": target, "devices": devs}


@mcp.tool()
def list_avds():
    """List AVDs installed on this machine (emulator -list-avds)."""
    out, _, _ = _run([_require_emulator(), "-list-avds"], timeout=60)
    avds = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("INFO")]
    return {"emulator": EMULATOR, "avds": avds}


@mcp.tool()
def start_emulator(avd_name: str = DEFAULT_AVD, cold_boot: bool = False, wait_for_boot: bool = True):
    """Boot an AVD ('Magisk API 34' and 'Magisk' both resolve to the Magisk AVD) and optionally wait until boot completes. Returns the emulator serial."""
    emu = _require_emulator()
    out, _, _ = _run([emu, "-list-avds"], timeout=60)
    avds = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("INFO")]
    low = avd_name.lower()
    pick = next((a for a in avds if a.lower() == low), None)
    if not pick:
        subs = [a for a in avds if low in a.lower() or a.lower() in low]
        if len(subs) == 1:
            pick = subs[0]
        elif len(subs) > 1:
            raise RuntimeError(f"ambiguous AVD '{avd_name}': {subs}")
        else:
            raise RuntimeError(f"AVD '{avd_name}' not found. Available: {avds}")

    for d in _devices():
        if d["serial"].startswith("emulator-") and d["state"] == "device":
            try:
                if (_avd_name(d["serial"]) or "").lower() == pick.lower():
                    return {"avd": pick, "serial": d["serial"], "note": "already running"}
            except Exception:
                pass

    before = {d["serial"] for d in _devices()}
    args = [emu, "-avd", pick, "-no-boot-anim"]
    if cold_boot:
        args.append("-no-snapshot-load")
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=CREATE_NO_WINDOW)
    if not wait_for_boot:
        return {"avd": pick, "note": "launched, not waiting for boot"}

    deadline = time.time() + 300
    serial = None
    while time.time() < deadline and not serial:
        for d in _devices():
            if d["serial"].startswith("emulator-") and d["state"] == "device" \
                    and d["serial"] not in before:
                serial = d["serial"]
                break
        if not serial:
            time.sleep(3)
    if not serial:
        raise RuntimeError(f"emulator '{pick}' did not come online within 300s")

    booted = False
    while time.time() < deadline:
        out, _, _ = _adb("shell", "getprop sys.boot_completed", device=serial, timeout=15)
        if out.strip() == "1":
            booted = True
            break
        time.sleep(3)
    return {"avd": pick, "serial": serial, "boot_completed": booted}


@mcp.tool()
def stop_emulator(device_id: str = ""):
    """Shut down a running emulator (adb emu kill)."""
    dev = _resolve_device(device_id or None)
    _, err, _ = _adb("emu", "kill", device=dev, timeout=30)
    return f"kill sent to {dev}" + (f" ({err.strip()})" if err.strip() else "")


@mcp.tool()
def device_info(device_id: str = ""):
    """Model, Android version/API level, ABI, AVD name, screen size/density, debuggable flag and root status of the target device."""
    dev = _resolve_device(device_id or None)
    out, _, _ = _adb("shell", "getprop", device=dev, timeout=30)
    props = dict(re.findall(r"\[([^\]]+)\]: \[([^\]]*)\]", out))
    wm, _, _ = _adb("shell", "wm size; wm density", device=dev, timeout=30)
    rooted, root_ctx = False, ""
    try:
        rid, _, _ = _adb("shell", "su -c id", device=dev, timeout=20)
        rooted = "uid=0" in rid
        root_ctx = rid.strip().splitlines()[0] if rid.strip() else ""
    except Exception:
        pass
    return {
        "serial": dev,
        "avd": props.get("ro.boot.qemu.avd_name"),
        "model": props.get("ro.product.model"),
        "manufacturer": props.get("ro.product.manufacturer"),
        "android": props.get("ro.build.version.release"),
        "api_level": props.get("ro.build.version.sdk"),
        "abi": props.get("ro.product.cpu.abi"),
        "build_type": props.get("ro.build.type"),
        "debuggable": props.get("ro.debuggable") == "1",
        "rooted": rooted,
        "root_context": root_ctx,
        "screen": [l.strip() for l in wm.splitlines() if l.strip()],
    }


@mcp.tool()
def current_activity(device_id: str = ""):
    """Foreground app/activity (resumed activity + focused window) — verify a launch or a fired deeplink landed."""
    cmd = ("dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' | head -3; "
           "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp' | head -4")
    return _shell_ok(cmd, device=device_id or None, timeout=60)


# ---------------------------------------------------------------- shell

@mcp.tool()
def adb_shell(command: str, device_id: str = "", timeout: int = 120):
    """Run a shell command on the device (non-root adb shell). Returns stdout/stderr and exit code."""
    out, err, rc = _shell(command, device=device_id or None, timeout=timeout)
    text = out
    if err.strip():
        text += ("\n" if text else "") + "[stderr] " + err
    if rc != 0:
        text += f"\n[exit {rc}]"
    return text.strip() or f"[exit {rc}]"


@mcp.tool()
def root_shell(command: str, device_id: str = "", timeout: int = 120):
    """Run a shell command as root via 'su -c' (the Magisk image grants adb shell uid=0). Use for /data/data, protected files, frida-server setup, memory inspection."""
    out, err, rc = _shell(command, device=device_id or None, root=True, timeout=timeout)
    text = out
    if err.strip():
        text += ("\n" if text else "") + "[stderr] " + err
    if rc != 0:
        text += f"\n[exit {rc}]"
    return text.strip() or f"[exit {rc}]"


# ---------------------------------------------------------------- packages

@mcp.tool()
def list_packages(third_party_only: bool = True, filter: str = "", device_id: str = ""):
    """List installed packages (third-party only by default). filter matches a substring of the package name."""
    flag = "-3" if third_party_only else ""
    out, _, _ = _shell(f"pm list packages {flag}".strip(), device=device_id or None, timeout=60)
    pkgs = sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:"))
    if filter:
        pkgs = [p for p in pkgs if filter.lower() in p.lower()]
    return {"count": len(pkgs), "packages": pkgs}


@mcp.tool()
def package_info(package: str, device_id: str = ""):
    """Curated 'dumpsys package' summary: version, SDK levels, uid, data dir, code paths, installer, declared/requested permissions."""
    dev = _resolve_device(device_id or None)
    out, _, _ = _adb("shell", f"dumpsys package {_shq(package)}", device=dev, timeout=60)
    if not out.strip() or "Unknown package" in out:
        return f"package not found: {package}"
    info = {"package": package}
    for key, pat in (
        ("version_name", r"versionName=(\S+)"),
        ("sdk_line", r"(versionCode=\S+.*)"),
        ("user_id", r"userId=(\d+)"),
        ("data_dir", r"dataDir=(\S+)"),
        ("code_path", r"codePath=(\S+)"),
        ("installer", r"installerPackageName=(\S+)"),
        ("first_install", r"firstInstallTime=(.*)"),
        ("last_update", r"lastUpdateTime=(.*)"),
    ):
        m = re.search(pat, out)
        if m:
            info[key] = m.group(1).strip()
    m = re.search(r"requested permissions:\s*\n((?:\s+\S+\n)+)", out)
    if m:
        info["requested_permissions"] = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    m = re.search(r"declared permissions:\s*\n((?:\s+\S+\n)+)", out)
    if m:
        info["declared_permissions"] = [l.strip() for l in m.group(1).splitlines() if l.strip()]
    pout, _, _ = _adb("shell", f"pm path {_shq(package)}", device=dev, timeout=30)
    paths = [l.split(":", 1)[1] for l in pout.splitlines() if l.startswith("package:")]
    if paths:
        info["apk_paths"] = paths
    return info


@mcp.tool()
def install_apk(apk_path: str, device_id: str = "", reinstall: bool = True,
                grant_all_permissions: bool = False, allow_downgrade: bool = False,
                allow_test_packages: bool = True):
    """Install an APK, or a directory of split APKs (install-multiple). Returns adb's Success/Failure output."""
    dev = _resolve_device(device_id or None)
    p = Path(apk_path).expanduser()
    if not p.exists():
        return f"path not found: {p}"
    flags = []
    if allow_test_packages:
        flags.append("-t")
    if reinstall:
        flags.append("-r")
    if grant_all_permissions:
        flags.append("-g")
    if allow_downgrade:
        flags.append("-d")
    if p.is_dir():
        apks = sorted(str(f) for f in p.iterdir() if f.suffix.lower() == ".apk")
        if not apks:
            return f"no .apk files in {p}"
        out, err, rc = _adb("install-multiple", *flags, *apks, device=dev, timeout=600)
    else:
        out, err, rc = _adb("install", *flags, str(p), device=dev, timeout=600)
    return (out + err).strip()


@mcp.tool()
def uninstall_package(package: str, keep_data: bool = False, device_id: str = ""):
    """Uninstall a package (keep_data=True keeps data/cache dirs via pm uninstall -k)."""
    flag = " -k" if keep_data else ""
    return _shell_ok(f"pm uninstall{flag} {_shq(package)}", device=device_id or None)


@mcp.tool()
def clear_app_data(package: str, device_id: str = ""):
    """Wipe an app's data (pm clear) — reset login/state between test runs."""
    return _shell_ok(f"pm clear {_shq(package)}", device=device_id or None)


@mcp.tool()
def grant_permission(package: str, permission: str, device_id: str = ""):
    """Grant a runtime permission (pm grant), e.g. android.permission.ACCESS_FINE_LOCATION."""
    return _shell_ok(f"pm grant {_shq(package)} {_shq(permission)}", device=device_id or None)


@mcp.tool()
def revoke_permission(package: str, permission: str, device_id: str = ""):
    """Revoke a runtime permission (pm revoke)."""
    return _shell_ok(f"pm revoke {_shq(package)} {_shq(permission)}", device=device_id or None)


@mcp.tool()
def launch_app(package: str, activity: str = "", device_id: str = ""):
    """Launch an app: explicit entry if activity is given ('am start -n package/activity'), else its launcher intent via monkey."""
    if activity:
        comp = activity if "/" in activity else f"{package}/{activity}"
        return _shell_ok(f"am start -n {_shq(comp)}", device=device_id or None, timeout=60)
    return _shell_ok(f"monkey -p {_shq(package)} -c android.intent.category.LAUNCHER 1",
                     device=device_id or None, timeout=60)


@mcp.tool()
def force_stop(package: str, device_id: str = ""):
    """Force-stop a package (am force-stop)."""
    return _shell_ok(f"am force-stop {_shq(package)}", device=device_id or None)


# ---------------------------------------------------------------- intents / IPC

@mcp.tool()
def send_uri(uri: str, action: str = "android.intent.action.VIEW",
             extras: dict[str, str] | None = None, component: str = "",
             package: str = "", flags: str = "", device_id: str = ""):
    """Fire an intent with a data URI via 'am start' — deeplink / exported-activity testing. extras become --es key value pairs; component is 'pkg/.Act' (or 'pkg/Act')."""
    parts = ["am", "start", "-a", _shq(action), "-d", _shq(uri)]
    if component:
        parts += ["-n", _shq(component)]
    if package:
        parts += ["-p", _shq(package)]
    if flags:
        parts += ["-f", _shq(flags)]
    for k, v in (extras or {}).items():
        parts += ["--es", _shq(k), _shq(v)]
    return _shell_ok(" ".join(parts), device=device_id or None, timeout=60)


@mcp.tool()
def send_broadcast(action: str, extras: dict[str, str] | None = None,
                   component: str = "", package: str = "", device_id: str = ""):
    """Send a broadcast via 'am broadcast' — exported / unprotected receiver testing."""
    parts = ["am", "broadcast", "-a", _shq(action)]
    if component:
        parts += ["-n", _shq(component)]
    if package:
        parts += ["-p", _shq(package)]
    for k, v in (extras or {}).items():
        parts += ["--es", _shq(k), _shq(v)]
    return _shell_ok(" ".join(parts), device=device_id or None, timeout=60)


@mcp.tool()
def query_provider(uri: str, projection: list[str] | None = None, where: str = "",
                   device_id: str = ""):
    """Query a content:// URI via 'content query' — exported-provider data exposure testing."""
    cmd = f"content query --uri {_shq(uri)}"
    if projection:
        cmd += " --projection " + _shq(",".join(projection))
    if where:
        cmd += " --where " + _shq(where)
    return _shell_ok(cmd, device=device_id or None, timeout=60)


# ---------------------------------------------------------------- UI

@mcp.tool()
def screenshot(device_id: str = "", save_path: str = ""):
    """PNG screenshot of the device screen; returns the image, optionally also saved to save_path."""
    dev = _resolve_device(device_id or None)
    data = b""
    err = ""
    out, err, _ = _adb("exec-out", "screencap", "-p", device=dev, timeout=60, binary=True)
    if isinstance(out, bytes):
        data = out
    if not data.startswith(b"\x89PNG"):
        remote = "/sdcard/__androidbb_mcp_screenshot.png"
        _adb("shell", f"screencap -p {remote}", device=dev, timeout=60)
        tmp = Path(tempfile.gettempdir()) / "__androidbb_mcp_screenshot.png"
        _adb("pull", remote, str(tmp), device=dev, timeout=60)
        _adb("shell", f"rm -f {remote}", device=dev, timeout=30)
        if tmp.is_file():
            data = tmp.read_bytes()
    if not data.startswith(b"\x89PNG"):
        return f"screenshot failed: {err.strip() or 'no PNG data returned'}"
    if save_path:
        Path(save_path).expanduser().write_bytes(data)
    return Image(data=data, format="png")


@mcp.tool()
def ui_dump(device_id: str = "", full_xml: bool = False):
    """Dump the current screen's UI hierarchy (uiautomator). Compact mode lists nodes with class, text, resource-id, content-desc, flags, bounds and computed tap=(x,y) centers. full_xml=True returns the raw XML."""
    dev = _resolve_device(device_id or None)
    remote = "/sdcard/__androidbb_mcp_ui.xml"
    out = ""
    for _ in range(2):
        out, err, _ = _adb("shell", f"uiautomator dump {remote}", device=dev, timeout=60)
        if "dumped to" in out:
            break
        time.sleep(1)
    tmp = Path(tempfile.gettempdir()) / "__androidbb_mcp_ui.xml"
    if tmp.exists():
        tmp.unlink()
    _adb("pull", remote, str(tmp), device=dev, timeout=60)
    if not tmp.is_file():
        return f"ui dump failed: {out.strip()} {err.strip()}"
    xml = tmp.read_text(encoding="utf-8", errors="replace")
    if full_xml:
        return xml
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        return f"XML parse failed ({e}); raw start: {xml[:500]}"
    lines = []

    def walk(node, depth):
        a = node.attrib
        cls = a.get("class", "").rsplit(".", 1)[-1]
        text = a.get("text", "")
        rid = a.get("resource-id", "")
        desc = a.get("content-desc", "")
        bounds = a.get("bounds", "")
        interesting = bool(text or rid or desc) or a.get("clickable") == "true" \
            or a.get("scrollable") == "true"
        if interesting and bounds != "[0,0][0,0]":
            flags = ",".join(f for f in
                             ("clickable", "scrollable", "checkable", "checked",
                              "selected", "focused", "long-clickable")
                             if a.get(f) == "true")
            seg = f"{'  ' * depth}{cls}"
            if text:
                seg += f' text="{text}"'
            if rid:
                seg += f" id={rid.split('/')[-1]}"
            if desc:
                seg += f' desc="{desc}"'
            if flags:
                seg += f" [{flags}]"
            m = re.match(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]", bounds)
            if m:
                x1, y1, x2, y2 = map(int, m.groups())
                seg += f" {bounds} tap=({(x1 + x2) // 2},{(y1 + y2) // 2})"
            else:
                seg += f" {bounds}"
            lines.append(seg)
        for child in node:
            walk(child, depth + 1)

    walk(root, 0)
    return "\n".join(lines) or "no interesting nodes found; try full_xml=True"


@mcp.tool()
def input_tap(x: int, y: int, device_id: str = ""):
    """Tap at screen coordinates (use ui_dump to find tap= centers)."""
    return _shell_ok(f"input tap {int(x)} {int(y)}", device=device_id or None, timeout=30)


@mcp.tool()
def input_swipe(x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300,
                device_id: str = ""):
    """Swipe/drag between two points (duration in ms; same point + long duration = long-press)."""
    return _shell_ok(f"input swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {int(duration_ms)}",
                     device=device_id or None, timeout=60)


@mcp.tool()
def input_text(text: str, device_id: str = ""):
    """Type text into the focused input field (spaces/unicode handled via device-side base64)."""
    enc = base64.b64encode(text.encode("utf-8")).decode("ascii")
    cmd = f"input text \"$(echo {enc} | base64 -d | sed 's/ /%s/g')\""
    return _shell_ok(cmd, device=device_id or None, timeout=60)


_KEYCODES = {
    "home": "KEYCODE_HOME", "back": "KEYCODE_BACK", "enter": "KEYCODE_ENTER",
    "tab": "KEYCODE_TAB", "delete": "KEYCODE_DEL", "del": "KEYCODE_DEL",
    "menu": "KEYCODE_MENU", "power": "KEYCODE_POWER", "wakeup": "KEYCODE_WAKEUP",
    "sleep": "KEYCODE_SLEEP", "camera": "KEYCODE_CAMERA", "search": "KEYCODE_SEARCH",
    "escape": "KEYCODE_ESCAPE", "esc": "KEYCODE_ESCAPE", "space": "KEYCODE_SPACE",
    "recents": "KEYCODE_APP_SWITCH", "app_switch": "KEYCODE_APP_SWITCH",
    "volume_up": "KEYCODE_VOLUME_UP", "volume_down": "KEYCODE_VOLUME_DOWN",
    "volume_mute": "KEYCODE_VOLUME_MUTE", "mute": "KEYCODE_VOLUME_MUTE",
    "dpad_up": "KEYCODE_DPAD_UP", "dpad_down": "KEYCODE_DPAD_DOWN",
    "dpad_left": "KEYCODE_DPAD_LEFT", "dpad_right": "KEYCODE_DPAD_RIGHT",
    "dpad_center": "KEYCODE_DPAD_CENTER",
}


@mcp.tool()
def input_key(key: str, device_id: str = ""):
    """Press a key: a friendly name (home, back, enter, delete, recents, volume_up, wakeup, ...), a raw KEYCODE_*, or a numeric keycode."""
    k = _KEYCODES.get(key.strip().lower())
    if not k:
        raw = key.strip().upper()
        if raw.startswith("KEYCODE_") or raw.isdigit():
            k = raw
    if not k:
        return f"unknown key '{key}'. Known names: {sorted(_KEYCODES)} (or KEYCODE_*)"
    return _shell_ok(f"input keyevent {k}", device=device_id or None, timeout=30)


# ---------------------------------------------------------------- logging

@mcp.tool()
def logcat(lines: int = 200, package: str = "", level: str = "", tag: str = "",
           device_id: str = ""):
    """Recent logcat output (logcat -d, threadtime format). Filter by package (pid lookup), minimum level (V/D/I/W/E/F) or tag substring. clear_logcat first, then reproduce, then read."""
    dev = _resolve_device(device_id or None)
    args = ["logcat", "-d", "-t", str(int(lines)), "-v", "threadtime"]
    if level:
        args.append(f"*:{level.upper()[0]}")
    if package:
        pout, _, _ = _adb("shell", f"pidof {_shq(package)}", device=dev, timeout=30)
        pids = pout.strip().split()
        if not pids:
            return f"{package} is not running (no pid)"
        args += ["--pid", ",".join(pids)]
    out, err, _ = _adb(*args, device=dev, timeout=60)
    text = out
    if tag:
        text = "\n".join(l for l in out.splitlines() if tag.lower() in l.lower())
    if err.strip():
        text += ("\n" if text else "") + "[stderr] " + err.strip()
    return text.strip() or "(no matching log lines)"


@mcp.tool()
def clear_logcat(device_id: str = ""):
    """Clear the logcat buffer — call before reproducing a bug so logs are clean."""
    _shell("logcat -c", device=device_id or None, timeout=30)
    return "logcat cleared"


# ---------------------------------------------------------------- network / proxy

@mcp.tool()
def set_proxy(host: str, port: int, device_id: str = ""):
    """Set the global HTTP proxy for traffic interception (settings put global http_proxy). From the emulator, your host machine is 10.0.2.2 — e.g. Burp on 10.0.2.2:8080. Verify with get_proxy."""
    value = f"{host}:{int(port)}"
    out = _shell_ok(f"settings put global http_proxy {value}; settings get global http_proxy",
                    device=device_id or None, timeout=30)
    return f"http_proxy -> {value} (device reports: {out})"


@mcp.tool()
def clear_proxy(device_id: str = ""):
    """Clear the global HTTP proxy (settings put global http_proxy :0)."""
    _shell("settings put global http_proxy :0", device=device_id or None, timeout=30)
    out = _shell_ok("settings get global http_proxy", device=device_id or None, timeout=30)
    return f"http_proxy cleared (device reports: {out})"


# ---------------------------------------------------------------- files

@mcp.tool()
def pull_file(remote_path: str, local_path: str, device_id: str = ""):
    """adb pull a file from the device to the local machine."""
    dev = _resolve_device(device_id or None)
    out, err, _ = _adb("pull", remote_path, str(Path(local_path).expanduser()),
                       device=dev, timeout=300)
    return (out + err).strip()


@mcp.tool()
def push_file(local_path: str, remote_path: str, device_id: str = ""):
    """adb push a local file to the device (e.g. frida-server to /data/local/tmp)."""
    dev = _resolve_device(device_id or None)
    p = Path(local_path).expanduser()
    if not p.is_file():
        return f"local file not found: {p}"
    out, err, _ = _adb("push", str(p), remote_path, device=dev, timeout=300)
    return (out + err).strip()


@mcp.tool()
def list_app_files(package: str, subpath: str = "", device_id: str = ""):
    """List an app's private data dir as root (ls -la /data/data/<pkg>[/subpath]) — insecure-storage hunting: shared_prefs, databases, files, cache."""
    path = f"/data/data/{package}"
    if subpath:
        path += "/" + subpath.strip("/")
    return _shell_ok(f"ls -la {_shq(path)}", device=device_id or None, root=True, timeout=60)


if __name__ == "__main__":
    mcp.run()
