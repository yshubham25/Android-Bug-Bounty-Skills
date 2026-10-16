#!/usr/bin/env python3
"""Smoke test: spawns server.py over stdio and exercises key tools.

Usage: python test_client.py [path/to/app.apk [package.name]]
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = str(Path(__file__).resolve().parent / "server.py")
APK = sys.argv[1] if len(sys.argv) > 1 else None
PKG = sys.argv[2] if len(sys.argv) > 2 else None


async def main():
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(name, args=None, limit=900):
                r = await session.call_tool(name, args or {})
                chunks = []
                for c in r.content:
                    t = getattr(c, "text", None)
                    if t is not None:
                        chunks.append(t)
                    else:
                        mime = getattr(c, "mime_type", "") or getattr(c, "mimeType", "")
                        chunks.append(f"<{getattr(c, 'type', '?')} {mime}>")
                body = "\n".join(chunks)
                tag = "ERROR" if r.is_error else "ok"
                print(f"\n=== {name} [{tag}] ===\n{body[:limit]}")
                return r

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"tools ({len(names)}): {', '.join(names)}")

            await call("device_info")
            await call("list_devices")
            await call("root_shell", {"command": "id; getprop ro.boot.qemu.avd_name"})
            await call("current_activity")
            await call("ui_dump", limit=1200)
            await call("screenshot")

            if APK:
                await call("install_apk", {"apk_path": APK})
                if PKG:
                    await call("launch_app", {"package": PKG})
                    await asyncio.sleep(4)
                    await call("current_activity")
                    await call("logcat", {"package": PKG, "lines": 40})
                    await call("ui_dump", limit=1500)
                    await call("screenshot")
                    await call("list_app_files", {"package": PKG})


asyncio.run(main())
