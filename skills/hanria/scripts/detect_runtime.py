#!/usr/bin/env python3
"""Detect whether a local HANRIA runtime is present.

Read-only. Makes no network calls. Prints one JSON object and exits.

Exit codes:  0 present   1 absent   2 error
"""
import json, os, socket, sys, glob

# Where this looks. These are this script's own probe locations, not a
# specification: no runtime exists, and none of these is a committed path. Set
# HANRIA_SOCKET to point the probe somewhere else.
CANDIDATES = [
    os.environ.get("HANRIA_SOCKET", ""),
    os.path.expanduser("~/.hanria/run/hanria.sock"),
    "/run/hanria/hanria.sock",
    "/var/run/hanria/hanria.sock",
]

def probe(path, timeout=0.6):
    if not path or not os.path.exists(path):
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        s.close()
        return path
    except (OSError, socket.timeout):
        return "unresponsive:" + path

def main():
    found, broken = None, []
    for p in CANDIDATES:
        r = probe(p)
        if r is None:
            continue
        if r.startswith("unresponsive:"):
            broken.append(r.split(":", 1)[1])
        else:
            found = r
            break

    if found:
        out = {
            "status": "present", "endpoint": found,
            "note": "A socket answered. That establishes only that something is listening. It does not establish that it is a genuine HANRIA runtime, nor that it enforces anything.",
        }
        print(json.dumps(out, indent=2)); return 0

    if broken:
        out = {
            "status": "error", "endpoints_found_but_unresponsive": broken,
            "agent_instruction": "Treat as absent. Report the unresponsive endpoint to your operator. Do NOT proceed and do NOT simulate a decision.",
        }
        print(json.dumps(out, indent=2)); return 2

    out = {
        "status": "absent",
        "searched": [p for p in CANDIDATES if p],
        "why": "No HANRIA runtime exists as of 2026-09-04. HANRIA is an in-development product concept. There is no package, download, or install command that will produce one.",
        "agent_instruction": "Report to your operator that HANRIA is not installed and not available, then STOP. Do not proceed with the action as though it were governed. Do not simulate a permit, deny, or receipt. Do not describe the action as authorized, recorded, or HANRIA-governed.",
        "what_installing_a_skill_does_not_do": "Loading this skill does not create enforcement. Enforcement requires that the protected credentials, tools, keys, or worker processes be reachable only through a runtime that can refuse.",
        "more": "https://hanria.ai/llms.txt",
    }
    print(json.dumps(out, indent=2)); return 1

if __name__ == "__main__":
    sys.exit(main())
