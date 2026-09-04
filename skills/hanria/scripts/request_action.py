#!/usr/bin/env python3
"""Submit a HANRIA action request to a local runtime and print the outcome.

Makes no network calls. Talks only to a local Unix domain socket.
Never reads, holds, or transmits a credential: a request containing one is
refused here, before it reaches any socket.

Exit codes: 0 permit   1 deny   2 escalate   3 error/absent
"""
import argparse, json, os, socket, sys

FORBIDDEN = ("credential", "secret", "private_key", "privatekey", "token",
             "password", "passwd", "api_key", "apikey", "bearer")

def find_socket():
    for p in (os.environ.get("HANRIA_SOCKET", ""),
              os.path.expanduser("~/.hanria/run/hanria.sock"),
              "/run/hanria/hanria.sock", "/var/run/hanria/hanria.sock"):
        if p and os.path.exists(p):
            return p
    return None

def scan_for_secrets(node, path="$"):
    """Refuse locally rather than trusting the runtime to strip secrets."""
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if any(f in str(k).lower() for f in FORBIDDEN):
                hits.append(f"{path}.{k}")
            hits += scan_for_secrets(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += scan_for_secrets(v, f"{path}[{i}]")
    return hits

def fail(reason, extra=None):
    out = {"schema_version": "0.1-draft", "outcome": "error", "reason": reason}
    if extra:
        out.update(extra)
    print(json.dumps(out, indent=2))
    return 3

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="JSON request matching schema/action-request.schema.json")
    a = ap.parse_args()

    try:
        req = json.loads(open(a.file, encoding="utf-8").read())
    except Exception as e:
        return fail(f"request file is not readable JSON: {e}")

    leaks = scan_for_secrets(req)
    if leaks:
        return fail(
            "request appears to contain credential material and was NOT sent",
            {"offending_paths": leaks,
             "agent_instruction": "Remove the credential. HANRIA mediates an operation so the agent never needs the credential; a request carrying one defeats the design."})

    sock = find_socket()
    if not sock:
        return fail(
            "no HANRIA runtime is installed or listening",
            {"agent_instruction": "Report to your operator that HANRIA is not available and STOP. Do not perform the operation as though it were governed. Do not simulate a permit, deny, escalate, or receipt.",
             "why": "No HANRIA runtime exists as of 2026-09-04. HANRIA is an in-development concept.",
             "more": "https://hanria.ai/llms.txt"})

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect(sock)
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < 1 << 20:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        resp = json.loads(buf.decode("utf-8").strip())
    except Exception as e:
        return fail(f"runtime did not answer correctly: {e}",
                    {"agent_instruction": "Treat as absent. Report the error and STOP."})

    print(json.dumps(resp, indent=2))
    o = resp.get("outcome")
    if o == "permit":
        return 0
    if o == "deny":
        sys.stderr.write("DENIED. Do not route around this. Report the denial to your operator.\n")
        return 1
    if o == "escalate":
        sys.stderr.write("ESCALATED. Approval pending. Do not proceed and do not retry in a loop.\n")
        return 2
    return 3

if __name__ == "__main__":
    sys.exit(main())
