#!/usr/bin/env python3
"""Exercise the runtime detector against a model of its probe.

The detector (`skills/hanria/scripts/detect_runtime.py`) looks at four
locations in order: the path in HANRIA_SOCKET, `~/.hanria/run/hanria.sock`,
`/run/hanria/hanria.sock` and `/var/run/hanria/hanria.sock`. A location
that does not exist is skipped; one that exists and accepts a connection
is the runtime, reported present with exit 0 and the search stopped; one
that exists and refuses is unresponsive, and if no location accepted the
detector reports error with exit 2 and every unresponsive location in
order; otherwise it reports absent with exit 1 and every non-empty
location it searched.

This tool controls the first two locations: HOME is pointed at a
directory of its own, and HANRIA_SOCKET is left unset, set empty, or
pointed at a path of its own or at the HOME location. At each controlled
path it places nothing, a listening Unix socket, a stale socket file with
no listener, or a regular file, and runs the detector on every
combination. A model written from the description above predicts the
status, the exit code, the endpoint or the list reported, and the
searched list, and the tool compares the detector's JSON with the
prediction. The two system locations are outside its control; if either
exists on the host the tool stops, since the model could not then be
trusted.

The listening socket is not accepted from while the detector runs: its
connect succeeds on the listen backlog. Afterwards the tool drains the
backlog and requires one queued connection per round when that path was
the endpoint reported and none otherwise, each closed by the detector
with nothing sent.

Exit 0 when every combination agrees, 1 on a disagreement, 2 on a host
the tool cannot model.
"""
import argparse
import itertools
import json
import os
import socket
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTOR = os.path.join(ROOT, "skills", "hanria", "scripts", "detect_runtime.py")
SYSTEM_LOCATIONS = ["/run/hanria/hanria.sock", "/var/run/hanria/hanria.sock"]
KINDS = ["missing", "listening", "stale", "regular"]
ENV_KINDS = ["unset", "empty", "own-missing", "own-listening", "own-stale", "own-regular", "home"]


def place(path, kind, keep):
    """Put a thing of `kind` at `path`; listening sockets are kept open."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.lexists(path):
        os.remove(path)
    if kind == "missing":
        return
    if kind == "regular":
        with open(path, "w", encoding="ascii") as handle:
            handle.write("not a socket\n")
        return
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    if kind == "listening":
        server.listen(8)
        keep.append((path, server))
    else:
        server.close()  # the file stays; nothing listens


def model(env_setting, env_path, home_path, kinds):
    """The predicted report. `kinds` maps a path to what is at it."""
    candidates = [env_setting, home_path] + SYSTEM_LOCATIONS
    found, broken = None, []
    for candidate in candidates:
        if not candidate:
            continue
        kind = kinds.get(candidate, "missing")
        if kind == "missing":
            continue
        if kind == "listening":
            found = candidate
            break
        broken.append(candidate)
    if found:
        return {"status": "present", "exit": 0, "endpoint": found}
    if broken:
        return {"status": "error", "exit": 2, "endpoints_found_but_unresponsive": broken}
    return {"status": "absent", "exit": 1, "searched": [c for c in candidates if c]}


def run_detector(env_setting, home):
    env = {k: v for k, v in os.environ.items() if k not in ("HANRIA_SOCKET", "HOME")}
    env["HOME"] = home
    if env_setting is not None:
        env["HANRIA_SOCKET"] = env_setting
    proc = subprocess.run(
        [sys.executable, DETECTOR], env=env, capture_output=True, text=True, timeout=30, check=False
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {"unparseable": proc.stdout, "stderr": proc.stderr}
    return proc.returncode, report


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--output", required=True, help="a directory of the tool's own; socket paths must stay short")
    parser.add_argument("--rounds", type=int, default=2, help="how many times each combination runs (determinism)")
    args = parser.parse_args()

    for location in SYSTEM_LOCATIONS:
        if os.path.lexists(location):
            print(json.dumps({"status": "cannot-model", "why": "a system location exists on this host", "location": location}))
            return 2

    home = os.path.join(args.output, "h")
    home_path = os.path.join(home, ".hanria", "run", "hanria.sock")
    own_path = os.path.join(args.output, "o", "hanria.sock")
    if max(len(home_path), len(own_path)) > 100:
        print(json.dumps({"status": "cannot-model", "why": "socket paths would exceed the Unix socket path limit", "length": max(len(home_path), len(own_path))}))
        return 2

    combinations = list(itertools.product(ENV_KINDS, KINDS))
    disagreements = []
    counts = {"present": 0, "error": 0, "absent": 0}
    for env_kind, home_kind in combinations:
        keep = []
        kinds = {}
        place(home_path, home_kind, keep)
        kinds[home_path] = home_kind
        if env_kind == "unset":
            env_setting = None
        elif env_kind == "empty":
            env_setting = ""
        elif env_kind == "home":
            env_setting = home_path
        else:
            env_setting = own_path
            own_kind = env_kind.split("-", 1)[1]
            place(own_path, own_kind, keep)
            kinds[own_path] = own_kind
        if env_kind not in ("own-missing", "own-listening", "own-stale", "own-regular") and os.path.lexists(own_path):
            os.remove(own_path)
        expected = model(env_setting or "", own_path, home_path, kinds)
        reports = []
        for _ in range(args.rounds):
            reports.append(run_detector(env_setting, home))
        for path, listener in keep:
            # Every connection the detector made is still queued on the
            # listener: drain them all. Each must be closed by the detector
            # (end of file on read) with nothing sent, and there must be one
            # per round when the path was reached and none when it was not.
            listener.setblocking(False)
            queued = 0
            while True:
                try:
                    conn, _ = listener.accept()
                except BlockingIOError:
                    break
                queued += 1
                conn.setblocking(False)
                try:
                    data = conn.recv(1)
                except BlockingIOError:
                    data = None  # the peer is still open: the detector did not close
                conn.close()
                if data is None:
                    disagreements.append({"env": env_kind, "home": home_kind, "path": path, "why": "a connection was left open"})
                elif data:
                    disagreements.append({"env": env_kind, "home": home_kind, "path": path, "why": "the detector sent data", "data": data.hex()})
            listener.close()
            reached = expected["status"] == "present" and expected["endpoint"] == path
            expected_queued = args.rounds if reached else 0
            if queued != expected_queued:
                disagreements.append({"env": env_kind, "home": home_kind, "path": path, "why": "connections queued", "expected": expected_queued, "actual": queued})
        for path in (home_path, own_path):
            if os.path.lexists(path):
                os.remove(path)
        code, report = reports[0]
        actual = {"status": report.get("status"), "exit": code}
        for key in ("endpoint", "endpoints_found_but_unresponsive", "searched"):
            if key in report:
                actual[key] = report[key]
        if actual != expected:
            disagreements.append({"env": env_kind, "home": home_kind, "expected": expected, "actual": actual, "report": report})
            continue
        if any(other != reports[0] for other in reports[1:]):
            disagreements.append({"env": env_kind, "home": home_kind, "why": "not deterministic", "reports": reports})
            continue
        required = {
            "present": ["note"],
            "error": ["agent_instruction"],
            "absent": ["why", "agent_instruction", "what_installing_a_skill_does_not_do", "more"],
        }[expected["status"]]
        missing = [key for key in required if key not in report]
        if missing:
            disagreements.append({"env": env_kind, "home": home_kind, "why": "documented keys missing", "missing": missing})
            continue
        counts[expected["status"]] += 1

    summary = {
        "status": "disagreement" if disagreements else "agreement",
        "combinations": len(combinations),
        "rounds": args.rounds,
        "by_status": counts,
        "disagreement_count": len(disagreements),
        "disagreements": disagreements[:5],
    }
    print(json.dumps(summary, indent=2))
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
