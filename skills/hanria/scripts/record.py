#!/usr/bin/env python3
"""Append a decision to a local hash-chained log, and verify the chain.

Local, standard library only. No network calls.

    python3 record.py append --log LOG.jsonl --action ACTION.json --outcome OUTCOME.json
    python3 record.py verify --log LOG.jsonl

Exit codes:  0 ok   1 chain broken   3 error

WHAT THE CHAIN DOES. Each entry carries the digest of the entry before it, so
altering or removing any earlier entry changes every digest after it and
`verify` reports the first index that fails. That is tamper *detection* by
whoever holds the log.

WHAT IT DOES NOT DO. There is no signature, no published record format and no
independent verifier, so the chain proves nothing to a third party: anyone who
can write the file can rebuild it end to end and produce a log that verifies.
It is a local integrity check, not evidence. Do not describe an entry here as a
receipt, an attestation, or proof that an action was authorized.
"""
import argparse
import datetime as _dt
import hashlib
import json
import os
import sys

# Domain separation, so a digest computed here cannot be confused with one
# computed by any other component.
TAG = b"hanria-skill-log-v1"
GENESIS = "0" * 64


def digest(previous_hex, body_bytes):
    h = hashlib.sha256()
    h.update(TAG)
    h.update(bytes.fromhex(previous_hex))
    h.update(body_bytes)
    return h.hexdigest()


def canonical(entry):
    """Bytes that a digest commits to. Sorted keys and no insignificant space,
    so the same entry always hashes the same way."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_log(path):
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit("line %d of %s is not valid JSON: %s"
                                 % (i + 1, path, exc))
    return entries


def verify(path):
    entries = read_log(path)
    if not entries:
        print(json.dumps({"status": "empty", "entries": 0}, indent=2))
        return 0

    previous = GENESIS
    for i, entry in enumerate(entries):
        for field in ("index", "previous", "digest", "body"):
            if field not in entry:
                print(json.dumps({
                    "status": "broken", "at": i,
                    "reason": "entry is missing %r" % field}, indent=2))
                return 1
        if entry["index"] != i:
            print(json.dumps({
                "status": "broken", "at": i,
                "reason": "entry claims index %s but is at position %d"
                          % (entry["index"], i)}, indent=2))
            return 1
        if entry["previous"] != previous:
            print(json.dumps({
                "status": "broken", "at": i,
                "reason": "entry names predecessor %s; the previous entry "
                          "digests to %s" % (entry["previous"][:16], previous[:16])
                }, indent=2))
            return 1
        expected = digest(entry["previous"], canonical(entry["body"]))
        if entry["digest"] != expected:
            print(json.dumps({
                "status": "broken", "at": i,
                "reason": "entry body does not match its digest; the entry was "
                          "altered after it was written"}, indent=2))
            return 1
        previous = entry["digest"]

    print(json.dumps({"status": "intact", "entries": len(entries),
                      "head": previous}, indent=2))
    return 0


def append(path, action_path, outcome_path):
    for p, what in ((action_path, "action"), (outcome_path, "outcome")):
        if not os.path.exists(p):
            raise SystemExit("no %s file at %s" % (what, p))

    with open(action_path, encoding="utf-8") as fh:
        action = json.load(fh)
    with open(outcome_path, encoding="utf-8") as fh:
        outcome = json.load(fh)

    # Refuse to append to a log that is already broken, so a damaged chain is
    # not buried under later entries that verify against the damage.
    entries = read_log(path)
    if entries:
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            if verify(path) != 0:
                sys.stdout.write(buf.getvalue())
                raise SystemExit("refusing to append: the existing log does not verify")
        previous = entries[-1]["digest"]
        index = len(entries)
    else:
        previous, index = GENESIS, 0

    body = {
        "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "action": action,
        "outcome": outcome,
    }
    entry = {
        "index": index,
        "previous": previous,
        "digest": digest(previous, canonical(body)),
        "body": body,
    }

    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

    print(json.dumps({"status": "appended", "index": index,
                      "digest": entry["digest"]}, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Append decisions to a local hash-chained log and verify it. "
                    "Local integrity detection only; not evidence to a third party.")
    sub = ap.add_subparsers(dest="command", required=True)

    a = sub.add_parser("append", help="append one decision")
    a.add_argument("--log", required=True)
    a.add_argument("--action", required=True)
    a.add_argument("--outcome", required=True)

    v = sub.add_parser("verify", help="verify the whole chain")
    v.add_argument("--log", required=True)

    args = ap.parse_args()
    if args.command == "append":
        return append(args.log, args.action, args.outcome)
    return verify(args.log)


if __name__ == "__main__":
    sys.exit(main())
