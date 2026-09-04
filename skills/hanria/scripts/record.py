#!/usr/bin/env python3
"""Append a decision to a local hash-chained log, and verify the chain.

Local, standard library only. No network calls.

    python3 record.py append --log LOG.jsonl --action ACTION.json --outcome OUTCOME.json
    python3 record.py verify --log LOG.jsonl

Exit codes:  0 ok   1 chain broken   3 error

WHAT THE CHAIN DOES. Each entry carries the digest of the entry before it, so
altering or removing an entry that has anything after it changes every digest
that follows, and `verify` reports the first index that fails.

TRUNCATION IS THE EXCEPTION, and it is worth understanding before you rely on
this. Deleting entries from the *end* leaves a shorter chain that is internally
perfect, because nothing downstream remains to disagree with it. A chain alone
cannot detect its own truncation.

The head file closes that gap, but only as far as you protect it. `append`
maintains `<log>.head`, holding the current head digest and entry count, and
`verify` checks the log against it whenever it is present. Someone who can
rewrite both files can still produce a consistent pair -- so keep the head file
somewhere the log writer cannot reach, or record the head out of band, if
truncation is a threat you actually face. `--expect-head` lets you supply a head
you retained yourself.

WHAT IT DOES NOT DO. There is no signature, no published record format and no
independent verifier, so the chain proves nothing to a third party: anyone who
can write the file can rebuild it end to end and produce a log that verifies.
It is a local integrity check, not evidence. Do not describe an entry here as a
receipt, an attestation, or proof that an action was authorized.
"""
import argparse
import contextlib
import datetime as _dt
import fcntl
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _schema  # noqa: E402

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schema")
ENTRY_KEYS = {"index", "previous", "digest", "body"}

# Domain separation, so a digest computed here cannot be confused with one
# computed by any other component.
TAG = b"hanria-skill-log-v1"
GENESIS = "0" * 64

# Exit codes, documented in the manifest and the skill text.
OK, BROKEN, ERROR = 0, 1, 3


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


def _action_digest(action):
    """Must match check_action.action_digest byte for byte."""
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(b"hanria-action-v1" + canonical.encode("utf-8")).hexdigest()


def head_path(path):
    return path + ".head"


def write_head(path, head, count):
    with open(head_path(path), "w", encoding="utf-8") as fh:
        json.dump({"head": head, "count": count}, fh)
        fh.write("\n")


def read_head(path):
    p = head_path(path)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or "head" not in d or "count" not in d:
            return {"malformed": True}
        return d
    except (json.JSONDecodeError, OSError):
        return {"malformed": True}


def read_log(path):
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            # Strict, like every other document this skill reads. An entry
            # with a duplicate key is ambiguous: a reader sees the first value
            # and json keeps the last, so a forged body can sit above the one
            # the digest commits to and the chain still verifies as intact.
            # Refused rather than resolved -- main turns SchemaError into a
            # non-intact verdict, so append refuses the log as well.
            entries.append(_schema.loads(line, "line %d of %s" % (i + 1, path)))
    return entries


def verify(path, expect_head=None):
    entries = read_log(path)
    pinned = read_head(path)
    if pinned and pinned.get("malformed"):
        print(json.dumps({
            "status": "broken",
            "reason": "the head file %s exists but could not be read; refusing "
                      "to report a chain as intact against an unreadable pin"
                      % head_path(path)}, indent=2))
        return 1

    if not entries:
        if pinned and pinned.get("count", 0) > 0:
            print(json.dumps({
                "status": "broken", "at": 0,
                "reason": "the log is empty but the head file records %d "
                          "entries; the log was truncated"
                          % pinned["count"]}, indent=2))
            return 1
        print(json.dumps({"status": "empty", "entries": 0}, indent=2))
        return 0

    previous = GENESIS
    for i, entry in enumerate(entries):
        for field in ("index", "previous", "digest", "body"):
            if field not in entry:
                print(json.dumps({
                    "status": "broken", "at": i,
                    "reason": "entry is missing %r" % field}, indent=2))
                return BROKEN
        # Only `body` is committed to by the digest, so any other field an entry
        # carries would be shown to a reader while sitting outside the chain.
        # Refuse rather than let unverified data travel inside a verified entry.
        extra = set(entry) - ENTRY_KEYS
        if extra:
            print(json.dumps({
                "status": "broken", "at": i,
                "reason": "entry carries field(s) %s that the digest does not "
                          "cover; anything outside `body` is unverified"
                          % ", ".join(sorted(repr(e) for e in extra))}, indent=2))
            return BROKEN
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

    # A chain cannot detect its own truncation: dropping entries from the end
    # leaves a shorter chain that verifies perfectly. Only a head retained
    # outside the log can catch that.
    expected = expect_head or (pinned or {}).get("head")
    expected_count = None if expect_head else (pinned or {}).get("count")

    if expected and expected != previous:
        print(json.dumps({
            "status": "broken", "entries": len(entries), "head": previous,
            "reason": "the chain is internally consistent but its head is %s, "
                      "not the expected %s; entries were removed from the end "
                      "or the log was rebuilt"
                      % (previous[:16], expected[:16])}, indent=2))
        return 1
    if expected_count is not None and expected_count != len(entries):
        print(json.dumps({
            "status": "broken", "entries": len(entries),
            "reason": "the log holds %d entries but %d were recorded; the log "
                      "was truncated" % (len(entries), expected_count)}, indent=2))
        return 1

    print(json.dumps({
        "status": "intact", "entries": len(entries), "head": previous,
        "truncationChecked": bool(expected),
        "note": None if expected else
                "No retained head was available, so terminal truncation could "
                "not be ruled out. Keep %s, or pass --expect-head."
                % head_path(path)}, indent=2))
    return 0


@contextlib.contextmanager
def _exclusive(path):
    """Serialize appends.

    Read-modify-write on the chain is not atomic: concurrent appends read the
    same head, and the losers are lost or interleaved, leaving a log that no
    longer verifies. An advisory lock on a sidecar file is enough here, and
    costs nothing when there is no contention.
    """
    lock = open(path + ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def append(path, action_path, outcome_path):
    with _exclusive(path):
        return _append(path, action_path, outcome_path)


def _append(path, action_path, outcome_path):
    for p, what in ((action_path, "action"), (outcome_path, "outcome")):
        if not os.path.exists(p):
            raise SystemExit("no %s file at %s" % (what, p))


    def _read(path, schema_name, what):
        with open(path, encoding="utf-8") as fh:
            doc = _schema.loads(fh.read(), "%s at %s" % (what, path))
        _schema.validate(doc, _schema.load(os.path.join(SCHEMA_DIR, schema_name)), what)
        return doc

    # What is recorded is validated before it is committed to. Otherwise a
    # fabricated permit, or a malformed outcome, would be hashed into the chain
    # and thereby made to look checked.
    action = _read(action_path, "action-request.schema.json", "action")
    outcome = _read(outcome_path, "action-outcome.schema.json", "outcome")

    # The outcome carries the digest of the request it was produced for.
    # Without this check a `permit` could be filed beside an action that was
    # denied, and the entry would look checked without being checked.
    # An outcome with no digest was produced before any request was evaluated
    # -- an error about the mandate itself. There is no decision about this
    # action in it, so there is nothing to record.
    if "action_digest" not in outcome:
        raise SystemExit(
            "the outcome carries no action_digest, so it was not produced for "
            "any particular request; refusing to record it as a decision about "
            "this one")

    expected = _action_digest(action)
    if outcome.get("action_digest") != expected:
        raise SystemExit(
            "the outcome was produced for a different action (it names %s, this "
            "action digests to %s); refusing to record a decision beside a "
            "request it was not made about"
            % (str(outcome.get("action_digest"))[:16], expected[:16]))

    # Refuse to append to a log that is already broken, so a damaged chain is
    # not buried under later entries that verify against the damage.
    entries = read_log(path)
    pinned = read_head(path)

    # Verify whenever there is anything to verify against -- entries, or a
    # retained head. An empty log with a head recording entries is a truncated
    # log, and starting a fresh chain over it would erase the evidence of that.
    if entries or (pinned and (pinned.get("malformed") or pinned.get("count", 0) > 0)):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = verify(path)
        if rc != 0:
            sys.stdout.write(buf.getvalue())
            return BROKEN

    if entries:
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

    write_head(path, entry["digest"], index + 1)

    print(json.dumps({"status": "appended", "index": index,
                      "digest": entry["digest"],
                      "head": head_path(path)}, indent=2))
    return 0


def _die(reason):
    print(json.dumps({"status": "error", "reason": reason}, indent=2))
    raise SystemExit(ERROR)


def main():
    ap = argparse.ArgumentParser(
        description="Append decisions to a local hash-chained log and verify it. "
                    "Local integrity detection only; not evidence to a third party.")
    ap.error = lambda m: (_die("usage: %s" % m))
    sub = ap.add_subparsers(dest="command", required=True)

    a = sub.add_parser("append", help="append one decision")
    a.add_argument("--log", required=True)
    a.add_argument("--action", required=True)
    a.add_argument("--outcome", required=True)

    v = sub.add_parser("verify", help="verify the whole chain")
    v.add_argument("--log", required=True)
    v.add_argument("--expect-head", default=None,
                   help="a head digest you retained yourself; overrides the "
                        "head file and detects truncation")

    args = ap.parse_args()
    try:
        if args.command == "append":
            return append(args.log, args.action, args.outcome)
        return verify(args.log, args.expect_head)
    except _schema.SchemaError as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        return ERROR
    except SystemExit as exc:
        if exc.code == ERROR:
            raise
        # Documented contract: 3 means error. A bare SystemExit carrying a
        # message would otherwise exit 1 and be read as "chain broken".
        print(json.dumps({"status": "error", "reason": str(exc.code)}, indent=2))
        return ERROR
    except Exception as exc:  # noqa: BLE001 - deliberate
        print(json.dumps({"status": "error",
                          "reason": "%s: %s" % (type(exc).__name__, exc)}, indent=2))
        return 3


if __name__ == "__main__":
    sys.exit(main())
