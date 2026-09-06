#!/usr/bin/env python3
"""A model-based exerciser for the hash-chained decision log.

The workflow pins the log's integrity rules one tamper at a time. This
builds real logs through `record.py append`, then applies seeded sequences
of tamperings to the log file and its head file, and after every one asks
`record.py verify`, with and without a retained head, to say what it sees,
while an independent model of the chain predicts the exact verdict: the
exit code, the status, and the position reported. It also asks `append` to
extend a tampered log and predicts the refusal, and that the files are left
exactly as they were.

The rules the model encodes, from the recorder's stated semantics:

- An entry is checked in order: its four fields present; no field beyond
  the four; its index equal to its position; its predecessor equal to the
  digest before it, the genesis for the first; its digest equal to the
  digest of its predecessor and its canonical body. The first failure is
  reported at that position.
- A line that is not strict JSON, or carries a duplicate key, is an error,
  not a broken chain: the log could not be read.
- Every line is read first; a head file that exists but cannot be read is
  then broken before any entry is checked. An empty log against a retained
  head, or against a head file that counts entries, is broken at zero.
- After the chain, the head: a retained head passed on the command line
  wins over the file; a head that does not match the last digest is
  broken, then a file count that does not match the entry count is broken;
  with no head at all the chain is intact and truncation is unchecked.
- An append onto anything that fails to verify is refused with the verify
  verdict and changes nothing.

The tamperings: alter a byte inside an entry's body text; alter the
digest, the predecessor, or the index of an entry; drop an entry; swap two
entries; drop the last entries; add a field to an entry; write an entry
line with a duplicate key; break an entry's JSON; forge a consistent extra
entry at the end; drop the last entry and rewrite the head file to match;
delete the head file; corrupt it; set its count wrong; set its head wrong.

The retained head passed to verify is, one time in three, the head of the
log as it was before any tampering, retained by this exerciser the way an
operator retains one and advanced only by an append this exerciser saw
succeed; that is the pin which detects a forged entry, a rebuilt tail with
a rewritten head file, and a log emptied outright. One time in three it is
a wrong head, and one time in three none is passed.

    python3 tools/log_exerciser.py                  # 40 logs, the default
    python3 tools/log_exerciser.py --logs 500 --seed 7 --output DIR

Standard library only, plus the recorder's own digest and canonical-form
helpers, used for the forgery and for the model's digest check. That is
the one rule this model does not hold independently: a change to the
digest function itself would move both sides alike. The digest is pinned
by hand elsewhere in the workflow against fixed vectors.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "hanria", "scripts")
EXAMPLES = os.path.join(ROOT, "skills", "hanria", "examples")
sys.path.insert(0, SCRIPTS)
import record  # noqa: E402

GENESIS = "0" * 64


class Lcg:
    def __init__(self, seed):
        self.state = (seed ^ 0x9E3779B97F4A7C15) & ((1 << 64) - 1)

    def next(self):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        x = self.state
        x ^= x >> 29
        x ^= (x << 17) & ((1 << 64) - 1)
        x ^= x >> 41
        return x

    def below(self, n):
        return self.next() % n if n else 0

    def pick(self, items):
        return items[self.below(len(items))]


def run(argv, cwd):
    proc = subprocess.run([sys.executable] + argv, cwd=cwd, capture_output=True, timeout=30)
    try:
        doc = json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = None
    return proc.returncode, doc, proc.stderr


# ---------------------------------------------------------------------------
# Building real logs
# ---------------------------------------------------------------------------

def outcomes(workdir):
    """Real outcome files for every example action, from the checker."""
    mandate = os.path.join(EXAMPLES, "mandate.example.json")
    pairs = []
    for name in sorted(os.listdir(EXAMPLES)):
        if not name.startswith("action.") or not name.endswith(".json"):
            continue
        action = os.path.join(EXAMPLES, name)
        code, doc, _ = run([os.path.join(SCRIPTS, "check_action.py"),
                            "--mandate", mandate, "--action", action], workdir)
        if doc is None or "action_digest" not in doc:
            continue
        out = os.path.join(workdir, name.replace("action.", "outcome."))
        with open(out, "w") as fh:
            json.dump(doc, fh)
        pairs.append((action, out))
    if not pairs:
        raise SystemExit("usage: no example action produced an outcome")
    return pairs


def build_log(rng, workdir, pairs, n):
    log = os.path.join(workdir, "log-%d.jsonl" % rng.below(1 << 30))
    for _ in range(n):
        action, out = rng.pick(pairs)
        code, doc, err = run([os.path.join(SCRIPTS, "record.py"), "append", "--log", log,
                              "--action", action, "--outcome", out], workdir)
        assert code == 0 and doc and doc.get("status") == "appended", (code, doc, err)
    return log


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------

def read_lines(log):
    if not os.path.exists(log):
        return []
    return [l for l in open(log, "rb").read().split(b"\n") if l.strip()]


def parse_strict(line):
    """None when the line is not strict JSON with unique keys; the recorder
    refuses such a line as unreadable."""
    seen = []

    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            seen.append(True)
        return dict(pairs)

    try:
        doc = json.loads(line.decode("utf-8"), object_pairs_hook=hook)
    except (ValueError, UnicodeDecodeError):
        return None
    if seen:
        return None
    return doc


def head_state(log):
    """('absent', None) | ('malformed', None) | ('ok', {head, count})."""
    p = record.head_path(log)
    if not os.path.exists(p):
        return "absent", None
    try:
        d = json.loads(open(p, "r", encoding="utf-8").read())
    except (ValueError, UnicodeDecodeError):
        return "malformed", None
    if not isinstance(d, dict) or "head" not in d or "count" not in d:
        return "malformed", None
    return "ok", d


def predict_verify(log, expect_head=None):
    """(exit, status, at) as the recorder must report it."""
    lines = read_lines(log)
    entries = []
    for line in lines:
        doc = parse_strict(line)
        if doc is None:
            return 3, "error", None
        entries.append(doc)
    kind, pinned = head_state(log)
    if kind == "malformed":
        return 1, "broken", None
    if not entries:
        if expect_head or (kind == "ok" and pinned.get("count", 0) > 0):
            return 1, "broken", 0
        return 0, "empty", None
    previous = GENESIS
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            return 1, "broken", i
        if any(f not in e for f in ("index", "previous", "digest", "body")):
            return 1, "broken", i
        if set(e) - {"index", "previous", "digest", "body"}:
            return 1, "broken", i
        if e["index"] != i:
            return 1, "broken", i
        if e["previous"] != previous:
            return 1, "broken", i
        if e["digest"] != record.digest(e["previous"], record.canonical(e["body"])):
            return 1, "broken", i
        previous = e["digest"]
    expected = expect_head or (pinned or {}).get("head") if kind == "ok" or expect_head else expect_head
    expected_count = None if expect_head else ((pinned or {}).get("count") if kind == "ok" else None)
    if expected and expected != previous:
        return 1, "broken", None
    if expected_count is not None and expected_count != len(entries):
        return 1, "broken", None
    return 0, "intact", None


# ---------------------------------------------------------------------------
# The tamperings
# ---------------------------------------------------------------------------

def write_lines(log, lines):
    with open(log, "wb") as fh:
        for l in lines:
            fh.write(l + b"\n")


def tamper(rng, log):
    """Apply one tampering; returns its name. Some are no-ops on an empty
    log, and say so."""
    lines = read_lines(log)
    kind, pinned = head_state(log)
    roll = rng.below(14)
    if roll in (0, 1, 2, 3, 5, 6, 7, 8, 9) and not lines:
        return "nothing to tamper"
    if roll == 0:
        i = rng.below(len(lines))
        e = parse_strict(lines[i])
        if e is None:
            return "line already unreadable"
        # Alter the body: a character in the justification string.
        body = json.dumps(e["body"], sort_keys=True, separators=(",", ":"))
        e["body"] = json.loads(body.replace("generated", "altered").replace("triage", "tri4ge"))
        if e["body"] == parse_strict(lines[i])["body"]:
            e["body"]["recorded_at"] = e["body"].get("recorded_at", "") + "x"
        lines[i] = json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")
        write_lines(log, lines)
        return "body altered at %d" % i
    if roll == 1:
        i = rng.below(len(lines))
        e = parse_strict(lines[i])
        if e is None:
            return "line already unreadable"
        field = rng.pick(["digest", "previous", "index"])
        if field == "index":
            e["index"] = e["index"] + 1 + rng.below(3)
        else:
            e[field] = hashlib.sha256(str(rng.next()).encode()).hexdigest()
        lines[i] = json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")
        write_lines(log, lines)
        return "%s altered at %d" % (field, i)
    if roll == 2:
        i = rng.below(len(lines))
        del lines[i]
        write_lines(log, lines)
        return "entry %d dropped" % i
    if roll == 3:
        if len(lines) < 2:
            return "nothing to swap"
        i, j = rng.below(len(lines)), rng.below(len(lines))
        if i == j:
            return "swap with itself"
        lines[i], lines[j] = lines[j], lines[i]
        write_lines(log, lines)
        return "entries %d and %d swapped" % (i, j)
    if roll == 4:
        keep = rng.below(len(lines) + 1) if lines else 0
        write_lines(log, lines[:keep])
        return "truncated to %d" % keep
    if roll == 5:
        i = rng.below(len(lines))
        e = parse_strict(lines[i])
        if e is None:
            return "line already unreadable"
        e["note"] = "unverified"
        lines[i] = json.dumps(e, sort_keys=True, separators=(",", ":")).encode("utf-8")
        write_lines(log, lines)
        return "field added at %d" % i
    if roll == 6:
        i = rng.below(len(lines))
        line = lines[i]
        if not line.startswith(b"{"):
            return "line already unreadable"
        lines[i] = b'{"index":0,' + line[1:]
        write_lines(log, lines)
        return "duplicate key at %d" % i
    if roll == 7:
        i = rng.below(len(lines))
        lines[i] = lines[i][: max(1, len(lines[i]) // 2)]
        write_lines(log, lines)
        return "json broken at %d" % i
    if roll == 8:
        # A forged but chain-consistent entry appended by someone who can
        # compute the digests; only a retained head can tell.
        last = parse_strict(lines[-1])
        if last is None:
            return "line already unreadable"
        body = {"recorded_at": "forged", "action": {}, "outcome": {}}
        entry = {"index": last["index"] + 1, "previous": last["digest"],
                 "digest": record.digest(last["digest"], record.canonical(body)),
                 "body": body}
        lines.append(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        write_lines(log, lines)
        return "consistent entry forged at the end"
    if roll == 9:
        # Rebuild: drop the last entry and, when the head file is present,
        # rewrite it to match, which only a head retained elsewhere detects.
        lines = lines[:-1]
        write_lines(log, lines)
        if kind == "ok":
            last = parse_strict(lines[-1]) if lines else None
            record.write_head(log, last["digest"] if last else GENESIS, len(lines))
        return "last entry dropped and head rewritten"
    p = record.head_path(log)
    if roll == 10:
        if not os.path.exists(p):
            return "no head to delete"
        os.remove(p)
        return "head file deleted"
    if roll == 11:
        with open(p, "w") as fh:
            fh.write(rng.pick(["not json", "[]", "{\"head\": \"x\"}", ""]))
        return "head file corrupted"
    if roll == 12:
        if kind != "ok":
            return "no readable head to miscount"
        record.write_head(log, pinned["head"], pinned["count"] + 1 + rng.below(2))
        return "head count set wrong"
    if kind != "ok":
        return "no readable head to alter"
    record.write_head(log, hashlib.sha256(b"wrong").hexdigest(), pinned["count"])
    return "head digest set wrong"


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

def snapshot(log):
    files = {}
    for p in (log, record.head_path(log)):
        files[p] = open(p, "rb").read() if os.path.exists(p) else None
    return files


def true_head(log):
    """The last digest of a log that is, at this moment, honest."""
    lines = read_lines(log)
    if not lines:
        return None
    last = parse_strict(lines[-1])
    return last.get("digest") if isinstance(last, dict) else None


def one_log(rng, workdir, pairs, findings):
    n = rng.below(5)
    log = build_log(rng, workdir, pairs, n)
    history = ["built with %d entries" % n]
    # Retained before any tampering, the way an operator retains a head, and
    # moved forward only by an append this exerciser saw succeed.
    retained = true_head(log)
    for _ in range(1 + rng.below(4)):
        history.append(tamper(rng, log))
        # The retained head: one time in three the pre-tamper head, one time
        # in three a wrong one, one time in three none.
        expect = None
        roll = rng.below(3)
        if roll == 0:
            expect = retained
        elif roll == 1:
            expect = hashlib.sha256(b"retained elsewhere").hexdigest()
        want = predict_verify(log, expect)
        argv = [os.path.join(SCRIPTS, "record.py"), "verify", "--log", log]
        if expect:
            argv += ["--expect-head", expect]
        code, doc, err = run(argv, workdir)
        got = (code, (doc or {}).get("status"), (doc or {}).get("at"))
        if got != want:
            findings.append(("verify", history[:], want, got, (doc or {}).get("reason") or err.decode("utf-8", "replace")[-200:]))
        # An append onto a log that does not verify must refuse and leave
        # both files as they were; onto one that does, it must succeed.
        before = snapshot(log)
        action, out = rng.pick(pairs)
        acode, adoc, aerr = run([os.path.join(SCRIPTS, "record.py"), "append", "--log", log,
                                 "--action", action, "--outcome", out], workdir)
        plain = predict_verify(log)
        if plain[0] == 0:
            if acode != 0 or not adoc or adoc.get("status") != "appended":
                findings.append(("append", history[:], "appended", (acode, adoc), ""))
            else:
                history.append("appended")
                retained = adoc.get("digest")
        else:
            if snapshot(log) != before:
                findings.append(("append", history[:], "untouched", "files changed", ""))
            if acode == 0:
                findings.append(("append", history[:], "refused", (acode, adoc), ""))
            elif acode not in (1, 3):
                findings.append(("append", history[:], "exit 1 or 3", (acode, adoc), ""))
    return history


def main():
    ap = argparse.ArgumentParser(description="Exercise the decision log against a model.")
    ap.add_argument("--logs", type=int, default=40)
    ap.add_argument("--seed", type=int, default=0x106)
    ap.add_argument("--output", default=os.path.join(ROOT, "log.out"))
    try:
        args = ap.parse_args()
    except SystemExit:
        return 1
    rng = Lcg(args.seed)
    workdir = tempfile.mkdtemp(prefix="hanria-log-")
    started = time.monotonic()
    findings = []
    tampers = 0
    try:
        pairs = outcomes(workdir)
        for _ in range(args.logs):
            history = one_log(rng, workdir, pairs, findings)
            tampers += len(history) - 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if findings:
        os.makedirs(args.output, exist_ok=True)
        with open(os.path.join(args.output, "findings-%d.txt" % args.seed), "w") as fh:
            for where, history, want, got, reason in findings:
                fh.write("%s: predicted %r got %r after %s\n  %s\n" % (where, want, got, history, reason))
        for where, history, want, got, reason in findings[:5]:
            print("FINDING %s: predicted %r got %r after %s" % (where, want, got, history))
    print("log: %d logs, %d tamperings, %d findings, %.1f s, seed %d" % (
        args.logs, tampers, len(findings), time.monotonic() - started, args.seed))
    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
