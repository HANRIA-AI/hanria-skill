#!/usr/bin/env python3
"""A mutational fuzzer for the scripts' inputs.

The mutation harness (`tools/mutants.py`) asks whether the workflow notices
a change to the scripts. This asks the other question: whether the scripts,
as they are, hold on inputs nobody wrote down. It takes the example
documents as seeds, mutates them at the byte level (bit flips, inserted and
deleted bytes, truncation, splices of two seeds, a byte-order mark, a NUL,
invalid UTF-8) and at the structural level (a key dropped, a key duplicated
in the text, a value's type changed, a string emptied or blanked or filled
with control characters, a number made huge or negative or fractional, a
level of nesting added, an unknown key added, a target respelled with
percent escapes or a decomposed accent), and runs every mutated pair through
`check_action.py`, then feeds whatever that produced to `record.py append`
on a fresh log and `record.py verify` on the result.

What counts as a finding, for any invocation:

1. A traceback on standard error, or an exit code outside 0 to 3.
2. Standard output that is not exactly one JSON object.
3. From the checker, an outcome object that does not conform to the
   published outcome schema, or whose `outcome` does not agree with the
   exit code (0 permit, 1 deny, 2 escalate, 3 error); from the recorder, a
   status that does not agree with the exit code (0 appended, intact or
   empty; 1 broken; 3 error), or an error without a reason.
4. A run that is not deterministic: the same inputs twice give different
   output or exit code.
5. An invocation slower than a budget of five seconds.
6. For the recorder: an append that exits 0 must leave a log that verifies,
   and an append that refuses must leave the log as it found it.

Findings are written under the output directory as the inputs and a text
naming the invocation and the finding, and the run then exits 2. Exit 0 is
a clean run; exit 1 is a usage or setup error.

    python3 tools/fuzz_inputs.py                     # 60 cases, the default
    python3 tools/fuzz_inputs.py --cases 5000 --jobs 8 --seed 7 --output DIR

No dependency beyond the standard library and the scripts' own `_schema`.
"""
import argparse
import concurrent.futures
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
SCHEMAS = os.path.join(ROOT, "skills", "hanria", "schema")
sys.path.insert(0, SCRIPTS)
import _schema  # noqa: E402

BUDGET_SECONDS = 5.0
OUTCOME_BY_EXIT = {0: "permit", 1: "deny", 2: "escalate", 3: "error"}


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

    def chance(self, one_in):
        return self.below(one_in) == 0

    def pick(self, items):
        return items[self.below(len(items))]


def seeds():
    mandates, actions = [], []
    for name in sorted(os.listdir(EXAMPLES)):
        if not name.endswith(".json"):
            continue
        text = open(os.path.join(EXAMPLES, name), "rb").read()
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        if "clauses" in doc:
            mandates.append(text)
        elif "operation" in doc:
            actions.append(text)
    if not mandates or not actions:
        raise SystemExit("usage: no mandate or action examples found under %s" % EXAMPLES)
    return mandates, actions


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

BYTES_TO_INSERT = [b"\xef\xbb\xbf", b"\x00", b"\xff", b"\xc3", b"\xe2\x80\xa8", b"\r", b"\n", b"\t",
                   b"\\u0000", b"\\ud800", b"{", b"}", b"[", b"]", b'"', b",", b":", b" "]

STRINGS = ["", " ", "   ", "\u00a0", "a b", "\ufeffx", "\u00e9", "e\u0301", "/", "//", "..",
           "/data/../etc", "%2e%2e", "%2F", "\x00", "x" * 300, "x" * 5000, "\U0001f600",
           "0.1-draft", "0.2-draft", "permit", "deny", "escalate", "error", "file", "read",
           "2027-01-01T00:00:00Z", "2027-01-01", "2020-01-01T00:00:00Z", "2027-13-01T00:00:00Z",
           "9999-12-31T23:59:60Z", "true", "null", "-1", "1e309"]

NUMBERS = [0, 1, -1, 2 ** 31, 2 ** 63, -(2 ** 63), 2 ** 64, 10 ** 400, 0.5, -0.0, 1e308, 1e-308]


def mutate_bytes(rng, text, other):
    b = bytearray(text)
    for _ in range(1 + rng.below(4)):
        kind = rng.below(8)
        if kind == 0 and b:
            i = rng.below(len(b))
            b[i] ^= 1 << rng.below(8)
        elif kind == 1 and b:
            i = rng.below(len(b))
            b[i] = rng.below(256)
        elif kind == 2:
            i = rng.below(len(b) + 1)
            b[i:i] = rng.pick(BYTES_TO_INSERT)
        elif kind == 3 and b:
            i = rng.below(len(b))
            n = min(1 + rng.below(8), len(b) - i)
            del b[i:i + n]
        elif kind == 4:
            b = b[:rng.below(len(b) + 1)]
        elif kind == 5 and other:
            i = rng.below(len(b) + 1)
            j = rng.below(len(other))
            n = 1 + rng.below(len(other) - j)
            b[i:i] = other[j:j + n]
        elif kind == 6 and b:
            i = rng.below(len(b))
            n = min(1 + rng.below(16), len(b) - i)
            chunk = bytes(b[i:i + n])
            at = rng.below(len(b) + 1)
            b[at:at] = chunk
        else:
            b += rng.pick(BYTES_TO_INSERT) * (1 + rng.below(3))
    return bytes(b)


def mutate_value(rng, value, depth=0):
    """One structural change somewhere in a parsed document."""
    roll = rng.below(12)
    if isinstance(value, dict) and value:
        keys = list(value)
        key = rng.pick(keys)
        if roll == 0:
            del value[key]
        elif roll == 1:
            value["unknown_" + key] = value[key]
        elif roll == 2:
            value[key] = rng.pick([None, True, 0, [], {}, "x", 1.5])
        elif roll == 3:
            value[key] = [value[key]]
        elif roll == 4:
            value[key] = {"nested": value[key]}
        elif roll == 5 and depth < 80:
            v = value[key]
            for _ in range(1 + rng.below(70)):
                v = [v]
            value[key] = v
        else:
            value[key] = mutate_value(rng, value[key], depth + 1)
        return value
    if isinstance(value, list):
        if roll == 0:
            return []
        if roll == 1 or not value:
            value.append(rng.pick(STRINGS))
            return value
        if roll == 2:
            value.append(value[0])
            return value
        i = rng.below(len(value))
        value[i] = mutate_value(rng, value[i], depth + 1)
        return value
    if isinstance(value, str):
        if roll < 6:
            return rng.pick(STRINGS)
        if roll == 6:
            return value + rng.pick(STRINGS)
        if roll == 7:
            return value.replace("/", "%2F") if "/" in value else value.upper()
        if roll == 8:
            return value.replace("e", "é")
        return rng.pick([None, 0, True, [value], {"k": value}])
    if isinstance(value, bool) or value is None:
        return rng.pick([not value, None, 0, "true", "", []])
    if isinstance(value, (int, float)):
        return rng.pick(NUMBERS + ["1", None, [value]])
    return value


def duplicate_key_text(rng, text):
    """A JSON text with one key repeated: written by hand, since the parser
    on the way in would collapse it."""
    try:
        doc = json.loads(text)
    except ValueError:
        return text
    if not isinstance(doc, dict) or not doc:
        return text
    key = rng.pick(list(doc))
    dumped = json.dumps(doc)
    needle = json.dumps(key) + ":"
    i = dumped.find(needle)
    if i < 0:
        return text
    extra = needle + " " + json.dumps(rng.pick(STRINGS)) + ", "
    return (dumped[:i] + extra + dumped[i:]).encode("utf-8")


def mutate_document(rng, text, other):
    roll = rng.below(4)
    if roll == 0:
        return mutate_bytes(rng, text, other)
    if roll == 1:
        return duplicate_key_text(rng, text)
    try:
        doc = json.loads(text)
    except ValueError:
        return mutate_bytes(rng, text, other)
    for _ in range(1 + rng.below(3)):
        doc = mutate_value(rng, doc)
    try:
        return json.dumps(doc, ensure_ascii=rng.chance(2)).encode("utf-8")
    except (ValueError, TypeError):
        return mutate_bytes(rng, text, other)


# ---------------------------------------------------------------------------
# Running the scripts and judging what they do
# ---------------------------------------------------------------------------

def run(argv, cwd):
    started = time.monotonic()
    try:
        proc = subprocess.run([sys.executable] + argv, cwd=cwd, capture_output=True,
                              timeout=BUDGET_SECONDS * 4)
    except subprocess.TimeoutExpired:
        return None, b"", b"timed out", BUDGET_SECONDS * 4
    return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started


def common(name, code, out, err, took, findings, exits):
    """The invariants that hold for any invocation of either script: a
    known exit code, no traceback, one JSON object on standard output, and
    the time budget. Returns the object, or None when there is none."""
    if code is None:
        findings.append((name, "timed out"))
        return None
    if b"Traceback" in err:
        findings.append((name, "traceback on stderr: " + err.decode("utf-8", "replace")[-400:]))
    if code not in exits:
        findings.append((name, "exit code %d outside %s" % (code, sorted(exits))))
    if took > BUDGET_SECONDS:
        findings.append((name, "slow: %.2f s" % took))
    try:
        doc = json.loads(out.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        findings.append((name, "stdout is not one JSON object: %r" % out[:200]))
        return None
    if not isinstance(doc, dict):
        findings.append((name, "stdout is JSON but not an object"))
        return None
    return doc


def judge_checker(name, code, out, err, took, findings):
    """check_action.py: an outcome object that conforms to the published
    schema and agrees with the exit code."""
    doc = common(name, code, out, err, took, findings, OUTCOME_BY_EXIT)
    if doc is None:
        return None
    try:
        _schema.validate(doc, OUTCOME_SCHEMA, "outcome")
    except Exception as exc:  # the validator raises its own refusal type
        findings.append((name, "outcome does not conform: %s" % exc))
    expected = OUTCOME_BY_EXIT.get(code)
    if expected is not None and doc.get("outcome") != expected:
        findings.append((name, "exit %d but outcome %r" % (code, doc.get("outcome"))))
    return doc


RECORDER_STATUS_BY_EXIT = {0: ("appended", "intact", "empty"), 1: ("broken",), 3: ("error",)}


def judge_recorder(name, code, out, err, took, findings):
    """record.py: a status object whose status agrees with the exit code
    (0 appended, intact or empty; 1 broken; 3 error) and a non-empty reason
    on error."""
    doc = common(name, code, out, err, took, findings, RECORDER_STATUS_BY_EXIT)
    if doc is None:
        return None
    allowed = RECORDER_STATUS_BY_EXIT.get(code, ())
    if doc.get("status") not in allowed:
        findings.append((name, "exit %d but status %r" % (code, doc.get("status"))))
    if doc.get("status") == "error" and not (isinstance(doc.get("reason"), str) and doc["reason"]):
        findings.append((name, "an error without a reason"))
    return doc


OUTCOME_SCHEMA = _schema.load(os.path.join(SCHEMAS, "action-outcome.schema.json"))


def one_case(args):
    seed, mandate_text, action_text, other_m, other_a = args
    rng = Lcg(seed)
    which = rng.below(3)
    m = mutate_document(rng, mandate_text, other_m) if which != 1 else mandate_text
    a = mutate_document(rng, action_text, other_a) if which != 0 else action_text
    findings = []
    d = tempfile.mkdtemp(prefix="hanria-fuzz-")
    try:
        mp, ap = os.path.join(d, "m.json"), os.path.join(d, "a.json")
        open(mp, "wb").write(m)
        open(ap, "wb").write(a)
        argv = [os.path.join(SCRIPTS, "check_action.py"), "--mandate", mp, "--action", ap]
        code, out, err, took = run(argv, d)
        doc = judge_checker("check_action", code, out, err, took, findings)
        code2, out2, _, _ = run(argv, d)
        if (code2, out2) != (code, out):
            findings.append(("check_action", "not deterministic: exit %r/%r" % (code, code2)))
        # The recorder, fed exactly what the checker produced, on a fresh log.
        if doc is not None:
            op = os.path.join(d, "o.json")
            open(op, "wb").write(out)
            log = os.path.join(d, "log.jsonl")
            before = None
            rec = [os.path.join(SCRIPTS, "record.py"), "append", "--log", log,
                   "--action", ap, "--outcome", op]
            rcode, rout, rerr, rtook = run(rec, d)
            judge_recorder("record append", rcode, rout, rerr, rtook, findings)
            after = open(log, "rb").read() if os.path.exists(log) else None
            if rcode == 0:
                vcode, vout, verr, vtook = run([os.path.join(SCRIPTS, "record.py"), "verify",
                                                "--log", log], d)
                judge_recorder("record verify", vcode, vout, verr, vtook, findings)
                if vcode != 0:
                    findings.append(("record verify", "a log the recorder just wrote does not verify"))
            elif after != before:
                findings.append(("record append", "a refused append changed the log"))
        return seed, m, a, findings
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Fuzz the scripts' inputs.")
    ap.add_argument("--cases", type=int, default=60)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=0x5EED)
    ap.add_argument("--output", default=os.path.join(ROOT, "fuzz.out"))
    try:
        args = ap.parse_args()
    except SystemExit:
        return 1
    mandates, actions = seeds()
    rng = Lcg(args.seed)
    cases = []
    for i in range(args.cases):
        cases.append((args.seed * 1_000_003 + i, rng.pick(mandates), rng.pick(actions),
                      rng.pick(mandates), rng.pick(actions)))
    total_findings = 0
    started = time.monotonic()
    with concurrent.futures.ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for seed, m, a, findings in pool.map(one_case, cases, chunksize=4):
            if not findings:
                continue
            total_findings += 1
            os.makedirs(args.output, exist_ok=True)
            tag = hashlib.sha256(m + b"\n" + a).hexdigest()[:16]
            open(os.path.join(args.output, tag + ".mandate.json"), "wb").write(m)
            open(os.path.join(args.output, tag + ".action.json"), "wb").write(a)
            with open(os.path.join(args.output, tag + ".txt"), "w") as fh:
                fh.write("seed %d\n" % seed)
                for where, what in findings:
                    fh.write("%s: %s\n" % (where, what))
            print("FINDING seed %d: %s" % (seed, findings), flush=True)
    print("fuzz: %d cases, %d with findings, %.1f s, seed %d" % (
        args.cases, total_findings, time.monotonic() - started, args.seed))
    return 2 if total_findings else 0


if __name__ == "__main__":
    sys.exit(main())
