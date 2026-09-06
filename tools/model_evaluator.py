#!/usr/bin/env python3
"""A reference evaluator, run against the checker on generated pairs.

`tools/fuzz_inputs.py` asks whether the checker breaks. This asks whether
its decisions are right on mandates and actions nobody wrote down. It holds
a second, independent implementation of the documented rules, generates
mandates and action requests from small universes chosen so that every rule
is exercised often (percent-encoded and decomposed spellings, tiered
amounts, counterparties, reserved kinds, expiry, unreachable clauses), and
compares the checker's decision with the reference's on every pair: the
outcome, and the clause relied on when one was.

The rules the reference encodes, from `SKILL.md`, the schemas, and the
checker's stated semantics:

- Clauses are evaluated in order and the first match decides; a request
  matching none takes the mandate default, which is deny or escalate.
- A clause matches when every condition present holds: the operation kind
  is one of the clause's; the verb, compared case-insensitively, is one of
  the clause's; the target begins with one of the clause's prefixes; the
  counterparty is one of the clause's; and an amount, when the clause
  bounds one, is present, in the ceiling's currency, and not above it.
- Prefixes and targets are canonically composed before comparison. A
  denial or escalation matches the target as written or percent-decoded to
  a fixed point; a permission matches the target as written only.
- A clause that permits a kind the mandate reserves for a person escalates
  instead, naming the clause.
- An expired mandate denies before any clause is read. A target with a
  parent-directory segment, as written or once decoded, is denied before
  any clause is read.
- A mandate is refused before evaluation when a restricting clause is
  unreachable: an earlier clause of a different effect already decides some
  request the later one covers, where two clauses overlap when their kinds
  intersect, their verbs intersect when both bound verbs, some spelling of a
  prefix of one extends some spelling of a prefix of the other when both
  bound targets, their counterparties intersect when both bound them, their
  currencies agree when both bound amounts, and, when the earlier bounds an
  amount, the later is not the same scope left unbounded or bounded higher.

A disagreement is a finding, written with the pair and both verdicts, and
the run exits 2. A finding is either a mistake in this reference or a
defect in the checker, and is investigated as such; the reference is not
the checker's oracle, it is a second reading of the same rules.

    python3 tools/model_evaluator.py                 # 2,000 pairs
    python3 tools/model_evaluator.py --pairs 200000 --seed 7 --output DIR

Standard library only, plus the checker itself, called in process.
"""
import argparse
import datetime as _dt
import json
import os
import sys
import time
import unicodedata
from decimal import Decimal
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "hanria", "scripts")
sys.path.insert(0, SCRIPTS)
import check_action  # noqa: E402

EXIT = {"permit": 0, "deny": 1, "escalate": 2, "error": 3}


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

    def subset(self, items, at_least=1):
        chosen = [x for x in items if self.chance(2)]
        while len(chosen) < at_least:
            x = self.pick(items)
            if x not in chosen:
                chosen.append(x)
        return chosen


# ---------------------------------------------------------------------------
# The universes
# ---------------------------------------------------------------------------

KINDS = ["file", "network", "transaction"]
RESERVABLE = ["file", "network", "transaction", "credential_use"]
VERBS = ["read", "write", "post", "transfer", "READ"]
NFC_E = "é"
NFD_E = "é"
PREFIXES = [
    "/data/",
    "/data/s" + NFC_E + "crets/",
    "/data/s" + NFD_E + "crets/",
    "/data/s%C3%A9crets/",
    "/data/ask/",
    "/tmp/",
    "https://api.example/",
    "https://api.example/v1/",
]
TARGETS = [
    "/data/x.txt",
    "/data/s" + NFC_E + "crets/k.txt",
    "/data/s" + NFD_E + "crets/k.txt",
    "/data/s%C3%A9crets/k.txt",
    "/data/s%25C3%25A9crets/k.txt",
    "/data/ask/y.txt",
    "/data/%61sk/y.txt",
    "/data%2Fx.txt",
    "/data/../etc/passwd",
    "/data/%2e%2e/etc",
    "/tmp/t",
    "/other/z",
    "https://api.example/v1/reply?text=hello%20world",
    "https://api.example.evil/x",
    "／data／x.txt",
]
COUNTERPARTIES = ["acme", "globex"]
CURRENCIES = ["USD", "EUR"]
AMOUNTS = ["5", "10", "10.00", "10.01", "100"]


def gen_clause(rng, index):
    m = {"kind": rng.subset(KINDS)}
    if rng.chance(2):
        m["verb"] = rng.subset(VERBS)
    if rng.chance(2):
        m["target_prefix"] = rng.subset(PREFIXES)
    if rng.chance(3):
        m["counterparty"] = rng.subset(COUNTERPARTIES)
    if rng.chance(3):
        m["max_amount"] = {"value": rng.pick(AMOUNTS), "currency": rng.pick(CURRENCIES)}
    clause = {"id": "c%d" % index, "effect": rng.pick(["permit", "deny", "escalate"]), "match": m}
    if rng.chance(2):
        clause["note"] = "why clause %d exists" % index
    return clause


def gen_mandate(rng):
    clauses = [gen_clause(rng, i) for i in range(1 + rng.below(3))]
    if rng.chance(2):
        # Restrictions first, as the skill text advises, so most generated
        # mandates are reachable and the permits below them get exercised;
        # the other half keeps the order as drawn, so unreachable mandates
        # are still generated and the refusal is still checked.
        clauses.sort(key=lambda c: c["effect"] == "permit")
    mandate = {
        "schema_version": "0.2-draft",
        "mandate_id": "m-%d" % rng.below(1000),
        "purpose": "generated for the reference evaluator",
        "default": rng.pick(["deny", "escalate"]),
        "clauses": clauses,
    }
    if rng.chance(2):
        mandate["requires_human"] = rng.subset(RESERVABLE, at_least=0)
    roll = rng.below(6)
    if roll == 0:
        mandate["not_valid_after"] = "2020-01-01T00:00:00Z"
    elif roll < 4:
        mandate["not_valid_after"] = "2999-01-01T00:00:00Z"
    return mandate


def gen_action(rng, mandate):
    op = {"kind": rng.pick(KINDS), "verb": rng.pick(VERBS), "target": rng.pick(TARGETS)}
    if rng.chance(2):
        op["counterparty"] = rng.pick(COUNTERPARTIES)
    if rng.chance(2):
        op["amount"] = {"value": rng.pick(AMOUNTS), "currency": rng.pick(CURRENCIES)}
    if rng.chance(2):
        # Aimed at one clause: every condition it states is satisfied as
        # written, so the accepting paths, and the reserved-kind escalation
        # behind them, are reached as often as the refusing ones.
        m = rng.pick(mandate["clauses"])["match"]
        op["kind"] = rng.pick(m["kind"])
        if "verb" in m:
            op["verb"] = rng.pick(m["verb"])
        if "target_prefix" in m:
            op["target"] = rng.pick(m["target_prefix"]) + rng.pick(["a.txt", "b/c", ""])
            if op["target"].endswith("/"):
                op["target"] += "d"
        if "counterparty" in m:
            op["counterparty"] = rng.pick(m["counterparty"])
        if "max_amount" in m:
            op["amount"] = {"value": rng.pick(AMOUNTS), "currency": m["max_amount"]["currency"]}
    return {
        "schema_version": "0.1-draft",
        "requested_by": {"agent": "gen", "session": "s"},
        "operation": op,
        "justification": "generated for the reference evaluator",
    }


# ---------------------------------------------------------------------------
# The reference
# ---------------------------------------------------------------------------

def nfc(text):
    return unicodedata.normalize("NFC", text)


def decode_stable(text):
    seen = set()
    while text not in seen:
        seen.add(text)
        text = unquote(text)
    return text


def spellings(prefix):
    return {nfc(prefix), nfc(decode_stable(prefix))}


def overlaps(e, l):
    em, lm = e["match"], l["match"]
    if not set(em["kind"]) & set(lm["kind"]):
        return False
    if "verb" in em and "verb" in lm:
        if not {v.lower() for v in em["verb"]} & {v.lower() for v in lm["verb"]}:
            return False
    if "target_prefix" in em and "target_prefix" in lm:
        if not any(a.startswith(b) or b.startswith(a)
                   for ep in em["target_prefix"] for lp in lm["target_prefix"]
                   for a in spellings(ep) for b in spellings(lp)):
            return False
    if "counterparty" in em and "counterparty" in lm:
        if not set(em["counterparty"]) & set(lm["counterparty"]):
            return False
    if "max_amount" in em and "max_amount" in lm and \
            em["max_amount"]["currency"] != lm["max_amount"]["currency"]:
        return False
    if "max_amount" in em:
        def scope(m):
            return {k: sorted(v) if isinstance(v, list) else v
                    for k, v in m.items() if k != "max_amount"}
        if scope(em) == scope(lm):
            if "max_amount" not in lm:
                return False
            if em["max_amount"]["currency"] == lm["max_amount"]["currency"] and \
                    Decimal(lm["max_amount"]["value"]) > Decimal(em["max_amount"]["value"]):
                return False
    return True


def unreachable(clauses):
    for i, later in enumerate(clauses):
        if later["effect"] == "permit":
            continue
        for earlier in clauses[:i]:
            if earlier["effect"] == later["effect"]:
                continue
            if overlaps(earlier, later):
                return later["id"]
    return None


def clause_matches(clause, op):
    m = clause["match"]
    if op["kind"] not in m["kind"]:
        return False
    if "verb" in m and op["verb"].lower() not in [v.lower() for v in m["verb"]]:
        return False
    if "target_prefix" in m:
        written = nfc(op["target"])
        forms = [written]
        if clause["effect"] != "permit":
            decoded = nfc(decode_stable(op["target"]))
            if decoded != written:
                forms.append(decoded)
        prefixes = [nfc(p) for p in m["target_prefix"]]
        if not any(t.startswith(p) for t in forms for p in prefixes):
            return False
    if "counterparty" in m and op.get("counterparty") not in m["counterparty"]:
        return False
    if "max_amount" in m:
        amount = op.get("amount")
        if not amount:
            return False
        if amount["currency"] != m["max_amount"]["currency"]:
            return False
        if Decimal(amount["value"]) > Decimal(m["max_amount"]["value"]):
            return False
    return True


def reference(mandate, action, now):
    """(outcome, clause id or None)."""
    dead = unreachable(mandate["clauses"])
    if dead is not None:
        return "error", None
    if "not_valid_after" in mandate:
        expiry = _dt.datetime.fromisoformat(mandate["not_valid_after"].replace("Z", "+00:00"))
        if now >= expiry:
            return "deny", None
    op = action["operation"]
    decoded = decode_stable(op["target"])
    if any(seg == ".." for seg in decoded.replace("\\", "/").split("/")):
        return "deny", None
    for clause in mandate["clauses"]:
        if clause_matches(clause, op):
            if clause["effect"] == "permit" and op["kind"] in mandate.get("requires_human", []):
                return "escalate", clause["id"]
            return clause["effect"], clause["id"]
    return mandate["default"], None


def checker(mandate, action, now):
    """The checker's decision, called in process: (outcome, clause id)."""
    try:
        out = check_action.evaluate(json.loads(json.dumps(mandate)),
                                    json.loads(json.dumps(action)), now)
    except check_action.CheckError:
        return "error", None
    return out["outcome"], out.get("clause")


def main():
    ap = argparse.ArgumentParser(description="Reference evaluator against the checker.")
    ap.add_argument("--pairs", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0x1DEA)
    ap.add_argument("--output", default=os.path.join(ROOT, "model.out"))
    try:
        args = ap.parse_args()
    except SystemExit:
        return 1
    rng = Lcg(args.seed)
    now = _dt.datetime.now(_dt.timezone.utc)
    started = time.monotonic()
    findings = 0
    tally = {}
    for i in range(args.pairs):
        mandate = gen_mandate(rng)
        action = gen_action(rng, mandate)
        want = reference(mandate, action, now)
        got = checker(mandate, action, now)
        tally[want[0]] = tally.get(want[0], 0) + 1
        if want != got:
            findings += 1
            os.makedirs(args.output, exist_ok=True)
            name = os.path.join(args.output, "pair-%d-%d" % (args.seed, i))
            json.dump({"mandate": mandate, "action": action, "reference": want, "checker": got},
                      open(name + ".json", "w"), indent=1, ensure_ascii=False)
            print("FINDING pair %d: reference %s, checker %s" % (i, want, got), flush=True)
    print("model: %d pairs, %d disagreements, %.1f s, seed %d; reference verdicts %s" % (
        args.pairs, findings, time.monotonic() - started, args.seed,
        json.dumps(tally, sort_keys=True)))
    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
