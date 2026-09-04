#!/usr/bin/env python3
"""Check a proposed action against an operator-authored mandate.

Local, read-only, standard library only. Makes no network calls and reads no
credentials.

    python3 check_action.py --mandate MANDATE.json --action ACTION.json

Prints one action-outcome object and exits.

Exit codes:  0 permit   1 deny   2 escalate   3 error

WHAT THIS IS NOT. This script evaluates and reports. It does not enforce.
Nothing here stands between an agent and a credential, so an agent that ignores
a `deny` still performs the operation. Enforcement is possible only where the
protected credentials, tools, signing keys or worker processes are reachable
exclusively through a component that can refuse. This is not that component.

The evaluation is fail-closed: any condition this script cannot resolve --- an
unreadable mandate, an expired one, a malformed request, an amount it cannot
compare --- produces `deny` or `error`, never `permit`.
"""
import argparse
import datetime as _dt
import json
import re
import sys
from decimal import Decimal, InvalidOperation

SCHEMA_VERSION = "0.2-draft"

# Substrings that suggest a secret has been placed in a request. A request is
# refused rather than sanitized: stripping a credential would hide the fact that
# the agent tried to send one, which is the more important signal.
SECRET_HINTS = (
    "credential", "secret", "private_key", "privatekey", "token",
    "password", "passwd", "api_key", "apikey", "access_key",
    "session_key", "bearer", "passphrase",
)

KINDS = {
    "file", "process", "package", "network", "device",
    "credential_use", "transaction", "administrative",
}


class CheckError(Exception):
    """Something could not be resolved. Always resolves to deny or error."""


def _outcome(outcome, reason, mandate_ref=None, clause=None, note=None):
    o = {"schema_version": "0.1-draft", "outcome": outcome, "reason": reason}
    if mandate_ref:
        o["mandate_ref"] = mandate_ref
    if clause:
        o["clause"] = clause
    if note:
        o["clause_note"] = note
    return o


def _load(path, what):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise CheckError("no %s at %s" % (what, path))
    except json.JSONDecodeError as exc:
        raise CheckError("%s at %s is not valid JSON: %s" % (what, path, exc))
    if not isinstance(doc, dict):
        raise CheckError("%s at %s is not a JSON object" % (what, path))
    return doc


def find_secrets(node, path="action"):
    """Return dotted paths of keys or string values that look like secrets."""
    hits = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = "%s.%s" % (path, key)
            if any(h in key.lower() for h in SECRET_HINTS):
                hits.append(here)
            hits.extend(find_secrets(value, here))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            hits.extend(find_secrets(value, "%s[%d]" % (path, i)))
    elif isinstance(node, str):
        low = node.lower()
        # A bare mention is not a secret; an assignment is the signal.
        if re.search(r"(?:%s)\s*[=:]\s*\S" % "|".join(SECRET_HINTS), low):
            hits.append(path)
    return hits


def parse_time(text, what):
    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise CheckError("%s is not an RFC 3339 timestamp: %r" % (what, text))


def to_decimal(value, what):
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise CheckError("%s is not a decimal: %r" % (what, value))


def validate_mandate(mandate):
    for field in ("schema_version", "mandate_id", "purpose", "default", "clauses"):
        if field not in mandate:
            raise CheckError("mandate is missing required field %r" % field)
    if mandate["schema_version"] != SCHEMA_VERSION:
        raise CheckError(
            "mandate schema_version is %r; this script evaluates %r only"
            % (mandate["schema_version"], SCHEMA_VERSION))
    if mandate["default"] not in ("deny", "escalate"):
        raise CheckError("mandate default must be 'deny' or 'escalate', not %r"
                         % mandate["default"])
    clauses = mandate["clauses"]
    if not isinstance(clauses, list) or not clauses:
        raise CheckError("mandate has no clauses")
    seen = set()
    for i, clause in enumerate(clauses):
        if not isinstance(clause, dict):
            raise CheckError("clause %d is not an object" % i)
        for field in ("id", "effect", "match"):
            if field not in clause:
                raise CheckError("clause %d is missing %r" % (i, field))
        if clause["id"] in seen:
            raise CheckError("duplicate clause id %r" % clause["id"])
        seen.add(clause["id"])
        if clause["effect"] not in ("permit", "deny", "escalate"):
            raise CheckError("clause %r has unknown effect %r"
                             % (clause["id"], clause["effect"]))
        kinds = clause["match"].get("kind")
        if not isinstance(kinds, list) or not kinds:
            raise CheckError("clause %r has no match.kind" % clause["id"])
        for kind in kinds:
            if kind not in KINDS:
                raise CheckError("clause %r names unknown kind %r"
                                 % (clause["id"], kind))
    for kind in mandate.get("requires_human", []):
        if kind not in KINDS:
            raise CheckError("requires_human names unknown kind %r" % kind)


def clause_matches(clause, op):
    """True when every condition present in the clause holds for the operation.

    Returns (matched, why_not). An amount above the clause ceiling is not a
    match, so evaluation continues to later clauses and ultimately to the
    mandate default rather than silently permitting.
    """
    m = clause["match"]

    if op.get("kind") not in m["kind"]:
        return False, "kind %r not in %s" % (op.get("kind"), m["kind"])

    if "verb" in m:
        verb = (op.get("verb") or "").lower()
        if verb not in [v.lower() for v in m["verb"]]:
            return False, "verb %r not in %s" % (op.get("verb"), m["verb"])

    if "target_prefix" in m:
        target = op.get("target") or ""
        if not any(target.startswith(p) for p in m["target_prefix"]):
            return False, "target %r matches no permitted prefix" % target

    if "counterparty" in m:
        if op.get("counterparty") not in m["counterparty"]:
            return False, "counterparty %r not named" % op.get("counterparty")

    if "max_amount" in m:
        amount = op.get("amount")
        if not amount:
            return False, "clause bounds an amount but the request states none"
        ceiling = m["max_amount"]
        if amount.get("currency") != ceiling["currency"]:
            return False, ("currency %r does not match the ceiling currency %r"
                           % (amount.get("currency"), ceiling["currency"]))
        got = to_decimal(amount.get("value"), "request amount")
        cap = to_decimal(ceiling["value"], "clause ceiling")
        if got > cap:
            return False, ("amount %s exceeds the ceiling %s %s"
                           % (got, cap, ceiling["currency"]))

    return True, None


def evaluate(mandate, action, now=None):
    validate_mandate(mandate)
    ref = mandate["mandate_id"]
    now = now or _dt.datetime.now(_dt.timezone.utc)

    if "not_valid_after" in mandate:
        expiry = parse_time(mandate["not_valid_after"], "not_valid_after")
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=_dt.timezone.utc)
        if now >= expiry:
            return _outcome("deny", "the mandate expired at %s"
                            % mandate["not_valid_after"], ref)

    if "operation" not in action or not isinstance(action["operation"], dict):
        return _outcome("deny", "the request states no operation", ref)
    op = action["operation"]
    if op.get("kind") not in KINDS:
        return _outcome("deny", "unknown operation kind %r" % op.get("kind"), ref)

    secrets = find_secrets(action)
    if secrets:
        return _outcome(
            "deny",
            "the request appears to carry a credential at %s; a request names "
            "what is to be done, never the means of doing it"
            % ", ".join(sorted(secrets)),
            ref)

    near_misses = []
    for clause in mandate["clauses"]:
        matched, why_not = clause_matches(clause, op)
        if not matched:
            # A clause written for this kind of operation that still did not
            # match is the useful thing to report. Without it, "no clause
            # covers this" sends a reviewer looking for a missing clause when
            # the clause exists and the request fell outside its bounds.
            if op.get("kind") in clause["match"]["kind"]:
                near_misses.append("%s (%s)" % (clause["id"], why_not))
            continue
        effect = clause["effect"]
        note = clause.get("note")
        if effect == "permit" and op["kind"] in mandate.get("requires_human", []):
            return _outcome(
                "escalate",
                "clause %r permits this, but %r always requires a person"
                % (clause["id"], op["kind"]), ref, clause["id"], note)
        return _outcome(
            effect, "clause %r applies" % clause["id"], ref, clause["id"], note)

    if near_misses:
        reason = ("no clause matched, so the mandate default applies; "
                  "the closest were %s" % "; ".join(near_misses))
    else:
        reason = ("no clause covers a %r operation, so the mandate default "
                  "applies" % op.get("kind"))
    return _outcome(mandate["default"], reason, ref)


def main():
    ap = argparse.ArgumentParser(
        description="Check a proposed action against a mandate. "
                    "Advisory only: this reports a decision, it cannot enforce one.")
    ap.add_argument("--mandate", required=True, help="path to a mandate JSON file")
    ap.add_argument("--action", required=True, help="path to an action-request JSON file")
    args = ap.parse_args()

    try:
        result = evaluate(_load(args.mandate, "mandate"), _load(args.action, "action request"))
    except CheckError as exc:
        print(json.dumps(_outcome("error", str(exc)), indent=2))
        return 3

    print(json.dumps(result, indent=2))
    return {"permit": 0, "deny": 1, "escalate": 2}.get(result["outcome"], 3)


if __name__ == "__main__":
    sys.exit(main())
