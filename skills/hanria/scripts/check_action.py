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

SCHEMA_VERSION = "0.2-draft"          # mandate
REQUEST_SCHEMA_VERSION = "0.1-draft"  # action request

# Field names that suggest a secret has been placed in a request. A request is
# refused rather than sanitized: stripping a credential would hide the fact that
# the agent tried to send one, which is the more important signal.
#
# THIS IS A HEURISTIC AND CANNOT BE COMPLETE. It recognizes common shapes. A
# credential in an unremarkably-named field holding an unremarkable-looking
# value will pass. Do not describe this as refusing every request that carries a
# credential; it refuses requests carrying *recognizable* credential material.
SECRET_HINTS = (
    "credential", "secret", "private_key", "privatekey", "token",
    "password", "passwd", "pwd", "api_key", "apikey", "access_key",
    "secret_key", "session_key", "bearer", "passphrase", "auth",
    "authorization", "cookie", "set-cookie", "signature", "sig",
    "client_secret", "refresh_token", "id_token", "sas", "otp",
)

# Value shapes that are credential material regardless of the field name.
SECRET_SHAPES = (
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"\bbasic\s+[A-Za-z0-9+/=]{12,}", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN (?:CERTIFICATE|OPENSSH|PGP)"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                              # AWS
    re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}"),               # GitHub
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),                                    # common API keys
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),                            # Slack
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),                                   # Google
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:"
               r"[A-Za-z0-9+/=]{16,}"),                                        # id:secret pairs
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
    """Return dotted paths of fields or values that look like credentials.

    Heuristic by nature -- see SECRET_HINTS. Matches on three signals: a field
    name from the vocabulary, a value carrying a recognizable credential shape,
    or a `name=value` assignment inside a free-text string.
    """
    hits = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = "%s.%s" % (path, key)
            k = key.lower().replace("-", "_")
            if any(h.replace("-", "_") in k for h in SECRET_HINTS):
                # A named credential field with an empty value is still an
                # attempt worth surfacing.
                hits.append(here)
            hits.extend(find_secrets(value, here))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            hits.extend(find_secrets(value, "%s[%d]" % (path, i)))
    elif isinstance(node, str):
        if any(p.search(node) for p in SECRET_SHAPES):
            hits.append(path)
        elif re.search(r"(?:%s)\s*[=:]\s*\S" % "|".join(SECRET_HINTS),
                       node.lower()):
            # A bare mention is not a secret; an assignment is the signal.
            hits.append(path)
    return hits


def parse_time(text, what):
    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise CheckError("%s is not an RFC 3339 timestamp: %r" % (what, text))


def to_decimal(value, what):
    """Parse a decimal, refusing anything that cannot be compared meaningfully.

    NaN and the infinities parse as Decimal but either poison or silently skew a
    comparison, and a negative amount would satisfy any positive ceiling. All
    three are refused rather than compared.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise CheckError("%s is not a decimal: %r" % (what, value))
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise CheckError("%s is not a decimal: %r" % (what, value))
    if not d.is_finite():
        raise CheckError("%s is not a finite decimal: %r" % (what, value))
    if d < 0:
        raise CheckError("%s is negative (%s); a negative amount would satisfy "
                         "any positive ceiling" % (what, d))
    return d


MATCH_KEYS = {"kind", "verb", "target_prefix", "counterparty", "max_amount"}
CLAUSE_KEYS = {"id", "effect", "note", "match"}
MANDATE_KEYS = {"schema_version", "mandate_id", "issued_by", "purpose",
                "not_valid_after", "default", "requires_human", "clauses"}
ACTION_REQUIRED = ("schema_version", "requested_by", "operation", "justification")
# Mirrors the closed `additionalProperties: false` in the published schemas.
ACTION_KEYS = {"schema_version", "requested_by", "operation", "justification",
               "mandate_ref", "idempotency_key"}
OPERATION_KEYS = {"kind", "target", "verb", "parameters", "amount", "counterparty"}


def _str_list(value, what):
    """Require a non-empty list of strings.

    A bare string here is the dangerous case: `"target_prefix": "/srv/"` would
    make `startswith` iterate the string character by character, so any target
    beginning with "/" would match. Refused rather than coerced.
    """
    if not isinstance(value, list) or not value:
        raise CheckError("%s must be a non-empty list, not %s"
                         % (what, type(value).__name__))
    for v in value:
        if not isinstance(v, str):
            raise CheckError("%s must contain only strings; found %r" % (what, v))
    return value


def _nonempty_str(value, what):
    if not isinstance(value, str) or not value.strip():
        raise CheckError("%s must be a non-empty string, not %r" % (what, value))
    return value


def validate_mandate(mandate):
    for field in ("schema_version", "mandate_id", "purpose", "default", "clauses"):
        if field not in mandate:
            raise CheckError("mandate is missing required field %r" % field)
    # Presence is not validity. A field present but null, empty or of the wrong
    # type is a malformed mandate, and a malformed mandate must not be evaluated.
    _nonempty_str(mandate["mandate_id"], "mandate_id")
    _nonempty_str(mandate["purpose"], "purpose")
    if "issued_by" in mandate:
        _nonempty_str(mandate["issued_by"], "issued_by")
    if "requires_human" in mandate and not isinstance(mandate["requires_human"], list):
        raise CheckError("requires_human must be a list, not %s"
                         % type(mandate["requires_human"]).__name__)
    unknown = set(mandate) - MANDATE_KEYS
    if unknown:
        # Fail closed on anything unrecognized. An operator who writes a
        # restricting condition this evaluator does not implement must be told,
        # not silently granted the permission they were trying to narrow.
        raise CheckError("mandate has unrecognized field(s) %s; this evaluator "
                         "will not ignore a condition it cannot enforce"
                         % ", ".join(sorted(repr(u) for u in unknown)))
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
        _nonempty_str(clause["id"], "clause %d id" % i)
        if "note" in clause and not isinstance(clause["note"], str):
            raise CheckError("clause %r note must be a string, not %s"
                             % (clause["id"], type(clause["note"]).__name__))
        if clause["id"] in seen:
            raise CheckError("duplicate clause id %r" % clause["id"])
        seen.add(clause["id"])
        if clause["effect"] not in ("permit", "deny", "escalate"):
            raise CheckError("clause %r has unknown effect %r"
                             % (clause["id"], clause["effect"]))
        unknown = set(clause) - CLAUSE_KEYS
        if unknown:
            raise CheckError("clause %r has unrecognized field(s) %s"
                             % (clause["id"], ", ".join(sorted(repr(u) for u in unknown))))

        m = clause["match"]
        if not isinstance(m, dict):
            raise CheckError("clause %r has a non-object match" % clause["id"])
        unknown = set(m) - MATCH_KEYS
        if unknown:
            raise CheckError(
                "clause %r has unrecognized match condition(s) %s. This "
                "evaluator refuses rather than ignoring them: an unimplemented "
                "condition you wrote to restrict a clause would otherwise widen it"
                % (clause["id"], ", ".join(sorted(repr(u) for u in unknown))))

        for kind in _str_list(m.get("kind"), "clause %r match.kind" % clause["id"]):
            if kind not in KINDS:
                raise CheckError("clause %r names unknown kind %r"
                                 % (clause["id"], kind))
        for key in ("verb", "target_prefix", "counterparty"):
            if key in m:
                _str_list(m[key], "clause %r match.%s" % (clause["id"], key))
        if "max_amount" in m:
            ceiling = m["max_amount"]
            if not isinstance(ceiling, dict):
                raise CheckError("clause %r match.max_amount must be an object"
                                 % clause["id"])
            for field in ("value", "currency"):
                if field not in ceiling:
                    raise CheckError("clause %r match.max_amount is missing %r"
                                     % (clause["id"], field))
            if not isinstance(ceiling["currency"], str) or not ceiling["currency"]:
                raise CheckError("clause %r match.max_amount.currency must be a "
                                 "non-empty string" % clause["id"])
            to_decimal(ceiling["value"],
                       "clause %r match.max_amount.value" % clause["id"])
    for kind in mandate.get("requires_human", []):
        if kind not in KINDS:
            raise CheckError("requires_human names unknown kind %r" % kind)

    _refuse_unreachable(clauses)


def _overlaps(earlier, later):
    """True when some request would match `earlier` as well as `later`.

    Clauses are first-match-wins, so any request in the overlap is decided by
    the earlier clause. Where the earlier clause permits and the later one
    restricts, every request in that overlap escapes the restriction -- and the
    restriction still reads, to whoever reviews the mandate, as though it
    applies. That is the exact failure this tool exists to catch, and nothing
    surfaces it unless something looks.

    Total shadowing is not required, and testing only for it would miss the
    common case: a denial that is dead for the verbs an earlier permit covers
    and live for the rest is the more confusing of the two, not the safer.
    """
    e, l = earlier["match"], later["match"]

    if not set(e["kind"]) & set(l["kind"]):
        return False

    if "verb" in e and "verb" in l:
        if not {v.lower() for v in e["verb"]} & {v.lower() for v in l["verb"]}:
            return False

    if "target_prefix" in e and "target_prefix" in l:
        # Two prefixes can both apply only if one extends the other.
        if not any(lp.startswith(ep) or ep.startswith(lp)
                   for ep in e["target_prefix"] for lp in l["target_prefix"]):
            return False

    if "counterparty" in e and "counterparty" in l:
        if not set(e["counterparty"]) & set(l["counterparty"]):
            return False

    # A bounded earlier clause leaves everything above its ceiling to the
    # clauses after it, which is how a tiered policy is written: permit small
    # refunds, escalate larger ones, deny the rest. The later clause is reached
    # for exactly the amounts the earlier one declines, so it is not dead.
    if "max_amount" in e:
        if "max_amount" not in l:
            return False
        ec, lc = e["max_amount"], l["max_amount"]
        if ec["currency"] != lc["currency"]:
            return False
        if to_decimal(lc["value"], "ceiling") > to_decimal(ec["value"], "ceiling"):
            return False

    return True


def _refuse_unreachable(clauses):
    for i, later in enumerate(clauses):
        if later["effect"] == "permit":
            continue
        for earlier in clauses[:i]:
            if earlier["effect"] != "permit":
                continue
            if _overlaps(earlier, later):
                raise CheckError(
                    "clause %r is unreachable for part or all of what it "
                    "covers: the earlier clause %r permits requests that %r "
                    "was written to restrict, and the first matching clause "
                    "decides. Move %r above %r. A restriction that never runs "
                    "is worse than one you never wrote, because it reads as "
                    "though it applies."
                    % (later["id"], earlier["id"], later["id"],
                       later["id"], earlier["id"]))


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

    if action.get("schema_version") != REQUEST_SCHEMA_VERSION:
        return _outcome("deny", "the request declares schema_version %r; this "
                        "evaluator reads %r only"
                        % (action.get("schema_version"), REQUEST_SCHEMA_VERSION), ref)
    if not isinstance(action.get("requested_by"), dict) or \
            not isinstance(action["requested_by"].get("agent"), str) or \
            not action["requested_by"]["agent"].strip():
        return _outcome("deny", "the request does not name a requesting agent", ref)
    if not isinstance(action.get("justification"), str) or \
            not action["justification"].strip():
        return _outcome("deny", "the request carries no justification", ref)

    missing = [f for f in ACTION_REQUIRED if f not in action]
    if missing:
        # A request that does not carry its required fields has not described
        # itself well enough to be evaluated, so it is not evaluated.
        return _outcome("deny", "the request is missing required field(s) %s"
                        % ", ".join(repr(f) for f in missing), ref)
    if not isinstance(action["operation"], dict):
        return _outcome("deny", "the request states no operation", ref)
    op = action["operation"]
    if op.get("kind") not in KINDS:
        return _outcome("deny", "unknown operation kind %r" % op.get("kind"), ref)
    for key in ("target", "verb", "counterparty"):
        if key in op and not isinstance(op[key], (str, type(None))):
            return _outcome("deny", "operation.%s must be a string" % key, ref)

    # Prefix matching is literal by design -- it resolves nothing -- so a target
    # containing a parent-directory segment could satisfy a prefix and still
    # land outside it. Refused before any clause is consulted, because no
    # honestly-described operation needs one.
    target = op.get("target") or ""
    if any(seg == ".." for seg in re.split(r"[/\\]", target)):
        return _outcome(
            "deny",
            "the target %r contains a parent-directory segment; prefix rules "
            "are matched literally, so such a target could satisfy a prefix "
            "and still resolve outside it. State the resolved target instead."
            % target, ref)
    if "amount" in op and not isinstance(op["amount"], dict):
        return _outcome("deny", "operation.amount must be an object", ref)

    # The published request schema is closed (additionalProperties: false), so
    # an unrecognized field means the request is not the shape it claims to be.
    unknown = set(action) - ACTION_KEYS
    if unknown:
        return _outcome("deny", "the request has unrecognized field(s) %s"
                        % ", ".join(sorted(repr(u) for u in unknown)), ref)
    unknown = set(op) - OPERATION_KEYS
    if unknown:
        return _outcome("deny", "operation has unrecognized field(s) %s"
                        % ", ".join(sorted(repr(u) for u in unknown)), ref)

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
    except Exception as exc:  # noqa: BLE001 - deliberate
        # Anything unforeseen is an error outcome with exit 3, never a traceback
        # and never a missing outcome. A caller reading the exit code must not
        # be able to mistake an internal fault for a decision.
        print(json.dumps(_outcome(
            "error", "internal error while evaluating (%s: %s)"
                     % (type(exc).__name__, exc)), indent=2))
        return 3

    print(json.dumps(result, indent=2))
    return {"permit": 0, "deny": 1, "escalate": 2}.get(result["outcome"], 3)


if __name__ == "__main__":
    sys.exit(main())
