#!/usr/bin/env python3
"""A reference for the strict loader and the schema validator.

Every document this skill reads passes through `_schema.loads`, and every
mandate, request, outcome and log entry is validated by `_schema.validate`.
This holds an independent reading of both and compares it with the module
on generated inputs.

For the loader: a JSON text is accepted exactly when it is valid JSON with
no object naming a key twice, no NaN or Infinity literal and no number
that overflows to one, at most the published size, and a structure nesting
at most the published depth; the value returned is the parsed value. The
reference decides depth from the parsed structure, not from a scan of the
text, so the loader's scan is checked against the thing it approximates;
brackets inside strings are the case that tells them apart.

For the validator: a document conforms to a schema exactly when every
constraint the schema states holds at every path the document reaches,
with the module's meaning for each keyword it implements (`const`, `enum`,
`type` including a list of types, `minLength`, `format` date-time as RFC
3339 with a real calendar date, `minItems`, `maxItems`, `items`,
`required`, `properties`, `additionalProperties` false); and a schema
using any other keyword, or a format other than date-time, anywhere in it,
is refused before any document is judged. That meaning is JSON Schema's
except in two places the reference encodes the same way, so that it can
check everything else: `const` and `enum` compare by Python equality, so a
boolean equals its integer and 1 equals 1.0; and `integer` means a Python
int, so 3.0 is not one, where JSON Schema says it is. A boolean is neither
an integer nor a number, as in JSON Schema. The reference checks the
date-time by parsing it, not by the module's pattern, and refuses a
trailing newline, which a dollar-anchored pattern would let through.

Generated texts include duplicate keys, the non-JSON literals, trailing
and leading junk, a byte-order mark, raw control characters and lone
surrogates inside strings, nesting to either side of the bound, and
brackets inside strings. Generated schemas draw from the supported
keywords, one time in eight with an unsupported one somewhere, and the
documents are drawn to satisfy the schema about half the time.

A disagreement is a finding, written with the input and both verdicts, and
the run exits 2.

    python3 tools/schema_exerciser.py                 # 3,000 of each
    python3 tools/schema_exerciser.py --texts 200000 --pairs 200000 --seed 7

Standard library only, plus the module under test.
"""
import argparse
import datetime as _dt
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "skills", "hanria", "scripts")
sys.path.insert(0, SCRIPTS)
import _schema  # noqa: E402

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 64


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


# ---------------------------------------------------------------------------
# The loader
# ---------------------------------------------------------------------------

def structural_depth(value):
    if isinstance(value, dict):
        return 1 + max((structural_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((structural_depth(v) for v in value), default=0)
    return 0


class _Dup(Exception):
    pass


class _Const(Exception):
    pass


def reference_loads(text):
    """('accept', value) or ('refuse', why)."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        return "refuse", "size"

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise _Dup()
        return dict(items)

    def const(literal):
        raise _Const()

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=const)
    except _Dup:
        return "refuse", "duplicate key"
    except _Const:
        return "refuse", "non-JSON literal"
    except (ValueError, RecursionError):
        return "refuse", "not JSON"
    if has_non_finite(value):
        return "refuse", "non-finite number"
    if structural_depth(value) > MAX_DEPTH:
        return "refuse", "depth"
    return "accept", value


def has_non_finite(value):
    """A float that is infinite or not a number anywhere in the value: an
    overflowing literal such as 1e999 becomes one in a plain parse."""
    if isinstance(value, float):
        return value != value or value in (float("inf"), float("-inf"))
    if isinstance(value, dict):
        return any(has_non_finite(v) for v in value.values())
    if isinstance(value, list):
        return any(has_non_finite(v) for v in value)
    return False


STRINGS = ["", "a", "key", "k1", "k2", "x y", "é", "日本", "\U0001f600", "[[[", "]]]", "{{{", "}}}",
           "\\\"", "a\"b", "with \\u0000 escape", "2027-01-01T00:00:00Z", "tab\there"]


def gen_value(rng, depth, budget):
    if budget[0] <= 0 or depth > 70:
        return rng.pick([0, 1, -1, 2 ** 53, 1.5, -0.0, True, False, None, rng.pick(STRINGS)])
    budget[0] -= 1
    roll = rng.below(9)
    if roll == 0:
        return {rng.pick(STRINGS): gen_value(rng, depth + 1, budget) for _ in range(rng.below(4))}
    if roll == 1:
        return [gen_value(rng, depth + 1, budget) for _ in range(rng.below(4))]
    if roll == 2 and depth == 0:
        # A chain toward and past the depth bound.
        v = rng.pick([0, "leaf", []])
        for _ in range(60 + rng.below(10)):
            v = [v] if rng.chance(2) else {"d": v}
        return v
    if roll == 3:
        return rng.pick(STRINGS)
    if roll == 4:
        return rng.below(1_000_000)
    if roll == 5:
        return rng.pick([True, False, None])
    if roll == 6:
        return rng.below(100) / 7.0
    return rng.pick(STRINGS)


def gen_text(rng):
    """A JSON text, most of the time a dump of a generated value, sometimes
    edited into one of the shapes the loader must refuse or must survive."""
    value = gen_value(rng, 0, [1 + rng.below(40)])
    indent = rng.pick([None, None, 1, 2])
    text = json.dumps(value, indent=indent, ensure_ascii=rng.chance(2),
                      separators=rng.pick([None, (",", ":"), (", ", ": ")]))
    roll = rng.below(14)
    if roll == 0 and isinstance(value, dict) and value:
        key = rng.pick(list(value))
        needle = json.dumps(key) + ":"
        i = text.find(needle)
        if i >= 0:
            text = text[:i] + needle + " 1, " + text[i:]
    elif roll == 1:
        text = text.replace("1", rng.pick(["NaN", "Infinity", "-Infinity"]), 1) if "1" in text else "NaN"
    elif roll == 2:
        text = text + rng.pick([" x", ",", "}", "]", " // c", "\x00"])
    elif roll == 3:
        text = rng.pick(["﻿", " ", "\n", "\t", "\x00", "#"]) + text
    elif roll == 4:
        text = text.replace('"a"', '"a\x01b"', 1) if '"a"' in text else '"\x01"'
    elif roll == 5:
        text = text.replace('"a"', '"\\ud800"', 1) if '"a"' in text else '"\\ud800"'
    elif roll == 6:
        text = text[: max(0, len(text) - 1 - rng.below(3))]
    elif roll == 7:
        text = rng.pick(['"[[[[[[[[[["', '{"k": "]]]]]]]]]]"}', '["{{{{{{{{{{{{"]', '"\\"[["'])
    elif roll == 8:
        text = rng.pick(["", " ", "null", "true", "1e999", "-", "[", "{", "[1,]", "{\"a\":}", "01", "1."])
    elif roll == 9:
        # Brackets inside a string, more of them than the depth bound: the
        # structure is shallow and the text must be accepted; a scan that
        # counted them would refuse it.
        run = rng.pick(["[", "{", "]", "}", "[{", "\\\"["]) * (MAX_DEPTH + 6)
        text = json.dumps(rng.pick([{"k": run}, [run], run, {"a": [{"b": run}]}]))
    elif roll == 10 and rng.chance(40):
        # The size bound exactly, which is accepted, and one byte over it,
        # which is refused. Drawn rarely, since each is a megabyte.
        over = rng.chance(2)
        body = "x" * (MAX_BYTES - 2 + (1 if over else 0))
        text = '"' + body + '"'
    elif roll == 11:
        text = rng.pick(["1e999", "-1e999", "[1e400]", '{"n": 1e309}', "1e308", "1.7976931348623157e308"])
    return text


def loader_findings(text):
    want = reference_loads(text)
    try:
        got = ("accept", _schema.loads(text, "t"))
    except _schema.SchemaError as exc:
        got = ("refuse", str(exc)[:60])
    except Exception as exc:  # noqa: BLE001 - a crash is a finding
        return ["loader raised %s: %s" % (type(exc).__name__, exc)]
    if want[0] != got[0]:
        return ["reference %s (%s), loader %s (%s)" % (want[0], want[1] if want[0] == "refuse" else "value", got[0], got[1] if got[0] == "refuse" else "value")]
    if want[0] == "accept" and want[1] != got[1]:
        return ["both accept but values differ"]
    return []


# ---------------------------------------------------------------------------
# The validator
# ---------------------------------------------------------------------------

SUPPORTED = {"$schema", "$id", "title", "description", "$comment", "type", "required",
             "properties", "additionalProperties", "items", "enum", "const", "minLength",
             "minItems", "maxItems", "format"}
TYPE_NAMES = ["object", "array", "string", "number", "integer", "boolean", "null"]


def type_holds(value, name):
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if isinstance(value, bool):
        return False
    if name == "integer":
        return isinstance(value, int)
    if name == "number":
        return isinstance(value, (int, float))
    raise ValueError(name)


def is_rfc3339(value):
    """RFC 3339 date-time by parsing: date, 'T' or 't', time with optional
    fraction, 'Z'/'z' or a numeric offset, and a real calendar date."""
    if len(value) < 20:
        return False
    date, sep, rest = value[:10], value[10], value[11:]
    if sep not in "Tt":
        return False
    try:
        _dt.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
    except ValueError:
        return False
    if not (date[4] == "-" and date[7] == "-" and date[:4].isdigit() and date[5:7].isdigit() and date[8:10].isdigit()):
        return False
    if rest[-1] in "Zz":
        clock, offset = rest[:-1], None
    else:
        if len(rest) < 6 or rest[-6] not in "+-" or rest[-3] != ":":
            return False
        clock, offset = rest[:-6], rest[-5:]
        if not (offset[:2].isdigit() and offset[3:].isdigit() and 0 <= int(offset[:2]) <= 23 and 0 <= int(offset[3:]) <= 59):
            return False
    if len(clock) < 8 or clock[2] != ":" or clock[5] != ":":
        return False
    hh, mm, ss, frac = clock[0:2], clock[3:5], clock[6:8], clock[8:]
    if not (hh.isdigit() and mm.isdigit() and ss.isdigit()):
        return False
    if not (0 <= int(hh) <= 23 and 0 <= int(mm) <= 59 and 0 <= int(ss) <= 60):
        return False
    if frac and not (frac[0] == "." and len(frac) > 1 and frac[1:].isdigit()):
        return False
    return True


def schema_supported(schema):
    """False when any keyword or format anywhere in the schema is outside
    what the validator implements."""
    if set(schema) - SUPPORTED:
        return False
    if "format" in schema and schema["format"] != "date-time":
        return False
    for sub in schema.get("properties", {}).values():
        if not schema_supported(sub):
            return False
    if "items" in schema and not schema_supported(schema["items"]):
        return False
    return True


def conforms(doc, schema):
    if "const" in schema and doc != schema["const"]:
        return False
    if "enum" in schema and doc not in schema["enum"]:
        return False
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type_holds(doc, n) for n in names):
            return False
    if isinstance(doc, str):
        if "minLength" in schema and len(doc) < schema["minLength"]:
            return False
        if schema.get("format") == "date-time" and not is_rfc3339(doc):
            return False
    if isinstance(doc, list):
        if "minItems" in schema and len(doc) < schema["minItems"]:
            return False
        if "maxItems" in schema and len(doc) > schema["maxItems"]:
            return False
        if "items" in schema and not all(conforms(item, schema["items"]) for item in doc):
            return False
    if isinstance(doc, dict):
        if any(f not in doc for f in schema.get("required", [])):
            return False
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(doc) - set(props):
            return False
        if not all(conforms(v, props[k]) for k, v in doc.items() if k in props):
            return False
    return True


DATES = ["2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z\n", "2027-01-01t00:00:00z", "2026-02-29T00:00:00Z", "2028-02-29T12:00:00+05:30",
         "2027-01-01T23:59:60Z", "2027-01-01T24:00:00Z", "2027-13-01T00:00:00Z", "2027-01-01", "2027-01-01 00:00:00Z",
         "2027-01-01T00:00:00.5Z", "2027-01-01T00:00:00.Z", "2027-01-01T00:00:00-23:59", "2027-01-01T00:00:00+24:00",
         "27-01-01T00:00:00Z", "2027-01-01T00:00:00", "", "x"]


def gen_schema(rng, depth):
    s = {}
    if rng.chance(4):
        s[rng.pick(["title", "description", "$comment", "$id", "$schema"])] = "note"
    roll = rng.below(6)
    if roll == 0 and depth < 3:
        s["type"] = "object"
        props = {}
        for name in rng.pick([["a"], ["a", "b"], ["a", "b", "c"], []]):
            props[name] = gen_schema(rng, depth + 1)
        if props or rng.chance(2):
            s["properties"] = props
        if rng.chance(2) and props:
            s["required"] = [k for k in props if rng.chance(2)]
        if rng.chance(2):
            s["additionalProperties"] = False
    elif roll == 1 and depth < 3:
        s["type"] = "array"
        if rng.chance(2):
            s["items"] = gen_schema(rng, depth + 1)
        if rng.chance(3):
            s["minItems"] = rng.below(3)
        if rng.chance(3):
            s["maxItems"] = rng.below(4)
    elif roll == 2:
        s["type"] = "string"
        if rng.chance(2):
            s["minLength"] = rng.below(3)
        if rng.chance(3):
            s["format"] = "date-time"
    elif roll == 3:
        s["type"] = rng.pick(["number", "integer", "boolean", "null", ["string", "null"], ["integer", "boolean"]])
    elif roll == 4:
        s["enum"] = [rng.pick(["a", "b", 1, True, None]) for _ in range(1 + rng.below(3))]
    else:
        s["const"] = rng.pick(["a", 1, 1.0, True, None, [1], {"k": "v"}])
    if rng.chance(8):
        s[rng.pick(["pattern", "maxLength", "minimum", "oneOf", "$ref", "default"])] = 1
    if rng.chance(24):
        s["format"] = rng.pick(["email", "uri", "date"])
    return s


def gen_doc(rng, schema, aim):
    """A document; when `aim` is true, one meant to conform, else anything."""
    if not aim:
        return gen_value(rng, 0, [1 + rng.below(8)])
    if "const" in schema:
        return schema["const"] if rng.chance(4) else json.loads(json.dumps(schema["const"]))
    if "enum" in schema:
        return rng.pick(schema["enum"])
    t = schema.get("type")
    names = t if isinstance(t, list) else [t]
    t = rng.pick(names)
    if t == "object":
        doc = {k: gen_doc(rng, sub, rng.below(6) != 0) for k, sub in schema.get("properties", {}).items() if rng.below(4) != 0}
        for k in schema.get("required", []):
            if k not in doc and rng.below(6) != 0:
                doc[k] = gen_doc(rng, schema["properties"][k], True)
        if rng.chance(4):
            doc["extra"] = 1
        return doc
    if t == "array":
        n = rng.below(4)
        sub = schema.get("items", {})
        return [gen_doc(rng, sub, rng.below(6) != 0) for _ in range(n)]
    if t == "string":
        if schema.get("format") == "date-time":
            return rng.pick(DATES)
        return rng.pick(["", "a", "ab", "abc", "é"])
    if t == "integer":
        return rng.pick([0, 1, -3, 7])
    if t == "number":
        return rng.pick([0, 1.5, -2, 3.0])
    if t == "boolean":
        return rng.pick([True, False])
    if t == "null":
        return None
    return gen_value(rng, 0, [3])


def validator_findings(doc, schema):
    supported = schema_supported(schema)
    want = "refuse-schema" if not supported else ("accept" if conforms(doc, schema) else "refuse")
    try:
        _schema.validate(doc, schema, "$")
        got = "accept"
    except _schema.SchemaError as exc:
        text = str(exc)
        got = "refuse-schema" if ("unsupported keyword" in text or "does not implement" in text) else "refuse"
    except Exception as exc:  # noqa: BLE001 - a crash is a finding
        return ["validator raised %s: %s" % (type(exc).__name__, exc)]
    if want != got:
        return ["reference %s, validator %s" % (want, got)]
    return []


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Reference for the strict loader and the validator.")
    ap.add_argument("--texts", type=int, default=3000)
    ap.add_argument("--pairs", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=0x5C4E)
    ap.add_argument("--output", default=os.path.join(ROOT, "schema.out"))
    try:
        args = ap.parse_args()
    except SystemExit:
        return 1
    rng = Lcg(args.seed)
    started = time.monotonic()
    findings = 0
    accepted_texts = refused_texts = 0
    tally = {"accept": 0, "refuse": 0, "refuse-schema": 0}

    def record(kind, i, payload, what):
        nonlocal findings
        findings += 1
        os.makedirs(args.output, exist_ok=True)
        with open(os.path.join(args.output, "%s-%d-%d.json" % (kind, args.seed, i)), "w") as fh:
            json.dump({"input": payload, "finding": what}, fh, indent=1, ensure_ascii=False)
        print("FINDING %s %d: %s" % (kind, i, what), flush=True)

    for i in range(args.texts):
        text = gen_text(rng)
        f = loader_findings(text)
        if reference_loads(text)[0] == "accept":
            accepted_texts += 1
        else:
            refused_texts += 1
        if f:
            record("text", i, text, f)
    for i in range(args.pairs):
        schema = gen_schema(rng, 0)
        doc = gen_doc(rng, schema, rng.chance(2))
        want = "refuse-schema" if not schema_supported(schema) else ("accept" if conforms(doc, schema) else "refuse")
        tally[want] += 1
        f = validator_findings(doc, schema)
        if f:
            record("pair", i, {"schema": schema, "doc": doc}, f)
    print("schema: %d texts (%d accepted, %d refused), %d pairs %s, %d findings, %.1f s, seed %d" % (
        args.texts, accepted_texts, refused_texts, args.pairs, json.dumps(tally, sort_keys=True),
        findings, time.monotonic() - started, args.seed))
    return 2 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
