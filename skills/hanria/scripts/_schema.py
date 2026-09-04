#!/usr/bin/env python3
"""A small JSON Schema validator, standard library only.

Why this exists. The checker previously hand-wrote its validation: it looked for
the fields it cared about and ignored the rest. That is fine until something
claims the input was validated *against the published schema*, which is a much
larger promise -- and the gap between the two is where malformed input slipped
through and was evaluated anyway. Validating against the actual schema file
makes the promise and the behaviour the same thing.

It implements the subset the HANRIA schemas use, and REFUSES any schema keyword
it does not implement, so this file can never silently ignore a constraint the
way the hand-written checks did:

    type, required, properties, additionalProperties, items, enum, const,
    minLength, minItems, maxItems, format (date-time only), $schema, $id,
    title, description, $comment

`format: date-time` is enforced as RFC 3339, not as whatever
`datetime.fromisoformat` happens to accept -- it accepts date-only strings,
which are not date-times.
"""
import datetime as _dt
import json
import re

SUPPORTED = {
    "$schema", "$id", "title", "description", "$comment",
    "type", "required", "properties", "additionalProperties",
    "items", "enum", "const", "minLength", "minItems", "maxItems", "format",
}

_TYPES = {
    "object": dict, "array": list, "string": str,
    "number": (int, float), "integer": int, "boolean": bool, "null": type(None),
}

# RFC 3339 date-time: a full date, a time, and an offset (or Z).
# RFC 3339 5.6: date-time = full-date "T" full-time. The separator is T (or t);
# a space is the ISO 8601 alternative and is not this format. Second 60 is a
# legal leap second and must be accepted.
_RFC3339 = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"[Tt](?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(\.\d+)?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$")


def _check_date_time(value, path):
    """RFC 3339 shape AND a real calendar date.

    The pattern alone accepts 2026-02-31: bounded digits are not a calendar.
    """
    if not _RFC3339.match(value):
        raise SchemaError("%s must be an RFC 3339 date-time (a date, a time and "
                          "an offset), not %r" % (path, value))
    try:
        _dt.date(int(value[0:4]), int(value[5:7]), int(value[8:10]))
    except ValueError:
        raise SchemaError("%s is not a real calendar date: %r" % (path, value))


_FORMATS = {"date-time": _check_date_time}


class SchemaError(Exception):
    """The document does not conform, or the schema uses something unsupported."""


def _no_constants(literal):
    # json.load accepts Python's NaN, Infinity and -Infinity, which are not JSON.
    raise SchemaError("the document contains the non-JSON literal %r; a value "
                      "that is not JSON was never validated by anything"
                      % literal)


def _no_duplicates(pairs):
    """Reject duplicate object names instead of silently keeping the last.

    A reviewer reading {"effect": "deny", "effect": "permit"} sees the denial.
    Python's json keeps the last value, so the evaluator would see the
    permission. Nothing about that is safe to resolve automatically.
    """
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise SchemaError(
                "the document defines %r more than once. A reader sees the "
                "first value and a parser keeps the last, so the two disagree "
                "about what was written." % key)
        seen[key] = value
    return seen


# Validated bounds on any document this layer reads. Both are refused with a
# named reason before parsing, so exceeding them is a decision, not a crash.
# A mandate, a request or a log entry that needs more than this is not a
# shape this skill was written for.
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NESTING_DEPTH = 64


def nesting_depth(text):
    """Deepest bracket nesting in `text`, ignoring brackets inside strings.

    Scans the raw characters so the bound is checked before json.loads
    recurses. Malformed input is not diagnosed here; it is left to the parser,
    which reports it as invalid JSON.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
        elif ch in "]}":
            depth -= 1
    return deepest


def check_bounds(text, what="document"):
    """Refuse a document that exceeds the published size or nesting bound."""
    size = len(text.encode("utf-8")) if isinstance(text, str) else len(text)
    if size > MAX_DOCUMENT_BYTES:
        raise SchemaError(
            "%s is %d bytes; the bound is %d bytes. Nothing that large is a "
            "shape this skill evaluates." % (what, size, MAX_DOCUMENT_BYTES))
    depth = nesting_depth(text)
    if depth > MAX_NESTING_DEPTH:
        raise SchemaError(
            "%s nests %d levels deep; the bound is %d. Nothing that deep is a "
            "shape this skill evaluates." % (what, depth, MAX_NESTING_DEPTH))


def read_bounded(fh, what="document"):
    """Read at most the size bound plus one character from an open text file.

    The bound is applied to what was read, so a file larger than the bound is
    never materialized past it: at most MAX_DOCUMENT_BYTES + 1 characters are
    read (up to four bytes each), and the first check then refuses it by
    name. Use this instead of fh.read() for any document this layer reads.
    """
    text = fh.read(MAX_DOCUMENT_BYTES + 1)
    check_bounds(text, what)
    return text


def readline_bounded(fh, what="document"):
    """Read one line, at most the size bound plus one character of it.

    Returns None at end of file. A line longer than the bound is refused by
    name without reading the rest of it.
    """
    line = fh.readline(MAX_DOCUMENT_BYTES + 1)
    if line == "":
        return None
    if len(line) > MAX_DOCUMENT_BYTES and not line.endswith("\n"):
        raise SchemaError(
            "%s is longer than %d bytes; the bound is %d bytes. Nothing that "
            "large is a shape this skill evaluates."
            % (what, MAX_DOCUMENT_BYTES, MAX_DOCUMENT_BYTES))
    return line


def loads(text, what="document"):
    """Parse JSON strictly. Anything ambiguous is refused, not resolved.

    Size and nesting are checked against the published bounds first, so a
    document past either bound is refused with a named reason before the
    parser runs. Callers that read from a file should use read_bounded so the
    size bound also limits what is read, not only what is parsed.
    """
    check_bounds(text, what)
    try:
        return json.loads(text, parse_constant=_no_constants,
                          object_pairs_hook=_no_duplicates)
    except SchemaError:
        raise
    except json.JSONDecodeError as exc:
        raise SchemaError("%s is not valid JSON: %s" % (what, exc))
    except RecursionError:
        raise SchemaError("%s is nested beyond what the parser can handle; the "
                          "published bound is %d levels" % (what, MAX_NESTING_DEPTH))


def _type_ok(value, expected):
    if isinstance(expected, list):
        return any(_type_ok(value, e) for e in expected)
    py = _TYPES.get(expected)
    if py is None:
        raise SchemaError("unsupported type %r in schema" % expected)
    # JSON has no separate boolean-as-number; do not let True satisfy "number".
    if expected in ("number", "integer") and isinstance(value, bool):
        return False
    return isinstance(value, py)


def check_schema(schema, path="$"):
    """Walk the whole schema and refuse any keyword or format not implemented.

    Doing this only while traversing a document would miss every branch the
    document does not reach -- an unimplemented constraint under an absent
    property, or inside the items of an empty array, would be "supported"
    purely because nothing went there.
    """
    unsupported = set(schema) - SUPPORTED
    if unsupported:
        raise SchemaError(
            "schema at %s uses unsupported keyword(s) %s; this validator "
            "refuses rather than ignoring them"
            % (path, ", ".join(sorted(repr(u) for u in unsupported))))
    if "format" in schema and schema["format"] not in _FORMATS:
        raise SchemaError("schema at %s uses format %r, which this validator "
                          "does not implement" % (path, schema["format"]))
    for key, sub in schema.get("properties", {}).items():
        check_schema(sub, "%s.%s" % (path, key))
    if "items" in schema:
        check_schema(schema["items"], path + "[]")


def validate(doc, schema, path="$", _checked=False):
    """Raise SchemaError on the first violation. Returns None on success."""
    if not _checked:
        check_schema(schema, path)
        _checked = True

    if "const" in schema and doc != schema["const"]:
        raise SchemaError("%s must be %r, not %r" % (path, schema["const"], doc))

    if "enum" in schema and doc not in schema["enum"]:
        raise SchemaError("%s must be one of %s, not %r"
                          % (path, schema["enum"], doc))

    if "type" in schema and not _type_ok(doc, schema["type"]):
        raise SchemaError("%s must be of type %s, not %s"
                          % (path, schema["type"], type(doc).__name__))

    if isinstance(doc, str):
        if "minLength" in schema and len(doc) < schema["minLength"]:
            raise SchemaError("%s must be at least %d character(s)"
                              % (path, schema["minLength"]))
        if "format" in schema:
            fmt = schema["format"]
            if fmt not in _FORMATS:
                raise SchemaError(
                    "schema at %s uses format %r, which this validator does not "
                    "implement; it refuses rather than ignoring it" % (path, fmt))
            _FORMATS[fmt](doc, path)

    if isinstance(doc, list):
        if "minItems" in schema and len(doc) < schema["minItems"]:
            raise SchemaError("%s must have at least %d item(s)"
                              % (path, schema["minItems"]))
        if "maxItems" in schema and len(doc) > schema["maxItems"]:
            raise SchemaError("%s must have at most %d item(s)"
                              % (path, schema["maxItems"]))
        if "items" in schema:
            for i, item in enumerate(doc):
                validate(item, schema["items"], "%s[%d]" % (path, i), True)

    if isinstance(doc, dict):
        for field in schema.get("required", []):
            if field not in doc:
                raise SchemaError("%s is missing required field %r" % (path, field))
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(doc) - set(props)
            if extra:
                raise SchemaError("%s has unrecognized field(s) %s"
                                  % (path, ", ".join(sorted(repr(e) for e in extra))))
        for key, value in doc.items():
            if key in props:
                validate(value, props[key], "%s.%s" % (path, key), True)


def load(path, what=None):
    with open(path, "r", encoding="utf-8") as fh:
        return loads(read_bounded(fh, what or path), what or path)
