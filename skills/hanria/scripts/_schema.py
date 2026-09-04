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
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


class SchemaError(Exception):
    """The document does not conform, or the schema uses something unsupported."""


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


def validate(doc, schema, path="$"):
    """Raise SchemaError on the first violation. Returns None on success."""
    unsupported = set(schema) - SUPPORTED
    if unsupported:
        raise SchemaError(
            "schema at %s uses unsupported keyword(s) %s; this validator "
            "refuses rather than ignoring them"
            % (path, ", ".join(sorted(repr(u) for u in unsupported))))

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
        if schema.get("format") == "date-time" and not _RFC3339.match(doc):
            raise SchemaError(
                "%s must be an RFC 3339 date-time (a date, a time and an "
                "offset), not %r" % (path, doc))

    if isinstance(doc, list):
        if "minItems" in schema and len(doc) < schema["minItems"]:
            raise SchemaError("%s must have at least %d item(s)"
                              % (path, schema["minItems"]))
        if "maxItems" in schema and len(doc) > schema["maxItems"]:
            raise SchemaError("%s must have at most %d item(s)"
                              % (path, schema["maxItems"]))
        if "items" in schema:
            for i, item in enumerate(doc):
                validate(item, schema["items"], "%s[%d]" % (path, i))

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
                validate(value, props[key], "%s.%s" % (path, key))


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
