# The schema exerciser

`tools/schema_exerciser.py` holds an independent reading of the two
functions every document passes through, `_schema.loads` and
`_schema.validate`, and compares it with the module on generated inputs.

For the loader, a text is accepted exactly when it is valid JSON with no
object naming a key twice, no NaN or Infinity literal and no number that
overflows to one, at most the published size, and a structure nesting at
most the published depth. The reference decides
depth from the parsed structure; the loader decides it from a scan of the
text before parsing, so the scan is checked against the thing it
approximates, and brackets inside strings are the case that tells the two
apart. Generated texts include duplicate keys, the non-JSON literals,
trailing and leading junk, a byte-order mark, raw control characters and
lone surrogates inside strings, chains to either side of the depth bound,
and runs of seventy brackets inside a string.

For the validator, a document conforms exactly when every constraint the
schema states holds at every path reached, with the module's meaning for
each implemented keyword: `const`, `enum`, `type` including a list of
types and a boolean being neither an integer nor a number, `minLength`,
`format` date-time as RFC 3339 with a real calendar date, `minItems`,
`maxItems`, `items`, `required`, `properties`, and `additionalProperties`
false; a schema using any other keyword or format anywhere is refused
before any document is judged. The reference checks the date-time by
parsing it, not by the module's pattern. Generated schemas draw from the
supported keywords, one time in eight with an unsupported one somewhere,
and documents are drawn to satisfy the schema about half the time.

## What it found on 2026-09-06

No disagreement: three thousand texts and three thousand pairs per
push-gate run, two hundred thousand of each in ten seconds before the
bracket-run shape was added, three hundred thousand of each in fifteen
seconds after it, and three hundred thousand of each in 22 seconds after the module fixes.

## What its audit found in the module

The audit of the first draft found two defects in `_schema.py`, both
fail-open. The date-time pattern ended in a dollar sign, which in Python's
regular expressions matches before a trailing newline, so a date-time with
a newline appended passed as a date-time; the anchor is now the end of the
string. And a number too large for a float, such as 1e999, became
infinity in the parser and was accepted, although the literal Infinity is
refused on the ground that a value that is not JSON was never validated by
anything; an overflowing number is now refused on the same ground. The
helper for that is defined at the end of the module so that no line the
mutation lists name moved; its five mutants are all caught. A hand case on
the push gate pins both, the reference refuses both, the generator now
draws a trailing-newline date-time and overflowing numbers, and with each
fix reverted in a copy the exerciser disagrees.

The audit also corrected the claim that the validator carries JSON
Schema's meaning throughout: `const` and `enum` compare by Python
equality, so a boolean equals its integer and 1 equals 1.0, and `integer`
means a Python int, so 3.0 is not one. The reference encodes those two
departures the same way, so that it can check everything else, and says
so. The size bound was unexercised by the first generator; it now draws
texts exactly at the bound and one byte over it, rarely, since each is a
megabyte.

## The reference proven able to disagree

Six slips introduced into copies of the module: duplicate keys tolerated
produced fifty-seven disagreements in six thousand texts; brackets inside
strings counted toward depth produced two hundred and ninety-seven, once
the generator produced strings with more brackets than the bound (the
first generator never did, and that negative found nothing until it was
made to); a boolean accepted as an integer produced nine in six thousand
pairs; any string accepted as a date-time produced sixty-three; the
dollar anchor restored produced fourteen; the overflow accepted again produced
three hundred and twenty-one.

## Where it runs

The push gate runs three thousand of each in a fifth of a second; under
the mutation harness that is paid once per mutant, and the step and the
hand case were run under the harness in a Linux container before commit. `fuzz.yml` runs as
many as asked on dispatch, after the other three, and uploads findings.
