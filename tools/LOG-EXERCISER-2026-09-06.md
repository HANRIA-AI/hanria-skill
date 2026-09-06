# The log exerciser

`tools/log_exerciser.py` asks whether the hash-chained decision log's
integrity rules hold under tamperings nobody wrote down. It builds real
logs through `record.py append` from the example actions and their real
outcomes, applies seeded sequences of tamperings to the log and its head
file, and after every one asks `record.py verify`, one time in three with
the head retained before any tampering and advanced only by an append the
exerciser saw succeed, one time in three with a wrong head, one time in
three with none, and then asks `append` to extend the log, while an
independent model of the chain predicts the exact verdict: exit code,
status and position for verify; a refusal that leaves both files byte for
byte as they were, or a success, for append.

The tamperings: a byte altered inside an entry's body; an entry's digest,
predecessor or index altered; an entry dropped; two entries swapped; the
tail truncated; a field added to an entry; a key duplicated in an entry
line; an entry's JSON broken; the head file deleted, corrupted, its count
set wrong, or its digest set wrong; a chain-consistent entry forged at the
end; and the last entry dropped with the head rewritten to match, which
only a head retained elsewhere detects, including when it empties the log.

The model encodes the recorder's stated order of checks: the four fields
present, nothing beyond them, index equal to position, predecessor equal
to the digest before, digest equal to the digest of predecessor and
canonical body, the first failure reported at its position; an unreadable
line or a duplicate key an error rather than a broken chain; every line
read first, then an unreadable head broken before any entry is checked; an
empty log against a retained head or a counting head broken at zero; after
the chain, a retained
head passed on the command line over
the file's, a mismatched head broken, then a mismatched count broken; no
head at all intact with truncation unchecked. The digest itself is the
one rule the model does not hold independently: it computes digests with
the recorder's own helpers, so a change to the digest function would move
both sides alike; that function is pinned by hand elsewhere in the
workflow against fixed vectors.

## What it found on 2026-09-06

No disagreement: forty logs and 127 tamperings on the first run, eight
logs per push-gate run, five hundred logs with 1,465 tamperings in 97
seconds before the retained head was added, five hundred logs with
1,460 tamperings in 99 seconds after it, and five hundred logs with 1,515
tamperings in 99 seconds after the recorder's fix.

## What its audit found in the recorder

The audit of the first draft observed that when the log is empty the
recorder never consulted a retained head: a log truncated to nothing
passed an operator's pin as `empty`, exit 0, which is the one truncation
a retained head exists to catch. The recorder now refuses an empty log
against a retained head as broken at position zero, the model predicts
it, a hand case on the push gate pins it, and with the fix reverted in a
copy the exerciser produced twenty-one disagreements in two hundred logs.
The change moved the line numbers of twenty-eight listed record.py
mutants; each was re-identified against the live listing and the reasons
file follows. Two mutants of the new branch survive and are listed with
their reasons: its indentation, and the sixteen-character prefix of the
retained head in its reason string, the two classes already on the list.

## The model proven able to disagree

Four slips introduced into copies of the recorder: the count check
skipped produced one disagreement in sixty logs, on a head whose count was
set wrong; append no longer refusing a broken chain produced one hundred
and six, each an append that changed files the model said must stay as
they were; verify ignoring the retained head and reading the file's only
produced thirteen, among them a deleted head file the retained head still
pinned and a wrong file head the retained head overrode; and the
empty-log fix reverted produced twenty-one in two hundred logs.

## Where it runs

The push gate runs eight logs in under two seconds; under the mutation
harness that is paid once per mutant, and both that step and the hand
case for the empty log against a retained head were run under the harness
in a Linux container before commit. `fuzz.yml` runs as many logs
as asked on dispatch, after the input fuzzer and the reference evaluator,
and uploads findings.
