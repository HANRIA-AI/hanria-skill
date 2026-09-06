# The reference evaluator

`tools/model_evaluator.py` asks whether the checker's decisions are right
on mandates and actions nobody wrote down. It holds a second, independent
implementation of the documented rules (first match decides; every stated
condition must hold; canonical composition before prefix comparison; a
denial or escalation matches the written or the percent-decoded spelling,
a permission the written one only; a reserved kind escalates over a
permit; expiry and parent-directory segments decide before any clause; an
unreachable restricting clause refuses the mandate, with overlap defined
over kinds, verbs, prefix spellings, counterparties, currencies and
tiered ceilings), generates mandates and requests from small universes in
which every rule fires often, aims half the requests at one clause so the
accepting paths are reached, and compares the outcome and the clause
relied on with the checker's, calling the checker in process so thousands
of pairs cost seconds. A disagreement is a finding either way, in the
reference or in the checker, and is investigated as such.

## Where the rules are written

Every rule the reference encodes is stated for operators in `SKILL.md`,
`README.md` or `LIMITATIONS.md` except that, until the commit that added
this paragraph, the tiering carve-out (a later clause that also narrows a
bounded scope is dead below the earlier ceiling and refused) was stated
only in the checker's comments; it is now in the README's tiering
paragraph and the limitations file's unreachable-clause entry.

## What it found on 2026-09-06

No disagreement: two thousand pairs per push-gate run; two hundred
thousand pairs in 137 seconds on the first generator; three hundred
thousand in 213 seconds on the final one, whose verdicts were 128,629
denials, 65,775 refusals of an unreachable mandate, 79,142 escalations and
26,454 permits. The reference was written after the rules, from the
skill text, the schemas and the checker's stated semantics, and agreed
with the checker on its first run; that is worth less than a disagreement
would have been, and the negatives below are what give it weight.

## The reference proven able to disagree

Two slips introduced into copies of the checker: a permission that also
matched the percent-decoded spelling produced sixty-seven disagreements in
twenty thousand pairs; reserved kinds ignored produced two hundred and
twenty-four. Each disagreement carries the pair and both verdicts.

## Where it runs

The push gate runs two thousand pairs in under two seconds; under the
mutation harness that is paid once per mutant, and a mutant that changes a
decision now disagrees with the reference. The step was run under the
harness in a Linux container before commit. `fuzz.yml` runs as many pairs
as asked on dispatch, after the input fuzzer, and uploads findings.
