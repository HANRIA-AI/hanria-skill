# The input fuzzer

`tools/fuzz_inputs.py` asks the question the mutation harness does not:
whether the scripts, as they are, hold on inputs nobody wrote down. It
takes the example documents as seeds, mutates them at the byte level and at
the structural level, runs every mutated mandate-and-action pair through
`check_action.py`, and feeds whatever that produced to `record.py append`
on a fresh log and `record.py verify` on the result. A finding is a
traceback, an exit code outside the contract, standard output that is not
one JSON object, an outcome that does not conform to the published schema
or disagrees with the exit code, a recorder status that disagrees with the
exit code or an error without a reason, a non-deterministic run, an
invocation over five seconds, an append that succeeded but left a log that
does not verify, or a refused append that changed the log. Findings are
written with their inputs and the run exits 2. Standard library only.

## What it found on 2026-09-06

Nothing. Sixty cases on the push gate, four thousand cases in fifty-five
seconds on eight workers, and twenty thousand more, all without a finding.
The scripts' fail-closed handling of malformed input was pinned by hand on
2026-09-04 (invalid and overlong UTF-8, a byte-order mark, empty and
directory paths, NUL, a five-thousand-digit amount, an array where an
object belongs); the fuzzer reaches those and the shapes between them.

## What the first draft got wrong

The recorder's output is a status object, not an action outcome, and the
first judge held both scripts to the outcome schema, so every case was a
false finding until the judges were split: the checker's outcome against
its schema and exit code, the recorder's status against its exit code.

## The fuzzer proven able to find

A copy of the checker was made to raise on any mandate whose text
contains the six characters of the JSON escape for NUL, backslash-u-0000;
three hundred cases against it produced six findings, each with the
traceback and the inputs, and exit 2.

## Where it runs

The push gate runs sixty cases in about three seconds; under the mutation
harness that is paid once per mutant, and the step was run under the
harness in a Linux container before commit. `fuzz.yml` runs as many cases
as asked on every core of a runner, on dispatch, and uploads any finding
with the run.
