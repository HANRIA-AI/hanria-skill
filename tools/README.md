# tools/mutants.py

A mutation run of the four scripts under `skills/hanria/scripts/` against this
repository's own checks. Every guard in the scripts is meant to have a step in
`.github/workflows/checks.yml` that fails without it; this makes that a
mechanical claim rather than a habit.

How it works. Each mutant is one small change to one script, made on the
syntax tree: a comparison operator swapped, `and` for `or`, a `not` dropped, an
`if` condition forced false, a `raise` replaced by `pass`, a call statement
removed, `True` for `False`, an integer literal incremented. The mutated script
is written into a copy of the repository and every `run:` step of the workflow
is executed against that copy, in order, stopping at the first failure. A mutant
no step fails on is a survivor.

The baseline. Mutants are written back with `ast.unparse`, which drops comments
and reformats. Before any mutant runs, all four scripts are re-written that way
unmutated and the steps must pass, so a survivor is a statement about behaviour
and not about formatting.

Running it. Needs Python 3.9 or later and `pyyaml` (to read the workflow).

    python3 tools/mutants.py --list                  # print the mutants
    python3 tools/mutants.py --jobs 4                # run them all
    python3 tools/mutants.py --re 'record.py'        # a subset, by regex
    python3 tools/mutants.py --names missed.txt      # exactly these, by name

Each mutant runs in its own copy of the repository, and every `/tmp/` path a
step writes is rewritten to a scratch directory inside that copy, so parallel
runs cannot clobber one another's fixtures. Each step runs in its own process
group; a step that exceeds `--step-timeout` is killed with its whole tree and
run once more, and only a second stall counts as a timeout, since a loaded
machine stalls a step the same way an infinite loop does. The baseline gets a
second attempt on the same reasoning, and prints the failing step's output.
Every step starts with the interrupt signal at its default: a shell launches a
background job with that signal ignored and every child inherits it, and the
step that interrupts a script would otherwise wait for an exit that never comes.
Every step is also told, in `HANRIA_MUTANTS_SOURCE_TREE`, where the scripts
were read from: in the copy it runs in the mutated script has been
re-unparsed, its line numbers moved (in the baseline, all four), and a step
that reads the scripts as data rather than running them (`check_lists.py`)
must read the tree as it is. Outside the harness the
variable is unset and that tree is the checkout.

Output goes to `mutants.out/` (`caught.txt`, `missed.txt`, `timeout.txt`). Exit
codes follow cargo-mutants: 0 all caught, 2 survivors, 3 timeouts, 4 baseline
failed, 1 usage (a `--names` file naming mutants that no longer exist is a
usage error: the list is stale).

`equivalent.txt` lists the survivors no step can kill on the shipped tree, one
per line in the harness's own naming, each with its reason in `EQUIVALENT.md`.
`timeouts.txt` lists the mutants that make a script loop or read forever, which
a step detects only by not finishing. The dispatch-only workflow `mutants.yml`
fails unless the survivors are exactly the first list and the timeouts exactly
the second. The names carry line and column, so an edit that moves a listed
site must move its line here too. `check_lists.py`, on the push gate, refuses a
listed name that no longer exists and an equivalent without a cited reason,
in about a second, so a stale list fails before the dispatch would; the
dispatch prints the diff when it fails.

Limits. The steps take a minute or more per run, so a full sweep is hours, not
minutes, and it is not on the push gate. The operators are the common ones, not
all of them: string literals, arithmetic, and return values are not mutated, so
a survivor-free run says every listed kind of change is caught, no more.

## The input fuzzer

`tools/fuzz_inputs.py` mutates the example documents and runs every pair
through both scripts, judging tracebacks, exit codes, output shape, schema
conformance, determinism, time, and the recorder's log; sixty cases on the
push gate, as many as asked on dispatch (`fuzz.yml`). See
`tools/FUZZ-INPUTS-2026-09-06.md`.

## The reference evaluator

`tools/model_evaluator.py` holds a second implementation of the documented
evaluation rules and compares it with the checker on generated mandates
and requests, outcome and clause alike; two thousand pairs on the push
gate, as many as asked on dispatch (`fuzz.yml`). See
`tools/MODEL-EVALUATOR-2026-09-06.md`.
