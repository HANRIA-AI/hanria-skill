#!/usr/bin/env python3
"""Check the two survivor lists against the mutants that exist and the reasons given.

Every line of `equivalent.txt` and `timeouts.txt` must name a mutant the harness
would generate from the scripts as they are, and every `equivalent.txt` entry
must have its file and line cited in `EQUIVALENT.md`. A listed name that no
longer exists is a stale list: the source moved under it, and the dispatch
workflow would fail hours later on the diff. This runs in seconds on the push
gate instead.

Exit 0 when both lists are clean, 1 otherwise, with each problem on its own line.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mutants  # noqa: E402


def main():
    # Under the mutation harness this runs inside a copy of the tree in which
    # the mutated script has been re-unparsed, so its line numbers have moved
    # and one site has changed; in the baseline all four are re-unparsed and
    # none is mutated.
    # The harness names the tree the scripts were read from; the lists are
    # checked against that tree, so the check decides the same question in
    # both places. Outside the harness the variable is unset and the tree is
    # this checkout.
    root = os.environ.get("HANRIA_MUTANTS_SOURCE_TREE") or mutants.ROOT
    existing = set()
    for path in mutants.TARGETS:
        source = open(os.path.join(root, path), encoding="utf-8").read()
        for mutant, _ in mutants.generate(path, source):
            existing.add(mutant.name())
    reasons = open(os.path.join(HERE, "EQUIVALENT.md"), encoding="utf-8").read()
    cited, current = set(), None
    for file, line, bare in re.findall(r"`([a-z_]+\.py):(\d+)`|`:(\d+)`", reasons):
        if file:
            current = file
            cited.add((file, line))
        elif current:
            cited.add((current, bare))
    problems = []
    for list_name in ("equivalent.txt", "timeouts.txt"):
        for raw in open(os.path.join(HERE, list_name), encoding="utf-8"):
            name = raw.strip()
            if not name:
                continue
            if name not in existing:
                problems.append("%s: no such mutant now: %s" % (list_name, name))
            if list_name == "equivalent.txt":
                file, line = name.split(":")[0].split("/")[-1], name.split(":")[1]
                if (file, line) not in cited:
                    problems.append("equivalent.txt: no reason cited in EQUIVALENT.md for %s" % name)
    for problem in problems:
        print(problem)
    print("%d listed, %d problems" % (
        sum(1 for l in open(os.path.join(HERE, "equivalent.txt")) if l.strip())
        + sum(1 for l in open(os.path.join(HERE, "timeouts.txt")) if l.strip()), len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
