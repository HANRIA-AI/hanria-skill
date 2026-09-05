#!/usr/bin/env python3
"""Mutation run of the skill's scripts against the workflow's own steps.

Every guard in the scripts should have a step in `.github/workflows/checks.yml`
that fails without it. This makes that a mechanical claim: each mutant is one
small change to one script, written into a copy of the repository, and every
`run:` step of the workflow is executed against that copy. A mutant that
survives every step is a guard no step holds.

Standard library only. Mutants are built on the syntax tree and written back
with `ast.unparse`, so comments are dropped; the baseline run first confirms the
steps pass on the re-written but unmutated sources, which is what makes a
survivor a statement about behaviour rather than formatting.

Operators: comparison swap (== != < <= > >= in not-in is is-not), boolean
and/or swap, `not x` -> `x`, `if cond` -> `if False`, `raise` -> `pass`, a
call statement removed, True <-> False, an integer literal incremented.

Exit codes follow cargo-mutants: 0 all caught, 2 survivors, 3 timeouts,
4 baseline failed, 1 usage (including a --names file naming mutants that no
longer exist: the list is stale and the run would answer a different question).
"""
import argparse
import ast
import concurrent.futures
import copy
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = [
    "skills/hanria/scripts/_schema.py",
    "skills/hanria/scripts/check_action.py",
    "skills/hanria/scripts/record.py",
    "skills/hanria/scripts/detect_runtime.py",
]
WORKFLOW = ".github/workflows/checks.yml"

COMPARE_SWAPS = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE, ast.LtE: ast.Lt,
    ast.Gt: ast.GtE, ast.GtE: ast.Gt,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
    ast.Is: ast.IsNot, ast.IsNot: ast.Is,
}


class Mutant:
    def __init__(self, path, node, description):
        self.path = path
        self.line = getattr(node, "lineno", 0)
        self.col = getattr(node, "col_offset", 0)
        self.description = description

    def name(self):
        return "%s:%d:%d: %s" % (self.path, self.line, self.col + 1, self.description)


def _walk_with_parents(tree):
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if isinstance(value, list):
                for index, child in enumerate(value):
                    if isinstance(child, ast.AST):
                        yield parent, field, index, child
            elif isinstance(value, ast.AST):
                yield parent, field, None, value


def generate(path, source):
    """Yield (Mutant, mutated_source) for one file.

    One parse; each site is mutated in place, the tree unparsed, and the
    change reverted, so generation is linear in the number of sites.
    """
    tree = ast.parse(source, filename=path)
    sites = []
    for parent, field, index, node in _walk_with_parents(tree):
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                swap = COMPARE_SWAPS.get(type(op))
                if swap is not None:
                    sites.append(("compare", parent, field, index, node, i, swap))
        elif isinstance(node, ast.BoolOp):
            sites.append(("boolop", parent, field, index, node, None,
                          ast.Or if isinstance(node.op, ast.And) else ast.And))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            sites.append(("not", parent, field, index, node, None, None))
        elif isinstance(node, ast.If):
            sites.append(("if-false", parent, field, index, node, None, None))
        elif isinstance(node, ast.Raise):
            sites.append(("raise", parent, field, index, node, None, None))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            sites.append(("call", parent, field, index, node, None, None))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            sites.append(("bool", parent, field, index, node, None, None))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, int)
              and not isinstance(node.value, bool)):
            sites.append(("int", parent, field, index, node, None, None))
    for kind, parent, field, index, node, extra, swap in sites:
        if kind == "compare":
            original = node.ops[extra]
            node.ops[extra] = swap()
            desc = "replace %s with %s" % (_opname(original), _opname(swap()))
            yield Mutant(path, node, desc), ast.unparse(tree) + "\n"
            node.ops[extra] = original
        elif kind == "boolop":
            original = node.op
            node.op = swap()
            desc = "replace %s with %s" % (_opname(original), _opname(swap()))
            yield Mutant(path, node, desc), ast.unparse(tree) + "\n"
            node.op = original
        elif kind == "not":
            _replace(parent, field, index, node.operand)
            yield Mutant(path, node, "delete not"), ast.unparse(tree) + "\n"
            _replace(parent, field, index, node)
        elif kind == "if-false":
            original = node.test
            node.test = ast.Constant(value=False)
            yield Mutant(path, node, "replace if condition with False"), ast.unparse(tree) + "\n"
            node.test = original
        elif kind == "raise":
            _replace(parent, field, index, ast.Pass())
            yield Mutant(path, node, "replace raise with pass"), ast.unparse(tree) + "\n"
            _replace(parent, field, index, node)
        elif kind == "call":
            callee = ast.unparse(node.value.func)
            _replace(parent, field, index, ast.Pass())
            yield Mutant(path, node, "delete call to %s" % callee), ast.unparse(tree) + "\n"
            _replace(parent, field, index, node)
        elif kind == "bool":
            original = node.value
            node.value = not original
            yield Mutant(path, node, "replace %s with %s" % (original, not original)), ast.unparse(tree) + "\n"
            node.value = original
        else:
            original = node.value
            node.value = original + 1
            yield Mutant(path, node, "replace %d with %d" % (original, original + 1)), ast.unparse(tree) + "\n"
            node.value = original


def _replace(parent, field, index, new):
    if index is None:
        setattr(parent, field, new)
    else:
        getattr(parent, field)[index] = new


def _opname(op):
    return {
        ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">",
        ast.GtE: ">=", ast.In: "in", ast.NotIn: "not in", ast.Is: "is",
        ast.IsNot: "is not", ast.And: "and", ast.Or: "or",
    }[type(op)]


def workflow_steps():
    """The workflow's run steps, in order, as (name, script) with the pip line dropped."""
    import yaml  # noqa: PLC0415 - optional; CI installs it, local runs have it
    steps = yaml.safe_load(open(os.path.join(ROOT, WORKFLOW)))["jobs"]["verify"]["steps"]
    out = []
    for step in steps:
        if "run" not in step:
            continue
        body = "\n".join(l for l in step["run"].split("\n") if "pip install" not in l)
        out.append((step.get("name", "?"), body))
    return out


def copy_repo(dest):
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "mutants.out", "__pycache__",
                                                              "step-tmp"),
                    dirs_exist_ok=True)


def run_steps(tree, steps, step_timeout):
    """Return ('caught', step) at the first failing step, ('timeout', step), or ('survived', None).

    The workflow's steps write their fixtures under /tmp by literal path. Runs
    in parallel would clobber one another's fixtures there, so every "/tmp/"
    in a step is rewritten to a scratch directory private to this run.
    """
    scratch = os.path.join(tree, "step-tmp")
    os.makedirs(scratch, exist_ok=True)
    for name, body in steps:
        body = body.replace("/tmp/", scratch + "/")
        result = None
        # A step that runs out of time is run once more before it counts as a
        # timeout: a loaded machine stalls a step the same way an infinite
        # loop does, and only the second stall is evidence about the mutant.
        for _attempt in (1, 2):
            # Each step runs in its own process group so that a timeout kills
            # the whole tree, not only the shell: a mutant that makes a script
            # loop forever must not leave that script running.
            # SIGINT is reset to its default for the step: a shell starts a
            # background job with it ignored, every child inherits that, and
            # the step that interrupts a script would then wait forever.
            # preexec_fn runs in a pool worker process, which has no threads
            # of its own, so the documented thread hazard does not apply.
            # In the copy the mutated script has been re-unparsed (in the
            # baseline, all four). A step that reads the scripts as data
            # rather than running them (the list check) must read the scripts
            # as they are, so every step is told where those are. Without
            # this, the list check reported the listed names in the
            # re-unparsed script as missing, all but the few whose line and
            # column coincide after re-unparsing, which caught every mutant
            # of that script and failed the baseline outright (found
            # 2026-09-05 before the step ever ran on GitHub).
            proc = subprocess.Popen(["bash", "-eo", "pipefail", "-c", body], cwd=tree,
                                    env=dict(os.environ, HANRIA_MUTANTS_SOURCE_TREE=ROOT),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True,
                                    preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
            try:
                out, err = proc.communicate(timeout=step_timeout)
                result = proc
                break
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                proc.communicate()
                result = None
        if result is None:
            return "timeout", name
        if result.returncode != 0:
            # The whole of both streams: a kill that is really the step
            # failing for its own reasons is only explicable from all of it.
            run_steps.last_failure = ("--- stdout ---\n" + (out or b"").decode("utf-8", "replace")
                                      + "\n--- stderr ---\n" + (err or b"").decode("utf-8", "replace")
                                      + "\n--- exit %d ---\n" % result.returncode)
            return "caught", name
    return "survived", None


def _run_one(args):
    mutant_name, path, mutated, steps, step_timeout, logs = args
    tree = tempfile.mkdtemp(prefix="hanria-mutant-")
    try:
        copy_repo(tree)
        with open(os.path.join(tree, path), "w", encoding="utf-8") as fh:
            fh.write(mutated)
        started = time.time()
        run_steps.last_failure = None
        outcome, step = run_steps(tree, steps, step_timeout)
        if outcome == "caught" and logs:
            # Evidence of the kill: which step, and what it printed. A kill
            # that is really a step failing for its own reasons shows here.
            with open(os.path.join(logs, _log_name(mutant_name)), "w", encoding="utf-8") as fh:
                fh.write("%s\ncaught by %r\n\n%s\n" % (mutant_name, step, run_steps.last_failure or ""))
        return mutant_name, outcome, step, time.time() - started
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def _log_name(mutant_name):
    # The sanitized name is not injective (every operator becomes "_"), so a
    # short digest of the full name keeps two mutants' logs apart.
    import hashlib
    digest = hashlib.sha256(mutant_name.encode("utf-8")).hexdigest()[:8]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", mutant_name)[:160] + "-" + digest + ".log"


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, which here means survivors. Usage is 1."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    ap = _Parser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="list mutants and exit")
    ap.add_argument("--re", default=None, help="only mutants whose name matches this regex")
    ap.add_argument("--names", default=None,
                    help="only mutants whose exact name is a line of this file (a previous "
                         "missed.txt or timeout.txt; a trailing '  [step]' is ignored)")
    ap.add_argument("--file", action="append", default=None, help="only this target (repeatable)")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--step-timeout", type=float, default=300.0)
    ap.add_argument("--output", default=os.path.join(ROOT, "mutants.out"))
    ap.add_argument("--baseline", choices=["run", "skip"], default="run")
    args = ap.parse_args()

    targets = args.file or TARGETS
    sources = {path: open(os.path.join(ROOT, path), encoding="utf-8").read() for path in targets}
    wanted = None
    if args.names:
        wanted = set()
        for line in open(args.names, encoding="utf-8"):
            line = line.split("  [")[0].strip()
            if line:
                wanted.add(line)
    mutants = []
    for path in targets:
        for mutant, mutated in generate(path, sources[path]):
            if args.re and not re.search(args.re, mutant.name()):
                continue
            if wanted is not None and mutant.name() not in wanted:
                continue
            mutants.append((mutant.name(), path, mutated))
    if wanted is not None:
        missing = wanted - {name for name, _, _ in mutants}
        if missing:
            print("%d named mutants no longer exist (the source moved); the list is stale:"
                  % len(missing))
            for name in sorted(missing):
                print("  " + name)
            return 1
    if args.list:
        for name, _, _ in mutants:
            print(name)
        return 0

    steps = workflow_steps()
    os.makedirs(args.output, exist_ok=True)
    print("%d mutants over %d files; %d workflow steps; %d jobs" % (
        len(mutants), len(targets), len(steps), args.jobs), flush=True)

    if args.baseline == "run":
        # Every target re-written by ast.unparse, none mutated: the steps must
        # pass, or a survivor could be formatting rather than behaviour.
        tree = tempfile.mkdtemp(prefix="hanria-baseline-")
        try:
            copy_repo(tree)
            for path, source in sources.items():
                with open(os.path.join(tree, path), "w", encoding="utf-8") as fh:
                    fh.write(ast.unparse(ast.parse(source, filename=path)) + "\n")
            started = time.time()
            # The baseline gets one more attempt: a step that fails only under
            # a momentary load spike is not a statement about the sources.
            for _attempt in (1, 2):
                outcome, step = run_steps(tree, steps, args.step_timeout)
                if outcome == "survived":
                    break
                print("baseline attempt %d failed at step %r (%s)" % (_attempt, step, outcome), flush=True)
                if getattr(run_steps, "last_failure", None):
                    print(run_steps.last_failure, flush=True)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        if outcome != "survived":
            print("baseline failed at step %r (%s); the steps must pass on the re-written sources"
                  % (step, outcome))
            return 4
        print("baseline passed in %.0fs" % (time.time() - started), flush=True)

    caught, missed, timeouts = [], [], []
    logs = os.path.join(args.output, "logs")
    os.makedirs(logs, exist_ok=True)
    work = [(name, path, mutated, steps, args.step_timeout, logs) for name, path, mutated in mutants]
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(_run_one, item) for item in work]
        # Reported as each finishes, not in submission order: one mutant that
        # loops forever must not hold back the report of every later one.
        for future in concurrent.futures.as_completed(futures):
            name, outcome, step, seconds = future.result()
            tag = {"caught": "CAUGHT ", "survived": "MISSED ", "timeout": "TIMEOUT"}[outcome]
            print("%s %s%s (%.0fs)" % (tag, name, (" by %r" % step) if step else "", seconds),
                  flush=True)
            {"caught": caught, "survived": missed, "timeout": timeouts}[outcome].append(
                name if outcome == "survived" else "%s  [%s]" % (name, step))
    for label, rows in (("caught", caught), ("missed", missed), ("timeout", timeouts)):
        with open(os.path.join(args.output, label + ".txt"), "w", encoding="utf-8") as fh:
            fh.write("".join(row + "\n" for row in rows))
    print("%d mutants tested: %d caught, %d missed, %d timeout" % (
        len(mutants), len(caught), len(missed), len(timeouts)))
    if missed:
        return 2
    if timeouts:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
