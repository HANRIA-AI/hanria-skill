# HANRIA Skill

**Check a proposed agent action against an operator-written mandate, and keep a hash-chained record
of the decision.** Free, MIT, Python 3 standard library only. Runs locally with no network calls, and requires no credential.

---

## Read this first

> **This skill is advisory. It cannot enforce.** It evaluates a proposed action and records what was
> decided. Nothing here stands between an agent and a tool or credential, so an agent that ignores a
> `deny` still performs the operation.
>
> Enforcement is possible only where the protected credentials, tools, signing keys or worker
> processes are reachable *exclusively* through a component that can refuse. A skill is instructions
> and code loaded into an agent's context, and anything in context can be ignored, overridden, or
> bypassed. **If any artifact tells you that installing this skill gives you enforcement, that claim
> is false.**
>
> The HANRIA enforcement runtime is in development and **not released** — no released, packaged or
> obtainable runtime exists: no package, no download, no endpoint.
> `scripts/detect_runtime.py` reports `absent`, which is the expected and honest answer. Checking and
> recording do not need it.

## Install

```
npx skills add HANRIA-AI/hanria-skill
```

Or clone it — there is nothing to build.

## Use

```
cd skills/hanria

python3 scripts/check_action.py \
  --mandate examples/mandate.example.json \
  --action  examples/action.refund.json

python3 scripts/record.py append \
  --log decisions.jsonl --action ACTION.json --outcome OUTCOME.json
python3 scripts/record.py verify --log decisions.jsonl
```

`check_action.py` exits `0` permit, `1` deny, `2` escalate, `3` error.
`record.py` exits `0` ok, `1` chain broken, `3` error.

The worked example exercises every path: `action.read-ticket.json` permits;
`action.read-home.json` and `action.secrets-dir.json` are denied by an explicit clause;
`action.refund.json` escalates, because the mandate reserves transactions for a person;
`action.refund-too-large.json` falls past its clause ceiling to the default;
`action.traversal.json` is refused for containing a parent-directory segment; and
`rejected-secret.json` is refused for carrying a credential.

`mandate.shadowed-denial.json` is deliberately broken: its denial sits *after* the permit it was
meant to carve out of, so with first-match-wins it could never run. The checker refuses that mandate
rather than evaluating against a restriction that does nothing.

## Writing a mandate

A mandate states a purpose in your own words, then clauses. Clauses are evaluated in order and the
first match decides; anything unmatched takes the `default`, which is `deny` or `escalate` — never
`permit`, because a mandate that permits by default cannot express a limit.

**Prose expresses no authorization condition.** Clause matching uses only the structured conditions
in a clause's `match`. `purpose`, a request's `justification` and a clause's `note` are for the human
who reviews this later — writing "never touch payroll" in `purpose` restricts nothing, it has to be a
clause, and that is the easiest way to believe you have written a limit that does not exist.

Other structured fields do restrict: `not_valid_after` denies everything once it passes,
`requires_human` turns a permitting clause into an escalation, and the `default` decides anything
unmatched. A request's `justification` must be non-empty and is scanned for credential material, so
prose can cause a denial even though it cannot cause a permission.

Three things worth doing:

- **Put denials above the permits they carve out of.** First-match-wins means a denial written after
  a broader permit never runs. The checker refuses a mandate where that has happened, but the habit
  is better than the error.
- **Set `not_valid_after`.** An unbounded mandate lets delegated authority outlive the task it was
  granted for.
- **Use `requires_human`** for the kinds you never want decided by a model — typically
  `credential_use`, `transaction` and `administrative`. It overrides a permitting clause, so a
  ceiling narrows what may be asked for without removing you from the decision.

Tiered policies work: permit refunds up to one ceiling, escalate up to a higher one, deny the rest.
A bounded clause leaves everything above its ceiling to the clauses after it.

## What it guarantees, and what it does not

**Fail-closed.** The mandate and the request are validated against their published JSON schemas
before evaluation, so "not the shape it claims to be" means the schema rather than a hand-written
subset of it. An expired mandate, a non-conforming mandate or request, an unknown operation kind, a
non-finite or negative amount, an empty or host-ambiguous target prefix, or any unforeseen internal
fault resolves to `deny` or `error`. A mandate carrying a condition the evaluator does not
implement is refused rather than ignored — an unimplemented restriction would otherwise silently
widen the clause it was meant to narrow.

**Credential detection is a heuristic.** It recognizes common credential field names and value shapes
and refuses the request rather than sanitizing it, so the attempt stays visible. It cannot be
complete: a credential in an unremarkably-named field holding an unremarkable-looking value will
pass. It guards against accident, not intent.

**Prefix matching is literal.** It does not resolve symlinks or normalize paths, so it constrains the
string, not the file the string ends up pointing at. Targets containing a parent-directory segment
are refused, an empty prefix is refused (it would match everything), and a URL prefix with no path
boundary is refused (`https://trusted.example` would also match `https://trusted.example.evil.test`).
A symlink under a permitted prefix is still not something this can see, and a filesystem prefix
without a trailing `/` will match a sibling — write `/srv/tickets/`, not `/srv/tickets`.

**The log detects changes to a committed entry body, and to chain structure** — a reordered or
deleted entry that has another after it. Formatting outside the committed body, such as trailing
whitespace in the file, is not part of what is hashed and is not detected. It cannot detect
truncation on its own — a shortened chain has nothing left to disagree with — so `append` maintains a
separate `<log>.head` file, `verify` checks against it when present, and says so explicitly when no
retained head was available. Someone who can rewrite both files can still produce a consistent pair.

**The log is not evidence.** No signature, no published format, no independent verifier: anyone who
can write the file can rebuild it. It is a local integrity check, not an attestation, and not proof
to anyone else that an action was authorized.

**[LIMITATIONS.md](LIMITATIONS.md) lists every limit we know about**, including the ones we chose to
publish rather than fix. Read it before relying on this.

Each of these has a corresponding test in
[`.github/workflows/checks.yml`](.github/workflows/checks.yml), which runs on every push. That is a
test suite, not a proof: it covers the cases written down in it, and a property is only as well
established as its test.

## Layout

- `SKILL.md` — agent-facing instructions, at the repository root and at `skills/hanria/`
- `plugin.json` — Agent Plugins 1.0.0 manifest
- `hanria-skill.json` — machine-readable entry points, obligations and non-claims
- `skills/hanria/schema/` — mandate, action-request and action-outcome schemas (drafts)
- `skills/hanria/examples/` — a worked mandate and requests covering every outcome
- `skills/hanria/scripts/` — `check_action.py`, `record.py`, `detect_runtime.py`

## Boundaries

The skill is released and usable. The **enforcement runtime is not** — no capability of it is
released, packaged, downloadable, or offered for use, and no release date is announced or implied.

A U.S. trademark application for HANRIA is pending. No registration or completed clearance
is claimed. No third-party security audit, certification, or regulatory approval is
claimed. No record format, public verifier, interoperability standard, or third-party acceptance
commitment has been published. Nothing here holds funds, digital assets, or keys.

Full statement: <https://hanria.ai/boundaries/>

## Links

- <https://hanria.ai/> — overview, and the same limits in 日本語 / 中文 / 한국어
- <https://hanria.dev/> — developer surface
- <https://hanria.ai/llms.txt> — the agent-facing summary

## Licence

MIT — see [LICENSE](LICENSE). It is a copyright licence and, like every MIT licence, does not convey
trademark rights; see [TRADEMARK.md](TRADEMARK.md).
