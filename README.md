# HANRIA Skill

**Check a proposed agent action against an operator-written mandate, and keep a hash-chained record
of the decision.** Free, MIT, Python 3 standard library only. Runs locally with no network calls.

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
> The HANRIA enforcement runtime is in development and **not released** — no package, no download,
> no endpoint. `scripts/detect_runtime.py` reports `absent`, which is the expected and honest answer.
> Checking and recording do not need it.

## Install

```
npx skills add HANRIA-AI/hanria-skill
```

Or clone — there is nothing to build.

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

Exit codes: `0` permit, `1` deny, `2` escalate, `3` error.

The worked example exercises every path: `action.read-ticket.json` permits, `action.read-home.json`
and `action.secrets-dir.json` are denied by an explicit clause, `action.refund.json` escalates
because the mandate reserves transactions for a person, `action.refund-too-large.json` falls past its
clause ceiling to the default, `action.traversal.json` is refused for containing a parent-directory
segment, and `rejected-secret.json` is refused for carrying a credential.

`mandate.shadowed-denial.json` is deliberately broken: its denial sits *after* the permit it was
meant to carve out of, so with first-match-wins it could never run. The checker refuses that mandate
rather than evaluating against a restriction that does nothing.

## What it guarantees, and what it does not

**Fail-closed.** An expired mandate, a malformed or unrecognized one, a request missing required
fields, an unknown operation kind, a non-finite or negative amount, or any unforeseen internal fault
resolves to `deny` or `error`. No input path returns `permit` by accident. A mandate carrying a
condition the evaluator does not implement is refused rather than ignored — an unimplemented
restriction would otherwise silently widen the clause it was meant to narrow.

**Credential detection is a heuristic.** It recognizes common credential field names and value shapes
and refuses the request rather than sanitizing it, so the attempt stays visible. It cannot be
complete: a credential in an unremarkably-named field holding an unremarkable-looking value will
pass. It guards against accident, not intent.

**The log detects alteration**, and deletion of any entry followed by another. It cannot detect
truncation on its own — a shortened chain has nothing left to disagree with — so `append` maintains a
separate `<log>.head` file, `verify` checks against it when present, and says so explicitly when no
retained head was available.

**The log is not evidence.** No signature, no published format, no independent verifier: anyone who
can write the file can rebuild it. It is a local integrity check, not an attestation.

Every one of these is asserted in CI, not merely documented.

## Install

**Via any Agent Plugins 1.0.0 or skills-registry client** — resolves straight from this repository, no submission or listing required:

```bash
npx skills add HANRIA-AI/hanria-skill
```

That installs for Claude Code, Codex, Cursor, GitHub Copilot, Amp, Antigravity and a dozen other runtimes.

**Or clone it.** No dependencies beyond Python 3.9+. Nothing here makes a network call.

```bash
git clone https://github.com/HANRIA-AI/hanria-skill.git
cd hanria-skill
python3 skills/hanria/scripts/detect_runtime.py
```

For agent frameworks that load skills from a directory, point them at this repository root. `SKILL.md`
carries the agent-facing instructions and frontmatter.

## Use

**1. Check for a runtime.** Read-only, no network.

```bash
python3 skills/hanria/scripts/detect_runtime.py
```

| Exit | Status | What the agent must do |
|---|---|---|
| 0 | `present` | Continue |
| 1 | `absent` | **Report unavailability and stop.** Do not simulate a decision |
| 2 | `error` | Treat as absent. Report the error text |

**2. Build a request** against [`skills/hanria/schema/action-request.schema.json`](skills/hanria/schema/action-request.schema.json).
See [`skills/hanria/examples/`](skills/hanria/examples/). A request describes an operation in typed form and **never contains a
credential, secret, key, or token.**

**3. Submit it.**

```bash
python3 skills/hanria/scripts/request_action.py --file skills/hanria/examples/read-file.json
```

| Exit | Outcome | Obligation |
|---|---|---|
| 0 | `permit` | Report the receipt reference. Do not re-perform the operation yourself |
| 1 | `deny` | **Stop. Do not route around it.** Report the denial and its reason |
| 2 | `escalate` | Report that approval is pending. Do not proceed or retry in a loop |
| 3 | `error` | Report it. Do not retry with a broadened request |

**A denial is a result, not an obstacle.** Attempting the operation by another path after a `deny`
defeats the only thing this system does.

## Safety properties this client actually has

These are enforced by the code in this repository, not merely documented:

- **Refuses to leak credentials.** `request_action.py` scans a request for credential-shaped keys
  (`credential`, `secret`, `private_key`, `token`, `password`, `api_key`, `bearer`) and refuses to send
  it, naming the offending JSON path. Tested — see [`skills/hanria/examples/rejected-secret.json`](skills/hanria/examples/rejected-secret.json).
- **No network calls.** Local Unix domain socket only.
- **Never fabricates an outcome.** With no runtime present it returns `error` with an explicit
  instruction to stop, not a synthetic `permit`.
- **No credential handling of any kind.** It never reads, holds, or transmits one.

## What the concept is

A proposed local runtime that would sit between an agent and a protected operation:

1. **Describe** — the agent submits a typed description of a proposed operation rather than receiving
   unrestricted tool access.
2. **Evaluate** — the proposal is checked against an owner-defined mandate: purpose, scope, limits,
   duration, approval conditions.
3. **Context** — what context a decision should depend on, and what it proves, is an **open design
   question**. Undecided and unspecified.
4. **Mediate** — where permitted, the operation runs through the boundary instead of releasing the
   credential.
5. **Record** — a structured record links proposal, inputs, decision, operation, and outcome.

## Links

- **[hanria.dev](https://hanria.dev/)** — developer surface: install, schemas, outcome obligations
- **[hanria.ai](https://hanria.ai/)** — the concept, boundaries and FAQ
  · [日本語](https://hanria.ai/ja/) · [中文](https://hanria.ai/zh/) · [한국어](https://hanria.ai/ko/)
- [llms.txt](https://hanria.ai/llms.txt) · [llms-full.txt](https://hanria.ai/llms-full.txt) · [agent card](https://hanria.ai/.well-known/hanria.json)

## Boundaries

HANRIA is in development. No capability is released or offered for use. The name is a candidate under
internal trademark review — **no registration, completed clearance, or exclusive rights are claimed.**
No third-party security audit, penetration test, certification, product attestation, or regulatory
approval is claimed. No receipt format, public verifier, interoperability standard, or third-party
acceptance commitment has been published. HANRIA would not hold funds, digital assets, or customer
keys, and is not a bank, wallet, exchange, money transmitter, custodian, or regulated financial
service. Nothing here prevents, detects, reverses, or indemnifies unauthorized, fraudulent, mistaken,
or loss-causing activity.

## Packaging

This repository is an **[Agent Plugins 1.0.0](https://agent-plugins.org/) plugin** — `plugin.json` at the
root, the skill under `skills/hanria/`. Agent Plugins is the vendor-neutral packaging standard published by
Vercel with AWS, Anysphere, GitHub, Microsoft and OpenAI, so a conformant client can load this without
knowing anything HANRIA-specific.

`SKILL.md` is also kept at the repository root so registry clients that resolve a bare `owner/repo` continue
to work. CI asserts both paths exist, because breaking either silently breaks a distribution channel.

## Licence

[MIT](LICENSE). The licence covers this client code. It grants no rights in the name HANRIA.

## Licence

MIT — see [LICENSE](LICENSE). The licence covers the code and grants no rights in the name HANRIA; see [TRADEMARK.md](TRADEMARK.md).
