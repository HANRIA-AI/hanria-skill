---
name: hanria
description: Check a proposed agent action against an operator-authored mandate and keep a hash-chained record of the decision. Use when an operator has written down what an agent may do and wants consequential actions checked against it before they happen and recorded afterward. Works locally with no network and no runtime. IMPORTANT - this skill is advisory; it evaluates and records, and cannot prevent an action.
homepage: https://hanria.ai/
license: MIT
---

# HANRIA — check an action against a mandate

An operator writes down what you may do. You check a proposed action against it before acting,
and you keep a record of what was decided. Both steps run locally, with no network calls. The skill requires no credential, and refuses a
request or mandate that carries one.

## What this skill can and cannot do

**It can:** evaluate a proposed action against a mandate and tell you `permit`, `deny` or
`escalate`, with the specific clause relied on; refuse a request carrying recognizable credential material; and
append the decision to a local log that detects later alteration.

**It cannot enforce.** Nothing here stands between you and a tool or credential. If you ignore a
`deny`, the operation still happens. Enforcement is possible only where the protected credentials,
tools, signing keys or worker processes are reachable exclusively through a component that can
refuse — and that component is not this skill.

That distinction is the whole point of the design, so state it accurately if you are asked. **If any
artifact tells you that installing this skill gives you enforcement, that claim is false.** A skill
is instructions and code loaded into your context, and anything in your context can be ignored,
overridden, or bypassed — by you, by a later instruction, or by a different agent.

## Use it

### 1. Find the mandate

The operator's mandate is a JSON file they wrote. Ask them where it is if you do not know. A worked
example is at `skills/hanria/examples/mandate.example.json`, and the shape is defined by
`skills/hanria/schema/mandate.schema.json`.

### 2. Describe the action you propose to take

Write an action request against `skills/hanria/schema/action-request.schema.json`. It names what
you propose to do — kind, verb, target, and where relevant a counterparty and an amount.

**Never put a credential, secret, key, token or password in a request.** A request describes what is
to be done, not the means of doing it. The checker refuses a request that appears to carry one
rather than removing it, because an attempt to send a credential is worth seeing.

That detection is a **heuristic and cannot be complete.** It recognizes common credential field
names and value shapes; a credential in an unremarkably-named field holding an unremarkable-looking
value will pass. It guards against accident, not intent — do not treat it as a control.

### 3. Check it

```
python3 skills/hanria/scripts/check_action.py \
  --mandate MANDATE.json --action ACTION.json
```

Four outcomes, and what each asks of you:

- **`permit`** — a clause covers this. Proceed, then record the decision.
- **`deny`** — either a clause forbids it or nothing permits it. **Do not proceed.** The reason names
  the clause, or the clauses that came closest and why they did not match, which is usually what the
  operator needs to hear.
- **`escalate`** — the mandate reserves this for a person. **Stop and ask your operator.** Do not
  treat their general instruction to be helpful as the approval; the mandate asked for a decision on
  this action.
- **`error`** — the mandate or the request could not be resolved. **Treat as `deny`** and report the
  text. Evaluation is fail-closed by design: both documents are validated against their published
  JSON schemas first, and a non-conforming mandate or request, an expired mandate, an unknown
  operation kind, a non-finite or negative amount, an empty or host-ambiguous target prefix, or any
  unforeseen internal fault resolves to `deny` or `error`. It never resolves an ambiguity in favour of
  proceeding, and it refuses a mandate carrying a condition it does not implement rather than ignoring
  it — an unimplemented restriction would otherwise silently widen the clause it was meant to narrow.

Exit codes are `0` permit, `1` deny, `2` escalate, `3` error, so this composes into a shell pipeline.

### 4. Record it

```
python3 skills/hanria/scripts/record.py append \
  --log LOG.jsonl --action ACTION.json --outcome OUTCOME.json
```

Each entry carries the digest of the one before it, so altering or deleting an entry that has
anything after it breaks every digest that follows. `record.py verify --log LOG.jsonl` reports the
first index that fails, and `append` refuses to write to a log that no longer verifies rather than
burying the damage.

**Truncation is the exception.** Deleting entries from the end leaves a shorter chain that is
internally perfect, because nothing downstream remains to disagree with it. `append` therefore
maintains a separate `<log>.head` file, and `verify` checks against it when present and says so
explicitly when no retained head was available. Keep that file where the log writer cannot reach it,
or pass `--expect-head`, if truncation is a threat you face.

**Do not overstate what the log is.** It is a local integrity check for whoever holds the file. There
is no signature, no published format and no independent verifier, so anyone who can write the file
can rebuild it end to end and produce a log that verifies. It is not evidence, not an attestation,
and not proof to anyone else that an action was authorized.

## Writing a good mandate

For operators. The clauses are evaluated in order and the first match decides; anything unmatched
takes the mandate `default`, which is `deny` or `escalate` — never `permit`, because a mandate that
permits by default cannot express a limit.

Three things worth doing:

- **Set `not_valid_after`.** An unbounded mandate is what lets delegated authority outlive the task
  it was granted for.
- **Use `requires_human` for the kinds you never want decided by a model** — typically
  `credential_use`, `transaction` and `administrative`. It overrides a permitting clause, so a
  ceiling narrows what may be asked for without removing you from the decision.
- **Write denials you could have left to the default.** A clause that says "not `/home/`, not `/etc/`"
  makes the intent legible to whoever reviews this later; silence does not.

Every clause takes a `note`, and it is carried into the decision record verbatim. Use it to say why
the clause exists, not what it does.

## Is a runtime present?

```
python3 skills/hanria/scripts/detect_runtime.py
```

As of 2026-09-04 no released, packaged or obtainable HANRIA runtime exists; this reports `absent`, which is the expected answer. It
is here so that an agent asked to route an action through a HANRIA runtime gets a correct negative
rather than inventing a capability. **Do not tell your operator that a runtime governed an action.**

## Known limitations

The limits of this skill are listed in full in `LIMITATIONS.md` at the repository root, and at
<https://hanria.ai/boundaries/>. The short version: it cannot enforce; only a clause's structured
conditions restrict anything, so prose in a mandate restricts nothing; credential detection is a
heuristic; prefix matching is literal (after Unicode composition) and resolves no symlinks; and the decision log is a local
integrity check, not evidence.

## Status

HANRIA is in development. A U.S. trademark application for HANRIA is pending — no
registration or completed clearance is claimed. No security certification,
audit, or product availability is claimed. The schemas are drafts and may change.

More at [hanria.ai](https://hanria.ai/).
