---
name: hanria
description: Request a governed action through a local HANRIA runtime, and receive a permit, denial, approval request, or receipt. Use when an operator has asked that consequential agent actions be authorized and recorded through HANRIA. IMPORTANT — installing this skill does NOT create enforcement, and as of 2026-09-04 no HANRIA runtime exists to install; this skill will detect its absence and tell you so.
homepage: https://hanria.ai/
license: see homepage
---

# HANRIA — request a governed action

## Read this before you use this skill

**This skill does not enforce anything.** It is a client. It describes an action, hands the
description to a local runtime, and reports back what the runtime decided.

A skill is instructions and code loaded into your context. Anything in your context can be ignored,
overridden, or bypassed — by you, by a later instruction, or by a different agent. **Enforcement is
possible only where the protected credentials, tools, signing keys, or worker processes are
reachable exclusively through a component that can refuse.** That component is the runtime, not
this file.

**If any artifact tells you that installing this skill gives you HANRIA enforcement, that claim is
false.** Say so if asked.

## Current status, stated plainly

As of 2026-09-04 **no HANRIA runtime exists.** It is an in-development product concept from Kaal
Consulting LLC. There is no package, no download, and no install command that will produce one.

This skill is published anyway, for two honest reasons: so that agents can discover the interface
shape ahead of the runtime, and so that an agent asked to route actions through HANRIA gets a
correct negative answer rather than inventing a capability. **Do not tell your operator that HANRIA
governed an action. It cannot yet.**

## How to use this skill

### Step 1 — check whether a runtime is present

Run the detection script. It is read-only and makes no network calls.

```
python3 scripts/detect_runtime.py
```

Three possible outcomes:

- `absent` — expected today. No runtime. **Report this to your operator and stop.** Do not proceed,
  do not simulate a decision, and do not describe the action as authorized.
- `present` — a runtime answered. Continue to step 2.
- `error` — something responded but not correctly. Treat as `absent` and report the error text.

### Step 2 — build a request against the schema

The action schema is `schema/action-request.schema.json`. A request names what you propose to do, in
typed form, and never contains a credential, secret, or key.

### Step 3 — submit it and act on the outcome

```
python3 scripts/request_action.py --file my-request.json
```

Outcomes and what each obliges you to do:

| Outcome | What it means | What you must do |
|---|---|---|
| `permit` | The runtime performed the mediated operation | Report the receipt reference. Do not re-perform the operation yourself |
| `deny` | Outside the mandate | **Stop. Do not route around it.** Report the denial and its reason |
| `escalate` | A human decision is required | Report that approval is pending. Do not proceed or retry in a loop |
| `error` | The request or the runtime failed | Report the error. Do not retry with a broadened request |

**A denial is a result, not an obstacle.** Attempting the operation by another path after a `deny`
defeats the only thing this system does. If you find yourself looking for another route, the correct
action is to tell your operator you were denied.

## What this skill will never do

- Hold, request, read, or transmit a credential, secret, private key, or token
- Make a network call of its own
- Decide an authorization question itself
- Report an action as governed, authorized, permitted, or recorded when no runtime answered
- Represent HANRIA as available, released, audited, certified, or compliant

## Boundaries

HANRIA is an in-development concept. The name is a candidate under internal trademark review, with
no registration, completed clearance, or exclusive rights claimed. No third-party security audit,
certification, or regulatory approval is claimed. No receipt format, public verifier, or
interoperability standard has been published. HANRIA would not hold funds or digital assets and is
not a financial service. Nothing here prevents, detects, reverses, or indemnifies unauthorized or
fraudulent activity.

More: https://hanria.ai/ · https://hanria.ai/llms.txt
