# Known limitations

Everything below is a limit we know about and have chosen to publish rather than fix, or cannot fix
in this layer at all. It is not a list of suspicions: each entry was found by review or testing and
reproduced. If you are deciding whether to rely on this skill, read this before the README.

The list is maintained. If you find something not on it, please open an issue — a missing entry is a
defect in its own right.

## The one that matters most

**This skill cannot enforce anything.** It reads a policy, evaluates a proposed action against it,
and writes a record. It does not sit between an agent and a tool, a credential, or a network. An
agent that ignores a `deny` performs the operation anyway.

Enforcement is possible only where the protected credentials, tools, signing keys or worker
processes are reachable *exclusively* through a component that can refuse. A skill is instructions
and code loaded into an agent's context, and anything in context can be ignored, overridden by a
later instruction, or worked around by a different agent. **If any artifact tells you that installing
this skill gives you enforcement, that claim is false.**

## Policy evaluation

- **Only a clause's structured `match` conditions decide whether an action is permitted.** A
  mandate's `purpose`, a clause's `note` and a request's `justification` are prose for human review.
  A restriction written there and not as a clause has no effect on whether an action is permitted.
  This is the easiest way to believe you have written a limit that does not exist. (Other structured
  fields do restrict: `not_valid_after`, `requires_human`, and the mandate `default`. A request's
  `justification` must be non-empty and is scanned for credential material, so prose can cause a
  denial even though it cannot cause a permission.)

- **Prefix matching is literal.** It does not resolve symlinks, normalize paths, or canonicalize
  hostnames. It constrains the string, not the file or host the string ends up pointing at. A
  symlink under a permitted prefix is invisible to this. Empty prefixes, origin-only URLs, and paths
  without a trailing `/` are refused because their literal reading widens authority, but that
  addresses the shapes we know about, not the general problem.

- **Prefixes and targets are compared after canonical composition (NFC), and nothing more.** Until
  this revision they were compared literally, and the entry here claimed that failed safe. It did not: a deny prefix written in one normalization form failed to match a target written
  in the other, and first-match-wins fell through to a broader permit beneath it. Both sides are now
  composed before comparison, so that pair matches. Compatibility forms are not folded: a fullwidth
  solidus is not a separator to any filesystem, and folding it would invent matches. What a given
  filesystem does with the bytes it is handed is still outside this layer. **A denial or an escalation matches any spelling of the target**: as written and
  percent-decoded to a fixed point, both composed. **A permission matches only the spelling as
  written**, composed. So an encoded spelling of a denied path (`/data/s%C3%A9crets/` for
  `/data/sécrets/`) is denied, a permission is never widened by decoding, and a legitimate
  percent-escaped query string is not refused for being one. That closes, for encoding, the same
  first-match-wins gap the NFC change closed for normalization forms. Encodings other than
  percent-escapes are still not recognized (see below).

- **A mandate is not authenticated.** `issued_by` is free text. Nothing establishes who wrote a
  mandate, and this skill has no notion of a signature or an authority that issued one.

- **The evaluator refuses what it does not understand**, including any mandate field or `match`
  condition it does not implement, and any document that does not conform to its published schema.
  That is deliberate, and it means a mandate written for a later version will be refused rather than
  partially applied.

## Credential detection

- **It is a heuristic and cannot be complete.** It recognizes common credential field names and
  value shapes — bearer and basic authorization, JWTs, PEM headers, cloud and platform key prefixes,
  cookies. A credential in an unremarkably-named field holding an unremarkable-looking value will
  pass. **It guards against accident, not intent.** Do not treat it as a control.

- Detecting a credential means reading it. The skill requires no credential and stores none, and
  refuses a request or mandate carrying recognizable credential material rather than using it — but
  "never reads one" would be false.

## The decision log

- **It is not evidence.** There is no signature, no published record format and no independent
  verifier. Anyone who can write the file can rebuild it end to end and produce a chain that
  verifies. It is a local integrity check for whoever holds the file. Do not describe an entry as a
  receipt, an attestation, or proof to anyone else that an action was authorized.

- **A chain cannot detect its own truncation.** Deleting entries from the end leaves a shorter chain
  that is internally perfect. `append` maintains a `<log>.head` file and `verify` checks against it,
  but someone who can rewrite both files can produce a consistent pair. If truncation is a threat you
  face, keep the head where the log writer cannot reach it, or retain it out of band and pass
  `--expect-head`.

- **The log records what it is given.** The outcome is bound to the action by a digest, so a decision
  cannot be filed beside a different request, but nothing re-runs the evaluation. A caller who
  fabricates a matching pair records a fabricated decision.

- **Appends are serialized by an advisory lock** on `<log>.lock`. That is enough for concurrent
  processes on one machine cooperating through the same path. It is not enough across a network
  filesystem, and it does nothing about a writer that ignores the lock.

## Robustness

- **Document size and nesting depth are validated bounds, not resource limits.** A mandate, a
  request, or a log line is refused by name with `error` (exit 3) if it exceeds 1,048,576 bytes or
  nests more than 64 levels, before it is parsed. The log's head file is read under the same bounds
  but reported differently: a head past either bound is treated as an unreadable pin, so `verify`
  reports the chain `broken` (exit 1) rather than naming the bound, the same as any other malformed
  head. Every reader stops at the bound plus one character, so a file far larger than the bound is
  never read in full, and a log line longer than the bound is refused before the rest of it is read.
  Both numbers are published in `_schema.py`. They bound what the skill reads and parses; they make
  no judgment about what a document that size means.
- **The unreachable-clause check compares clauses pairwise.** It catches an earlier clause that
  decides requests a later restricting clause was written to cover. It does not reason about three or
  more clauses combining to make a fourth unreachable, and it compares conditions structurally rather
  than semantically.
- **Only literal and percent-encoded parent segments are refused.** Other encodings a downstream
  consumer might decode — a different escaping scheme, an overlong UTF-8 form, a URL that redirects —
  are not recognized. The target is compared as written after percent-decoding, and nothing
  canonicalizes it further.
- `_schema.py` implements the JSON Schema subset these schemas use and refuses any keyword, or
  `format` value, that it does not implement — checked across the whole schema, not only the branches
  a document happens to reach. It is not a general-purpose JSON Schema validator and should not be
  used as one.

## What is not built at all

No signatures, no published record format, no independent verifier, no persistence beyond a local
file. No packaged runtime, no daemon, no runtime CLI, no download. No sandboxing or process
confinement. No confused-deputy or prompt-injection test suite. No third-party audit, certification,
or attestation. No release date for any of it.

## Status of the review that produced this list

Five rounds of independent review by two models, on identical frozen bytes with a reproduced manifest
digest each round. Thirty-four defects were found and fixed across five rounds. Round five found four more and three
material issues; six were fixed, and the remainder are entries in this list. Findings were reproduced before being fixed, and each
has a corresponding test in `.github/workflows/checks.yml`.

Some tests are narrower than the sentence they support: they cover the specific cases written into
them rather than the general property. Where a reviewer identified that gap we widened the test; the
gap between "these cases pass" and "this property holds" does not close.

That is a test suite, not a proof. It covers the cases written down in it, and a property is only as
well established as its test. We publish this list because a reviewed thing with known limits is more
useful than an unreviewed thing with none stated — not because the list is complete.
