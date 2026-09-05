# Why each listed survivor is equivalent

One entry per group in `equivalent.txt`. A mutant is listed only when no step
can tell it from the shipped code on any input, and the reason is stated here.
An entry that stops being true must leave the list, and the workflow will say
so: it fails when the survivors are not exactly this list.

- `check_action.py:34`, `record.py:43`, the `sys.path.insert(0, <script dir>)`
  line, deleted or with index 1: when a script runs as a script, Python already
  puts its own directory first on `sys.path`, so `_schema` imports either way.
  The line matters only to an importer that is not the script itself, which no
  shipped caller is.
- `check_action.py:602` and `:615`, the request's `schema_version` and the
  type of `operation` re-checked by hand after the schema pass: the published
  request schema fixes both (`const` and `type: object`), and it runs first, so
  the hand check is never the one that refuses.
- `detect_runtime.py:26`, the socket timeout: it changes behaviour only when a
  listener's backlog is full and `connect` would block, which no test can
  produce deterministically across platforms.
- `detect_runtime.py:28`, the socket close after a successful connect: a
  resource release with no observable output; the process exits at once.
- `detect_runtime.py:50`, `:57`, `:67`, the `indent=2` of the printed JSON:
  every step parses the output as JSON, and indentation is not content.
- `check_action.py:182` and `:183`, the type guard in front of the decimal
  parse: a boolean, list, object, or null that reaches it fails inside
  `Decimal(str(value))` in the next line with the same message, so no input
  tells the guard from its absence. (The request schema types the amount as a
  string, so nothing but a string reaches it in any case.)
- `_schema.py:127`, `if depth > deepest` in the depth counter: with `>=`, the
  assignment `deepest = depth` runs one extra time when the two are already
  equal, storing the value it already holds.
- `_schema.py:157`, the bound check inside `read_bounded`: `loads` applies the
  same check to the same text before parsing, so the first is never the one
  that refuses.
- `_schema.py:195`, the parser's recursion error: the nesting bound refuses a
  document sixty-five levels deep before the parser sees it, and the parser
  handles far more than that.
- `_schema.py:238`, `:272`, `:286`, the `_checked` flag that stops the schema
  walk repeating at each level: with it false the walk repeats, refusing the
  same things it already refused.
- `_schema.py:257` and `:258`, the format re-check inside `validate`: the
  schema walk refuses an unknown format anywhere in the schema before any
  value is visited.
- `_schema.py:308`, closing descriptor 1 before reopening the null device:
  without it the device lands on a fresh descriptor and is moved onto 1 by
  the `dup2` that follows, the same end state.
- `_schema.py:333` and `:349`, flushes of standard error and of argparse's
  message stream: standard error is unbuffered, and a buffered message on a
  closed pipe reaches the guard's SystemExit flush, which exits 3 the same.
- `_schema.py:391`, the indentation of the interrupt object: parsed as JSON.
- `check_action.py:162`, the expiry's shape check in `parse_time`: the schema
  enforces the RFC 3339 format on `not_valid_after` before the evaluator runs,
  and no other caller passes it anything else.
- `check_action.py:265`, `:361`, `:365`, `:372`, `:376`, `:380`, `:620`, `:623`,
  `:645`, the evaluator's hand re-checks of shapes the published schemas fix
  (list-typed prefixes, the `requires_human` list, the closed mandate key set,
  the version constant, the default's enum, the non-empty clause list, the
  operation kind's enum, the string fields, the amount object): the schema pass
  runs first and refuses the same documents.
- `_schema.py:319`, closing the spare descriptor after the null device has
  been duplicated onto 1: a leak of one descriptor in a process about to exit.

- `check_action.py:162`, `:163`, `:265`, `:266`, `:269`, `:353`, `:362`,
  `:369`, `:373`, `:377`, `:380`, `:381`, `:384`, `:390`, `:396`, `:400`,
  `:405`, `:408`, `:440`, `:651`, `:655`: the raise inside, or the other
  clause of, a hand check the published schemas already make (the expiry's
  format, list shapes and item types, required fields, closed key sets on the
  mandate, its clauses, their match, the request, and its operation, the
  enums for effect and kind, the note's type, the object types, the ceiling's
  object type and its required value and currency at `:427`, `:428`, `:431`,
  `:432`).
  The schema pass runs first and refuses the same documents with its own
  reason.
- `check_action.py:165`, the count on the replacement that restores the one
  separator `T` after the whole string was lower-cased to `t`: a date-time
  that passed the RFC 3339 shape has exactly one separator, so a count of two
  replaces the same single character.
- `check_action.py:172`, the parse failure after the shape check in
  `parse_time`: the schema's calendar check refuses an impossible date
  first, and only `not_valid_after` is ever parsed.
- `check_action.py:270`, `:354`, `:385`, `:387`, `:388`, `:391`, `:397`,
  `:401`, `:406`, `:409`, `:416`, `:417`, `:420`, `:441`: the raise
  inside, or the required-field test of, hand
  checks listed above as shadowed by the schema.
- `check_action.py:596`, the fallback that makes a timezone-naive expiry
  aware: the schema's RFC 3339 format requires an offset, so the parsed
  expiry always carries one.
- `check_action.py:626`, the string-type check on the operation's target,
  verb, and counterparty: the request schema types all three as strings.
- `check_action.py:598`, the expiry comparison at the exact instant of
  expiry: the evaluator reads its own clock and takes no time argument, so no
  test can produce a request evaluated at that instant.
- `check_action.py:746`, the exit code for an outcome that is none of
  permit, deny, or escalate: the evaluator returns only those three, and
  every error path prints its object and returns 3 itself.
- `check_action.py:712`, `:734`, `:742`, `:745`, the indentation of the printed
  outcome objects: every step parses them as JSON.
- `record.py:237` and `:238`, releasing and closing the append lock: the
  process exits immediately afterwards, and the kernel releases both.
- `record.py:137`, `:146`, `:148`, `:157`, `:168`, `:174`, `:181`, `:188`,
  `:204`, `:210`, `:219`, `:328`, `:333`, `:378`, `:385`, `:389`, the
  indentation of printed status
  objects: parsed as JSON.
- `record.py:141` and `:293` (column 79), the default count read from a head
  file that has none: a head without a count is refused as malformed before the
  default is consulted (the head's shape is checked at `:98`). The threshold
  beside it, column 84, is live: raised to one, an append over a truncated
  log of one entry would skip the verification that refuses it.
- `record.py:293`, the gate that decides whether an append verifies the
  existing chain first, widened to a head recording zero entries: that
  verification reports the log empty and lets the append proceed, the same
  as skipping it.
- `record.py:180`, `:204`, `:283`, the number of digest characters shown in
  a refusal's reason: presentation; the refusal itself is decided on the
  full digests, and the reason's words are what the steps read.
- `record.py:381` and `:382`, the branch of the SystemExit handler that
  re-raises an exit already carrying code 3: the parser's usage exit is
  raised by `parse_args` before the `try` block and never reaches the
  handler, and nothing inside the block raises that code, so the branch is
  never entered.

# Why each listed timeout loops

- `_schema.py:168`, the end-of-file test in the line reader turned false: at
  the end of a log the reader returns an empty line forever instead of `None`,
  and every caller that reads a log loops on it. A step detects that only by
  not finishing.
- `check_action.py:224`, the set that records each spelling seen while
  percent-decoding a target until it stops changing: without it a target that
  decodes to itself in a cycle is decoded forever.
