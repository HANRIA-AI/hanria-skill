# The runtime exerciser, 2026-09-06

`skills/hanria/scripts/detect_runtime.py` is seventy lines that decide
whether the skill may claim a runtime is present, and the wording of
its absent report is the adoption story. Its gate step ran it once on a
runner and required absent with exit 1. This tool runs it on every
combination of what its controllable probe locations hold.

## What is controlled

The detector probes, in order, the path in `HANRIA_SOCKET`,
`~/.hanria/run/hanria.sock`, `/run/hanria/hanria.sock` and
`/var/run/hanria/hanria.sock`. The tool points HOME at a directory of its
own and sets `HANRIA_SOCKET` to one of seven settings: unset, empty, a
path of its own holding nothing, a listening socket, a stale socket file
or a regular file, or the home location's path. The home location holds
one of the same four things. That is twenty-eight combinations, each run
twice to check determinism. The two system locations cannot be
controlled; if either exists on the host the tool reports that it cannot
model the host and exits 2, and the gate would fail rather than trust a
prediction the host could falsify. A listening socket is bound and
listened on but not accepted from while the detector runs; its connect
lands on the backlog. Afterwards the tool drains the backlog and
requires one queued connection per round when that socket was the
endpoint reported and none when the search never reached it, each
closed by the detector with nothing sent, since the detector states that
it sends no application data and stops at the first answer.

## The model

Written from the detector's stated behaviour: a location that does not
exist is skipped; the first that accepts a connection is present, exit
0, the search stopping there; a location that exists but refuses is
unresponsive, and if none accepted, error with exit 2 and every
unresponsive location in probe order; otherwise absent with exit 1 and
every non-empty location searched. The tool also requires the documented
keys of each report: the note under present, the agent instruction under
error, and the why, agent instruction, what-installing-does-not-do and
more keys under absent.

## Result

Twenty-eight combinations agree, ten present, fourteen error, four
absent, each deterministic over two rounds. Four slips in copies of the
detector were caught, each proving a different part of the model: the
stop after the first answering socket removed, caught on the one
combination where both controlled locations listen and the detector then
reported the later one; the collection of unresponsive locations removed,
caught on every combination with a stale or regular file and no
listener, reported absent instead of error; the error exit code changed
to 1, caught on the same combinations by the exit code alone; and the
detector made to send one byte after connecting, caught by the drain
on all ten combinations that reach a listening socket. The summary
reports how many combinations disagreed and shows the first five.

## What this does not cover

The two system locations, and a listening socket whose backlog is full,
where connect would block and the detector's timeout would decide;
nothing here fills a backlog, and the equivalence list records the
timeout mutant as unobservable for that reason.
