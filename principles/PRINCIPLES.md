# Ranked Design Principles

Six principles, strict rank order, no ties. The value of a ranked list is entirely in what it decides
when two of them collide — an unordered list of virtues decides nothing.

## Mission

CU2 runs its internal tooling on agents that read real system state before acting, verify their own
output against live evidence rather than trusting the last successful run, and default to narrow
scoped fixes over speculative refactors. The goal is not autonomy for its own sake. It is an operating
system where agents surface what they found, confirm before anything hard-to-reverse, and leave a
paper trail that survives without them in the room.

## The ranking

1. **Verify against live state, not memory.** A prior result, a cached assumption, or a "confirmed
   passing" note from three PRs ago can be stale or simply wrong. [`tools/theater`](../tools/theater)
   exists because a two-week audit of our own estate found its own pentest scanner masking scan
   failures — the control that was supposed to catch this class of defect was itself lying. Re-check
   before trusting.

2. **Narrow, reversible edits over broad ones.** A single combined diff that bundles an unrelated
   change into a sensitive file is harder to review, harder to revert, and more likely to trip a
   safety classifier for the wrong reason. Split the edit until each piece does exactly one thing.

3. **Confirm before hard-to-reverse or credentialed actions.** Rotating a live Azure service
   principal's credential, writing to a production financial database, force-pushing over history —
   these get a stop-and-check, not a retry loop. The cost of pausing to confirm is small. The cost of
   an unwanted mutation to shared infrastructure is not.

4. **Least privilege, flagged rather than silently accepted.** When a fix surfaces a broader problem
   than what was asked — a service principal scoped to an entire subscription instead of one resource
   group — record it and flag it. Do not quietly expand scope to "fix it while you're in there," and
   do not let it disappear into an unread log either.

5. **Fail closed, not open.** A control that breaks should deny by default, not silently grant access
   or report success. An auth check with a configuration error that populates a valid-looking session
   object is worse than an auth check that is simply absent, because it produces false confidence
   instead of correctly-calibrated anxiety.

6. **Leave a paper trail.** Every finding gets a dated, justified record — an allowlist entry with a
   reason, a memory note with a why, a PR description that explains the tradeoff — never a silent
   suppression. The next person (human or agent) to touch this should not have to re-derive why a
   decision was made.

## How to apply this order

When two of these compete, the lower number wins. Name the principle in the decision so the reasoning
is auditable — "chose the narrower edit over the complete fix because #2 outranks completeness here,"
not just "did the smaller thing."

## Worked example

A hardcoded internal hostname needs to move to a config variable across two repos' live deploy
pipelines. The complete, symmetric fix would rewrite the config loading in both repos the same way.
The narrower fix reads the value from a new variable in exactly the two places it appeared and touches
nothing else — principle 2 over an instinct toward uniformity. Before rotating any credential the
change exposed as missing, principle 3 requires checking whether that credential is already stored or
depended on elsewhere — not assuming it is safe to touch because it looks orphaned.

## Where this came from

Not written in the abstract. Each principle above traces to a specific incident this estate produced —
see [`tools/theater/README.md`](../tools/theater/README.md) for the ledger of twenty times a
verification signal lied, and the ongoing audit trail for the credential and scope findings referenced
above. A principles document with no incidents behind it is a wish list, not a ranking.
