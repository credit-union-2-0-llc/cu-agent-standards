# Finding Classification: Relationship, Not Just Severity

A review — a security scan, a code review, a QA pass, an audit — produces findings. Most
classification schemes stop at severity (how bad is this). That answers "how loud should the
alarm be" but not "what is this agent now allowed to do about it." Those are different
questions, and collapsing them is how a reviewer's legitimate finding turns into unauthorized
scope creep, or how a broken review gets treated as a clean one.

This is a second, orthogonal axis: not how severe a finding is, but what its *relationship* is
to the review that produced it. Three relationships, every finding gets exactly one:

## The three relationships

**`direct`** — the finding is squarely inside what this review was scoped to check, and its
severity determines what happens next (a P0/P1 direct finding blocks; a P2/P3 direct finding
gets recorded and scheduled). This is the ordinary case and needs no special handling beyond
normal severity triage.

**`adjacent`** — the finding is real, but outside what this review was scoped to check. A
security scanner that notices an unrelated performance bug, a QA pass that turns up a docs gap,
a CVE remediation sweep that spots a hardcoded config value nothing asked it to look for. The
correct response is [principle 4](PRINCIPLES.md#the-ranking): record it, flag it, hand it to
whoever owns that scope — never fold it silently into the current work, and never let it vanish
into an unread report either. An agent that treats every adjacent finding as license to keep
working has turned an approved, scoped task into an unapproved, unscoped one.

**`review_machinery`** — the finding is that the review apparatus itself is broken: a test that
never executes the path it claims to cover, a gate that reports success without checking the
failure condition it exists to catch, evidence that was fabricated or reused from a stale run.
This is not a severity-4 version of a direct finding — it is categorically worse, because it
means every other verdict this review has ever produced is now suspect, not just the one thing
caught this time. [Principle 1](PRINCIPLES.md#the-ranking) exists because of exactly this shape
of failure.

## Why this needs to be a field, not an instinct

`tools/theater`'s origin story is the canonical `review_machinery` case: a two-week audit of
this estate found its own pentest scanner masking scan failures — the control whose entire job
was catching this class of defect was itself lying about having run. Severity triage alone
would have filed that as one more P1 among many. Naming it `review_machinery` instead says
something a severity label can't: don't just fix this one instance and move on — go back and
re-verify everything this scanner ever cleared, because its clean reports were never
trustworthy evidence of anything. See `tools/theater/README.md`'s incident ledger for the
fuller record.

The `adjacent` case is just as easy to get wrong in the other direction. Without a named
category, an agent working through a review either silently expands the task (fixing the
adjacent thing too, without approval) or silently drops it (noting it internally, never
surfacing it). Both are worse than the third option: flag it, keep it visible, do not act on it
without separate sign-off.

## How to apply this

Any role or tool whose output is a set of review findings — see
[`archetypes/security-scanner.md`](../agents/archetypes/security-scanner.md) for a worked
example — should tag each finding with one of these three relationships alongside its severity.
`direct` findings are triaged on severity as usual. `adjacent` findings are recorded and routed,
never actioned in-scope. `review_machinery` findings escalate immediately regardless of their
individual severity, because their real cost is every other finding this review already
produced, not just the one line item.

This is a classification scheme for CU2's own review flows, developed independently; it is not
copied from any external source.
