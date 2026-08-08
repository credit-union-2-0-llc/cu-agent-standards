# Security Policy

## What this actually is

This is a public, single-maintainer repository under `credit-union-2-0-llc`. It ships two dependency-
free, offline Python static-analysis tools (`tools/sanitize`, `tools/theater`) plus the docs, schemas,
and worked examples built on top of them. There is no deployed service, no server, no database, and no
user data belonging to this repository itself. What a "vulnerability" means here is narrower than it
would be for a running application, and this document is honest about that scope rather than reaching
for boilerplate that doesn't fit it.

There is no contracted SLA. Response time is best-effort from one maintainer, same as everything else
in this repo.

## What counts as a security issue here

Roughly in order of how seriously it's taken:

1. **A false negative in `cu2_sanitize_scan.py`** — an input containing something the tool's own
   documented tiers (`secret`, `pii`, `internal`) claim to catch, that the scanner reports clean. This
   is the most serious category: a repository using this gate as its publication check could ship a
   real leak believing it was caught. See [`tools/sanitize/README.md`](tools/sanitize/README.md) for
   what each tier is supposed to catch.
2. **A false clean in `theater_scan.py` or `workflow_health.py`** on something genuinely exploitable —
   for example, a CI step that discards a security-relevant failure in a shape none of the T1–T12
   detectors recognize. This tool exists specifically to find controls that lie about whether they ran;
   a gap in its own coverage is on-topic, not embarrassing, to report — see the ledger in
   [`tools/theater/README.md`](tools/theater/README.md), which publishes exactly this kind of finding
   about itself on purpose.
3. **An actual code-execution or supply-chain issue in the tooling** — path traversal, unsafe
   deserialization, command injection, anything of that shape in `tools/sanitize/cu2_sanitize_scan.py`,
   `tools/theater/theater_scan.py`, `tools/theater/workflow_health.py`, or `tools/lint/format_lint.py`.
   These scripts are meant to be run, including in CI, against arbitrary source trees — including ones
   an attacker partly controls (a PR diff) — so an issue that lets scanned content do something other
   than get scanned is a real vulnerability, not a false-positive report.
4. **A GitHub Actions supply-chain concern** in `.github/workflows/*.yml` or the reusable workflows
   this repo publishes for other repositories to call
   (`reusable-sanitize.yml`, `reusable-theater.yml`) — for example, an action pinned to a mutable tag
   instead of a SHA where that matters.

**Not a security report, just a regular issue:** a detector missing a pattern that was never claimed
in the first place, a documentation gap, or a false positive (the tool flags something that's actually
fine). Those are welcome as normal GitHub issues — see [CONTRIBUTING.md](CONTRIBUTING.md).

## How to report

**If the report itself would require pasting a real secret, real PII, or anything from a private
repository to demonstrate the miss:** do not open a public issue. That would be the exact leak this
repository's own sanitize gate exists to prevent. Use GitHub's private vulnerability reporting instead
— the "Report a vulnerability" option under this repository's Security tab — or construct a synthetic
reproduction (a fake SSN-shaped string, a fake connection string) that demonstrates the gap without
containing anything real, and open a normal issue with that.

**For everything else — including a theater-gate blind spot, a sanitize false negative you can
demonstrate with synthetic data, or a tooling bug in the scanners themselves:** open a public issue.
Include:

- Which tool and which profile or detector (`--profile internal`, `T3`, etc.)
- The exact input that should have been caught, or the exact behavior that shouldn't be possible
- What happened instead of what should have happened
- Whether you can reproduce it against a fixture, per the pattern in
  `tools/theater/test_fixture_mutations.py` / `tools/sanitize/test_fixture_mutations.py`

This repository's convention throughout is receipts over vibes (see
[`SUPPRESSIONS.md`](SUPPRESSIONS.md) and the bug ledger in
[`tools/theater/README.md`](tools/theater/README.md)) — a report with a concrete reproduction gets
fixed faster than a description of a general concern.

## Supported versions

There are no tagged releases. `main` is the only line that gets fixes; if you depend on a specific
commit (via `reusable-theater.yml`/`reusable-sanitize.yml` or by vendoring the scanner), pin to a SHA
and re-pin deliberately rather than floating on `@main` if reproducibility matters to you.
