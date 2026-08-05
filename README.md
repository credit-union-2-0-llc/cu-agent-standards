# cu-agent-standards

**Examiner-grade patterns for running a credit union on AI agents.**

Two gates, published MIT. Both are stdlib-only Python 3 with no dependencies, and both are in
production use across a 92-repository estate.

| Tool | What it stops |
|---|---|
| [`tools/sanitize`](tools/sanitize) | internal context leaving a repository |
| [`tools/theater`](tools/theater) | **controls that lie about whether they ran** |

## Why the second one exists

A two-week audit of our own estate found that the dominant defect class was not bugs. It was
**verification theater**: a signal that exists, is consumed, and lies.

- A search endpoint returning `items: []` on backend failure — every caller read it as "no prior art exists"
- A `/health` field named `spark_reachable` that reported a Redis ping, and read healthy the entire time the service was down
- CI running `pnpm lint/typecheck/test || true` against a package defining none of those scripts — 15 test files had **never** run
- `ruff` configured to ignore F821, hiding 35 real `NameError`s across four unusable CLI command groups

A missing control produces appropriate anxiety. A broken control produces false confidence, which is
worse. As far as we can find, nobody has published a linter whose job is to find controls that do not
control.

## What it found

Swept across 92 repositories on 2026-07-28: **774 T1–T6 candidates** and 6 red-or-absent scheduled
workflows. Roughly half the candidates are legitimate suppressions, which the tool asks you to
*declare* rather than remove.

This paragraph said "767" until 2026-08-05. The measured figure in
[`tools/theater/README.md`](tools/theater/README.md) was 774 the whole time — the front page carried a
number seven lower than the tool's own output, which is the defect this repository is named after,
committed in the sentence that announces the finding. Both figures are estate measurements taken at a
point in time and cannot be reproduced from this repository alone; the per-repo table is internal
because it names 92 private repositories. Everything you *can* verify here — the ledger row count, the
test count, the suite count — is asserted in CI.

```bash
python3 tools/theater/theater_scan.py .                    # T1-T6, T8 — offline, no credentials
python3 tools/theater/theater_scan.py . --diff-base main   # ratchet: only what this change adds
python3 tools/theater/workflow_health.py OWNER/REPO        # T7 — needs the GitHub Actions API
```

## The part worth reading

[`tools/theater/README.md`](tools/theater/README.md) carries a ledger of **the twenty-two times this
toolchain lied to us** — each one pinned by a named regression test.

The first: a pattern meant to find skipped tests matched `exit(` as well as `xit(`, and reported 490
skipped tests where there were 39. A 12× inflation, produced by the tool built to find inflated
signals. Six of the first ten were caught not by tests but by reading the output and disbelieving it.
Two were caught later still — only when somebody moved to *act* on a finding and opened the file.
Seven are T10's, found by running it against repositories whose answer was already known by hand;
four of those were false *cleans*, the direction nobody investigates.

**This count has now gone stale twice.** It said "eleven" for six commits after the ledger reached
seventeen. It was corrected by hand — and then said "seventeen" for the twenty-row ledger, while
`reusable-theater.yml`, the file every adopting repository calls, still said "eleven". A stale count
in the front door of a repository about signals that lie is the joke writing itself; a stale count
that recurs *after* being corrected by hand is the argument for not correcting it by hand.

Both are recorded here rather than quietly fixed, and the count is now asserted in CI
(`ledger-count` in `.github/workflows/ci.yml`) against the actual row count, in every file that
states it. A prose number nothing checks is a signal that lies, which is this tool's entire thesis
applied to its own README.

We publish that list on purpose. A tool that argues checks lie has no standing to be coy about its
own, and the ledger is more useful than the code.

## Adopting the gate

The gate is a **ratchet**: it fails only on theater a change introduces, never on the backlog a
repository already carries. That is what makes it possible to switch on at all — a gate that failed
on 767 existing findings would never be enabled, and an un-enabled gate is worth nothing.

See [`tools/theater/README.md`](tools/theater/README.md) for the detectors, the declared-suppression
convention, and the known blind spots.

## Repo map

| Path | What it is |
|---|---|
| [`tools/sanitize`](tools/sanitize) | the internal-context leak gate |
| [`tools/theater`](tools/theater) | the verification-theater gate |
| [`principles`](principles) | ranked design principles, each tied to a real incident |
| [`agents`](agents) | role-spec schema and archetypes for narrow-scoped specialist agents |
| [`skills`](skills) | procedure schema and worked examples, landmines included |

## Scope

This repository publishes the tooling, the ranked principles behind how it is used, a set of
sanitized agent role archetypes, and worked skill examples — all adapted from patterns actually
running in production. The incident knowledge base itself — the internal, unredacted record each of
these traces back to — stays private;
what is here is what generalizes.

## License

MIT — see [LICENSE](LICENSE). Portions of `cu2_sanitize_scan.py` are adapted from work by
Darryl Hicks, MIT licensed.
