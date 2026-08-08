# Changelog

This repository has never cut a tagged release — there are no git tags and no GitHub Releases as of
this writing. `main` is the only supported line, and downstream workflows already pin to it by commit
convention (`reusable-theater.yml` documents fetching `@main`). So instead of semantic-version
sections, the entries below are grouped by the actual body of work each run of merged pull requests
represents, newest first, reconstructed from `gh pr list --state merged --limit 100` against
[credit-union-2-0-llc/cu-agent-standards](https://github.com/credit-union-2-0-llc/cu-agent-standards)
plus the direct-to-`main` commits that predate PR-based review. Every date below is a real PR merge
timestamp or commit date, not an estimate.

## 2026-08-05 – 2026-08-08 — Sanitizer hardening and fixture-mutation harnesses

- [#19](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/19) —
  test(theater): add fixture-mutation harness across the full detector set
- [#18](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/18) —
  fix(sanitize): catch space-separated SSNs and hardcoded public IPs
- [#17](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/17) —
  test(sanitize): add fixture-mutation harness across the full rule set
- [#16](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/16) —
  fix(sanitize): catch passwords containing punctuation, and connection-string credentials

## 2026-08-04 – 2026-08-05 — Principles, agent archetypes, skills layer, and schema enforcement

This is the day the repo grew from "two gates" into the current shape: ranked principles, sanitized
agent archetypes, worked skill examples, and the linter that keeps the published schemas honest.

- [#15](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/15) —
  fix: make every number in this repo verifiable or dated
- [#14](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/14) —
  fix: enforce the published schemas, and stop the ledger count lying
- [#13](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/13) —
  feat: add skills layer with two session-grounded worked examples
- [#12](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/12) —
  feat: publish ranked principles and agent archetypes
- [#11](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/11) —
  feat: add reusable-sanitize.yml, mirroring reusable-theater.yml

## 2026-08-02 – 2026-08-03 — Detector precision fixes and a CLI flag bug

- [#10](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/10) —
  fix(theater): `--detector` must override `--profile`, not intersect with it
- [#9](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/9) —
  fix(theater): T3 block-form must not cross a class/def boundary
- [#8](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/8) —
  fix(theater): T3/T12 blindness to trailing comments and reason-text keyword leaks

## 2026-07-31 – 2026-08-01 — Suppression convention, detector renumbering, and T12

*(There is no PR #7 in this repo's history. #7 is an open, non-code issue — an automated dependency/
security sweep report — not a merged pull request, so it does not appear in this changelog.)*

- [#6](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/6) —
  feat(theater): T12 — the HTTP failure branch T3 structurally cannot see
- [#5](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/5) —
  docs: SUPPRESSIONS.md — when `theater-ok` is right, and how to audit it
- [#4](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/4) —
  fix(theater): rename the `|| echo` detector T9 -> T11 — T9 was already taken
- [#3](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/3) —
  feat(theater): T9 — exit status discarded by `|| echo`, plus two T1 false-positive fixes

## 2026-07-29 – 2026-07-31 — First CI, and the ledger count catches its own front page lying

Before [#2](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/2), this repository had no
workflow that ran on `push` or `pull_request` at all — `reusable-theater.yml` is `workflow_call`-only,
so it never fired here, and the toolchain's own tests had nowhere to run.

- [#2](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/2) —
  ci: the toolchain had no CI; most of its own tests ran nowhere
- [#1](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/1) —
  docs: the front-page ledger count said eleven; the ledger has seventeen

## 2026-07-28 — Initial public release

Committed directly to `main`, before PR-based review started on this repo (that switch is itself
`#1`, above). This is the day the `sanitize` and `theater` gates first shipped:

- Initial public release: the sanitize and theater gates
- Add T9 — default-branch CI that is red, honest, and ignored *(this is `workflow_health.py`'s T9;
  a second, unrelated T9 added three days later in
  [#3](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/3) collided with it and was the
  one renamed, in [#4](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/4) — this
  original T9 kept its number)*
- T9: only evaluate workflows that declare a push trigger
- T5: scan JSON only for the jest flag, not for code patterns
- T10: find test suites that no workflow runs
- T10: a test invocation that cannot fail the job is not coverage
- fix: rewrite the reusable workflow — regex surgery had duplicated it
- Remove the dead secrets declaration and its stale comment
- Drop the App token — a public source needs no credential
- Add `.pre-commit-hooks.yaml` so the gates are consumable as pre-commit hooks
- Drop a committed `.pyc` and ignore `__pycache__`; drop the two remaining committed `.pyc` files

---

*A note on drift, since that is this repository's whole subject: the groupings above are a snapshot at
the time this file was written. New PRs will land after it. If this file stops matching
`gh pr list --state merged`, that is the same class of defect
[`tools/lint/test_measured_claims.py`](tools/lint/test_measured_claims.py) polices for prose test and
suite counts — the fix is to update this file, not to trust it unread.*
