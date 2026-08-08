# Contributing

This is a single-maintainer public repository under `credit-union-2-0-llc`. Contributions are
welcome, but they land through the same narrow-scope discipline the tools in here enforce on
everything else — see [principle 2](principles/PRINCIPLES.md#the-ranking). A PR that does one clearly
described thing gets reviewed faster than one that bundles a detector fix with a README rewrite.

There are four shapes a contribution here usually takes. Pick the one that matches before you start,
because each has a different bar.

## 1. A new or fixed detector (`theater_scan.py`, `cu2_sanitize_scan.py`)

Theater detectors are numbered `Tn`. Check the table in
[`tools/theater/README.md`](tools/theater/README.md) before claiming a number — this has gone wrong
before: [PR #3](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/3) added a `T9`, and
[PR #4](https://github.com/credit-union-2-0-llc/cu-agent-standards/pull/4) had to rename it to `T11`
because `T9` was already taken. Claim the next free number, not the next round one.

A detector change needs, in the same PR:

- The implementation.
- A regression test in `tools/theater/test_theater_scan.py` (or `tools/sanitize/test_cu2_sanitize_scan.py`
  for a sanitize rule) that fails without the fix and passes with it.
- A fixture-mutation case in `test_fixture_mutations.py` for the tool you touched — it mutates a
  known-good fixture into a deliberately bad one and asserts the rule catches it. See
  [`tools/theater/README.md`](tools/theater/README.md) and
  [`tools/sanitize/README.md`](tools/sanitize/README.md) for how the existing cases are structured.
- If the change fixes a detector that previously produced a wrong answer, a row in the ledger in
  `tools/theater/README.md` — that ledger is the most-read part of this repo and it stays accurate
  by every entry being pinned to a named test, not by anyone remembering to update it later.

You do not need to fix the standing backlog to get a detector PR merged. The self-gate in CI runs
`theater_scan.py --profile gate --diff-base <PR base> --tracked-only` — a ratchet against what your
diff introduces, not the whole tree. That is a deliberate design choice
([principle 1](principles/PRINCIPLES.md#the-ranking)): a gate that failed a PR for pre-existing
findings would train people to route around it.

## 2. A new agent archetype

Follow [`agents/README.md`](agents/README.md) — "How to spec one." In short: one job per agent, no
"and" in the mission line, approval boundaries written before the capability list, and the shape must
match [`agents/AGENT-SPEC.schema.md`](agents/AGENT-SPEC.schema.md) exactly (required frontmatter keys,
required section headings, and — checked mechanically by
[`tools/lint/format_lint.py`](tools/lint/format_lint.py) — at least a real paragraph under each
required heading, not just the heading itself).

## 3. A new skill

Follow [`skills/README.md`](skills/README.md) — "How to build one." Leave the Landmines section empty
until the skill has actually been used and has actually failed once; a landmines section written in
advance is a guess, not scar tissue. Same schema-conformance requirement as archetypes, this time
against [`skills/SKILL.schema.md`](skills/SKILL.schema.md).

For both archetypes and skills: this repo publishes sanitized, not hollow, examples. Strip repository
names, hostnames, tenant names, and anything that maps back to a specific live system before you draft
— see the "Depth note" in [`agents/README.md`](agents/README.md). If you're not sure whether a detail
is safe to publish, that's what the sanitize gate below is for — run it before you ask.

## 4. Everything else (docs, README, principles)

Smaller bar, same rule: one change, one PR, and if you're touching a number that describes this
repository's own size (a test count, a suite count) or the private estate it was built against (a
repository count, a finding count), read
[`tools/lint/test_measured_claims.py`](tools/lint/test_measured_claims.py) first. It fails CI on any
prose claim about this repo's own tests/suites that doesn't match a fresh count, and on any estate
figure that isn't dated — this repository has gone stale on exactly this kind of number twice already
(see the front-page ledger-count story in [`README.md`](README.md)), and would rather fail your build
than do it a third time.

## Branch and PR naming actually used here

Feature branches are named `<type>/<short-kebab-description>` most of the time —
`feat/mission-principles-agent-archetypes`, `fix/sanitize-ssn-space-and-public-ip`. Not universally:
a couple of branches in this repo's own history skipped the prefix
(`sanitize-fixture-mutation-harness`). Prefer the prefixed form; don't block a PR on fixing an old one.

PR and commit titles follow Conventional Commits — `feat:`, `fix:`, `docs:`, `ci:`, `test:`, with an
optional scope: `fix(theater): …`, `feat(sanitize): …`. Run `git log --oneline` if you want the real
pattern instead of a style guide nobody actually follows — every merged PR in this repo's history
matches it.

## What CI actually gates

Read [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the source of truth; this table is a
map, not a substitute.

| Check | What it does | Blocking |
|---|---|---|
| **Toolchain self-tests** | Discovers every `test_*.py` under `tools/` (not a hardcoded list — a missing runner is exactly how two suites went unrun for a day, see the comment block at the top of `ci.yml`), runs each one, fails if any fail or if the discovered count drops below a floor. | Yes — required status check |
| **Theater gate (self, ratchet)** | Runs `theater_scan.py` against the PR's own proposed source (not a copy fetched from `main`), so a PR changing the detector is judged by the version it introduces. | Yes — required status check |
| **Schema conformance** | `tools/lint/format_lint.py` — parses the required frontmatter keys and section headings straight out of `AGENT-SPEC.schema.md` and `SKILL.schema.md`, and fails any archetype or skill file that doesn't match, including one with all the right headings and nothing underneath them. | Yes — runs inside the self-gate job; must exit 0 |
| **Sanitize gate** | `cu2_sanitize_scan.py --profile internal --tracked-only` — nothing in the `secret` or `pii` tier may land in this public repo. | Yes — runs inside the self-gate job |
| **Standing backlog (non-blocking)** | Reports the full, non-ratcheted finding count with `--report`, always, even when the gate above fails. Exists so a green ratchet is never mistaken for a clean repository. | No — `if: always()`, no verdict to give |
| **CodeQL / "Analyze (actions)"** | GitHub's default code-scanning setup — configured in repo settings, not a checked-in workflow file. | Yes — required status check in branch protection |

Branch protection on `main` also requires every open review thread to be resolved before merge, blocks
force-pushes and branch deletion, and applies all of the above to the maintainer's own pushes too
(`enforce_admins` is on) — there is no admin bypass on this repo, including for the person who owns it.

There is no minimum-reviewer count configured, because there is one maintainer. A PR merges when it's
green and has actually been read — not automatically the moment the checks above pass.

## Before you touch `.cu2-sanitize-allow`

The allowlist is not a place to make a false positive go away quietly. Every line needs the same
justification the sanitize scan's own exceptions carry — see the comments at the top of
[`.cu2-sanitize-allow`](.cu2-sanitize-allow) and the "why can't this fail" framing in
[`SUPPRESSIONS.md`](SUPPRESSIONS.md) (written for the theater gate's `theater-ok` marker, but the
question is the same one). If you can't answer "what fails instead if this pattern really is
sensitive," you want a fix to the detector, not an allowlist entry.

## If you're not sure any of this applies

Open an issue describing the gap before writing code. This exact file exists because an outside
comparison flagged that this repo was missing it — reporting "this repo doesn't have X, here's what X
usually looks like" is a completely legitimate contribution on its own, and the same publish-what-we-
found-wrong pattern that produced the ledger in `tools/theater/README.md` applies here too.
