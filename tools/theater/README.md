# theater_scan — the verification-theater detector

Finds controls that exist, are relied upon, and do not check the thing everyone believes they check.

Two tools, deliberately separate:

| Tool | Detectors | Dependencies |
|---|---|---|
| `theater_scan.py` | T1–T6 | Python 3 stdlib only. No network, no credentials. Safe in a pre-commit hook. |
| `workflow_health.py` | T7 | Needs the GitHub Actions API (`gh`) and PyYAML. |

T7 cannot be answered from a repository's contents at all — a workflow file can declare a perfectly
good `on: schedule` and still be failing nightly, disabled by GitHub, or have never fired once.
Folding a network dependency into the offline scanner would cost it the one property that makes it
trustworthy everywhere, so T7 lives in its own file.

```bash
python3 tools/theater/theater_scan.py .                      # gate profile, fails on findings
python3 tools/theater/theater_scan.py . --profile all        # adds skipped tests
python3 tools/theater/theater_scan.py . --report             # size the work, always exit 0
python3 tools/theater/theater_scan.py . --inventory          # list declared suppressions
python3 tools/theater/theater_scan.py . --tracked-only       # skip untracked local junk

python3 tools/theater/workflow_health.py OWNER/REPO ...              # T7, fails on findings
python3 tools/theater/workflow_health.py --repos-file repos.txt --report
python3 tools/theater/workflow_health.py OWNER/REPO --as-of 2026-07-25   # reproducible verdicts
python3 tools/theater/workflow_health.py OWNER/REPO --clones-dir ./clones

python3 tools/theater/theater_scan.py . --profile gate --diff-base main   # ratchet (CI)
python3 tools/theater/theater_scan.py . --profile gate --staged           # ratchet (pre-commit)

python3 tools/theater/test_theater_scan.py       # 59 tests
python3 tools/theater/test_workflow_health.py    # 44 tests
```

Exit codes (both tools): `0` clean · `1` undeclared findings · `2` bad input.

**`gh` auth in this estate:** `~/.zshrc` exports a `GH_TOKEN` from a GitHub App installation token
that expires hourly, and a dead `GH_TOKEN` silently shadows the working keyring credential. Prefix
scripted `gh` calls with `env -u GH_TOKEN`. `workflow_health.py` handles this itself — it probes the
credential, and drops a dead `GH_TOKEN` only if dropping it actually helps, so a CI runner where
`GH_TOKEN` is the *only* credential keeps working.

## Why this exists

A two-week audit found that CU2's dominant defect class is not bugs. It is **verification
theater** — a signal that exists, is consumed, and lies. Documented instances:

| What lied | For how long |
|---|---|
| `catalog.search` returning `items: []` on backend failure | unknown; every agent read it as "no prior art exists" |
| `/health` reporting a Redis ping in a field named `spark_reachable` | read healthy the entire time Spark was down |
| CI running `pnpm lint/typecheck/test \|\| true` against a package with no such scripts | 15 test files had **never** run |
| `ruff` ignoring F821 | hid 35 real `NameError`s; 4 CLI command groups could not run |
| `cu2-agent-studio/cache-stats-daily` red | **19** consecutive scheduled runs, last green 2026-07-05 |
| `dev-studio/SAST (semgrep)` red on schedule | **6 of 6** scheduled runs — it had never once passed on schedule |

A missing control produces appropriate anxiety. A broken control produces false confidence,
which is worse.

**Both scheduled-workflow rows were re-measured, and both had drifted.** The knowledge base recorded
cache-stats-daily as "red 15 consecutive days"; the API says 19 consecutive scheduled failures — the
inherited number understated it. And both workflows were **fixed between the audit and this sweep**
(cache-stats-daily on 2026-07-25, semgrep on 2026-07-28), so as of today T7 correctly reports both
clean. An inherited incident record is a hypothesis with a timestamp, not a finding. `--as-of`
exists so a verdict can be reproduced against the date it was made.

## Detectors

| ID | What it finds | Severity | In `gate` profile |
|---|---|---|---|
| **T1** | `\|\| true`, `\|\| :`, `\|\| exit 0`, `; true` on a CI step | high | yes |
| **T2** | `continue-on-error: true` | high | yes |
| **T3** | `[]`, `{}`, or `pass` returned from an `except`/`catch` | high | yes |
| **T4** | Correctness rule disabled — F821, `strict: false`, `noImplicitAny: false`, `ignore_errors` | high | yes |
| **T5** | Skipped tests — `it.skip`, `@pytest.mark.skip`, `passWithNoTests` | medium | no |
| **T6** | CI invokes an npm/pnpm script no `package.json` defines | high | yes |
| **T7** | A scheduled workflow everyone believes is running, and is not | high | `workflow_health.py` |
| **T8** | A scanner configured so it cannot fail — `exit-code: '0'`, `soft_fail: true` | high | yes |

### T7's kinds

A scheduled control can lie in four ways, and all four look identical to a human reading the repo —
a nightly scan exists:

| Kind | Meaning | Finding |
|---|---|---|
| `red` | It runs on schedule and has failed N times consecutively (default threshold 2) | yes |
| `never_ran` | It declares `on: schedule` and has **never once** run on schedule | yes |
| `stale` | It used to run on schedule and has silently stopped | yes |
| `disabled` | GitHub has switched it off while the file still declares a cron | yes |
| `error` | Could not be determined — a first-class unknown | yes |
| `descheduled` | Ran on schedule historically; the file no longer declares a cron | no |
| `orphaned` | The workflow record exists but the file is deleted from the default branch | no |

`never_ran` and `disabled` are the purest form of the defect class: there is not even a red X
anywhere to notice. GitHub only runs `schedule` triggers on the default branch, which is the usual
cause of a cron that has never fired.

**The two non-findings are load-bearing, not bookkeeping.** `orphaned` and `descheduled` are the
states T7 originally collapsed into findings, and between them they accounted for a 15× and a 29%
inflation. A workflow that cannot run is not a control that lies.

**Staleness is judged against the schedule's own cadence, not a fixed threshold.** T7 parses each
cron expression and derives the maximum expected gap between firings, so a quarterly job is not
"stale" at 40 days. `0 14 15,16,17,18,19,20 2,5,8,11 *` yields 87 days; `0 5 * * *` yields 1.

**What T7 does not measure.** It cannot observe whether a human is watching — nothing in the API
exposes that. So no field is named `watched`. What it measures, and what the fields are named after,
is `consecutive_scheduled_failures` and `days_since_last_scheduled_success`. "Nobody is watching" is
an inference *you* draw from a workflow red for 19 days. Naming a field after the inference rather
than the measurement is exactly the `spark_reachable` defect, and
`test_no_field_is_named_after_the_inference` enforces the rule.

**T7's blind spot, stated rather than glossed:** a workflow whose only job is gated behind an `if:`
that evaluates false reports `conclusion: success` while doing nothing. This tool reads it as
healthy. So does the GitHub UI.

**T3 is the one to take seriously.** An exception handler that returns an empty collection makes
failure indistinguishable from a legitimate empty result. Every caller downstream reads "nothing
found" and proceeds confidently. In the audit, every instance examined was hiding a real broken
thing.

**T8 is the purest of the static detectors.** T1 and T2 both miss it, because the step carries no
`|| true` and no `continue-on-error` — the action's own options do the work:

```yaml
- uses: aquasecurity/trivy-action@...
  with:
    severity: HIGH,CRITICAL
    exit-code: '0'          # scans, reports, and cannot fail
```

The step is green, the SARIF uploads, the badge is present, and the threshold can never trip.
Nothing about the workflow looks suppressed. Found in 5 repos. It is legitimate when a later step
reads the SARIF and gates on it — `cu2-billing` does exactly that — so as everywhere else, it is
resolved by declaration rather than cleverness.

**T4 draws a line that matters.** `F401` (unused import) and `E501` (line length) are style
preferences. `F821` (undefined name) is a runtime crash. They do not belong in the same ignore
list, and this tool only flags the second kind.

## Ratchet mode — how this gets switched on at all

The estate carries **774 existing candidates**, and `cu2-standards` itself holds 47. A gate that
failed on the backlog could never be enabled, so it would never be enabled, and the backlog would
keep growing — `gandalf-protocol` acquired a new T1 in the two days between the pilot sweep and the
full one.

So the gate ships in **ratchet mode**: it fails only on theater the change *introduced*.

```bash
python3 tools/theater/theater_scan.py . --profile gate --diff-base "$BASE"  # CI
python3 tools/theater/theater_scan.py . --profile gate --staged             # pre-commit
```

- `--diff-base REF` is a **three-dot** `REF...HEAD` diff: the lines this *branch* added, measured
  against the merge base, so a busy base branch does not drag unrelated lines into the gate.
- `--staged` diffs the **index**: the lines this *commit* adds.
- Rename detection is on. Relocating a file does not present its contents as newly added — without
  that, a refactor would fail the gate on findings it did not introduce, and the fix would be to
  turn the gate off.

This decouples prevention from remediation. Remediation makes the number go down; the ratchet stops
it going up. The two can proceed independently, which is the only reason either happens.

**The failure mode this must not have.** A ratchet whose diff silently matches nothing reports a
confident clean on every commit forever. Every way the diff can fail — unresolvable ref, not a git
repo, unparseable output — exits `2` with a message. It never degrades to "no changes". `fetch-depth:
0` is therefore required on `actions/checkout`, and the error message says so by name.

That is not hypothetical: the pre-commit hook was first written as `--diff-base HEAD`, which expands
to `HEAD...HEAD`. The merge base of HEAD with itself is HEAD, so the diff was always empty and the
hook passed with theater sitting in the index. It was caught before shipping and is bug 10 in the
ledger below.

**What the ratchet cannot see.** If you add `except Exception:` above a pre-existing `return []`, the
finding is reported on the `return []` line, which your diff did not touch — so the ratchet misses
it. Widening the diff window would manufacture false positives, so the gap is documented rather than
papered over. The non-blocking backlog step in the workflow prints the standing total on every run,
so a green ratchet is never mistaken for a clean repo.

## Adopting it in another repo

One file, ten lines, no per-repo setup. Copy `tools/theater/templates/theater.yml`:

```yaml
name: Theater gate
on:
  push: { branches: [main] }
  pull_request: {}
jobs:
  theater:
    uses: credit-union-2-0-llc/cu2-standards/.github/workflows/reusable-theater.yml@main
    secrets:
      FORGE_BUILD_APP_ID: ${{ secrets.FORGE_BUILD_APP_ID }}
      FORGE_BUILD_PRIVATE_KEY: ${{ secrets.FORGE_BUILD_PRIVATE_KEY }}
```

`FORGE_BUILD_APP_ID` and `FORGE_BUILD_PRIVATE_KEY` are **organisation** secrets with visibility
`all`, and the `cu2-forge-build` App is installed on every repo with `contents: read`, so the two secrets resolve everywhere without per-repo setup. The reusable workflow mints a fresh installation token
scoped to `cu2-standards` alone, per run — no long-lived PAT, and none of the
`~/.gh-app-token`-expires-hourly problem that makes interactive `gh` calls here need
`env -u GH_TOKEN`.

### Never `secrets: inherit`

The first rollout template used `secrets: inherit`, and **semgrep caught it** —
`yaml.github-actions.security.secrets-inherit` — on the one repo in the estate whose branch
protection required a passing SAST check. It was right. `inherit` hands the called workflow *every*
secret the caller holds; this one needs exactly two. If the reusable workflow were ever modified
maliciously, it could read Azure credentials, API keys and DB connection strings from every adopting
repo. Naming the two secrets costs the same number of lines.

Worth recording plainly: the over-grant reached **71 merged repos** before a real security gate,
running on a repo that actually enforces it, stopped the 72nd. The gate that caught it is precisely
the kind of control this project exists to keep honest — and the 71 repos that let it through are
the reason the rest of the estate needs the same enforcement.

### Caller visibility is a hard constraint

`cu2-standards` is **private**, and GitHub only lets a private repository's reusable workflows be
called by *other private repositories in the same organisation*. Measured across the whole estate,
the separation is exact:

| Caller | Result | n |
|---|---|---:|
| **private**, in `credit-union-2-0-llc` | works | **78 / 78** |
| **internal** | fails to compile | 0 / 3 |
| **public** | fails to compile | 0 / 4 |
| owned by a **user account** rather than the org | fails | 0 / 2 |

The failure mode is nasty: **zero jobs, no log, no annotation**, and only
*"This run likely failed because of a workflow file issue"* in the UI. Nothing in the REST API
exposes the cause, and the caller file is byte-identical to the 78 that work — so there is nothing
to diff. Setting `access_level: organization` on the source repo is necessary but not sufficient;
it does not lift the visibility restriction.

Affected repos, all confirmed: `broflo`, `cu2-action-gateway-lint`, `cu2-shared-lib`,
`gandalf-protocol-swarmhack` (public); `Onramp-`, `autonomous-training-platform`, `cu3-platform`
(internal); and two repositories owned by a user account rather than the organisation.

**The fix is to publish the detector**, which Phase 5 already plans: an MIT-licensed public
`cu-agent-standards` repo. A public source can be called by callers of any visibility, and needs no
App token and no `access_level` change at all. Until then those nine repos need the detector
vendored, or they go without.

**Reusable rather than copied, deliberately.** The detector has been wrong ten times and will be
wrong again. Vendoring it into 92 repos means every fix needs 92 PRs and the copies drift. Here a
correction propagates on merge.

**It fails closed if the detector does not arrive.** A half-successful checkout — wrong ref, sparse
pattern matching nothing, a rename upstream — would otherwise run nothing and go green, leaving 91
repos with a passing badge for a gate that never executed. That would be a more perfect instance of
this defect class than anything the detector looks for. So the workflow asserts the file is present
and runs the detector's own 59-test suite before trusting it to judge anyone else's code.

`cu2-standards` itself uses the direct (non-reusable) workflow, since it already has the files and
needs no token to reach itself.

## Declared suppression — the core convention

`|| true` is correct on an advisory step and wrong on a gate. No regex reads intent. A blanket ban
gets worked around within a week.

So beyond a small built-in list of genuinely idempotent infrastructure commands
(`az extension add`, `az … delete`, `mkdir`, `rm -f`, `docker rmi`, `cat /tmp/…`), the tool does
not guess. It requires a **declaration**:

```yaml
- run: pnpm audit --audit-level=high || true   # theater-ok: advisory, tracked RISK-123
```

- **Undeclared** suppression → reported, fails the gate.
- **Declared** suppression → passes, and lands in `--inventory`.
- **Generic reason** → rejected. `theater-ok: intentional`, `theater-ok: known`, `theater-ok: wip`
  and anything under 12 characters do not count as reasons, for the same reason the sanitize gate
  rejects an allowlist entry of `.*`.

The output of this convention is the artifact worth having. Not "we have no verification theater,"
which nobody should believe, but **"here are our N declared suppressions, each with a reason and an
owner, reviewed quarterly."** That survives an examiner asking about it.

## The bugs that justify this tool

**This toolchain has now lied to us ten times.** Every one is pinned by a named test. The list is
kept in the README rather than in a commit log because it is the single most persuasive argument for
the false-positive-regression rule, and because a tool that finds dishonest signals has no standing
to be coy about its own.

| # | The bug | The lie it told | Pinned by |
|---|---|---|---|
| 1 | `xit(` matched `exit(` | 490 skipped tests; the real number was **39** — a **12×** inflation | `test_xit_does_not_match_exit` |
| 2 | `_is_workflow()` required a leading `/` | matched **nothing** for repo-root-relative workflows; would have reported a confident clean across every workflow in the estate | the T1/T2/T6 positive tests |
| 3 | T7 inferred "is this scheduled?" from an unfiltered 60-run page | dev-studio's `SAST (semgrep)` has 1070 runs, almost all `push` — so T7 called a nightly cron `never_ran`, with total confidence | `test_busy_workflow_is_not_misread_as_never_ran` |
| 4 | T6 didn't know about dependency-provided binaries | 11 T6 findings on the first estate sweep, **100% false**: `pnpm prisma` ×5, `pnpm tsc`, `npm view`, `npm sbom` | `test_t6_ignores_dependency_provided_binaries` |
| 5 | T7 fetched the workflow listing without `--paginate` | `bond` has **301** workflow records; the run audited the first 100 and reported a total as if complete | `test_listing_is_paginated` |
| 6 | T7 treated "cannot read the workflow file" as unknown | GitHub keeps workflow records after the file is deleted, still marked `active` — so 103 deleted throwaway workflows became 103 findings, taking the estate total from **7 to 110**, a **15×** inflation | `test_deleted_workflow_file_is_orphaned_not_a_finding` |
| 7 | T5 didn't skip comment lines, though T1 and T4 do | 6 findings that were *documentation about* skipped tests — best of them a docstring announcing the stubs had been **converted to active passing tests**, counted as a skipped test | `test_t5_ignores_prose_in_comments` |
| 8 | T7 inferred "is this scheduled?" from run history rather than the file | reported `cu2-platform/soc2-evidence-collector.yml` — deliberately migrated to an ACA Job and reduced to `workflow_dispatch` — as a dead SOC 2 control. **This one shipped, and was escalated as the top finding of the sweep** | `test_deliberately_descheduled_workflow_is_not_stale` |
| 10 | The pre-commit ratchet was spelled `--diff-base HEAD` | `HEAD...HEAD` is always empty, so the hook passed with theater staged — a silent clean on every commit forever, which is the failure the ratchet exists to prevent, rebuilt inside the ratchet. Caught before shipping | `test_staged_mode_sees_the_index` |
| 9 | T7 judged staleness against a fixed 30-day threshold | `ncua-query-api`'s cron fires Feb/May/Aug/Nov only; 69 days of silence was correct with the next window three weeks out. T7 now parses the cron and derives the cadence | `test_quarterly_cron_is_not_stale_at_69_days` |

Six of those ten were found by *reading the sweep output and disbelieving it* rather than by a test.
That is the part that does not automate — and bugs 8 and 9 were not caught even then. They were
caught only when somebody moved to **act** on a finding and opened the workflow file, which was the
first moment anyone looked at the source behind the count. Both `stale` rows in the first estate run
were false positives: a 29% error rate in T7, with the loudest of them escalated first.

Note the direction of travel. Bugs 1, 4, 6, 7, 8 and 9 inflated counts. Bugs 2 and 3 **deflated**
them — false *cleans*, which is worse, because nobody investigates good news. When you add a
detector, add both halves of the test, or you are writing the thing this repo exists to eliminate.

The generator that writes `INVENTORY.md` produced two of its own: a leaked loop variable printed `0`
in every row's total while the footer said 780, and a default label read "Reconciles exactly" beside
a row showing Δ=−1. Both are now blocked by assertions. Nothing here is immune.

## Measured baseline

**Full estate, 92 non-archived repos, 2026-07-28** — see
`.planning/phases/verification-theater-01/INVENTORY.md` for the per-repo table.

The 8-repo pilot found 169 findings. The naive extrapolation to 92 repos would have been ~1,944. The
measured figure is **774 T1–T6 candidates plus 7 T7 findings** — so the pilot's own projection was
wrong by 2.5×, in the direction of overstating. Report what you measure.

- 91 of 92 repos scanned; the 92nd is empty and has a stated row.
- 42 repos are clean at `--profile all`; the top 8 hold 59% of all candidates.
- T3 is **55%** of candidates, not the 78% the pilot's sample suggested — that sample was biased
  toward Python tooling repos. T5 is **28%**, far larger than the pilot's 7%.
- Two confirmed security gates that cannot fail still reproduce and serve as regression cases:
  `cu2-agent-studio/.github/workflows/deploy.yml:133` and `servd/.github/workflows/ci.yml:100`.
- T7 finds **6**: five `red`, one `never_ran`. The largest is `bond/eval-baseline-daily.yml` at 24
  consecutive scheduled failures. Two others have never once passed on schedule
  (`brand-voice-tool/ops-scan.yml`, `ncua-query-api/quarterly-import.yml`).

**No number here is a defect count.** A detector hit is a candidate; some are legitimate suppressions
that Phase 4 will *declare* rather than remove. Classifying them is Phase 2's job.

## What it cannot catch

- **A control that checks the right thing incorrectly.** A health endpoint querying the wrong
  service returns 200 and this tool has nothing to say about it. That was the `spark_reachable`
  incident, and it is invisible to static analysis.
- **A test that runs and asserts nothing.** `expect(true).toBe(true)` executes, passes, and counts
  toward coverage.
- **A mock shaped like the code rather than like reality.** An `AsyncMock` standing in for a sync
  callee passes in tests and crashes in production.
- **Thresholds set so loose they never trip.** A coverage gate at 5% is a gate.

This tool finds the *mechanical* forms of the defect. The judgment forms still need a human who is
suspicious of good news.

## Relationship to the other gates

```
gitleaks              credentials, full git history
cu2_sanitize_scan     internal context leaving the repo
theater_scan          controls that lie about whether they ran        (offline, T1-T6)
workflow_health       scheduled controls that are not running at all  (Actions API, T7)
```

Four tools, one posture: enforcement in the plumbing, fail closed, and a narrow documented
escape hatch that the tool itself polices.
