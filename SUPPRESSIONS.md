# Declared suppressions

`# theater-ok: <reason>` tells the theater detectors that a finding is intentional. This
document says when that is the right answer, when it is not, and how to audit the estate
yourself rather than trusting a list in a file.

**There is deliberately no manifest of current suppressions here.** A checked-in inventory
of other repositories' contents is stale the day after it is written, and a stale inventory
that reads as authoritative is the same defect class the detectors look for. The command to
produce a live one is below.

---

## The rule

A suppression is correct when **the control genuinely cannot fail, and something else
carries the verdict.** It is wrong when it is standing in for work.

Two questions to answer in the reason string:

1. **Why can this step not meaningfully fail?**
2. **What fails instead if the underlying thing is broken?**

If you cannot answer the second one, you do not want a suppression — you want a fix. A
reason that says "not needed here" or "known issue" is the thing this convention exists to
prevent, because it is indistinguishable from having given up.

### Shapes that are usually right

| shape | why the exit code is meaningless | what actually gates |
|---|---|---|
| `az containerapp hostname add … \|\| true` | idempotent; "already present" is success spelled as failure, and the error text is not contractual | the next step asserts `bindingType==SniEnabled` and a non-empty `certificateId` |
| `grep -q <forbidden-pattern> … \|\| true` | **no match is the PASS case**, so grep exiting 1 is expected | a file-count precondition proves the scan actually ran over something |
| `cp -n src dst \|\| true` | `cp -n` exits non-zero merely for *skipping* an existing file | a later assertion checks the artifact exists and is non-empty |
| `bandit … \|\| true` on a report-only step | bandit exits 1 for *finding* issues, which is its job | the SARIF gate, or a separate enforcing bandit step |
| best-effort teardown in a `trap EXIT` | the real work already succeeded or failed on its own merits | the step being cleaned up after |

### Shapes that are usually wrong

- **Anything on the step that is the only check.** If nothing downstream re-asserts it,
  suppressing it deletes the control.
- **`continue-on-error: true` on a test or scan job.** That is not a suppression, it is
  turning the job into decoration.
- **A whole file marked exempt to silence one route or one line.** Scope to the line or the
  route. A file-level exemption silently stops checking everything else in the file, and
  nobody notices the day a real problem lands next to the one you meant to allow.
- **"Fails in CI but works locally."** That is a bug report, not a justification.

### The suppression that is not one

A `# theater-ok:` comment on a command the detector *already* exempts suppresses nothing. It
looks like a control decision and is inert. One exists in the estate today
(`kirk-helper/.github/workflows/willis-deploy.yml`, on an
`az containerapp hostname add … || true` that is already on the built-in idempotent-
infrastructure list). Harmless, but it inflates the apparent count and it will mislead
whoever audits next. If you add a declaration, confirm the finding existed first.

---

## `@synth-only` is a different tool

For MSW handler files in a frontend, `// @synth-only` on the first non-blank line exempts
the file from `MswHandlerControllerParity`. That marker means **"this route has no backend
and is not pretending to"** — a classification, not a suppression.

Use it when a mocked route's backend genuinely does not exist yet. Do **not** use it to
quiet a route whose backend exists somewhere the test cannot see; that needs a scoped
route-level allowlist with the location named, because the two require opposite follow-up
work.

---

## Auditing the estate

Declared suppressions, one row per declaration line, attributable and countable:

```bash
for r in $(gh repo list credit-union-2-0-llc --limit 300 --json name --jq '.[].name'); do
  for wf in $(gh api "repos/credit-union-2-0-llc/$r/contents/.github/workflows" --jq '.[].name' 2>/dev/null); do
    body=$(gh api "repos/credit-union-2-0-llc/$r/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | base64 -d)
    [ -z "$body" ] && { echo "ERROR|$r|$wf|fetch failed"; continue; }
    printf '%s' "$body" | grep -n "theater-ok:" | while IFS= read -r hit; do
      echo "HIT|$r|$wf|${hit%%:*}"
    done
  done
done
```

Two things about that loop, both learned the hard way:

- **Print rows, do not accumulate a total.** A running sum inside a loop reported `0` for a
  repository that has a declaration, and an opaque zero cannot be distinguished from a
  failed fetch. Count the printed rows afterwards.
- **Record fetch failures as `ERROR`, never as zero.** A repository you could not read is
  not a repository with nothing in it.

For the per-repo *undeclared* backlog, every gate run prints it in its non-blocking
"Standing backlog" step:

```
theater_scan: 7 undeclared finding(s) [profile=all]
  by detector: T1=3 T3=2 T6=2
```

A repo with no retrievable run is **UNMEASURED**, which is a third state. Do not fold it in
with clean.

---

## Measured baseline — 2026-07-31

A dated snapshot, not a live figure. Reproduce with the commands above before acting on it.

**Declared: 39 declaration lines across 9 repositories, suppressing 43 findings.**

| repo | lines |
|---|---:|
| ops-platform | 11 |
| cu2-agent-studio | 7 |
| broflo | 5 |
| Onramp- | 4 |
| mcdrake-print | 3 |
| kirk-helper | 3 |
| AI_CU_CDP | 3 |
| scienceworks-platform | 2 |
| cu2-platform | 1 |

Lines and findings differ, and the arithmetic is worth stating so a future audit does not
"correct" it: three `ops-platform` lines each suppress two findings (a `pnpm`/`yarn`
invocation that is both a swallowed exit **and** an undefined script — T1 and T6), two
`mcdrake-print` declarations cover both a step's `|| true` and its `continue-on-error` (T1
and T2), and one `kirk-helper` line is the inert declaration described above. So
39 + 5 − 1 = 43.

**Undeclared: 750 findings across 88 gate-carrying repositories.** 40 measured clean, 48
with findings, 0 unmeasured.

| detector | findings | share |
|---|---:|---:|
| **T3** — `except`/`catch` returning empty | **413** | 55% |
| **T5** — skipped tests | 251 | 34% |
| T1 — `\|\| true` | 48 | 6% |
| T2 — `continue-on-error` | 27 | 4% |
| T4 — correctness rule disabled | 6 | <1% |
| T8 — scanner cannot fail | 5 | <1% |

Split by whether they block: **499 are gate-profile**, 251 are advisory (T5 is deliberately
outside `gate`).

**This baseline predates T9** (`|| echo <plain text>` discarding exit status), added after
the census. Its findings are not in the 750, and the estate total is therefore an
undercount rather than an overcount.

### Where the work actually is

T3 is 55% of everything, and it is concentrated rather than diffuse — five repositories hold
240 of the 413:

| repo | T3 |
|---|---:|
| misty-9000 | 66 |
| resistance-wine | 51 |
| cu2-standards | 47 |
| kirk-helper | 39 |
| xdi-implementations-os | 37 |

That is a work order, not a fleet-wide slog. It is also the class that produces
`items: []` by construction: a caller cannot distinguish "nothing found" from "the query
threw", which is why it is `high` and in the gate profile.

By contrast T1/T2/T8 together are 80 findings, and those are the classes where *declaring*
is often the right answer rather than removing. Roughly the same order of magnitude as the
43 already declared — that part of the backlog closes by writing reasons, not code.
