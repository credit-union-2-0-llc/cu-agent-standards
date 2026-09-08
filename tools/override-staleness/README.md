# Override staleness detector

Fails a build when a dependency override pins a version that is **still
vulnerable**.

## The defect

An override exists to force a transitive dependency *past* a patched version.
It stops doing that not when someone edits it, but when the advisory **widens
underneath it**. The pin does not change; the range does.

```yaml
overrides:
  fast-uri: 3.1.5      # correct when written — the advisory then said < 3.1.5
```

Three weeks later the advisory says `< 3.1.6`. That line now pins a vulnerable
version *shut*, and:

- it installs cleanly
- it reads as remediation in review
- the alert stays open
- **Dependabot cannot fix it** — there is no way to raise a pull request against
  a version you force

The observable signature is a repository with open Dependabot alerts, **zero**
Dependabot PRs, and every CI gate green. Nothing anywhere says why.

## Why a gate and not an audit

A point-in-time audit was tried first, across the estate, and every dead pin it
found was fixed. Weeks later the count had grown back — not through neglect, but
because advisories on two widely-vendored packages widened afterwards. An audit
cannot keep up with a failure mode whose trigger is an advisory published later.

One repository is the whole argument in miniature: it had already shipped a
fix for exactly this defect on one package, and a second package broke the same
way in the same file a few weeks on. Nobody had done anything wrong in between.

## What it does

1. `pnpm audit --json` — reads the **lockfile**, so there is no `pnpm install`
   and the whole job is a checkout plus one registry call.
2. Collects declared overrides from all three homes:
   `package.json` → `overrides`, `package.json` → `pnpm.overrides`,
   `pnpm-workspace.yaml` → `overrides:`.
3. For every advisory, asks whether *this repository's own pin* is holding it
   open.

**Only advisories on packages the repository pins can fail the build.**
Everything else is printed for context and left to Dependabot, which can
actually fix it. A gate that goes red for reasons nobody in the repository can
act on is a gate they switch off — and a switched-off gate is worth nothing.

## Two things it gets right that are easy to get wrong

**A range pin is not an exact pin.** `^6.15.2` and `>=3.1.5 <4.0.0` both *reach*
the patched version and are fine. Only a range that **cannot** reach it — such
as `~3.1.5` when the fix is 3.2.0 — is dead. An earlier pass coerced range pins
to their floor and wrongly condemned two repositories that were never at risk.
False positives are how a security gate gets disabled.

**A scoped package begins with `@`.** The selector separator in
`@xmldom/xmldom@<0.8.13` is the *last* `@`, never the first. Splitting on the
first would turn the package name into `""` and the gate would silently stop
covering every scoped package — the same silent-coverage-loss class it exists to
catch.

## What it does NOT tell you

**This gate is complementary to Dependabot, not a superset of it.** `pnpm audit`
reads the npm advisory database; Dependabot reads the GitHub Advisory Database.
Observed on the same day, in the same estate, they disagreed **in both
directions**:

- one repository had a `browserslist` advisory Dependabot flagged and
  `pnpm audit` never reported — at either of that repo's two lockfiles
- another had `tmp` and `js-yaml` advisories `pnpm audit` reported and
  Dependabot did not flag at all

The second pair were live dead pins, caught by this gate on its first run in a
repository whose Dependabot alerts had just been swept to zero.

So: **a green gate means no pin is holding open an advisory that `pnpm audit`
knows about.** It is not a statement that the repository has no open alerts, and
zero Dependabot alerts is not a prediction that this gate will pass. Run both.

**It checks one directory per invocation.** A repository with more than one
lockfile needs one job per lockfile — see the `working-directory` input. A repo
where a second project sits outside the root workspace is exactly where an
"all alerts closed" sweep quietly isn't.

## Exit codes

| | |
|---|---|
| `0` | no override is holding an advisory open (or there is no `pnpm-lock.yaml`) |
| `1` | one is — the output names the pin, its home, the advisory and the fix |
| `2` | **the check could not run.** A check that did not run must never read as a check that passed, so this is loud rather than skipped |

## Fixing what it reports

1. **Raise the pin _and_ widen its selector key.** A key like
   `fast-uri@<3.1.5` that stops below the current vulnerable range leaves the
   tail unmatched — the same silent failure one layer up. Both halves, or the
   fix is partial.
2. **Choose the OLDEST version that clears the advisory, not the newest.** With
   pnpm's `minimumReleaseAge` set, a version published inside the cooldown is
   one pnpm will refuse, and the PR becomes unmergeable.
3. **Check *where* the pins live if the repo is on pnpm ≥ 10.16.**
   `package.json`'s `pnpm.overrides` is **silently ignored** from that version
   on and must move to `pnpm-workspace.yaml`. A repository can hold dozens of
   remediations in the ignored location, and a pnpm upgrade then drops them all
   with no error.
4. Regenerate the lockfile **with the repository's own pnpm** — see above.

## Files

| | |
|---|---|
| `check_override_staleness.py` | the detector |
| `semver_lite.py` | dependency-free range evaluation |
| `test_check_override_staleness.py` | self-test; the reusable workflow runs it before trusting the detector |

Run locally against any repo:

```bash
python3 tools/override-staleness/check_override_staleness.py /path/to/repo
```

## Usage

See `.github/workflows/reusable-override-staleness.yml`. Callers need four
lines and no secrets.
