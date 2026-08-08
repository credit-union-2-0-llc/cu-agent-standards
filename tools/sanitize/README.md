# cu2_sanitize_scan — the CU 2.0 publication gate

A fail-closed scanner for content that must not leave a CU2 repo, or must not leave the org at all.
Pure Python 3 standard library: no dependencies, no network, no secrets, no config server.

```bash
# Default: safe to run on any private CU2 repo today.
python3 tools/sanitize/cu2_sanitize_scan.py .

# Publication gate: everything above, plus internal operating context.
python3 tools/sanitize/cu2_sanitize_scan.py . --profile public

# Size the sanitization work without failing the build.
python3 tools/sanitize/cu2_sanitize_scan.py . --profile public --report

python3 tools/sanitize/test_cu2_sanitize_scan.py

# Fixture-mutation harness: for every rule, mutates a known-good fixture into
# a deliberately bad one and asserts the rule rejects it — see below.
python3 tools/sanitize/test_fixture_mutations.py

# Has .cu2-sanitize-allow gone stale? See "Allowlist drift" below.
python3 tools/sanitize/check_allowlist_drift.py .
python3 tools/sanitize/test_check_allowlist_drift.py
```

Exit codes: `0` clean · `1` findings · `2` bad input.

## This is not a gitleaks replacement

`cu2-agent-studio` already runs gitleaks against full git history, plus semgrep for SAST. Those stay.
This gate covers the thing they do not:

| Tool | Catches |
|---|---|
| **gitleaks** | Credentials, across full history. Provider token formats, entropy. |
| **semgrep** | Code-level security defects. |
| **cu2_sanitize_scan** | **Internal operating context** — Azure estate names, tenant credit union identities, internal hostnames, real filesystem paths, private repo slugs — plus member-data PII and a credential backstop. |

A repo can be perfectly clean under gitleaks and still be unpublishable. That gap is what this closes.

## Three tiers, two profiles

| Tier | Examples | Why |
|---|---|---|
| `secret` | private keys, provider tokens, connection strings, `cu2_*` API keys, SAS tokens | Backstop behind gitleaks |
| `pii` | member/share/NMLS IDs, SSNs, Luhn-valid PANs, routing numbers, emails, phones, named credit unions, live tenant names | Must never leave, public or private |
| `internal` | `*.azurecontainerapps.io`, `rg-*`, `ca-*`/`kv-*`/`pg-*`, subscription GUIDs, `*.cu-2.com`, `credit-union-2-0-llc/*`, `/Users/…`, `/home/…`, `*.ts.net`, CGNAT `100.64/10`, VNet `10.40/16` | Fine internally; fatal publicly |

- `--profile internal` *(default)* — fails on `secret` + `pii`.
- `--profile public` — fails on all three.

The internal profile is the one you wire into CI on private repos. The public profile gates anything
headed for a public repository.

## Two lists you will actually edit

Both live at the top of `cu2_sanitize_scan.py`:

- **`CU2_TENANT_NAMES`** — live tenant and partner credit unions. Naming one publicly discloses a client
  relationship. **Add every new tenant on the day it signs.** A tenant missing from this list is a tenant
  the gate cannot protect.
- **`PLACEHOLDER_EMAIL_LOCALS`** — local-parts that are documentation stand-ins (`user@`, `you@`, `test@`)
  rather than real people, so synthetic examples don't trip the gate.

There is also `KNOWN_SAFE_CU2_IDENTIFIERS`, for names that structurally look like a `cu2_*` API key but
are ordinary module names — this file would otherwise flag the scanner's own name every time it appears.

## Design notes worth knowing before you edit a rule

**Context qualification.** Short Azure prefixes (`ca-`, `caj-`, `cae-`, `kv-`, `pg-`) only fire when the
line also carries an Azure signal (`az `, `containerapp`, `azure`, `rg-`, `Container App`, `acr`, `key vault`).
Without this, pattern filenames like `pat-ca-secretref-stale-resolution.md` false-positive — a real finding
from the first run against this repo. Same idea for routing numbers, which require a financial context word
(`routing`, `ABA`, `account number`) before a bare 9-digit number is treated as sensitive.

**Validators, not just regexes.** Some rules run a Python predicate on the match:
Luhn checksum for card numbers, hex-length suppression so 40- and 64-character commit SHAs aren't reported
as base64 secrets, and the placeholder checks above.

**Everything is redacted on output.** Findings print `path:line: [tier] label` and a snippet with the matched
value replaced by `[REDACTED]` — including sensitive values found in *filenames*. CI logs are themselves a
publication surface; the gate does not leak the thing it caught.

## Allowlisting honestly

Copy `.cu2-sanitize-allow.example` to the scanned repo's root as `.cu2-sanitize-allow`.

```
line:<regex>    suppress any line matching the regex
path:<regex>    skip a whole file (must be anchored with ^ or contain /)
```

The gate **rejects** broad patterns (`.*`, `.+`, bare fragments under 4 characters) and unanchored `path:`
entries, and that rejection fails the run. You cannot quietly widen the net. Every entry needs a comment
explaining why the value is safe to publish. If a rule is genuinely noisy, fix the rule — don't allowlist
your way out of it.

## What it cannot catch

Be honest about the boundary. This is a backstop, not a DLP system, and a clean scan is not permission
to publish:

- **Names of people.** No regex finds "Kirk approved this on the call with their CFO." Presidio handles
  PERSON entities at runtime; a static scanner does not.
- **Confidential meaning in ordinary words.** Deal terms, roadmap commitments, examiner findings, and
  vendor pricing all read as plain prose.
- **Architecture that is sensitive by shape,** not by identifier — a diagram describing an unreleased
  control, for example.
- **Git history.** This scans the working tree. Use `gitleaks detect --source . --redact` for history
  before any publication.

Human review of the diff is required regardless of what the gate says. See the publication checklist in
`docs/` before anything goes public.

## Allowlist drift

`.cu2-sanitize-allow` suppresses a finding by matching literal text: a `line:` regex against a file's
content, or a `path:` regex against a repo-relative path. Nothing in the format ties an entry to the one
file its author had in mind, and nothing ever re-checks that the text an entry was written against is
still there. Both halves of that gap have bitten this org for real, in the same downstream repository,
each time as a one-off script written on the spot, used once, and thrown away:

1. **A comment reword broke a `line:` match.** An entry was written to match one exact line, including a
   trailing comment. A later, unrelated pull request reworded that comment. The sensitive substring the
   entry existed to excuse — a self-referential org/repo slug — never changed, but the entry's regex no
   longer matched the line it was written against, so the gate started failing again with no visible
   connection to what the breaking PR actually touched.
2. **A sibling file's line was never covered.** During later cleanup work, a second CI file started
   naming the same organization repo slug that a *different* file's line had already been allowlisted
   for — but this file's own occurrence had no entry of its own. Structurally the same defect as #1: an
   allowlist that was correct on the day it was written and had silently stopped describing reality.

Both incidents are already named, in general form, under "Landmines" in
[`skills/examples/sanitize-and-theater-gate-rollout.md`](../../skills/examples/sanitize-and-theater-gate-rollout.md)
("Allowlist entries drift silently when a nearby comment gets reworded"). `check_allowlist_drift.py`
turns that documented tribal knowledge into a standing, automated check instead of something a reviewer
has to remember to re-derive by hand every time.

```bash
python3 tools/sanitize/check_allowlist_drift.py .
python3 tools/sanitize/check_allowlist_drift.py . --tracked-only   # matches CI's invocation
python3 tools/sanitize/test_check_allowlist_drift.py
```

**What it checks.** The `.cu2-sanitize-allow` format has no per-entry file reference, so a `line:` entry
suppresses any line, in any tracked file, that its regex matches — there is no "its" file to check against.
The honest, format-faithful question is therefore: does this entry's pattern still match *anything* in the
repository's current tracked content? A `line:` entry drifts when no tracked file contains a matching
line anymore; a `path:` entry drifts when no tracked file's path matches anymore. A drifted entry means
one of two things, and the tool deliberately does not guess which: either the finding it excused is gone
(fixed, deleted, moved out of scope — delete the entry) or the content changed shape under it (a reword, a
rename — re-point the entry at what the content looks like today). Either way, a human has to look; that
is the same value an "unused suppression" lint provides for a stale `# noqa`.

**What it does not do.** It does not re-run any `cu2_sanitize_scan.py` rule — a drifted entry might
correspond to zero real findings today, or to a finding the gate would now catch on its own; run the
sanitize gate itself to tell which. It also does not enforce the "broad pattern" / "unanchored path"
policy `cu2_sanitize_scan.py`'s own allowlist loader already enforces — that is "this entry is dangerously
permissive," a different question from "this entry no longer refers to anything," and it is already
answered elsewhere.

**Wired in three places:** as a pre-flight step in `reusable-sanitize.yml` (on by default for every
caller — see that file), as a step in this repository's own CI against its own `.cu2-sanitize-allow`, and
as an available pre-commit hook (`cu2-allowlist-drift`, `.pre-commit-hooks.yaml`).

## Fixture-mutation testing

`test_cu2_sanitize_scan.py` proves every rule fires on a positive sample. That
leaves a gap: a rule can be quietly hardened into never firing on the input it
exists for, and a suite of isolated positive samples does not always notice —
this happened once, when the "Quoted secret assignment" and "Credential in
connection string" rules were narrowed to kill a false positive and, in the
same change, stopped catching any password containing normal punctuation.
Nothing caught it until a manual scan.

`test_fixture_mutations.py` closes that class of bug the way The Agent
Foundry's `gates/scripts/fixture_smoke.py` closes it for its own fixtures:
start from one fixture verified clean, apply a single targeted mutation per
rule, and assert that mutation alone flips the scan from clean to flagged —
through the real `scan_file()` pipeline, not the regex layer in isolation. The
mutation catalog is checked against the live rule table in both directions, so
a new rule without a mutation, or a mutation whose rule was renamed or
removed, fails CI rather than silently covering nothing. A second class of
mutation targets rules whose captured value is delimited by a quote or a `;`
rather than a character class, generalizing the punctuation regression above
into a standing check instead of a one-off fixture.

## Attribution

The allowlist loader, placeholder recognizer, redaction helpers, and fail-closed exit contract are adapted
from `gates/scripts/sanitize_scan.py` in [The Agent Foundry](https://github.com/the-agent-foundry/foundry),
MIT licensed, © 2026 Darryl Hicks. The full notice is retained in the header of `cu2_sanitize_scan.py`.
The tier model, profiles, and all CU2 and Azure rules are original.
