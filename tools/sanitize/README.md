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

## Attribution

The allowlist loader, placeholder recognizer, redaction helpers, and fail-closed exit contract are adapted
from `gates/scripts/sanitize_scan.py` in [The Agent Foundry](https://github.com/the-agent-foundry/foundry),
MIT licensed, © 2026 Darryl Hicks. The full notice is retained in the header of `cu2_sanitize_scan.py`.
The tier model, profiles, and all CU2 and Azure rules are original.
