---
name: sanitize-and-theater-gate-rollout
description: Onboards a new repository onto a leak-detection and verification-theater gate without a pre-existing backlog blocking adoption.
version: 1.0
owner: platform-security
tags: [security, ci, sanitization, verification]
tools: [git, sanitizer, theater-scanner, ci-workflow-authoring]
data_sensitivity: internal
approval_required: before_live_change
---

# Sanitize and Theater Gate Rollout

Two distinct checks, one rollout procedure: whether internal context is leaking out of a repository,
and whether a control that is supposed to protect quality or security actually runs, or just produces
a signal that looks like it does. See [`tools/sanitize`](../../tools/sanitize) and
[`tools/theater`](../../tools/theater) for the working tools this skill wraps.

## When to use

Use when bringing a new repository — especially one about to go public, or one that has never had a
security gate — onto both checks for the first time. Also use when a gate that was previously passing
starts failing on a merge that did not obviously touch anything sensitive; that is almost always
allowlist drift, not a new leak (see Landmines).

Do not use this to retrofit a gate that already exists and is already passing correctly — that is
maintenance, not rollout, and does not need the ratchet step below.

## Inputs

- Required: repository write access, the sanitizer and theater-scanner tooling (pinned to a ref, not
  a moving branch), and a decision on which profile to run (`public` for anything a wider audience can
  see, a narrower profile for internal-only repos).
- Optional: an existing `.cu2-sanitize-allow` or equivalent from a sibling repository, useful as a
  starting template but never copied verbatim — its entries describe *that* repository's specific
  accepted patterns, not this one's.
- If a repository has never been scanned before: run a full scan first, expect real findings, and do
  not proceed to wiring the gate into CI until the backlog is triaged (see Procedure step 2).

## Procedure

1. Run the sanitizer and the theater scanner locally against the full repository, not just recent
   changes. Expect noise — SHA-pinned CI hashes, lockfile integrity strings, and doc placeholders
   routinely outnumber real findings by an order of magnitude.
2. Triage every finding by hand into one of three buckets: real leak (fix it now), false positive
   (write a narrow, dated, reasoned allowlist entry — never a broad pattern that swallows a whole
   category), or accepted-and-functionally-required (same treatment as false positive, but the reason
   is "this has to be here for the pipeline to work," not "this isn't actually sensitive").
3. Wire the gate into CI as a **ratchet**: it fails only on what a given change introduces, checked
   against a diff base, never on the pre-existing backlog. A gate that fails on everything a repository
   already carries never gets turned on at all — the ratchet is what makes day-one adoption possible.
4. Confirm the gate's own CI-config self-reference is allowlisted (see Landmines) before merging the
   wiring PR, or the gate will fail on itself the moment it lands on the default branch.
5. Merge, then verify green on the default branch specifically — not just on the PR branch. A check
   passing on a PR does not guarantee it passes post-merge if the merge changes what "current state"
   means for a ratchet-mode check.

## What good looks like

A newly onboarded repository has zero pre-existing backlog blocking the gate, every allowlist entry
reads as a decision a different reviewer would make the same way twice, and the gate is confirmed
green by querying the default branch's own check-run state after merge — not assumed green because the
PR that added it passed.

## Output contract

- **Primary output:** a rollout record on the pull request that wires the gate, plus the
  `.cu2-sanitize-allow` file it lands with.
- **Required fields in the record:**
  - Full-scan counts before triage, by tier (`secret` / `pii` / `internal`).
  - Each finding's disposition: fixed, allowlisted, or accepted-and-functionally-required.
  - The profile the gate runs at, and the diff base if it runs as a ratchet.
  - Post-merge default-branch check-run state, quoted from the API rather than the PR.
- **Every allowlist entry must carry:** the pattern, a one-line reason, and a date. An entry without
  a reason is a suppression pretending to be a decision.
- **Destination:** the PR body and the repository's own `.cu2-sanitize-allow`. Never a side channel —
  the justification has to live next to the thing it justifies or the next reader cannot audit it.
- **Example skeleton:**

```md
Full scan: 63 findings (secret 0 / pii 4 / internal 59)
Fixed: 6 (see commits)
Allowlisted: 55 — each with reason + date in .cu2-sanitize-allow
Accepted as functionally required: 2 (ACR login server, resource group in az deploy)
Gate profile: public, full scan (not ratchet)
Default-branch check-run after merge: success (queried via gh api)
```

## Privacy and approval

- **Data this skill touches:** the full contents of every tracked file in the repository, including
  whatever secrets are actually present. Treat the scan output itself as sensitive until confirmed clean.
- **Blocked:** never paste raw scanner output containing an unredacted match into a PR body, an issue,
  a chat message, or a CI log. The scanner redacts matched values for this reason; defeating that by
  quoting the source line reintroduces the leak in a more durable place.
- **Redaction rule:** when a real finding needs discussion, reference it by file and line, never by value.
- **Approval required before:** merging the gate wiring into a live CI configuration; removing or
  narrowing any pre-existing allowlist entry; and enabling the gate on a repository you do not own.
- **No approval needed for:** running scans, and adding a new allowlist entry that carries a reason
  and a date.

## Verification

- Run the sanitizer and theater scanner locally before opening the PR.
- After merge, query the default branch's check-run API directly rather than trusting the PR's
  last-known status; a gate wired as a ratchet can pass on a PR branch and still fail post-merge if
  something about the merge itself (not the PR's own diff) trips a pattern.
- Spot-check that the gate fails when it should: temporarily reintroduce a known bad pattern in a
  scratch branch and confirm the gate catches it, then discard the branch.

## Maintenance

- **Add a landmine the first time a scan is wrong, in either direction.** A false positive and a false
  negative are equally worth pinning; the false *cleans* are the ones nobody investigates, so they need
  the discipline more.
- **Every scanner fix gets a named regression test**, and the ledger row referencing it gets a date.
  A ledger of pinned bugs is the argument for the tool; an undated one cannot be read chronologically.
- **Signals this skill has gone stale:** the scanner grows a rule class this procedure never mentions;
  a repository adopts the gate at a profile not described here; or the allowlist convention changes
  shape. Any of those means the Procedure section is now describing a tool that no longer exists.
- **Re-read the allowlist whenever a nearby comment is reworded.** Entries match literal text, and the
  drift is silent — see the second landmine below.

## Landmines

- **The gate flags its own CI-config self-reference**: a workflow file that references this
  organization's own reusable-workflow repo, or the repository's own name, matches the same
  "private org slug" pattern the gate is built to catch. Allowlist the gate's own wiring file
  explicitly — it will otherwise fail on itself the first time it runs on the default branch.
- **Allowlist entries drift silently when a nearby comment gets reworded.** An allowlist line matches
  literal text. A later, unrelated PR that rewords the exact comment or string the entry was written
  against breaks the match completely, and the gate starts failing with no connection to what the
  breaking PR actually changed. The failure looks like a false alarm about unrelated code; it is
  actually a stale regex. Before trusting a "confirmed passing" note from an earlier point in time,
  re-check the default branch's current check-run state — don't assume a prior green stays green.
- **A repo's own full slug (`org/repo-name`) trips the generic "private org repo slug" pattern even
  when the repo is itself already public.** The scanner has no way to know a given org/repo pair is
  self-referential and safe unless a self-reference allowlist entry already exists for it. Before
  writing new content that names a repository's own slug (a usage example, a `--repo` flag in a
  sample command), check whether that self-reference is already allowlisted — if not, it is cheaper
  to reword the content to avoid the slug than to add a new allowlist entry for it.
- **A scan run in "report" mode exits zero even when it finds something** — useful for a dry run, but
  do not wire report mode into a gate that is supposed to block a merge.
