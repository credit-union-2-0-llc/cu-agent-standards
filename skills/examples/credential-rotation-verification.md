---
name: credential-rotation-verification
description: Before rotating, removing, or narrowing any credential that investigation suggests is unused or orphaned, verify across every shared secret store and every other repository that might reference the same identity — not just the one place it was found.
version: 1.0
owner: platform-security
tags: [security, credentials, secrets]
tools: [cloud-cli-read-only, github-api, secret-store-read]
data_sensitivity: confidential
approval_required: before_live_change
---

# Credential Rotation Verification

## When to use

Use whenever a fix, an audit, or a routine cleanup surfaces a credential (a service principal secret,
an API key, a connection string) that looks unused, orphaned, or missing from where it's expected —
right before deciding it is safe to rotate, delete, or leave newly-set. Also use before narrowing an
over-scoped credential's permissions, since the same "is this depended on somewhere I haven't checked"
question applies to a scope reduction as much as to a full rotation.

Do not use this for a credential that is being rotated on a known, routine schedule with its dependents
already documented — that's ordinary key rotation, not the orphaned-credential case this skill exists
for.

## Inputs

- Required: read access to every shared secret store in the estate the credential could plausibly be
  registered in, not just the one repository or system where the question came up.
- Required: search access across every repository in the org, since a credential minted for one project
  can end up referenced by a completely differently-named sibling project.
- If the credential's original purpose or owner isn't documented anywhere found so far: that absence is
  itself informative (it increases, not decreases, the chance something depends on it without a
  paper trail) — do not treat "I can't find why this exists" as "this is safe to remove."

## Procedure

1. Before touching the credential, search every shared secret store in the estate for the credential's
   identity (its name, its principal ID, or any alias it might be stored under) — not just the store
   local to the repository where it was found.
2. Search every other repository in the org for a reference to the same identity, including repositories
   whose name doesn't obviously match the project the credential seems to belong to — a credential
   minted for one initiative can be reused by an unrelated one with a different name.
3. Check the credential's creation date against the timeline of the issue that surfaced it. A credential
   created the same day as a first failed deploy attempt, with no other reference found anywhere, is
   good evidence it was never wired in anywhere — but state this as evidence found, not as an assumption
   made instead of searching.
4. Only after both searches come back empty: proceed with rotation, deletion, or scope narrowing, and
   keep the credential's value out of any log, shell history, or chat transcript in the process.
5. If either search finds a live reference: stop. The credential is not orphaned, and rotating it
   without coordinating with whatever depends on it will break that dependent, not just the thing in
   front of you.

## What good looks like

A rotation or removal decision is backed by a stated, specific search — which secret stores were
checked, which repositories were searched, what was found — not by "it looks unused from here." A
reviewer reading the record should be able to see exactly what was checked and conclude independently
that nothing was missed, rather than trusting the conclusion on its own.

## Output contract

- **Primary output:** a rotation/removal record (in the PR, an incident note, or a decision log) stating
  what was searched and what was found before acting.
- **Required fields:**
  - Every secret store searched, by name, and the result (found / not found).
  - Every repository search performed (the query used) and the result.
  - The credential's creation date and any dated evidence about when/why it was minted, if found.
  - The action taken (rotated / deleted / scope narrowed) and confirmation the new value was set
    without ever being echoed, logged, or pasted in plaintext.
- **Destination:** the PR or decision log for the change that prompted the search — never a private
  note only the acting agent can see.

## Privacy and approval

- **Data this skill touches:** secret *metadata* (names, creation dates, which store holds them) across
  the estate. Secret *values* are touched only at the moment of rotation, and only to set the new value
  — never to read, echo, or compare the old one.
- **Blocked:** printing, logging, or pasting any credential value at any point in this procedure,
  including into a rotation command's visible arguments — pipe values directly rather than passing them
  through shell history or command-line arguments.
- **Approval required before:** the actual rotation, deletion, or scope-narrowing action itself, even
  after both searches come back empty. Finding nothing is evidence a human should confirm, not license
  to act without asking.
- **No approval needed for:** the search steps themselves (secret-store metadata read, repository
  search).

## Verification

- After rotation, confirm the dependent system(s) identified during the search (if any were found and
  coordinated with) still function against the new value before considering the task done.
- If the search found nothing and the credential turns out to still be needed somewhere undiscovered,
  that is itself a finding: the estate's secret-store coverage or repository search has a gap, and that
  gap is worth recording even though it wasn't this task's job to close it.

## Maintenance

- **Add a landmine whenever a search misses a real dependent** — the failure mode that matters most for
  this skill is a false negative (concluding "orphaned" when something still depends on it), so any
  instance of that gets recorded with exactly what the search should have checked but didn't.
- **Signals this skill has gone stale:** a new shared secret store gets stood up that this procedure's
  search list doesn't mention yet, or the org's repository-naming convention changes enough that a
  keyword search stops finding cross-project references reliably.

## Landmines

- **"This credential looks orphaned" is a hypothesis, not a fact.** A credential unused from inside one
  repository's own secret list can still be the only copy backing a completely different system's live
  access — the absence of a reference in the first place looked at is not evidence of absence across the
  estate.
- **A credential's creation date matching a known failure's timeline is good corroborating evidence, not
  proof on its own.** State it as one input alongside the search results, not as a substitute for
  actually searching every store and repository.
- **Rotating a credential without ever echoing the new value in a shell command's visible output still
  leaks it if the command is piped through something that logs its arguments** — prefer a mechanism that
  accepts the value on stdin or via a file descriptor over one that takes it as a plain argument.
