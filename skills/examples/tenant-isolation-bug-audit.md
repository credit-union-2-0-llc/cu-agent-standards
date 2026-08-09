---
name: tenant-isolation-bug-audit
description: Traces every raw-query and nested-transaction code path in a multi-tenant repository back to whether it actually engages the RLS tenant-context wrapper, and proves each fix with a two-tenant fixture test.
version: 1.0
owner: platform-security
tags: [security, database, multi-tenancy, rls]
tools: [repo-read, database-read-only, test-runner]
data_sensitivity: confidential
approval_required: before_write
---

# Tenant-Isolation Bug Audit

## When to use

Use when auditing a multi-tenant repository whose row-level-security policies depend on the
application layer setting a tenant-context value (a database session variable, an ORM-level tenant
scope) before every query — especially before a new tenant onboards, or after adding any raw-query or
transaction-nesting code to a data-access layer. Also use reactively the moment a raw query or a nested
transaction call is spotted during an unrelated review; those two shapes are exactly the ones that
bypass a context set elsewhere in the call stack.

Do not use this to review RLS policy SQL itself (whether the predicate logic is correct) — that is a
database-schema review, a different skill.

## Inputs

- Required: read access to the data-access layer source, and to the schema defining the tenant-context
  mechanism (how it's set, what it's named, which policies reference it).
- Required: a non-production database seeded with at least two distinguishable tenants, to run the
  actual fixture test against — a mocked context object cannot prove a real bypass is closed.
- If no multi-tenant fixture dataset exists yet: build the minimal two-tenant seed before auditing
  anything, since every claim this skill produces depends on it.

## Procedure

1. Search the data-access layer for every raw-query escape hatch (a driver-level raw call that bypasses
   the ORM's normal query builder).
2. For each hit, trace whether it executes inside the same wrapper/middleware that sets tenant-context
   for ordinary ORM calls, or on a connection that never received that call.
3. Separately, search for nested transaction calls — a transaction opened while already inside another
   transaction. Check whether the inner transaction inherits the outer one's tenant-context or silently
   starts fresh. Treat this as its own check, not a subset of step 1 — the query itself can look
   perfectly normal while the transaction boundary is what leaks.
4. For every finding, write a fixture test against the two-tenant seed: tenant A's session attempts to
   read or write tenant B's row through the found code path. It must fail (zero rows / a raised error)
   before the fix.
5. Apply the narrowest fix that routes the call through the existing tenant-context wrapper — do not
   invent a second, parallel scoping mechanism alongside it.
6. Confirm the fixture test flips from failing to passing across the fix, and that the full existing
   test suite still passes.

## What good looks like

Every raw-query and nested-transaction call site in the audited scope has a concrete, cited verdict,
and every fix ships with a fixture test that demonstrably failed before the fix and passes after —
proving the specific bypass closed, not just that the diff looks like it should have.

## Output contract

- **Primary output:** a pull request per finding (or one PR for a tightly related cluster), each with
  its own fixture test.
- **Required fields:**
  - The specific code path (file, line, call) and which mechanism bypassed tenant-context (raw query
    vs. nested transaction).
  - The fixture test added, with its pre-fix (failing) and post-fix (passing) result stated explicitly.
  - Confirmation the full existing suite still passes post-fix.
- **Destination:** the PR body and the new test file — a reviewer must be able to run the fixture test
  locally and see it fail against the pre-fix commit.
- **Example skeleton:**

```md
Finding: raw query in reports.service bypasses the tenant-context wrapper
Fixture: tenant-a session cannot read tenant-b row via generateReport() — FAILS pre-fix, PASSES post-fix
Full suite: 212/212 pass post-fix
```

## Privacy and approval

- **Data this skill touches:** schema and a non-production, seeded multi-tenant dataset only. Never a
  live tenant's real data.
- **Blocked:** running any part of this procedure, including the read-only trace step, against a
  database holding real tenant data.
- **Approval required before:** merging any fix that changes connection-pooling or per-request
  connection behavior, since that can carry a performance implication beyond the security fix; and
  before treating any finding as theoretical rather than filing a real PR for it.
- **No approval needed for:** the trace steps, and building or extending the two-tenant fixture seed.

## Verification

- The fixture test itself is the verification: run it explicitly against both the pre-fix and post-fix
  code and confirm it flips from failing to passing, rather than asserting it would.
- Re-run the full existing suite after the fix to confirm no regression.

## Maintenance

- **Add a landmine whenever a new ORM feature or driver API introduces a third way to bypass
  tenant-context** beyond raw queries and nested transactions — the two named here are not exhaustive
  for every stack.
- **Signals this skill has gone stale:** the ORM in use changes its transaction-nesting semantics, or
  the tenant-context mechanism itself changes (a different session variable, a different wrapper).

## Landmines

- **A nested transaction can silently start a new session that never received the outer call's
  tenant-context.** This looks nothing like a bypass in an ordinary code review — the query inside the
  inner transaction goes through the ORM normally — because the danger is in the transaction boundary,
  not the query syntax. Search for transaction nesting as its own check, not as something step 1's
  raw-query search would catch as a side effect.
- **A raw query used purely for an internal report can still bypass tenant scoping even when the
  surrounding function is otherwise well-scoped**, because the tenant-context wrapper applies per ORM
  call, not per function — a single raw call inside an otherwise-scoped function is enough to leak a
  row.
