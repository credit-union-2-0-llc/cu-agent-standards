---
name: first-deploy-bug-triage
description: Pre-flight checks and a fixed triage order for the class of bug that only surfaces once a new service's first real cloud deploy engages real auth, real RLS, real runtime images, and real architecture.
version: 1.0
owner: platform-security
tags: [deploy, ci, database, reliability]
tools: [cloud-cli-read-only, container-registry-read, ci-workflow-authoring]
data_sensitivity: internal
approval_required: before_write
---

# First-Deploy Bug Triage

## When to use

Use before and during a new microservice's first deploy to a real cloud environment, whenever that
service uses row-level security, role-based database grants, native libraries with system dependencies
(PDF/image/crypto libraries that assume fonts or system packages are present), or produces
architecture-specific build artifacts. Also use reactively the moment a first deploy fails for a reason
that doesn't reproduce locally — that mismatch is the signature this skill exists to resolve quickly
rather than by guessing.

Do not use this for a service's Nth deploy once the first-deploy class of bug has already been shaken
out — at that point a failure is more likely an ordinary regression, not an environment-mismatch bug.

## Inputs

- Required: read access to the deployed container's logs and revision history, read access to the
  container registry's image manifests (to check platform/architecture), and read-only access to the
  target environment's role assignments and Key Vault secret metadata (names and formats, not values
  where avoidable).
- Required: awareness that local integration tests likely ran with a sysadmin-equivalent database
  connection, the build host's own architecture, and the build host's own fonts/system packages — all
  of which differ from the deployed environment by design, not by accident.

## Procedure

1. Before the first deploy: confirm the built image explicitly targets the deploy platform's
   architecture (do not assume the build host's architecture matches — build and push for the target
   platform explicitly, even when testing locally on a different one).
2. Before the first deploy: run the runtime image's own shell and confirm the native dependencies a
   library will reach for are actually present (fonts, TLS/crypto libraries, `curl`/health-check
   tooling) — a slim runtime image commonly lacks what a local dev machine has installed.
3. Before the first deploy: confirm the format a Key-Vault-sourced secret is stored in matches what the
   consuming library expects (a connection-string library expecting one format can silently fail to
   parse a value stored in a different but valid format for the same underlying resource).
4. Add a CI test tier that runs against the database as a real, non-sysadmin, role-scoped user — not
   the default integration-test superuser — specifically so row-level-security and grant checks
   actually engage before the first deploy, not for the first time in production.
5. When a first-deploy failure occurs, triage in this fixed order before assuming the bug is in
   application logic: container logs, the last database command the app attempted, the app-tier
   identity's role/grant assignments, the actual Key Vault secret values (not just that they exist),
   then image architecture. This order resolves the large majority of first-deploy failures faster than
   starting from the application code.
6. Budget real time for this: a first deploy commonly needs 30-90 minutes covering several image
   rebuilds and revision bumps. State this up front rather than promising a fast ship and discovering
   the gap mid-deploy.

## What good looks like

Each first-deploy failure gets a named, specific root cause (a missing font, an unissued role grant, an
architecture mismatch, a secret stored in an unexpected format) rather than a retry loop against an
unexplained error. Every root cause found this way becomes a pre-flight check for the *next* new
service, so the same class of bug is caught before its next first deploy rather than rediscovered from
scratch.

## Output contract

- **Primary output:** either a pre-flight checklist result (pass/fail per check, before the deploy) or
  a triage report (root cause, fix, verification) for an actual first-deploy failure.
- **Required fields:**
  - Which specific bug class was hit (from: RLS/grants, native-dependency gap, architecture mismatch,
    secret-format mismatch, connection/pooling behavior) or which pre-flight check failed.
  - The fix applied and how it was verified against the real deployed environment, not just locally.
  - Time spent, so future deploy-window estimates for similar services stay realistic.
- **Destination:** the deploy's own PR or a dedicated runbook entry for the service, not a chat message
  that disappears once the deploy succeeds.

## Privacy and approval

- **Data this skill touches:** container logs, deployment metadata, role/grant assignments, and secret
  *names and formats* — never secret values beyond what's needed to confirm a format mismatch.
- **Blocked:** printing or logging an actual secret value while confirming its format; use metadata or
  a redacted representation.
- **Approval required before:** changing a live role assignment, rotating a credential the triage
  surfaces as misconfigured, or modifying a production resource's configuration directly.
- **No approval needed for:** reading logs, registry metadata, and role/secret *metadata*, and adding
  or extending CI pre-flight checks and the non-sysadmin test tier.

## Verification

- A pre-flight check is verified by actually running it (the image shell command, the architecture
  check) — not by reading the Dockerfile and assuming the result.
- A triage fix is verified by confirming the specific failure no longer reproduces against the real
  deployed environment, not just that the retried deploy succeeded (a transient success can mask an
  unfixed root cause).

## Maintenance

- **Add a landmine every time a new bug class survives this triage order** — the order here resolves
  the classes found so far; a new one means the order or the checklist needs to grow, not that the bug
  was unlucky.
- **Signals this skill has gone stale:** the deploy target changes its default architecture, the
  database platform changes how role/grant enforcement interacts with connection pooling, or the
  runtime base images change what they ship by default.

## Landmines

- **A local Testcontainers suite commonly runs with a sysadmin-equivalent database connection**, which
  bypasses row-level-security predicates and column-level grants entirely — a suite that passes locally
  proves nothing about whether RLS actually engages, because the local connection never had to earn
  through it.
- **A slim runtime image can be missing fonts or system libraries a PDF/image-generation library assumes
  exist**, and this fails only at the point the library is actually invoked — not at container startup
  — so a health check passing is not evidence the library will work.
- **An image built without an explicit target platform commonly matches the build host's architecture,
  not the deploy target's**, and the resulting "no child with matching platform" failure at deploy time
  has nothing in its error text pointing back to the build step that caused it.
- **A Key-Vault-sourced secret's stored format is not guaranteed to match what the consuming library
  expects**, even when the secret is for the exact resource the library talks to — a connection-string
  library expecting one representation can fail to parse a different, equally valid representation of
  the same underlying value.
