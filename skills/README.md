# Skills

A skill is a procedure an agent reaches for automatically the moment a matching task shows up: the
trigger, the steps, the quality bar, and — most importantly — the specific ways it has already gone
wrong.

## Why the last part matters most

Without a written skill, the same mistake gets re-made every time a similar task comes up, because
nothing carries the lesson forward. With one, a correction becomes permanent: the first time an
allowlist entry silently drifts out of sync, or a credential turns out to still be in use somewhere
unexpected, that specific failure gets written into the skill's Landmines section — not fixed quietly
and forgotten.

A skill that only describes the happy path is not finished. The [`examples/`](examples) in this folder
each carry landmines pulled from an actual incident, not a hypothetical one — see each example's
frontmatter and body for exactly what happened and what guardrail it produced.

## The format

- [`SKILL.schema.md`](SKILL.schema.md) — the canonical schema: required frontmatter, required
  sections, and the shape a skill has to match.
- [`examples/`](examples) — real, sanitized skills that follow it:
  - [`examples/sanitize-and-theater-gate-rollout.md`](examples/sanitize-and-theater-gate-rollout.md) —
    onboarding a repository onto a leak-detection and verification-theater gate as a ratchet, so
    adoption doesn't stall on an existing backlog.
  - [`examples/dependency-cve-remediation.md`](examples/dependency-cve-remediation.md) — closing
    dependency vulnerability alerts with real verification, and treating any credential or
    deploy-pipeline gap the fix surfaces as its own, higher-scrutiny piece of work.

## How to build one

1. Read [`SKILL.schema.md`](SKILL.schema.md).
2. Write "what good looks like" as if briefing a sharp but new hire — specific enough that a vague
   attempt is visibly not good enough, not just "do it well."
3. Write the approval boundary before the capability list. Decide what always needs a human first;
   see [principle 3](../principles/PRINCIPLES.md#the-ranking).
4. Leave Landmines empty until the skill has actually been used and has actually failed once. A
   landmines section written in advance is a guess, not scar tissue.
5. Add to Landmines every time the skill bites — that is where the compounding value lives.

## Pickup prompt

> Review this folder, especially `SKILL.schema.md` and the examples. Identify one recurring procedure
> in my own work that keeps needing the same correction, and draft a skill for it. Ask what good looks
> like and what requires approval before drafting the procedure itself.
