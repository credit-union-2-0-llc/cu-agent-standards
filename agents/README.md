# Agents

Specialists beat a generalist, for the same reason a credit union does not ask one examiner to cover
lending, BSA, and IT security simultaneously: pile enough distinct jobs onto one role and depth drops
across all of them.

## Why

A purpose-built agent does one job and gets good at it. It loads only the skills and tools that job
needs, so its context stays clean, and you can specify exactly what "good" means for that one job in
detail that would be noise for anything broader.

The shape that works in practice: a person holds context and reviews output, and one or more
specialist agents execute a narrow, well-bounded job. The specialist is not trusted to expand its own
scope — see [principle 4](../principles/PRINCIPLES.md#the-ranking) — and the boundary between "the
agent proceeds" and "the agent stops and asks" is written down per role, not left to judgment in the
moment.

## How to spec one

1. Read [`AGENT-SPEC.schema.md`](AGENT-SPEC.schema.md) — the canonical format.
2. Name the one job this agent owns, in a single sentence with no "and." If it needs two sentences,
   it is two agents.
3. Write its approval boundaries before its capabilities. Decide what always requires a human first;
   the capability list follows from that, not the other way around.
4. Give it only the skills and tools its one job needs.
5. Write "what good looks like" against a real example, not a general description.

## What is in this folder

- [`AGENT-SPEC.schema.md`](AGENT-SPEC.schema.md) — the canonical role-spec schema.
- [`archetypes/`](archetypes) — role specs adapted from patterns actually running in production:
  - [`archetypes/email-triage.md`](archetypes/email-triage.md) — reads inbound mail, drafts responses,
    files what's routine, and never sends without a human in the loop.
  - [`archetypes/security-scanner.md`](archetypes/security-scanner.md) — cross-repo sanitization and
    verification-theater detection, run as a ratchet so it can be adopted against an existing backlog.
  - [`archetypes/dependency-remediator.md`](archetypes/dependency-remediator.md) — triages CVE and
    dependency alerts across repositories, verifies each fix before proposing it, and treats live
    credential and deploy-pipeline changes as a distinct, higher-scrutiny tier of work.

## Depth note

These are sanitized, not hollow. They omit repository names, internal hostnames, resource identifiers,
and anything that would let an outside reader map a pattern back to a specific live system. What they
preserve is the operating pattern: the scope boundary, the approval gate, and the concrete incident
that shaped each one. A role spec with no incident behind its approval boundary is a guess, not a
standard.

## Pickup prompt

> Review this folder and tell me whether a version of one of these archetypes fits a job you already
> have an agent doing informally. Ask for the missing context before drafting a spec.
