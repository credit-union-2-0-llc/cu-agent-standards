# SKILL Schema (Canonical)

The format every skill in [`examples/`](examples) must match. A skill is a written procedure an
agent reaches for automatically when a matching task shows up — not a one-off prompt, and not a
general description of a vibe. It describes a procedure, not an implementation; where a concrete tool
or stack shows up, it is labeled as an example, never as the required path.

## Required frontmatter

A YAML frontmatter block at the top, delimited by `---`:

| Key | Meaning |
| --- | --- |
| `name` | Short, specific skill name, lowercase-with-hyphens. |
| `description` | One line: what it does and when it fires. |
| `version` | Bump when the procedure's behavior changes. |
| `owner` | A handle or role, never a real email. |
| `data_sensitivity` | Highest data class the skill may touch: `public`, `internal`, `confidential`, or `restricted`. |
| `approval_required` | Highest approval gate the skill's normal action requires: `none`, `before_write`, `before_external_send`, or `before_live_change`. |

Optional: `tags`, `tools`.

## Required sections

- **When to use** — the trigger, and just as important, when *not* to reach for this skill.
- **Inputs** — what it needs before it can start, and what happens if something is missing.
- **Procedure** — the actual steps, specific enough to run the same way twice.
- **What good looks like** — the concrete quality bar. This is the section the agent actually enforces
  against; vague quality bars produce vague output.
- **Verification** — how the agent proves it worked before claiming done, not just that a command ran.
- **Landmines** — the scar tissue. Specific failures already hit, and the guardrail each one produced.
  A skill with no landmines has not been used in anger yet.

## Canonical shape

```markdown
---
name: <skill-name>
description: <one line: what it does and when it fires>
version: <1.0>
owner: <handle-or-role>
tags: [<tag>, <tag>]
tools: [<tool-kind>, <tool-kind>]
data_sensitivity: <public|internal|confidential|restricted>
approval_required: <none|before_write|before_external_send|before_live_change>
---

# <Skill Name>

## When to use
<trigger conditions, and when NOT to use this>

## Inputs
<required inputs, optional inputs, behavior when something is missing>

## Procedure
1. <step>
2. <step>

## What good looks like
<the concrete definition of done>

## Verification
<checks, commands, or artifacts that prove it worked>

## Landmines
- <a specific failure already hit>: <the guardrail it produced>
```

## Notes

- A skill with a "Landmines" section that reads like a hypothetical rather than an incident is not
  finished. Every entry in this repo's examples traces to something that actually happened.
- `approval_required` should reflect the highest-risk normal action, not the average one. A skill
  that reads and drafts can be `none`; one that writes shared state is `before_write`; one that
  rotates a live credential or touches a running production system is `before_live_change`.
