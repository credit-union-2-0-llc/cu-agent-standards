# AGENT-SPEC Schema (Canonical)

The format every agent role spec in this repository must match: the archetypes in
[`archetypes/`](archetypes) and anything contributed alongside them. A linter (planned, see
[`tools/theater`](../tools/theater) for the pattern it would follow) can check the required
frontmatter keys and section headings mechanically. Keep the shape; fill in real content.

A role spec describes a job and its boundaries, not an implementation. It should read the same whether
the underlying agent runs on Claude, GPT, a local model, or something that does not exist yet. Where a
concrete tool or stack shows up, it is labeled as a reference example, never as the required path.

## Required frontmatter

A YAML frontmatter block at the top, delimited by `---`. Required keys:

| Key | Meaning |
| --- | --- |
| `role` | The job title in one phrase — e.g. "email triage assistant", "cross-repo security scanner". |
| `mission` | One line: the single job this agent owns. |
| `reports_to` | Who reviews and can override its output — usually a named person, not another agent. |

Optional but recommended: `skills` (list), `tools` (list), `escalation` (one line on what triggers a
stop-and-ask instead of proceeding).

## Required sections

- **Mission** — the one job, expanded, including what this role is explicitly *not* for.
- **Scope** — what is in bounds and what is out of bounds. The edges of the role.
- **Skills and tools** — the specific, lean set this role loads. A specialist that loads everything is
  a generalist wearing a specialist's name.
- **What good looks like** — the concrete quality bar for this role's output. Vague standards produce
  vague work; cite a real example of a correct output where possible.
- **Approval boundaries** — what the agent may do autonomously, and what always requires a human
  confirmation before proceeding. Ties directly to [principle 3](../principles/PRINCIPLES.md#the-ranking).

## Canonical shape

```markdown
---
role: <role>
mission: <one line: the single job this agent owns>
reports_to: <name or role>
skills: [<skill>, <skill>]
tools: [<tool-kind>, <tool-kind>]
escalation: <one line: what triggers a stop-and-ask>
---

# <Role Name>

## Mission
<the one job, expanded, including what this role is NOT for>

## Scope
<in bounds, out of bounds>

## Skills and tools
<the lean set this role loads>

## What good looks like
<the concrete quality bar, ideally with a real example>

## Approval boundaries
<what it may do alone, what needs a human>
```

## Notes

- One job per agent. If the mission needs "and" more than once, the scope is too broad — split it.
- Approval boundaries are not a formality. Every archetype in this repo exists because a real
  incident showed what happens when a boundary was assumed instead of written down.
