# security

Architecture notes on securing multi-tenant, multi-person agent deployments — the pattern layer, not
the implementation. One file per model so far:

| File | What it covers |
|---|---|
| [`tenant-and-data-subject-scoped-agent-security.md`](tenant-and-data-subject-scoped-agent-security.md) | Authorizing agent actions across two people at once — the requester asking, and the data subject whose data it is, when they differ. Forked from [`the-agent-foundry/foundry`](https://github.com/the-agent-foundry/foundry)'s `security/tenant-scoped-agent-security.md` with an explicit `data_subject` field added throughout. |

Unlike `skills/`, this directory isn't schema-linted by `tools/lint/format_lint.py` — these are
reference architecture models, not procedural runbooks, and forcing a `SKILL.schema.md` shape onto a
model this generic would mean fabricating a Landmines section before the pattern has actually failed
in production once, which `skills/README.md` explicitly warns against. Sanitize and theater gates
still apply to everything here, same as the rest of the repo.
