# Tenant- and Data-Subject-Scoped Agent Security

*How to keep a credit union agent from leaking one member's data to the wrong person — including when the person asking isn't the member.*

> **Adapted from:** [`the-agent-foundry/foundry`](https://github.com/the-agent-foundry/foundry),
> `security/tenant-scoped-agent-security.md` (MIT). An adversarial review scored the upstream
> file 9/10 and named it the best CU-relevant asset found — but flagged one specific gap: *it has no
> concept of a data subject who is not the requester*. Upstream's model assumes whoever is asking an
> agent to act **is** the person whose data is being handled. A credit union agent breaks that
> assumption constantly: a loan officer (the **requester**) asks the agent to pull up a **member's**
> (the **data subject's**) financial records. The member never asked for anything; their data is what
> gets handled anyway. Per that review's recommendation, this is a fork — not a copy — that adds an
> explicit `data_subject` field, distinct from `requester`, through every layer of the model below.
> Everywhere upstream said "the requester" or "the user" alone, this version asks whether that is also
> true of the data subject, and adds the check where it isn't.

This is a sanitized, internal architecture note. It is not anyone's live runtime, not a dump of private policy files, and not a promise that any specific framework implements this out of the box.

## The problem

A single agent may know about many members, accounts, loans, tickets, and staff. That is useful until a loan officer asks a normal question and the agent answers using another member's data — or hands a member's data to a person who has no current relationship to that member at all.

The failure usually does **not** look like a Hollywood breach. It looks like ordinary helpfulness:

- "Here's Member B's balance" when the loan officer asked a vague question about "the Jones account" and the system resolved the wrong Jones.
- A credit memo that includes a co-borrower's SSN or a different member's account number pulled in by an overbroad query.
- A tool query that returns every member on a branch's roster and hands them all to the model because the officer's role, not their actual assignment, gated the call.
- A generated report with hidden rows for members the requester has no active case, consent, or assignment for.
- An error message that leaks a member's account number, internal core-banking ID, or another member's name.

The security boundary cannot be "the prompt told the agent to check whose data this is." Prompt instructions are useful for behavior, but they are not an authorization layer. The guard has to live in the plumbing — and it has to check two people, not one, whenever they differ.

## Core mental model

Treat every answer, tool call, retrieval, file, and status update as an authorization problem — over **two** people, not one.

```text
requester + data_subject + tenant + resource + capability + surface -> decision
```

Where:

- **Requester**: the human, bot, or service account asking — a loan officer, teller, MSR, compliance reviewer, or a member using self-service.
- **Data subject**: the natural person whose data the resource represents, when that person is not the requester. If requester == data subject (a member checking their own balance), say so explicitly rather than leaving the field null. A null `data_subject` must never be read as "nobody to protect" — it should be read as "unresolved," and unresolved holds. This is the field upstream's model omits entirely.
- **Tenant**: the credit union/account/workspace that owns the resource.
- **Resource**: a member account, loan application, wire, ticket, document, credential, report, artifact, memory, or conversation.
- **Capability**: read balance, read credit report, read loan application, initiate wire, disclose account number, summarize, restart, mutate config, etc.
- **Surface**: retrieval, tool call, model context, generated artifact, final answer, attachment, error notice, audit log.
- **Decision**: allow, allow with redaction, hold for approval, block, or delivery-fail.

If your system cannot name those six fields for a request — not five — it cannot reliably enforce member-data isolation. A system that names only `requester + tenant + resource` can look fully authorized while showing the right employee the wrong member's data, because nothing in that triple asks whose data it is.

## The transferable lesson from Telegram-style routing — and where it stops

Telegram routing work starts with users, chats, topics, content categories, and egress surfaces. A CU staff-tools agent can reuse the same pattern with different nouns:

- Telegram requester -> staff requester (loan officer, teller, MSR)
- chat/topic -> tenant/branch/session
- content category -> resource classification (account, loan, wire, ticket)
- attachment -> statement/credit memo/report
- visible send -> answer, file, tool result, status update

The key insight is route-first and surface-aware:

1. Identify who is asking.
2. Identify where the answer will go.
3. Identify what resources/facts were used.
4. Decide whether that exact answer/action is authorized for that exact requester and route.
5. Record safe metadata about the decision.

That pattern is necessary and still correct. It is also **not sufficient** for a credit union agent, because it never asks a sixth question: *whose data is this, and is the requester that person or someone with a live relationship to them?*

The distinction is concrete in the routing itself. A **member self-service** chat (a member asking about their own account) collapses requester and data subject into one person — the pattern above is enough on its own. A **staff-facing** channel (a loan officer's tool used to look up a member) does not collapse them, and the routing pattern taken alone authorizes the wrong axis: it proves the employee is allowed to use the tool at all, not that this specific member's data may be shown to them right now.

## Architecture layers

### 1. Ingress authentication: who is asking, and about whom?

Authenticate the requester before the model sees the request — and resolve the data subject, if any, in the same step.

Minimum fields:

```yaml
subject:
  id: "user_loanofficer_jamie"
  type: "human"
  display_name: "Jamie Example"
  tenants: ["cu_westfield"]
  roles: ["loan_officer"]
  auth_source: "sso"

data_subject:
  id: "member_004821"
  type: "natural_person_member"
  tenant: "cu_westfield"
  status: "active_member"
  resolved_from: "explicit_account_reference"   # vs. "self" for member self-service
```

Do not rely on display names for either party. Use stable platform IDs, SSO subject IDs, core-banking member IDs, or verified account mappings. Display names are labels, not authority — and "the Jones account" is not a member ID.

### 2. Tenant/resource registry: what exists, who owns it, and whom is it about?

Every account/resource needs an ownership record — and, when it represents a natural person's data, a data-subject record.

```yaml
resource:
  id: "loan_app_LN-2026-00417"
  tenant: "cu_westfield"
  type: "loan_application"
  data_subject: "member_004821"
  classification: "confidential"
  allowed_capabilities:
    loan_officer: ["read_application_status", "read_credit_pull_summary"]
    branch_manager: ["read_application_status", "read_credit_pull_summary", "read_underwriting_notes"]
    admin: ["*"]
```

Unknown resource should not default to "global," and unknown data subject should not default to "anyone in this tenant may see it." Both should hold or fail loudly until ownership and data-subject identity are known.

### 3. Data-subject / relationship registry: does the requester have a live basis for *this* person's data?

This layer does not exist upstream, because upstream's model has no data subject distinct from the requester. It is the layer this fork adds.

A role scoped to a tenant ("loan officers can read application status") answers *can this employee use this capability at all*. It does not answer *may this employee see this specific member's data right now*. That second question needs its own record: a relationship, an assignment, or consent on file.

```yaml
relationship:
  subject_id: "user_loanofficer_jamie"
  data_subject_id: "member_004821"
  relationship_type: "assigned_loan_officer"
  basis: "loan_application:LN-2026-00417"
  scope_capabilities: ["read_application_status", "read_credit_pull_summary", "read_account_summary"]
  granted_at: "2026-07-01T00:00:00Z"
  expires_at: "2026-09-30T00:00:00Z"
  consent_on_file: true
```

The self-access baseline case still needs a record, not a silent bypass — an explicit `self` relationship makes it auditable rather than assumed:

```yaml
relationship:
  subject_id: "member_004821"
  data_subject_id: "member_004821"
  relationship_type: "self"
  basis: "authenticated_member_portal_session"
  scope_capabilities: ["*_own_records"]
```

A missing relationship or consent record should not default to "any staff member in this branch/tenant may view any member." It should hold or fail loudly — the same discipline the resource registry already applies to unknown resources, applied to the new second party.

### 4. Retrieval guard: what context may the model see, and about whom?

The safest place to enforce isolation is before retrieved data enters the model context — on both axes.

Bad pattern:

```text
retrieve all relevant member notes -> ask the model to only mention the right one
```

Good pattern:

```text
resolve requester -> resolve data subject -> resolve authorized tenant/resource/data-subject set -> retrieve only matching data -> attach provenance -> model answers
```

Every retrieved memory/document/log chunk should carry provenance naming whose data it is, not just which tenant owns it:

```yaml
provenance:
  tenant: "cu_westfield"
  resource_ids: ["loan_app_LN-2026-00417"]
  data_subject: "member_004821"
  source_type: "core_banking_excerpt"
  source_id: "corebank_member_004821_2026_07_01"
  classification: "confidential"
```

### 5. Tool guard: what actions may tools take, on whose record?

Tool calls must enforce policy at dispatch time, keyed to the requester **and** the data subject. The model should not be able to smuggle a same-tenant, wrong-member action through a clever prompt.

Every tool call should include or derive:

```yaml
tool_request:
  subject_id: "user_loanofficer_jamie"
  data_subject_id: "member_004821"
  tenant: "cu_westfield"
  resource_id: "loan_app_LN-2026-00417"
  capability: "read_credit_pull_summary"
  relationship_basis: "assigned_loan_officer:LN-2026-00417"
  reason: "Officer requested current application status for the member"
```

The tool wrapper checks authorization before core-banking/CRM/API access. If a backend query can return mixed-member rows (a household lookup, a joint account, a branch roster), filter before the model sees the result and assert that no returned row names a member outside the authorized `data_subject` set — the same assertion upstream makes for tenant, applied one level down.

### 6. Model context guard: what facts were assembled, and about whom?

Before the final prompt is built, validate the assembled context bundle against both parties.

Required invariant:

> Every context item visible to the model must be authorized for the requester, the data subject(s) it describes, the route, and the requested task.

If a context item lacks tenant provenance, classify it, redact it, or hold — upstream already says this. This fork adds: if requester and data subject differ, an item lacking a relationship/consent basis for that specific data subject is unprovenanceable in the second dimension even when its tenant provenance is fine. Treat it exactly the same as missing tenant provenance, not as a lesser gap.

### 7. Artifact guard: what files/reports were generated, and about whom?

Generated files are egress too. A clean message caption does not make a dirty attachment safe, and a correct tenant scope does not make a wrong-member attachment safe.

For every generated artifact, write a sidecar record naming both the tenant and the data subject(s):

```yaml
artifact:
  path: "reports/cu_westfield/member_004821/credit-memo.md"
  sha256: "example_only_not_a_real_hash"
  tenant_scope: ["cu_westfield"]
  data_subject_scope: ["member_004821"]
  resources: ["loan_app_LN-2026-00417"]
  classification: "confidential"
  generated_from:
    - source_id: "corebank_member_004821_2026_07_01"
      tenant: "cu_westfield"
      data_subject: "member_004821"
  relationship_basis: "assigned_loan_officer:LN-2026-00417"
  allowed_recipients: ["cu_westfield:loan_officer:assigned", "cu_westfield:branch_manager"]
```

Final delivery should inspect the artifact sidecar. If the sidecar is missing, stale, broader than the recipient's authority, or names a `data_subject_scope` the recipient has no relationship to, hold instead of sending.

### 8. Egress guard: what can be sent back, and to whom?

Final answers, edits, status messages, error notices, attachments, and retry fallbacks are all egress surfaces.

The final answer should be checked against:

- requester authority
- **the data subject(s) named in the content, and whether the requester has a current relationship or consent basis for each one**
- destination/route trust level
- **whether the destination is the data subject themselves, an authorized representative on file (co-borrower, guardian, power of attorney with a matching consent record), or staff with a live relationship — never assumed from tenant membership alone**
- tenant scope of retrieved context, tool results, and attached artifacts
- hard-denial categories such as secrets, raw credentials, private keys, cross-tenant resource names, private notes, unapproved logs, **and one member's data disclosed to a different member or an unlisted third party**

This is the part teams often miss, twice over. They guard the tool call, then leak in the helpful final summary — and even when they check tenant scope on that summary, they still don't check whether the *specific person* it names may be shown to the *specific person* receiving it.

### 9. Receipts and audits: what happened, and to whose data?

Audit logs should record decision metadata, not raw sensitive payloads — naming both parties.

Good audit record:

```yaml
decision:
  id: "decision_2026_07_01_001"
  subject_id: "user_loanofficer_jamie"
  data_subject_id: "member_004821"
  tenant_scope: ["cu_westfield"]
  resource_scope: ["loan_app_LN-2026-00417"]
  capability: "read_credit_pull_summary"
  surface: "final_answer"
  decision: "allow"
  reason_codes: ["subject_tenant_match", "data_subject_relationship_verified", "resource_acl_allows_capability", "no_cross_member_context"]
  payload_hash: "example_only"
```

Bad audit record:

```text
Full prompt, raw core-banking data, member SSNs/account numbers, and the whole final answer dumped into a shared log.
```

## Policy decision pseudocode

```python
def authorize(subject, data_subject, tenant, resource, capability, surface, context_items=None, artifacts=None):
    if subject is None or not subject.authenticated:
        return block("unknown_subject")

    if tenant not in subject.tenants:
        return block("subject_not_in_tenant")

    # Broad/list requests must first resolve the authorized resource set. Do not
    # let "all members" mean "all members the backend knows about".
    if resource is None and requires_resource_scope(capability):
        authorized_resources = resolve_authorized_resources(subject, tenant, capability)
        if not authorized_resources:
            return hold("no_authorized_resource_scope")

    if resource and resource.tenant != tenant:
        return block("resource_tenant_mismatch")

    if resource and not resource.allows(subject.roles, capability):
        return block("capability_denied")

    # The layer upstream's model has no equivalent for: a role scoped to the
    # tenant is not a relationship scoped to this specific person.
    if data_subject is None:
        return hold("unresolved_data_subject")

    if data_subject.id != subject.id:
        relationship = resolve_relationship(subject, data_subject)
        if relationship is None or not relationship.consent_on_file:
            return hold("no_data_subject_relationship_or_consent")
        if relationship.expires_at and relationship.expires_at < now():
            return block("data_subject_relationship_expired")
        if capability not in relationship.scope_capabilities:
            return block("capability_outside_relationship_scope")

    for item in context_items or []:
        if item.tenant != tenant:
            return block("cross_tenant_context")
        if item.data_subject and item.data_subject != data_subject.id and item.data_subject != subject.id:
            return block("cross_data_subject_context")
        if not item.provenance:
            return hold("missing_context_provenance")

    for artifact in artifacts or []:
        if tenant not in artifact.tenant_scope:
            return block("cross_tenant_artifact")
        if data_subject.id not in artifact.data_subject_scope:
            return block("cross_data_subject_artifact")
        if artifact.classification_requires_approval and not artifact.approval:
            return hold("artifact_requires_approval")

    if surface in {"final_answer", "attachment", "error_notice"}:
        if contains_secret_or_cross_tenant_identifier():
            return block("egress_sensitive_content")
        if recipient_is_not_data_subject_or_authorized_representative(surface, data_subject):
            return hold("recipient_data_subject_mismatch")

    return allow("authorized")
```

## Egress surface matrix

A real system should test every surface that can show a person information — checked against both the requester and the data subject.

| Surface | Risk | Required guard |
|---|---|---|
| Retrieval/RAG context | Model sees unauthorized facts about another member before answer | Pre-model tenant/resource/data-subject filter |
| Tool call | Model triggers an action against the wrong member's record | Tool-dispatch authorization keyed to `data_subject_id` and relationship basis |
| Tool result | Backend returns mixed-member rows (household, joint account, roster) | Post-result assertion before model context |
| Final answer | Summary leaks another member, or names the right member to the wrong recipient | Final egress check against recipient identity |
| Attachment/report | File includes hidden rows for a member outside the relationship scope | Artifact sidecar with `data_subject_scope` + content/metadata check |
| Status/progress update | "Checking member_004821's application" leaks target to an unrelated viewer | Safe status templates scoped to tenant and data subject |
| Error notice | Stack/path/account-number/member-name leak | Scrubbed operational notice |
| Retry/fallback path | Bypasses normal guard | Same guard at every send path |
| Admin/debug/compliance override | Permanent god-mode leaks any member to any staff | Explicit, scoped (which member, which capability), expiring override with audit |
| **Recipient identity mismatch** *(new)* | Content correctly scoped to Member A is delivered to a channel, ticket, or person associated with Member B | Recipient-vs-data-subject match check before every send, independent of tenant/role checks |

## Acceptance test matrix

At minimum, build fixtures that prove:

1. A loan officer with an active, non-expired relationship to Member A can read Member A's account summary.
2. A loan officer cannot read Member B's account summary without a relationship, assignment, or consent record for Member B — even inside the same credit union tenant.
3. A loan officer cannot ask for "everyone in my book" and receive members outside their actual assigned relationships.
4. A loan officer cannot receive a generated credit memo containing a different member's account rows.
5. A mixed-member backend response (household lookup, joint account, branch roster) is filtered to the authorized data-subject set before model context assembly.
6. A missing relationship/consent record holds loudly instead of defaulting to "any staff in this branch may view any member."
7. A final answer naming an unauthorized member's account number, balance, or SSN is blocked or redacted.
8. Error messages do not leak member account numbers, SSNs, internal core-banking IDs, or another member's name.
9. An admin/compliance override requires explicit scope naming *which member and which capability*, plus expiry, actor, and reason — never a standing "view all members" mode.
10. Audit records name both the requester's ID and the data subject's ID, plus the relationship basis, not raw account data.
11. A member using self-service (requester == data subject, `relationship_type: self`) is not blocked by relationship checks that exist only for the requester-differs-from-data-subject case.
12. A loan officer's relationship to a member that has expired (loan closed, case reassigned, employee off-boarded) can no longer be used to justify access, even if the tenant/role ACL is unchanged.
13. A report generated for Member A cannot be delivered to a channel, ticket, or contact associated with Member B, even if both members share the same loan officer.
14. A disclosure to a co-borrower, guardian, or power of attorney is allowed only when that person is on the data subject's authorized-recipient list with a matching consent record — never merely because they are also a member of the same credit union.

A machine-readable fixture set analogous to upstream's `egress-surface-test-matrix.example.yaml` is a recommended follow-on artifact for this fork; it is intentionally not included here so this document stays a single, reviewable file.

## Staff-facing vs. member-facing routing notes

Where upstream's Telegram section talks about bot-token hygiene and webhook lifecycle, the CU-specific addition is the routing distinction called out above: a **member self-service** channel and a **staff-facing** channel look structurally identical at the transport layer (a chat, a session, a topic) and are authorization-wise opposite cases.

- In a member self-service channel, the requester and the data subject are the same person by construction (an authenticated member session). The relationship record is `self`, and the routing pattern from upstream's Telegram section is, on its own, close to sufficient.
- In a staff-facing channel, the requester and data subject are different people by construction. Transport controls (which employee can open the tool, which branch's queue it's tied to) prove the employee may use the tool. They do not prove the employee may see *this* member's data — that proof lives in the relationship/consent registry (Layer 3), not in the chat's access list.
- Group topics, shared queues, and ticket routing are routes, not security principals, in both cases — a queue ID does not prove either party's authority. Upstream's own line on this ("a topic ID does not prove the requester may see a machine") applies unchanged; substitute "a member's record" for "a machine."
- Redact logs and audit records the same way upstream specifies, with member identifiers added to the redaction list alongside usernames and message text.
- Build retry/fallback sends through the same egress guard, including the recipient-vs-data-subject check — an emergency fallback that skips the relationship check is exactly where a wrong-member disclosure happens under pressure.

## Common bad patterns

### Prompt-only firewall

> "The system prompt says only show members their own data."

Useful instruction. Not a boundary. Enforce before retrieval, before tool dispatch, before final answer, and before attachment delivery.

### Requester authority mistaken for data-subject authority *(new)*

The agent grants a loan officer read access to any member's account because the loan officer's *role* has `read_account_summary` in the tenant ACL. Role-tenant capability answers "can this employee use this tool at all." It does not answer "may this employee see this specific member's data right now." Require a relationship or consent record scoped to the specific data subject before granting the capability — a tenant-level role is a necessary condition here, never a sufficient one.

### Global admin context by default

The agent runs with god-mode across every member in the tenant and promises to self-filter. That is convenient until a prompt injection or summary bug turns god-mode into a cross-member leak.

### Mixed-member retrieval then redaction

If another member's facts enter context, you are relying on the model to forget them. Filter before context assembly, on the data-subject axis as well as the tenant axis.

### Tool success treated as answer safety

A tool call can be authorized for the right tenant and still return, or the model can still summarize, the wrong member's row. Guard both, and guard the data-subject match specifically.

### Attachments as an afterthought

Generated files are often worse than chat text: more rows, more metadata, less scrutiny. Treat every file as an egress event, and check its `data_subject_scope` before it goes anywhere.

### Silent blocks

A silent block creates operational confusion and people route around the system. Prefer a safe receipt: "I can't provide that member's data from this account; ask from an account with an active relationship to this member, or route through compliance." Do not include the member's private details in the receipt.

## Design Principles Check

### Real goal
Help CU staff- and member-facing agents operate across many members and accounts without leaking one member's data to a person unauthorized to see it — including staff who are authorized to use the tool but not authorized for this particular person.

### Domain concept
Tenant- **and data-subject**-scoped authorization over agent memory, retrieval, tools, artifacts, and egress. Requester authorization is necessary but not sufficient; whenever requester and data subject differ, a live relationship or consent basis for that specific person is also required. This is not merely tenant access control, and it is not merely Telegram-style routing.

### Unattended breakage
New members, accounts, loan officers, branches, tools, and fallback paths appear over time, same as upstream. In addition: relationships expire — a loan closes, a case is reassigned, an employee changes teams or leaves. If expiry is not enforced against the relationship registry, access silently outlives the reason it was granted.

### Instance vs problem
This solves the class: "one agent, many members and staff, and the person asking is frequently not the person whose data it is." The examples use a fake member and a fake loan officer so the pattern can be adapted safely.

### Required state
Tenant registry, subject registry, resource ACLs, **data-subject/relationship registry with consent-on-file and expiry**, provenance on context/tool results/artifacts (tagged with data subject, not just tenant), egress decision logs, and recurring tests over all visible surfaces — including the self-service and staff-on-behalf-of-member cases separately.

### Tradeoffs / proxies
Classification, secret detection, and consent flags are proxies. They should supplement deterministic tenant/resource/data-subject authorization, not replace it.

### Decision hierarchy call
Privacy and reliability drive the design, same as upstream — with member-trust and regulatory exposure (GLBA-class member financial privacy obligations) as the CU-specific stakes behind "privacy." A privacy guard that silently breaks useful staff workflows will be bypassed; a reliable agent that discloses one member's data to the wrong person is unacceptable. The answer is deterministic gates plus clear receipts and tests, on both the tenant axis and the data-subject axis.

## Pickup prompt

> I operate an agent that lets credit union staff (loan officers, tellers, MSRs) look up member accounts, loans, and tickets, and that also supports member self-service. Read this tenant- and data-subject-scoped security model. Build me a proposed authorization design for my stack: subject registry, data-subject/relationship registry with consent-on-file and expiry, tenant/resource ACLs, retrieval filtering, tool dispatch guards keyed to both requester and data subject, artifact sidecars scoped by data subject, egress checks that verify the recipient against the data subject (not just tenant/role), audit records naming both parties, and an acceptance test matrix that covers the self-service and staff-on-behalf-of-member cases separately. Ask for missing context before implementation. Do not rely on prompt instructions as the security boundary, and do not assume that requester authority implies data-subject authority.
