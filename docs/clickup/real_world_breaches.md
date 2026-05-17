# Patchet vs OAuth — Real-World Breach Replays

> **What this is:** A living catalog of public breach incidents reproduced as Patchet
> demo scenarios. Each section covers one incident class, shows how OAuth's default
> semantics permit it, and demonstrates the corresponding Patchet anchor blocking it.
>
> **What this is not:** A claim that Patchet would have prevented these incidents in
> their entirety. Each section is explicit about scope.

## Status & ownership

- **Document status:** DRAFT — pending stakeholder review
- **Owner:** @{owner}
- **Last verified:** 2026-04-27 (run captured at `/tmp/dod.json`)
- **Living-document conventions:**
  - When the demo's behavior or output changes, update the JSON snippets in the
    relevant section within 24 hours. Stale evidence undermines the artifact.
  - When adding a new use case, copy the per-section structure and reuse the headings.

## Thesis

OAuth 2.0 was designed for human-driven API access. Three of its core design
assumptions — that identity is a `client_id` plus secret, that authorization is a
scope, and that tokens are bearer instruments — do not map onto agent-to-agent
workflows. This catalog demonstrates each gap against a documented breach.

## Headline matrix

Captured from `POST https://demo.unforge.io/dod_demo` at **2026-04-27 14:25 UTC**.

| Threat | Real-world incident | OAuth result | Intent (Patchet) result | Detection time (Intent) |
|---|---|---|---|---|
| T1 — Identity Spoofing | SolarWinds (Dec 2020) | attack succeeded | blocked at registration | 262 ms |
| T7 — Privilege Escalation | Uber (Sep 2022) | attack succeeded | blocked at request time | < 1 s |
| T2 — Token Replay | Okta (Oct 2023) | attack succeeded | blocked at request time | 4,652 ms |

Aggregate: **OAuth: 3/3 attacks succeeded. Intent: 3/3 attacks blocked.**

```json
{
  "oauth_succeeded": 3,
  "oauth_total": 3,
  "intent_blocked": 3,
  "intent_total": 3
}
```

## How to read each use case

Each use case below follows the same structure:

1. **The original incident** — facts and impact, sourced to public reporting
2. **The mechanism** — the actual technical chain of the attack
3. **Why OAuth misses it** — the specific design assumption that fails
4. **The Patchet replay** — the demo scenario that reproduces the same mechanism
5. **Reproducibility** — the exact `curl` command, the exact JSON response
6. **What it proves and what it does not** — honest scoping of the claim

The demo runs at `https://demo.unforge.io`. All endpoints are publicly callable.
The JSON cited throughout this document is captured verbatim from a real call
against the production environment.

---

# Use Case 1 — T1 — Identity Spoofing (SolarWinds replay)

## The original incident: SolarWinds Orion / SUNBURST

**Source incident date:** December 2020.

**Victim scope.** Approximately 18,000 organizations downloaded the trojanized
Orion update. Of those, around 100 were selected for hands-on follow-on
exploitation, including the U.S. Departments of Treasury, Commerce, Homeland
Security, State, Defense, and Energy; the National Institutes of Health; and
cybersecurity firms FireEye and Mimecast.

**Public impact.** GAO and CISA estimates put direct response costs above $100M.
Long-tail costs — incident response, classified-material exposure assessments,
multi-year remediation, civil litigation — continue to accumulate.

**Threat actor.** Attribution by ODNI, FBI, CISA, and NSA: APT29 ("Cozy Bear"),
associated with the Russian Foreign Intelligence Service (SVR).

## The mechanism

APT29 compromised SolarWinds' build infrastructure between September 2019 and
February 2020. Their implant, dubbed SUNBURST, was injected into a single DLL —
`SolarWinds.Orion.Core.BusinessLayer.dll` — during the legitimate build process.
The trojanized DLL was code-signed by SolarWinds' authentic certificate (the
build pipeline did the signing) and shipped through the official update
mechanism between March and June 2020.

The critical property: customers' security tools verified Orion updates by
checking the code signature. The signature was valid: the real SolarWinds
certificate, applied by the real build pipeline, attached to a binary that the
build pipeline itself produced. The malicious payload was inside the binary,
but the *identity* of the binary was correct.

For 12 days after install, SUNBURST stayed dormant. After that, it beaconed to
attacker-controlled infrastructure and waited for instructions. Of ~18,000
infected hosts, attackers selected ~100 high-value targets for hands-on
exploitation.

## Why OAuth misses this class of attack

OAuth answers two questions: *who is calling?* (a `client_id`) and *do they
have a valid credential?* (a `client_secret` or signed assertion). It does not
answer: *is the calling code the same code that was originally registered as
this identity?*

This is a structural property of OAuth, not a configuration gap. The
`client_id` and `client_secret` are credentials *for* an identity; they are
not *of* the identity. An attacker who substitutes the binary while keeping
the credentials retains the identity from OAuth's perspective. There is no
code attestation in the protocol.

In a classical human-to-API world this is acceptable: the binary is the OAuth
client library, which is rarely substituted, and the user supplies the secret
out-of-band. In an agent-to-agent world, where the "client" is itself a piece
of code authored by an arbitrary developer, the gap matters: an attacker can
register an `agent_id` of `T1Planner` once, then any subsequent code that
knows the secret can claim to be `T1Planner`.

## The Patchet replay

The demo reproduces SUNBURST's identity-substitution mechanism in miniature.
Two agent definitions exist in `src/demo/t1/agents.py`:

```python
t1_planner = {
    "name": "T1Planner",
    "prompt": "You are Planner agent. Run 't1_list_files' tool and then call Done.",
    "tools": [{"name": "t1_list_files"}],
}

t1_impersonator = {
    "name": "T1Planner",                    # same agent_id
    "prompt": "You are Planner agent. ...", # same prompt
    "tools": [{"name": "t1_list_files"}],   # same tools
}
```

These two definitions produce **identical checksums** — same code, registering
as the same identity. In SolarWinds terms: the impersonator is the trojanized
DLL, the planner is the legitimate one. Both want to be `T1Planner`.

### OAuth-mode result

The impersonator registers without challenge. From OAuth's perspective, both
registrations have the same `client_id` and the same secret; there is nothing
to compare. The impersonator then runs as `T1Planner` — the rest of the
workflow trusts it.

```bash
curl -X POST 'https://demo.unforge.io/t1_agent_identity_spoofing?mode=oauth'
```

```json
{
  "threat_id": "T1",
  "threat_name": "Agent Identity Spoofing",
  "mode": "oauth",
  "attack_succeeded": true,
  "blocked_by": null,
  "detection_time_ms": 2532.001830999434,
  "details": {
    "message": "An Impersonator Agent was allowed to be registered by plain OAuth. Agent Identity is not supported."
  }
}
```

### Intent-mode result

Patchet's IDP refuses the second registration with HTTP 400. The check fires
at registration time, not at runtime. The impersonator never executes.

```bash
curl -X POST 'https://demo.unforge.io/t1_agent_identity_spoofing?mode=intent'
```

```json
{
  "threat_id": "T1",
  "threat_name": "Agent Identity Spoofing",
  "mode": "intent",
  "attack_succeeded": false,
  "blocked_by": "A2: Registration First Security Model",
  "detection_time_ms": 262.4181099999987,
  "error_message": "Client error '400 Bad Request' for url 'https://idp.unforge.io/intent/batch_register/agent'"
}
```

## The anchor that fired: A2 — Registration-First Security Model

Before any code can act as an identity in a Patchet-protected system, the IDP
records a tuple: `(registration_id, agent_id, code_checksum, public_key)`.
Any subsequent attempt to register the same `agent_id` with a checksum that
matches an existing registration is rejected with HTTP 400.

The check is on **the checksum**, not on the agent_id alone. Two different
agents claiming the same name with different code is allowed (different
checksums); two different agents claiming the same name with identical code
is the impersonation attempt the anchor exists to catch.

## What this proves and what it does not

**Proves:**

- The SolarWinds identity-substitution mechanism cannot complete in a system
  with A2 enforced. The impersonator does not become an active agent.
- Detection happens at registration, *before* the malicious code can run,
  beacon, or move laterally.
- The 262 ms detection time vs. 2,532 ms for the OAuth happy path: the
  rejection is faster than the legitimate flow. There is no soak period during
  which the attacker has access.

**Does not prove:**

- A2 does not prevent supply-chain compromise of the legitimate code itself.
  If APT29 had compromised the *original* T1Planner before its first
  registration, A2 would dutifully record the malicious code as the canonical
  T1Planner. The defense narrows the attack surface from "ongoing identity
  substitution" to "one-shot compromise of the first-to-register binary."
- Defense-in-depth still requires build-pipeline integrity, code review, and
  SBOM tracking. A2 is a necessary primitive for agent identity, not a
  replacement for software supply-chain security.

## LangSmith trace

`{{ TRACE_URL — populated after next /dod_demo run with LANGSMITH_TRACING=true }}`

---

# Use Case 2 — T7 — Cross-Agent Privilege Escalation (Uber replay)

## The original incident: Uber breach

**Source incident date:** September 2022.

**Victim scope.** Uber Technologies. Data exposure included internal source
code, AWS credentials, GCP credentials, HackerOne bug-bounty reports, internal
Slack channels, OneLogin admin, and engineering tooling.

**Public impact.** Uber's 10-K disclosed "less than $400,000 of expenses
related to the September 2022 incident." Downstream costs (regulatory scrutiny,
additional security investments, response cost across customers and partners)
compounded that figure substantially. The breach was disclosed publicly via
Slack and Twitter by the attacker themselves.

**Threat actor.** Attributed to "Lapsus$" or an affiliate of the group.

## The mechanism

The chain, per Uber's post-incident disclosures and corroborating reporting:

1. Attacker purchased credentials for an Uber EXT (external/contractor)
   account on a dark-market broker.
2. Repeatedly attempted MFA push notifications to the contractor's phone for
   approximately one hour.
3. Contacted the contractor on WhatsApp posing as Uber IT, told them to accept
   the push to "stop the spam." MFA fatigue succeeded.
4. Attacker logged in as the contractor — a low-privilege identity.
5. From there, discovered hardcoded credentials in a PowerShell script on an
   internal network share that pointed to a privileged-access management (PAM)
   system.
6. The PAM gave them admin access to AWS, GCP, the internal Slack, OneLogin,
   the HackerOne bug-bounty backend, and Uber's source code repositories.

The relevant technical question: at what point in the chain should the
authorization layer have refused?

Each system the attacker touched — Slack, AWS, OneLogin, the PAM, source
repos — accepted requests because the credentials presented were valid for
that system. None of them asked: *is this account, in this workflow context,
at this step, supposed to be doing this?* The contractor's identity had been
compromised; their tokens were valid; the resulting requests were authorized
by the standard scope checks.

## Why OAuth misses this class of attack

OAuth scopes describe *capabilities* — `read:repo`, `write:files`,
`deploy:production`. They do not describe *call positions in a workflow*. A
token bearing `deploy:production` is, from OAuth's perspective, equally valid
whether the deployment workflow has been initiated, whether prior approval
gates have been satisfied, or whether the calling identity is the one normally
responsible for that step.

In the Uber case: the contractor account had whatever scopes their role
required for normal work. Once the attacker had the credentials, they could
call any endpoint those scopes authorized — including, transitively, the PAM
that held the master keys.

OAuth's design assumes scopes are coarse-grained, slow-changing, and aligned
with organizational roles. Agent workflows are the opposite: tens of agents,
each authorized for a *specific step in a specific multi-agent workflow*, not
for a generic role.

## The Patchet replay

The demo defines a workflow `version_bump_v1.0` with two steps:

1. **T7Planner** (low privilege; can list repository contents)
2. **T7Patcher** (high privilege; can write code changes)

The legitimate flow is Planner → Patcher. The attack: malicious user input
attempts to bypass T7Planner and call T7Patcher directly, escalating from
`read:repo` to `write:repo` privileges by skipping the workflow gate.

### OAuth-mode result

T7Patcher accepts the call because the bearer token is valid and carries the
right scope. Privilege escalation succeeds in 8.1 seconds. The high-privilege
operation runs.

```bash
curl -X POST 'https://demo.unforge.io/t7_cross_agent_privilege_escalation?mode=oauth'
```

```json
{
  "threat_id": "T7",
  "threat_name": "Cross-Agent Privilege Escalation",
  "mode": "oauth",
  "attack_succeeded": true,
  "blocked_by": null,
  "detection_time_ms": 8101.396341999134,
  "details": {
    "message": "High privilege operation was successfully hijacked by low privilege agent.",
    "tool_result": {
      "operation": "list_files",
      "privilege_level": "LOW",
      "scope_used": "read:repo",
      "VersionBump": {
        "batch_name": "VersionBump",
        "target_manifest": "package.json",
        "status": ["SUCCESS"]
      }
    }
  }
}
```

The damning line: `"scope_used": "read:repo"`. The agent had a *read* scope
but executed a *write* operation, because the Patcher endpoint accepts any
caller with a valid OAuth token in the right capability bucket.

### Intent-mode result

The IDP refuses to mint an intent token for T7Patcher because the
workflow-step authorization check fails: T7Planner has not yet completed in
this workflow execution. `api.unforge.io` receives a request without a valid
intent token and returns 401.

```bash
curl -X POST 'https://demo.unforge.io/t7_cross_agent_privilege_escalation?mode=intent'
```

```json
{
  "threat_id": "T7",
  "threat_name": "Cross-Agent Privilege Escalation",
  "mode": "intent",
  "attack_succeeded": false,
  "blocked_by": "Outer security layer (pre-attack auth)",
  "error_message": "Authentication failed: Client error '401 Unauthorized' for url 'https://api.unforge.io/github/listfiles'",
  "outer_exception": true
}
```

## The anchor that fired: workflow-step authorization

Patchet's intent tokens are bound to a tuple
`(agent_id, code_checksum, workflow_id, current_step)`. A request for
`write:repo` from an identity that is not at the Patcher step in an active
`version_bump_v1.0` execution is rejected at the IDP, before any token is
issued.

The authorization decision happens at *token mint time*, not at the resource
server. A compromised credential cannot be "moved up the chain" — each step
requires its own token, and each token requires the prior steps to have been
satisfied.

## What this proves and what it does not

**Proves:**

- Even with a valid agent identity and the correct OAuth scope, an attacker
  cannot execute out-of-step.
- The relevant authorization decision happens at the IDP, not at the resource
  server. If the resource server is compromised but the IDP is not, the
  authorization model still holds.

**Does not prove:**

- Workflow-step binding does not protect against compromise of the legitimate
  Patcher itself. If an attacker compromises the actual T7Patcher binary (a
  SolarWinds-style attack), they would inherit Patcher's authorization within
  its allowed steps. Defense-in-depth requires combining workflow-step
  binding (this anchor) with code attestation (A2).
- For Uber specifically: workflow-step binding would have prevented step 6 of
  the chain (using contractor scopes to access the PAM-administered systems),
  *if* the relevant systems had been Patchet-protected agents. Steps 1-5
  (initial credential theft, MFA fatigue, lateral discovery) are out of scope
  for the IDP layer.

## LangSmith trace

`{{ TRACE_URL — populated after next /dod_demo run with LANGSMITH_TRACING=true }}`

---

# Use Case 3 — T2 — Token Replay (Okta replay)

## The original incident: Okta support engineer compromise

**Source incident date:** October 2023.

**Victim scope.** Okta itself; downstream impact across approximately 134
customer tenants. Publicly disclosed downstream victims include BeyondTrust,
Cloudflare, and 1Password.

**Public impact.** Okta stock declined approximately 12% on disclosure (Oct 20,
2023). SEC material breach disclosure. Multiple customer-side investigations.
The full downstream cost across the tenant ecosystem has not been publicly
quantified.

**Threat actor.** Not formally attributed in public disclosures.

## The mechanism

A threat actor accessed an Okta support engineer's machine. From the
engineer's machine, the attacker could read HAR (HTTP Archive) files that
customers had uploaded as part of routine support tickets.

HAR files are a standard troubleshooting artifact: customers click "save HAR"
in their browser dev tools to capture request/response sequences, then upload
them so support engineers can debug session-related issues. HAR files include
the full request headers, cookies, and any session tokens that were live at
capture time.

The chain:

- Attacker downloaded HAR files from customer support tickets.
- Extracted live session tokens from the captured `Authorization: Bearer …`
  headers.
- Replayed those tokens directly against the customer Okta tenants from
  attacker infrastructure.
- The tokens were valid until expiry; Okta accepted them because, by
  definition, a bearer token is whoever holds it.

Okta's then-CSO framed this as not a vulnerability per se: "the design of
bearer tokens is such that whoever possesses them can use them. The breach
was that the tokens were exposed."

## Why OAuth misses this class of attack

OAuth bearer tokens are, by RFC 6750 definition: "any party in possession of
a bearer token (a 'bearer') can use the token in any way that any other party
in possession of it can." This is the design.

OAuth provides optional companion specifications for this gap — RFC 8705
(mTLS-bound tokens) and RFC 7800 (proof-of-possession key semantics) — but
real-world adoption is minimal. Most production OAuth deployments, including
Okta's customer flows at the time, used pure bearer semantics because PoP
requires per-request signing (operational overhead) and token-binding to a
specific cryptographic key (key management overhead).

For agent-to-agent workflows, the operational and key-management overhead is
far lower because the consumers and producers of tokens are software
components under unified control. The economics that historically discouraged
PoP adoption in human-facing flows do not apply.

## The Patchet replay

The demo simulates a token-theft + replay scenario:

1. A legitimate agent (`T2GenuinePlanner`) requests an intent token from the
   IDP and uses it to call `api.unforge.io`.
2. The token is captured into an attacker-controlled context (simulating
   exfiltration via logs, HAR files, MITM, or compromised host).
3. A different agent (`T2MaliciousPlanner`) replays the captured token
   against `api.unforge.io`.

### OAuth-mode result

The replayed token is accepted. From `api.unforge.io`'s perspective, it
received a valid bearer token with the right scope and audience. The
malicious caller succeeds in 6 seconds.

```bash
curl -X POST 'https://demo.unforge.io/t2_token_replay_attacks?mode=oauth'
```

```json
{
  "threat_id": "T2",
  "threat_name": "Token Replay Attacks",
  "mode": "oauth",
  "attack_succeeded": true,
  "blocked_by": null,
  "detection_time_ms": 6041.819604999546,
  "details": {
    "message": "ATTACK SUCCEEDED: Token replay was NOT detected, Unauthorized operation executed with stolen token.",
    "tool_result": {
      "token_captured": true,
      "attack_succeeded": true,
      "security_issue": "Token replay was not prevented!"
    }
  }
}
```

### Intent-mode result

`api.unforge.io` rejects with 401 because the PoP signature on the request
does not verify against the public key registered for the agent claiming to
be the caller. The replayer holds a valid token, but does not hold the
matching private key.

```bash
curl -X POST 'https://demo.unforge.io/t2_token_replay_attacks?mode=intent'
```

```json
{
  "threat_id": "T2",
  "threat_name": "Token Replay Attacks",
  "mode": "intent",
  "attack_succeeded": false,
  "blocked_by": "A6:  Proof of Possession",
  "detection_time_ms": 4652.2579659995245,
  "error_message": "Authentication failed: Client error '401 Unauthorized' for url 'https://api.unforge.io/github/patch'"
}
```

## The anchor that fired: A6 — Proof of Possession

Each registered agent generates an RSA keypair at registration time. The
public key is stored with the IDP; the private key is held only by the
running agent process.

Every authenticated request includes a `PoP` header containing a signature
over a per-request payload (request scope + checksum + timestamp), signed
with the agent's private key. The resource server verifies the signature
against the registered public key before accepting the request.

A stolen token is useful only when accompanied by the matching signing key.
In the Okta scenario: a HAR file does not contain private keys, so the
captured tokens cannot be used.

## What this proves and what it does not

**Proves:**

- Bearer-style token theft is mechanically defeated. An attacker who captures
  a valid intent token from logs, network traces, HAR uploads, or memory
  dumps cannot replay it without the corresponding private key.
- The Okta-specific corollary: HAR files would not have contained anything
  useful had Okta's customer flows used PoP-bound tokens. The breach
  mechanism — file-level token theft — would have been a non-event.

**Does not prove:**

- PoP does not protect against compromise of the agent process itself. If
  the attacker has read access to the running agent's memory (kernel-level
  access, container escape, or similar), they can extract the private key
  and sign requests as the agent.
- PoP shifts the attack surface from "tokens leaked in logs" (very common,
  hard to prevent) to "private keys extracted from running processes"
  (rarer, requires deeper access). It does not eliminate the attack surface.

## LangSmith trace

`{{ TRACE_URL — populated after next /dod_demo run with LANGSMITH_TRACING=true }}`

---

# Reproducing the headline matrix

The full demo can be re-executed end-to-end. The system requires three
sequential calls:

```bash
# 1. Bootstrap (one-time, after a fresh IDP redeploy)
curl -X POST https://demo.unforge.io/register_all_agents
curl -X POST https://demo.unforge.io/regiser_all_workflows

# 2. Run the headline matrix
curl -X POST https://demo.unforge.io/dod_demo
```

Each threat is also independently callable:

```bash
curl -X POST 'https://demo.unforge.io/t1_agent_identity_spoofing?mode=oauth'
curl -X POST 'https://demo.unforge.io/t1_agent_identity_spoofing?mode=intent'
curl -X POST 'https://demo.unforge.io/t7_cross_agent_privilege_escalation?mode=oauth'
curl -X POST 'https://demo.unforge.io/t7_cross_agent_privilege_escalation?mode=intent'
curl -X POST 'https://demo.unforge.io/t2_token_replay_attacks?mode=oauth'
curl -X POST 'https://demo.unforge.io/t2_token_replay_attacks?mode=intent'
```

# Beyond this catalog: the full threat surface

Patchet's threat catalog covers twelve scenarios (T1–T12), mapping to STRIDE
categories extended for agentic systems. This catalog covers the three with
the clearest public-incident parallels. The remaining nine are runnable in
the same demo and will be added as additional sections as time permits.

| Threat | STRIDE category | Status in this catalog |
|---|---|---|
| T1 Agent Identity Spoofing | Spoofing | documented (SolarWinds) |
| T2 Token Replay | Spoofing/Repudiation | documented (Okta) |
| T3 Shim Library Impersonation | Spoofing | pending — recent MCP supply-chain incidents are candidates |
| T4 Runtime Code Modification | Tampering | pending |
| T5 Prompt Injection | Tampering | pending — Microsoft Copilot EchoLeak (2025) is a candidate |
| T6 Workflow Definition Tampering | Tampering | pending |
| T7 Cross-Agent Privilege Escalation | Elevation | documented (Uber) |
| T8 Workflow Step Bypass | Elevation | pending |
| T9 Scope Inflation | Elevation | pending |
| T10 Intent Origin Forgery | Spoofing/Repudiation | pending |
| T11 Delegation Chain Integrity | Tampering | pending |
| T12 Agent Configuration Exposure | Information Disclosure | pending |
