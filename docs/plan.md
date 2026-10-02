# Agent Security MCP Gateway

## Phase 2 Project Plan

**Status:** Complete for the approved local non-production scope; production assurance deferred
**Current feature:** none; all 21 tracked Phase 2 features are complete

### Research extension: next session-sized deliverable

The [research extension plan](addon-md.txt) adds research validation after local
implementation completion. On 2026-09-27, its section 1 protocol deliverable was
completed in [research-protocol.md](research-protocol.md), with a source-checked
[Progent/MCIP comparison](research-related-work.md). This prepares the study; novelty,
semantic resolver accuracy, comparative effectiveness, and submission readiness remain
unverified. It does not reopen completed Phase 2 implementation features or authorize
production use.

Next action: construct a versioned candidate resolver corpus with tool contracts,
restricted grammar, initial resource states, expected effects, label provenance, and
family-level development/held-out splits. Obtain independent review before treating
candidate labels as ground truth. No corpus or experiment was completed by the
protocol task.

### Active code-review follow-up

The protected approval entrypoint, PostgreSQL authority resolver/approved-call loader,
and real `ClientApprovedCallExecutorV1` bridge are now composed. Startup fails unless a
trusted runtime module supplies a credential lease and exact forwarder. Integration
evidence covers approval, resolution, atomic consumption, one forwarding attempt, and
terminal failure/audit; Chromium covers the live keyboard denial path.

Approval decisions now enqueue a database-constrained dispatch in the same transaction.
The runtime claims it before session resolution, and concurrent restart recovery either
revokes an unconsumed approval with zero forwarding or records an already-consumed
ambiguous attempt as `UNKNOWN` without retrying it.

The protected runtime composes the approved HashiCorp Vault provider, non-exporting
credential broker, exact forwarding-attempt authorization, downstream authentication,
result mediation, and durable outcome persistence. Four Chromium workflows now cover
keyboard denial, governed `Approve once`, reload/reconnect, duplicate and two-tab
concurrency, expiry, coverage-driven revocation, provider failure, and invalid-result
quarantine. The UI shows the bound result disposition and schema verdict without raw
downstream content. `P2-F020` is complete with disposable evidence. Keep coverage
`UNPROTECTED` and protected forwarding remain disabled after local completion.
Independent hosts and external review are deferred production-assurance work and are
not claimed by local completion.

## 1. Product thesis

Agentic systems turn model output into effects across files, databases, cloud systems,
accounts, networks, and software supply chains. Prompt defenses and model alignment do
not create a security boundary. The project therefore places an authenticated,
fail-closed reference monitor between MCP clients and downstream servers.

The gateway's core value is deterministic mediation, not dynamic trust. Dynamic trust
is a research hypothesis that will remain in shadow mode until controlled evaluation
shows that bounded trust improves usability without increasing unsafe authorization.

The active product boundary is MCP traffic. Native shell, filesystem, browser, and
direct network actions remain outside the gateway and must be blocked independently
when they can reproduce a protected MCP effect. The primary research question is
whether canonical effect-based authorization and bidirectional mediation prevent
cross-tool and cross-server policy bypasses without unacceptable false denials,
approval burden, latency, or loss of legitimate task completion.

The generic concept of an MCP security gateway overlaps current related work. The
project's publishable claim must therefore be supported by comparative evidence for
representation invariance, exact transactional approval, result mediation, and
truthful bypass-aware coverage rather than by architecture description alone.

## 2. Design principles

1. **Complete mediation:** evaluate every supported call and every returned result.
2. **Canonical authorization:** decide from resolved resource, effect, environment,
   route, and data flow rather than tool name or syntax.
3. **Immutable safety:** trust, user policy, and model output cannot weaken hard denials
   or Tier 3 approval.
4. **Exclusive mediation:** protected credentials live only in the gateway and direct
   access is blocked independently.
5. **Bidirectional distrust:** clients, servers, discovery data, arguments, results,
   errors, and model summaries are untrusted.
6. **Exact approval:** one human approval authorizes one revalidated request once.
7. **Truthful coverage:** missing guarantees are visible and block protection claims.
8. **Trajectory accountability:** link every proposal, decision, retry, approval,
   forward, result, outcome, and trust event.
9. **Research discipline:** use seeded disposable tests, repeated trials, baselines,
   and both security and usability metrics.

## 3. Delivery milestones

### Milestone 1 - Safe protocol foundation

Features: `P2-F001` through `P2-F004`.

- Define versioned contracts for clients, sessions, servers, routes, schemas, calls,
  results, provenance, outcomes, and errors.
- Implement MCP initialization and capability negotiation without protected forwarding.
- Authenticate clients and isolate session state.
- Register downstream servers through an administrator-controlled path.
- Integrity-check discovery, schema hashes, route ownership, and capability changes.
- Add replay protection, quotas, recursion detection, cancellation, timeouts, payload
  limits, concurrency limits, and circuit breakers.

Exit condition: the gateway can negotiate and expose authorized discovery safely, but
cannot forward a protected mutation.

### Milestone 2 - Authorization reference monitor

Features: `P2-F005`, `P2-F006`, and the decision portions of `P2-F008`.

- Normalize resources, effects, environments, routes, data flows, and call chains.
- Implement immutable rules, category-specific analyzers, contextual risk escalation,
  and most-restrictive decision composition.
- Persist requests, normalized actions, evidence, and decisions in PostgreSQL.
- Implement exact five-minute approval, immediate revalidation, atomic consumption,
  and one-time forwarding state.
- Add cross-tool, cross-server, alternate-path, encoded-payload, retry, replay,
  concurrency, and time-of-check/time-of-use tests.

Exit condition: every supported request is denied, constrained, sandboxed, approved,
or allowed from canonical policy with a persisted decision.

### Milestone 3 - Complete execution boundary

Features: `P2-F007` through `P2-F010`.

- Forward one exact request with route-scoped gateway-held credentials.
- Bind returned content to authenticated server, route, schema, request, and session.
- Enforce result schema, size, redaction, secret detection, data-egress policy,
  instruction/content separation, and quarantine.
- Complete transactional request-to-outcome audit linkage and tamper evidence.
- Verify exclusive mediation with network, IAM, sandbox, OS, and downstream controls.
- Build truthful coverage diagnostics.
- Build approval, awareness, audit, and recovery interfaces from canonical data.

Exit condition: both request and result paths are mediated, protected credentials are
not agent-accessible, and bypass checks fail safely.

### Milestone 4 - Security evaluation and validation

Features: `P2-F011` and `P2-F012`.

- Build seeded protocol, policy-invariance, prompt/content, human, and trust suites.
- Adapt relevant AgentDojo, WASP, AgentHarm, OS-Harm, ToolEmu, and MCP-oriented cases.
- Test adaptive attackers that know the defense.
- Report repeated-trial security, usability, latency, cost, approval, re-planning, and
  coverage metrics.
- Validate equivalent workflows with at least two MCP-compliant hosts and concurrent
  isolated sessions.

Exit condition: all critical acceptance criteria pass and results are reproducible.

### Milestone 5 - Controlled research features

Features: `P2-F013` and `P2-F014`.

- Run dynamic trust in shadow mode.
- Compare static policy, policy plus awareness, and bounded trust.
- Promote limited trust influence only if predefined security and usability thresholds
  pass; otherwise retain shadow mode.
- Add a provider-neutral supervisor capability only after deterministic controls exist;
  it remains optional and disableable at runtime, while its tracked implementation and
  fail-safe acceptance criteria are required for Phase 2 completion.
- Keep supervisor output advisory, redacted, schema-validated, and fail-safe.

Milestone 5 feature implementation is complete. The production-candidate release gate
remains open while client-facing mediation, independent deployment controls, signed
artifacts, SBOM, and operational recovery evidence are unavailable.

### Milestone 6 - Operational integration and local release evidence

Features: `P2-F015` through `P2-F020`.

- Wire authenticated registry-backed discovery into the client-facing runtime.
- Compose `tools/call` through route resolution, protocol admission, canonical policy,
  PostgreSQL trajectory state, exact approval, one-time forwarding, and governed results.
- Replace disposable runtime providers with approved identity, credential, route,
  policy, and category-resolver adapters.
- Implement a runnable authenticated browser approval and audit interface connected to
  live protected-runtime and PostgreSQL state. The completed `P2-F010` interface model
  and report wireframes are not substitutes for this application.
- Validate two pinned open-source MCP implementations with reproducible local-only
  interoperability evidence.
- Produce non-production artifact, SBOM, deployment-isolation, recovery, upgrade, and
  rollback evidence without signing, publishing, or enabling protected forwarding.

Exit condition: the client-facing request/result path is exercised fail-safely, local
release evidence passes, all features are complete, coverage remains `UNPROTECTED`, and
protected forwarding remains disabled. Production approval is a separate deferred gate.

## 4. Implementation order

1. Contracts and schema-version rejection.
2. Client authentication and session namespaces.
3. Server registry, discovery integrity, schema hashes, and collision-safe routes.
4. Protocol guardrails and failure behavior.
5. Canonical normalizers and immutable policy.
6. PostgreSQL migrations and transactional decision records.
7. Human approval and forwarding coordinator.
8. Result provenance, redaction, egress policy, and quarantine.
9. Audit correlation, recovery classification, coverage, and health.
10. Host-neutral approval, audit, recovery, CLI-diagnostic, and awareness models.
11. Security evaluation harness and two-host validation.
12. Trust shadow experiment and optional supervisor.
13. Authenticated client-facing discovery.
14. Client-facing call-path composition and durable orchestration.
15. Production providers.
16. Functional authenticated approval and audit web interface with browser and
    end-to-end decision tests.
17. Named-host evaluation, deployment assurance, and release.

## 5. Evaluation baselines

1. Native MCP client/server behavior without the gateway.
2. Gateway with immutable policy and no awareness feedback.
3. Gateway with immutable policy and structured awareness.
4. Gateway with trust calculated in shadow mode.
5. Gateway with bounded trust influence, only if promotion criteria pass.

The comparison must distinguish task failure from policy violation. A task that succeeds
through an unsafe intermediate call is a security failure.

## 6. Required metrics

- dangerous-action prevention rate;
- attack success and risk ratio;
- completion under policy;
- false allow, false warning, and false denial rates;
- deterministic and end-to-end latency distributions;
- cost and downstream call amplification;
- approval frequency, response time, fatigue, and approval error;
- safe re-plan and repeated-risky-attempt rates;
- replay, quota, recursion, schema-drift, and result-quarantine events;
- percentage of scoped paths with verified `ENFORCED` coverage;
- trust-grinding success and identity/route/schema anomaly response.

## 7. Release gates

### Development gate

- disposable resources only;
- no protected forwarding;
- build, lint, typecheck, unit, integration, and feature validation pass.

### Enforced test gate

- authenticated client and downstream identities;
- request and result mediation;
- PostgreSQL persistence;
- fail-safe dependency behavior;
- exact approval and replay/concurrency tests;
- authenticated browser approval and denial through live PostgreSQL state, including
  expiry, reload, duplicate-click, multi-tab, CSRF/origin, and cross-user tests;
- verified isolation and no direct credential access.

### Local non-production completion gate — PASS

- all 21 tracked features complete under the approved local scope;
- two pinned open-source MCP implementations pass local-only interoperability checks;
- hardened disposable container verification passes without network or published ports;
- SBOM, manifest, image identity, reproducible build, and dependency audit verify;
- artifacts remain unsigned and unpublished, coverage remains `UNPROTECTED`, and
  protected forwarding remains disabled.

### Production-candidate gate — DEFERRED / BLOCKED

- independent security review;
- two-host validation;
- adaptive and repeated-trial evaluation;
- exclusive-mediation deployment evidence;
- documented recovery and incident response;
- signed artifacts, SBOM, dependency analysis, and upgrade/rollback procedure;
- no unresolved critical acceptance criterion;
- functional `P2-F020` human approval and audit UI completed; generated wireframes do
  not satisfy this gate.

## 8. Research position

The literature strongly supports external enforcement, least privilege, sandboxing,
human review, monitoring, and layered defenses. It does not yet establish persistent
behavior-derived trust as a safe authorization mechanism. The project will present
dynamic trust as an experimentally evaluated optimization, never as the security root.
