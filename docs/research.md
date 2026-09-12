# Phase 2 MCP Gateway Research Synthesis

**Date:** 2026-08-29  
**Purpose:** Convert the repository research papers into requirements for the active
MCP security gateway.

## 1. Sources

1. [Security of AI Agents](./Security%20of%20AI%20Agents.pdf), Yifeng He, Ethan Wang,
   Yuyang Rong, Zifei Cheng, and Hao Chen, 2024.
2. [Agentic AI Security: Threats, Defenses, Evaluation, and Open Challenges](./Agentic_AI_Security_Threats_Defenses_Evaluation_and_Open_Challenges.pdf),
   Anshuman Chhabra, Shrestha Datta, Shahriar Kabir Nahin, and Prasant Mohapatra,
   IEEE Access, 2026.

## 2. Security of AI Agents

### Core argument

An AI agent is a computer system capable of real effects, not merely a language model
that returns text. Once an LLM invokes shells, files, APIs, databases, or remote
services, model alignment is insufficient. Security must be enforced around the agent
program and its tools.

The paper analyzes confidentiality, integrity, and availability risks:

- weak session separation can mix user data and actions;
- interaction histories can leak private data or pollute later model behavior;
- tool-enabled agents can read confidential files, alter important data, consume local
  resources, or attack remote services;
- malicious tool documentation and environmental feedback can redirect actions;
- multi-step planning is effectful because intermediate steps can change the world
  before the agent selects a final answer.

### Evidence

The authors created 95 malicious Bash-agent tasks. The model generated attacking
instructions for 90 tasks, and 76 attacks executed successfully in the unrestricted
environment, an 80 percent overall compromise rate. Their constrained Docker variant
blocked the tested attacks.

This supports sandboxing and capability confinement, but it does not prove that a
container stops every agent attack. The experiment used a limited task set, older
models, Bash-oriented tools, and a simplified environment.

### Phase 2 implications

- Enforce decisions outside the model.
- Evaluate every intermediate call before it creates a side effect.
- Isolate user, agent, client, and downstream session state.
- Limit filesystem, process, network, CPU, memory, storage, and request-rate access.
- Minimize or transform sensitive values before they reach models, logs, supervisors,
  or unnecessary downstream services.
- Keep model and supervisor judgments advisory.
- Treat dynamic trust as unproven; the paper supports hard capability boundaries, not
  reputation-based permission expansion.

## 3. Agentic AI Security Survey

### Threat taxonomy

The survey covers:

- direct and indirect prompt injection;
- unintentional, multimodal, obfuscated, split-payload, and propagating injection;
- autonomous exploitation and tool abuse;
- persistent memory poisoning;
- malicious agents, impersonation, collusion, and recursive delegation;
- interface and state-management failures;
- governance problems caused by excessive autonomy and weak human oversight.

### MCP-specific threats

The threats most relevant to the gateway are:

- request flooding, infinite loops, recursive calls, and replay;
- leaked tokens, insecure proxies, credential compromise, and impersonation;
- malicious or compromised MCP servers;
- poisoned discovery metadata, tool descriptions, schemas, files, databases,
  retrieval sources, results, and errors;
- route and capability manipulation;
- response tampering, contextual-data leakage, and side channels;
- cascading compromise when downstream data is treated as trusted instruction.

The gateway must therefore govern both directions. Protecting outbound tool calls while
returning unvalidated downstream content leaves a major prompt-injection and data-flow
gap.

### Defense findings

The survey groups defenses into prompt/model techniques, human verification, runtime
policy, tool filtering, sandboxing, monitoring, rate limiting, audit, recovery, and
organizational governance. Its comparison shows that no single reviewed approach
provides every control.

Prompt delimiters, fine-tuning, LLM guards, and output filters can reduce risk but can
fail against adaptive attacks. Human approval is useful for sensitive effects but is
vulnerable to fatigue, social engineering, and misleading traces. Sandboxing limits
impact but may contain implementation flaws and does not replace authorization.

The appropriate layered pipeline is:

```text
authenticated identity
  -> integrity-checked discovery and route selection
  -> request validation and canonicalization
  -> immutable policy and risk classification
  -> exact human approval when required
  -> sandbox and capability enforcement
  -> one downstream request
  -> result provenance, validation, redaction, and egress policy
  -> outcome, audit, coverage, and trust evidence
```

### Evaluation findings

Final task success is not a sufficient safety metric. Evaluation must inspect the
entire trajectory, including unsafe intermediate calls, denied retries, near misses,
and side effects.

Required practices include:

- repeated-trial distributions rather than one demonstration;
- task completion under policy and a separate breach/risk ratio;
- false allow, false warning/denial, latency, cost, and approval burden;
- seeded disposable environments with documented fidelity;
- published attack and defense configurations;
- adaptive attackers that know the defense;
- automated-judge validation against humans;
- sensitivity across models, hosts, tool schemas, trace formats, random seeds, and task
  paraphrases.

Relevant benchmark families include AgentDojo and WASP for indirect prompt injection,
AgentHarm for harmful tool sequences, OS-Harm for desktop side effects, ToolEmu for
simulated tool risk, and MCP-oriented benchmark suites catalogued by the survey.

## 4. What the Literature Supports

The papers strongly support:

- an external reference monitor at the tool boundary;
- immutable deterministic policy before model judgment;
- least privilege, sandboxing, and independent network/IAM controls;
- authenticated and isolated sessions;
- human confirmation for high-risk effects;
- replay protection, rate limiting, monitoring, and complete audit linkage;
- disposable and reproducible security evaluation;
- treating prompt injection and malicious tool content as expected threats;
- layered defenses rather than a single classifier.

## 5. What Remains a Project Hypothesis

The papers do not establish that persistent behavior-derived trust can safely expand
permissions. They also do not validate the project's future score formula, evidence
weights, half-life, trust bands, novelty factor, or review rate.

Dynamic trust must therefore:

- start in shadow mode;
- remain unable to change Tier 3, immutable denial, unknown-action, environment, or
  degraded-coverage outcomes;
- use only verified eligible outcomes as positive evidence;
- freeze on audit gaps, identity changes, route/schema drift, missing outcomes, or
  anomalies;
- pass predefined repeated-trial promotion thresholds before influencing policy.

## 6. Required Gateway Upgrades

### 6.1 Bidirectional mediation

Every downstream result should carry authenticated server and route identity, schema
digest, request/session/call-chain linkage, content provenance, data classification,
redaction evidence, and untrusted-content markers.

Before returning content, enforce schema validity, size limits, secret detection,
data-egress policy, instruction/content separation, and deny/redact/quarantine actions.

### 6.2 Discovery and route integrity

- Use an administrator-controlled server registry.
- Namespace tools with stable server and tool identities.
- Record protocol version, capability set, schema, schema hash, credential audience,
  route ownership, environment, and policy scope.
- Quarantine unexpected schema or capability changes.
- Reject duplicate, ambiguous, shadowed, or unauthorized routes.
- Reauthorize every call even if discovery filtered the visible tools.

### 6.3 Protocol resilience

- Authenticate clients and servers outside model-controlled data.
- Require timestamps, nonces, request IDs, bounded skew, and replay caches.
- Apply quotas by user, agent, client, session, server, tool, route, destination, and
  action family.
- Bound call depth, delegation depth, fan-out, payload/result size, concurrency,
  redirects, retries, and execution time.
- Detect cyclic delegation and recursive loops.
- Propagate cancellation and safely terminate abandoned work.
- Use circuit breakers and block protected mutations during dependency failure.

### 6.4 Canonical authorization

Authorize the resolved resource, effect, environment, route, and data flow. Add tests
for equivalent effects across servers, aliases, Windows/Unix paths, links, junctions,
UNC paths, case changes, encodings, nested calls, split payloads, retries, concurrency,
and downstream content that attempts to induce a previously denied effect.

### 6.5 Session and capability isolation

- Namespace downstream state, connections, caches, approvals, quotas, results, audit,
  and trust by authenticated session.
- Keep credentials gateway-held, audience-bound, route-scoped, and short-lived.
- Block direct agent access through independent network, IAM, sandbox, OS, and
  downstream authorization.
- Continuously verify exclusive mediation and degrade coverage on bypass.

### 6.6 Human approval and recovery

Generate approval summaries only from validated canonical data. Show requester, server,
tool, route, target, data flow, provenance, untrusted influence, unresolved scope,
reversibility, blast radius, related attempts, recovery class, coverage, and missing
guarantees.

Tier 3 has no bulk, persistent, or always-allow option. Measure fatigue and approval
errors. Record recovery as verified compensating action, tested backup, partial,
irreversible, or unknown. A compensating action is separately evaluated.

### 6.7 Security evaluation

Build four seeded suites:

1. **Protocol:** replay, flooding, recursion, cancellation, schema drift, route
   collision, impersonation, credential audience, and dependency failure.
2. **Policy invariance:** equivalent tools, servers, paths, encodings, transports,
   retries, concurrency, split payloads, and time-of-check/time-of-use.
3. **Prompt and content:** direct, indirect, obfuscated, propagated, malicious
   tool-description, and malicious tool-result injection.
4. **Human and trust:** fatigue, misleading context, safe re-planning, grinding,
   identity changes, audit gaps, delayed harm, and anomaly freezes.

Report prevention, attack success, completion under policy, risk ratio, false allow,
false denial/warning, latency, cost, approval frequency/error, safe re-planning,
repeated risky attempts, and verified coverage.

## 7. Recommended Sequence

1. Versioned contracts and safe MCP negotiation.
2. Authenticated identities and isolated sessions.
3. Integrity-checked discovery and collision-safe routing.
4. Replay, quota, recursion, cancellation, timeout, and circuit-breaker controls.
5. Canonical normalization and immutable policy.
6. PostgreSQL decisions, approvals, forwarding state, results, and audit.
7. Exact single-use approval and one-time forwarding.
8. Downstream result provenance, redaction, egress policy, and quarantine.
9. Exclusive-mediation controls, truthful coverage, UI, awareness, and recovery.
10. Repeated-trial evaluation with two MCP-compliant hosts.
11. Dynamic-trust shadow experiment and optional advisory supervisor.

## 8. Current Related-Work and Novelty Check

The initial synthesis above is based on the two repository papers. A current novelty
check also found overlapping MCP-specific preprints:

- [SMCP](https://arxiv.org/abs/2602.01129) proposes identity, mutual authentication,
  policy enforcement, security-context propagation, and audit logging.
- [Breaking the Protocol / MCPSec](https://arxiv.org/abs/2601.17549) studies capability
  attestation, message authentication, and MCP-specific attack measurement.
- [MCP-Guard](https://arxiv.org/abs/2508.10991) evaluates layered malicious-content
  detection and provides MCP-AttackBench.
- [MCP Pitfall Lab](https://arxiv.org/abs/2604.21477) uses trace-grounded tests for tool
  poisoning, puppet servers, and cross-tool or multimodal data-flow failures.

These works make a generic "secure MCP gateway" claim insufficiently distinctive.
Phase 2 will instead test a narrower systems-security claim: canonical authorization
should produce the same decision for equivalent effects across tools, servers, routes,
paths, encodings, retries, concurrency, and transports. The evaluation must compare
native MCP, deterministic gateway baselines, and representative existing defenses,
then measure prevention, task completion, false decisions, approval load, and latency.

## 9. Consolidated Final Direction

Build an authenticated, fail-closed reference monitor for MCP traffic only. Mediate
discovery and both sides of every supported call; resolve canonical resource, effect,
environment, route, and data flow; apply immutable most-restrictive policy; require one
exact approval for Tier 3; forward at most one revalidated request; govern the result;
and record the complete trajectory.

Do not claim that the gateway controls native local actions. A resource qualifies as
protected only when gateway-held credentials and independent network, IAM, sandbox,
operating-system, or downstream controls prevent direct access. Detectable bypasses
are a measured result and must degrade coverage.

The initial publishable hypothesis is representation-invariant, bidirectional MCP
authorization. Dynamic behavioral trust remains a separate shadow-mode experiment and
may influence only predefined lower-risk outcomes after an empirical promotion gate.
It never grants global or full access and never overrides immutable denial, Tier 3
approval, ambiguity, schema drift, environment escalation, or degraded coverage.

## 10. Conclusion

The literature supports the gateway's foundation: external deterministic enforcement,
least privilege, isolation, exact approval, monitoring, audit, and layered controls.
The most important design expansion is bidirectional mediation: discovery, downstream
identity, schemas, tool descriptions, results, and protocol state are security inputs,
not trusted infrastructure.

Dynamic trust is the most novel and least validated element. The gateway must first be
a conventional fail-closed reference monitor. Trust can be evaluated later as a bounded
optimization and must never become the root of authorization.
