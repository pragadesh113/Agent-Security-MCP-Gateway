# Agent Security MCP Gateway #


This repository contains the active Phase 2 implementation of a production-oriented
security gateway for Model Context Protocol traffic.

The gateway will authenticate MCP clients, integrity-check discovery and routing,
canonicalize tool effects, enforce immutable policy, obtain exact single-use human
approval for Tier 3 actions, forward one authorized downstream request, validate the
result, and create a linked audit trail.

The current implementation is a non-forwarding protocol foundation with a
loopback-only Streamable HTTP lifecycle adapter. The adapter requires a trusted client
authenticator before MCP JSON parsing and binds that identity to an opaque transport
session. Disposable test infrastructure now isolates six session-state compartments,
issues short-lived audience/route/session-bound credential leases without returning
secret material, and quarantines active state on identity rotation. It accepts
initialization and ping and conditionally exposes registry-backed `tools/list`, while
forwarding no protected calls and reporting `UNPROTECTED`. Discovery uses the freshly
authenticated session, a server-configured scope, bounded output, and gateway-owned
untrusted-content markers. A disposable administrator-controlled downstream registry
also authenticates discovery observations, computes capability/tool/schema
integrity evidence, latches drift quarantine, prevents route collisions, and repeats
authorization at call resolution. A disposable protocol guard adds session-scoped
replay protection, nine-dimensional rate/concurrency quotas, operation bounds, cycle
detection, aborting deadlines/cancellation, and dependency circuits. Protected
mutual-TLS runtime identity and durable rotation/revocation are implemented, while a
concrete external secret manager remains unselected. A host-neutral canonicalizer now
binds authenticated session and current route evidence to trusted resolver output,
normalizes path/URI representations, and keeps failed or unsupported analysis
unresolved. Deterministic policy classifies risk, applies most-restrictive rules,
protects Tier 3 approval, and denies non-enforced mutations. The resolver and policy
state remain disposable. A disposable approval service now binds one authenticated
human decision to the exact action and revalidates
identity, route, schema, and policy immediately before one process-local atomic
consumption. PostgreSQL-backed trajectory persistence now applies forward-only
migrations and transactionally links decisions, approval consumption, forwarding,
governed results, outcomes, shadow trust evidence, and hash-chained audit across
connections and restart. Result mediation exists in a separate disposable exact-
forwarding flow: the vault injects
a route/audience/profile/origin-bound credential internally, redirects are refused,
and authenticated results are schema- and size-checked, redacted, egress-governed,
provenance-bound, and marked as untrusted data before release. Protected client-facing
forwarding, production deployment hardening, and exclusive credential mediation remain
incomplete.

The local status dashboard is operational and informational. The completed `P2-F010`
trustworthy-interface layer supplies canonical approval, awareness, audit, recovery,
and fatigue data. Completed `P2-F020` renders that data in a functional authenticated
web interface with live pending approvals, exact `Approve once` and `Deny` actions,
PostgreSQL-backed state, governed result/outcome/audit display, and browser plus
end-to-end security tests. Its evidence is disposable and does not establish protected
deployment coverage.

A provider-neutral supervisor contract now redacts and bounds semantic context before
any external submission, validates digest-bound advisory output, and records an
append-only audit. It is disabled by default and can be disabled by policy scope;
timeouts, invalid or low-confidence output, provider failure, and audit failure remain
deterministic fail-safe paths. This research component does not authorize protected
forwarding, and overall coverage remains `UNPROTECTED`.

The active research direction is deliberately MCP-only: build an effect-based,
bidirectional reference monitor and evaluate whether equivalent effects receive
equivalent authorization across tools and servers. Native local actions are outside
the gateway; if they can reproduce a protected effect, coverage must degrade. Dynamic
trust remains a later shadow-mode experiment and never grants unrestricted access.

## Documentation

- [`handbook.md`](../handbook.md) - beginner-friendly explanation, setup, architecture, security model, workflows, status, and glossary
- [`project-guide.md`](project-guide.md) - complete self-study guide with architecture, operation, evidence, research plan, code-reading route, and comprehension questions
- [`project-guide.html`](project-guide.html) - navigable reading edition with chapter navigation, diagrams, and print layout
- `docs/technical-specification.md` - authoritative architecture and security requirements
- `docs/featurelist.json` - machine-readable Phase 2 feature tracking
- `docs/progress.md` - current delivery status and validation evidence
- `docs/plan.md` - implementation sequence and research evaluation roadmap
- `docs/research.md` - research-paper synthesis and design implications
- `docs/release-gate-audit.md` - evidence matrix and blockers for production-candidate release
- `dashboard/index.html` - local security and release-gate status dashboard
- `docs/operations/recovery-and-rollback.md` - disposable recovery and rollback runbook
- `docs/security-review-packet.md` - independent review scope, evidence, and disposition template
- `docs/AGENTS.md` - authoritative agent operating and validation instructions

## Commands

```powershell
npm install
npm run build
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run validate:features
```

No production resource may be connected until exclusive mediation, gateway-held
credentials, independent bypass controls, and the corresponding acceptance tests are
in place.
