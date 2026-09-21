# Phase 2 Release-Gate Audit

**Status:** Local non-production release evidence complete; not production-approved
**Last audited:** 2026-09-20
**Coverage:** `UNPROTECTED`

The one-command non-production preparation automation passes. Docker Desktop's Linux
engine was restored without factory reset by preserving and recreating only stale
runtime-socket directories and disabling Docker AI/Model Runner for this current
Windows AF_UNIX socket bug. The complete workflow rebuilt and inspected the hardened
image, ran the disposable smoke, generated and verified current SBOM/manifest evidence,
verified reproducibility, and completed the dependency audit.

This document records the difference between completed Phase 2 implementation work
and the evidence still required before a production-candidate release. Passing
disposable tests does not establish production protection.

The local dashboard in `dashboard/index.html` presents this same distinction. For a
live view that rereads the authoritative docs on every request, run
`npm run dashboard:serve` and open `http://127.0.0.1:4173/`. The generated
`dashboard/status.json` remains available for static previews. Both views are
informational and are not authorization or forwarding surfaces.

The dashboard must not be confused with the human approval application. The separate
`approval-ui/` route loads live canonical PostgreSQL state and submits exact
`Approve once` or `Deny` decisions through the protected-runtime boundary. `P2-F020`
has disposable browser evidence; neither browser application establishes production
deployment isolation.

The live view also exposes a guard-decision flow and background activity feed. These
events describe dashboard/lifecycle and coverage-guard work only; they are not a
claim that operational MCP calls are currently accepted or forwarded.
When the non-production gateway is running, the dashboard also reads its sanitized
loopback `/status` telemetry. This provides real process request counts and outcomes
without exposing MCP arguments, results, credentials, or approval material.

For an end-to-end disposable gateway process, run `npm run gateway:serve`. It binds
only to loopback, accepts the fixture header `Authorization: Bearer local-fixture`,
supports lifecycle traffic, and intentionally rejects operational forwarding. This
is a development harness, not a production deployment or identity boundary.
With that process running, `npm run gateway:smoke` drives invalid authentication,
initialize, initialized notification, and `tools/call`, then checks `/status` for
`UNPROTECTED`, disabled forwarding, and zero downstream calls.

`Dockerfile.non-production` packages the same harness in a multi-stage image. It is
explicitly labeled unreleased, uses fixture authentication, binds to container
loopback, publishes no host port, and must not be pushed to a registry. A container
build or in-container smoke test is local development evidence only.

`compose.non-production.yml` provides the matching disposable smoke composition. It
uses `network_mode: none`, publishes no port, and is intended only for an in-container
lifecycle check.

`npm run deploy:verify:non-production` automates that deployment check with a unique
disposable container. It verifies the effective Docker configuration (`network=none`,
no port bindings, read-only root filesystem, all capabilities dropped,
`no-new-privileges`, and a non-root user), runs the authentication/lifecycle/tool-call
smoke inside the container, checks `UNPROTECTED`/zero-forwarding telemetry, and removes
the exact container on success or failure. `npm run release:prepare:non-production`
runs the complete local validation, packaging, deployment, SBOM, manifest,
reproducibility, and high-severity dependency-audit ladder in one command. Neither
command signs, publishes, or production-approves an artifact.

## Current evidence

| Area | Current state | Evidence or limitation |
|---|---|---|
| Docker packaging | Local non-production only | `Dockerfile.non-production` and `compose.non-production.yml` build a fixture-only image with no host port and no network egress; nothing is published. |
| Gateway service | Local discovery-only | The client-facing MCP adapter accepts lifecycle traffic and authenticated registry-backed `tools/list`, but forwards no protected call. `tools/call` remains denied under `UNPROTECTED` coverage with zero downstream requests. |
| Production identity | Protected profile implemented | Mutual-TLS peer identity and durable PostgreSQL rotation/revocation exist; full production deployment evidence remains absent. |
| Credential custody | Not production-ready | The disposable vault demonstrates metadata-only leases and internal injection, but no production secret manager or gateway-held deployment credential is configured. |
| Human approval web UI | Implemented with disposable evidence | Live canonical pending approvals, exact decisions, PostgreSQL transitions, governed outcome/result disposition, audit display, reload, races, expiry, revocation, and failure paths pass in Chromium; production deployment isolation remains absent. |
| Independent bypass controls | Not configured | No production network, IAM, sandbox, OS, or downstream control blocks direct access around the gateway. |
| Security review | Deferred production assurance | No independent review report is present; the approved local delivery does not claim one. |
| Two-server interoperability | Local evidence complete | Pinned MCP Everything and Microsoft Playwright MCP servers pass local harmless/unknown-tool interoperability smoke. Both are locally operated and the artifact explicitly records that limitation. |
| Adaptive/repeated evaluation | Research evidence only | Seeded/adversarial suites exist, but no production deployment evaluation package or independent repeated-trial report is present. |
| Artifacts and SBOM | Verified unsigned local evidence | The 277-component CycloneDX SBOM, 138-file release manifest plus image identity, 264-file reproducible build, and zero-vulnerability dependency audit pass locally; signing and publication remain deferred. |
| Recovery and rollback | Local exercise complete | The one-command workflow exercised clean rebuild, hardened disposable deployment, lifecycle smoke, exact-container cleanup, manifest verification, and rollback inputs; production owners and objectives remain deferred. |

## Gate disposition

### Development gate — PASS

- Disposable resources only.
- No protected forwarding.
- `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` pass.

### Enforced test gate — PARTIAL / TEST INFRASTRUCTURE ONLY

The repository contains disposable authenticated identities, policy and approval
tests, PostgreSQL persistence tests, result mediation tests, fail-safe behavior, and a
functional protected-runtime browser workflow. These remain disposable evidence and
do not establish an independently isolated production deployment.

### Production-candidate gate — BLOCKED

The following evidence is still required:

1. Independent security review with findings resolved or accepted by an authorized owner.
2. Two-host validation using independently operated MCP-compliant hosts.
3. Adaptive, repeated-trial evaluation with retained metrics and baselines.
4. Deployment evidence that gateway credentials and network/IAM/sandbox/OS controls
   prevent direct or alternate-path access.
5. Operational recovery and incident-response runbooks exercised against disposable
   resources, with ownership and recovery objectives recorded.
6. Reproducible signed artifacts, SBOM, dependency analysis, upgrade procedure, and
   tested rollback procedure.

These production-candidate items are deferred by the user-approved 2026-09-20 local
completion scope. Their absence keeps production approval blocked but no longer blocks
completion of the explicitly non-production Phase 2 deliverable.

## Safe preparation sequence

The next implementation work may add local packaging and verification artifacts,
container definitions, and disposable deployment tests. It must remain non-forwarding
and use fixture credentials until the production architecture and deployment controls
receive explicit approval. Production deployment, publishing, credential acquisition,
and external security sign-off are separate approval-gated actions.

Before any production-candidate claim, retain:

- exact source revision and reproducible build output;
- repeat-build verification (`npm run build:verify-reproducible`);
- package-boundary verification (`npm run verify:package-boundary`);
- local CycloneDX SBOM generated from the lockfile (`npm run sbom:generate`);
- image digest and signature verification record, if containerized;
- SBOM and dependency-vulnerability report;
- two-host and bypass-test results;
- recovery/rollback exercise logs; and
- an independent security review and disposition of critical findings.

The local preparation commands also generate an unsigned SBOM and deterministic
`artifacts/release-manifest.json` with source/config/SBOM hashes and the local Docker
image ID. This is reproducibility evidence only; `signed`, `published`, and
`productionApproved` remain false.
Run `npm run release:verify` to recompute those hashes and compare the recorded local
image ID before a disposable smoke test or rollback exercise.
Manifest verification requires the exact source/config/automation input set and a
non-null local image ID. Evidence capture verifies that manifest before recording it.
With both local processes running, `npm run evidence:capture` stores a sanitized
snapshot of gateway telemetry, dashboard gates, and the release manifest. It refuses
to write evidence unless the gateway is still `UNPROTECTED`, non-forwarding, and has
zero downstream calls.
The independent review packet is `docs/security-review-packet.md`; its disposition
remains `NOT PERFORMED` until an independent reviewer supplies findings and an
authorized owner records the outcome.
