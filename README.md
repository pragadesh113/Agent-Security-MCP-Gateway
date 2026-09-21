# Agent Security MCP Gateway

A fail-closed reference monitor for Model Context Protocol traffic. The gateway is
designed to authenticate MCP clients, resolve canonical tool effects, enforce immutable
policy, obtain exact single-use human approval for high-risk actions, govern downstream
results, and retain a linked PostgreSQL audit trajectory.

## Current status

Phase 2 is complete for the approved local non-production scope. The implemented protocol, policy, persistence,
approval, forwarding, result-governance, identity, administration, Vault, evaluation,
and coverage boundaries have automated evidence, but production coverage remains
`UNPROTECTED`.

The runtime must not be treated as a production security boundary yet:

- independent deployment controls have not established exclusive mediation;
- two pinned open-source MCP implementations pass local interoperability checks;
- independently operated hosts and external security review are deferred production
  assurance and are not claimed by this local deliverable;
- the authenticated human approval and audit web boundary and its disposable browser
  race/reconnect/expiry/revocation/failure matrix are complete, but deployment evidence
  remains;
- protected forwarding remains disabled unless exact disposable test evidence is used.

The authoritative status and evidence are maintained in
[`docs/progress.md`](docs/progress.md) and
[`docs/featurelist.json`](docs/featurelist.json).

## Security model

The gateway applies these core invariants:

- deterministic policy is enforced outside the model;
- `DENY > REQUIRE_APPROVAL > SANDBOX > ALLOW_WITH_CONSTRAINTS > ALLOW`;
- Tier 3 actions require one current, exact, single-use human approval or are denied;
- unknown, ambiguous, unsupported, or schema-drifted actions fail safely;
- discovery filtering never replaces call-time authorization;
- downstream descriptions, results, errors, and resource content remain untrusted;
- credentials stay gateway-held, audience-bound, route-scoped, and non-exportable;
- non-`ENFORCED` coverage blocks protected mutations;
- native shell, filesystem, browser, and direct network access are outside the MCP
  boundary and must be blocked independently.

See the [technical specification](docs/technical-specification.md) for the complete
architecture and threat model.

## Repository layout

```text
src/          TypeScript protocol, policy, identity, persistence, and evaluation code
test/         Unit, integration, adversarial, and disposable workflow tests
migrations/   Forward-only PostgreSQL migrations
scripts/      Validation, gateway, dashboard, Vault, and release-evidence tooling
docs/         Authoritative specification, plan, research, progress, and operations
infra/        Disposable local PostgreSQL simulation
dashboard/    Informational local project-status dashboard
approval-ui/  Authenticated exact approval and audit browser interface
paper/        Research manuscript source
```

The closed `phase-1/` archive, dependencies, generated builds, local evidence,
credentials, and scratch output are excluded from Git.

## Requirements

- Node.js 24 or later
- npm
- PostgreSQL for runtime persistence and integration workflows
- Docker Desktop for the optional hardened non-production release workflow
- HashiCorp Vault only for the disposable concrete-provider verification workflow

## Install and validate

```powershell
npm ci
npm run build
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run test:browser
npm run validate:features
```

These seven commands form the validation baseline for browser UI changes; the six
non-browser root commands remain mandatory for every task.

## Local non-production workflows

Run the intentionally non-production gateway and its real MCP lifecycle smoke test:

```powershell
npm run gateway:serve
npm run gateway:smoke
```

Run two pinned open-source MCP servers with sanitized environments and disposable
harmless/unknown-tool workflows:

```powershell
npm run mcp-servers:verify:disposable
```

This verifies local interoperability with the MCP Everything reference server and
Microsoft Playwright MCP. The generated artifact is explicitly
`LOCAL_INTEROPERABILITY_ONLY`; locally launching open-source software does not make
the servers independently operated evidence for `P2-F018`.

Run the informational status dashboard:

```powershell
npm run dashboard:build
npm run dashboard:serve
```

The protected approval UI has a separate mutual-TLS entrypoint and no fixture
authentication fallback. Startup fails unless a trusted protected-runtime dependency
module is supplied; that module provides the approved credential lease and exact
downstream forwarder while PostgreSQL reloads session and call authority:

```powershell
npm run approval:serve:protected
```

It requires `DATABASE_URL`, `APPROVAL_UI_ORIGIN`, the TLS certificate/key and client
CA file variables, a configured `APPROVAL_UI_HUMAN_ID` and positive identity revision,
`APPROVAL_UI_RUNTIME_KEY_ID`, a base64-encoded 32-byte
`APPROVAL_UI_RUNTIME_KEY_BASE64`, and an absolute trusted local
`APPROVAL_UI_RUNTIME_MODULE`. The module must export
`createProtectedApprovalRuntimeDependenciesV1`, returning `issueCredentialLease` and
an exact `forwarder`. The client-certificate credential ID and authorized policy
scopes must be registered in PostgreSQL before a browser session can be created.
The entrypoint uses a finite two-minute execution timeout by default and durably
recovers stale dispatches. Operators may set
`APPROVAL_UI_DISPATCH_RECOVERY_INTERVAL_MS` (at most 60000) and
`APPROVAL_UI_DISPATCH_CLAIM_TIMEOUT_MS` (at most 360000); the claim timeout must exceed
the configured execution timeout. Recovery revokes an approved call that never reached
atomic consumption and records an already-consumed call without an outcome as
`UNKNOWN`; it never retries an ambiguous downstream effect.

Prepare and verify the disposable non-production artifact set:

```powershell
npm run release:prepare:non-production
npm run evidence:capture
```

Nothing in these workflows authorizes production deployment or changes coverage from
`UNPROTECTED`.

## Documentation

- [Startup and operation guide](startup.md)
- [Beginner-friendly project handbook](handbook.md)
- [Technical specification](docs/technical-specification.md)
- [Feature tracker](docs/featurelist.json)
- [Progress and handoff](docs/progress.md)
- [Delivery plan](docs/plan.md)
- [Research synthesis](docs/research.md)
- [Release-gate audit](docs/release-gate-audit.md)
- [Recovery and rollback](docs/operations/recovery-and-rollback.md)
- [Independent review packet](docs/security-review-packet.md)
- [Agent instructions](docs/AGENTS.md)

## License

Apache-2.0 is the target license. A root license file has not yet been added, so do not
assume the repository is licensed for redistribution beyond the permissions explicitly
granted by its owner.
