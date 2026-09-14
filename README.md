# Agent Security MCP Gateway

A fail-closed reference monitor for Model Context Protocol traffic. The gateway is
designed to authenticate MCP clients, resolve canonical tool effects, enforce immutable
policy, obtain exact single-use human approval for high-risk actions, govern downstream
results, and retain a linked PostgreSQL audit trajectory.

## Current status

Phase 2 is under active development. The implemented protocol, policy, persistence,
approval, forwarding, result-governance, identity, administration, Vault, evaluation,
and coverage boundaries have automated evidence, but production coverage remains
`UNPROTECTED`.

The runtime must not be treated as a production security boundary yet:

- independent deployment controls have not established exclusive mediation;
- named-host operational trials and independent security review are still required;
- the authenticated human approval and audit web boundary and UI assets are present,
  but protected runtime wiring and end-to-end browser evidence are still required;
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
npm run validate:features
```

These six commands form the mandatory repository validation baseline.

## Local non-production workflows

Run the intentionally non-production gateway and its real MCP lifecycle smoke test:

```powershell
npm run gateway:serve
npm run gateway:smoke
```

Run the informational status dashboard:

```powershell
npm run dashboard:build
npm run dashboard:serve
```

Prepare and verify the disposable non-production artifact set:

```powershell
npm run release:prepare:non-production
npm run evidence:capture
```

Nothing in these workflows authorizes production deployment or changes coverage from
`UNPROTECTED`.

## Documentation

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
