# Agent Security MCP Gateway: Startup Guide

This guide explains how to install, start, inspect, test, and stop the Phase 2 project
on Windows. Follow the **Quick start** first. The protected approval interface is an
advanced workflow and is not required to explore the local project.

## 1. Know what this local project does

The default local gateway is a safe demonstration and development harness:

- it listens only on the local computer;
- it uses the disposable credential `Bearer local-fixture`;
- it supports MCP initialization and tool discovery;
- it deliberately blocks protected forwarding;
- its coverage is `UNPROTECTED`;
- it must not use production credentials, data, databases, or services.

`UNPROTECTED` is expected. It means the local project does not claim that it controls
native shell, browser, filesystem, network, or other paths around the MCP gateway.

## 2. Prerequisites

Install or confirm:

1. Windows 10 or Windows 11.
2. Node.js 24 or a compatible current Node.js LTS release.
3. npm, which is included with Node.js.
4. Git, if the repository is obtained from source control.
5. Docker Desktop with the Linux engine, only for container and release verification.

From PowerShell, check the main tools:

```powershell
node --version
npm --version
git --version
docker version
```

Docker is optional for the ordinary gateway and dashboard. It is required for
`npm run deploy:verify:non-production` and
`npm run release:prepare:non-production`.

## 3. Open the repository

Open PowerShell and change to the repository directory:

```powershell
cd <path-to-agent-security>
```

For the current workstation, that path is:

```powershell
cd V:\agent-security
```

All commands in this guide run from the repository root. Do not work from the closed
`phase-1` archive.

## 4. First-time installation

Install the exact locked dependencies:

```powershell
npm ci
```

Build the TypeScript project:

```powershell
npm run build
```

If both commands pass, the basic installation is ready.

## 5. Quick start

Use two PowerShell windows.

### Terminal 1: start the local gateway

```powershell
cd V:\agent-security
npm run gateway:serve
```

Expected output includes:

```text
Non-production gateway listening at http://127.0.0.1:4174/mcp
Authentication: Bearer local-fixture
protected forwarding: disabled
coverage: UNPROTECTED
```

Leave this terminal running.

### Terminal 2: start the status dashboard

```powershell
cd V:\agent-security
npm run dashboard:serve
```

Open this address in a browser:

```text
http://127.0.0.1:4173/
```

The dashboard shows feature status, validation counts, security controls, release
gates, current coverage, recent local gateway activity, and the next action.

## 6. Confirm that the gateway works

While the gateway is running, open a third PowerShell window:

```powershell
cd V:\agent-security
npm run gateway:smoke
```

The smoke workflow checks:

- rejection of invalid authentication;
- MCP initialization;
- the initialized notification;
- tool discovery;
- fail-safe rejection of `tools/call` forwarding;
- `UNPROTECTED` coverage;
- zero downstream tool calls.

You can also inspect the sanitized gateway status directly:

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:4174/status `
  -Headers @{ Authorization = "Bearer local-fixture" }
```

Inspect the live dashboard status as JSON:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:4173/api/status
```

## 7. Addresses and ports

| Component | Address | Purpose |
|---|---|---|
| Dashboard | `http://127.0.0.1:4173/` | Human-readable project and security status |
| Dashboard API | `http://127.0.0.1:4173/api/status` | Sanitized live JSON status |
| Local MCP gateway | `http://127.0.0.1:4174/mcp` | Disposable MCP lifecycle endpoint |
| Gateway status | `http://127.0.0.1:4174/status` | Authenticated local telemetry |
| Protected approval UI | `https://127.0.0.1:4175/approval/` by default | Advanced mutual-TLS approval workflow |

Ports can be changed with `DASHBOARD_PORT`, `GATEWAY_PORT`, or `APPROVAL_UI_PORT`.
Keep the development services bound to loopback.

## 8. How to work on the project

Use this simple loop after changing code:

1. Make one small, coherent change.
2. Add or update the focused tests.
3. Run the focused test file.
4. Run the mandatory repository validation.
5. Update the authoritative progress and feature evidence when behavior changes.

Run one unit test file:

```powershell
npm exec vitest run test/unit/<test-file>.test.ts
```

Run one integration test file:

```powershell
npm exec vitest run test/integration/<test-file>.test.ts
```

Run the mandatory validation baseline:

```powershell
npm run build
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run validate:features
```

For approval-browser changes, also run:

```powershell
npm run test:browser
```

Important source areas:

| Path | Contents |
|---|---|
| `src/` | Protocol, identity, policy, approval, forwarding, persistence, and evaluation code |
| `test/unit/` | Fast unit and security-rule tests |
| `test/integration/` | PostgreSQL and real component-boundary tests |
| `test/browser/` | Chromium approval-interface workflows |
| `migrations/` | Forward-only PostgreSQL migrations |
| `scripts/` | Servers, smoke tests, dashboards, and release verification |
| `approval-ui/` | Approval and audit browser assets |
| `dashboard/` | Informational local status dashboard |
| `docs/` | Authoritative specification, plan, feature tracker, and progress |

## 9. Run the open-source MCP interoperability check

This launches two pinned open-source MCP server implementations with sanitized,
disposable inputs:

```powershell
npm run mcp-servers:verify:disposable
```

It verifies MCP initialization, tool discovery, a harmless tool call, and rejection of
an unknown tool. The resulting artifact is local interoperability evidence only. It is
not independent-host or production evidence.

## 10. Build and verify the local container release

Start Docker Desktop and wait until this succeeds:

```powershell
docker version
```

Then run the complete local release workflow:

```powershell
npm run release:prepare:non-production
```

This command performs the repository validation, package-boundary check, dashboard
generation, SBOM generation, hardened Docker build and smoke, manifest generation and
verification, reproducible-build check, and dependency audit.

Nothing is published or signed. The container remains non-production and
`UNPROTECTED`.

Useful individual commands:

```powershell
npm run docker:build:non-production
npm run deploy:verify:non-production
npm run sbom:generate
npm run release:manifest
npm run release:verify
npm run build:verify-reproducible
```

## 11. Capture local evidence

First keep both the gateway and dashboard running. Ensure a current release manifest
exists, then run:

```powershell
npm run evidence:capture
```

Generated local artifacts include:

- `artifacts/local-evidence.json`;
- `artifacts/open-source-mcp-smoke.json`;
- `artifacts/release-manifest.json`;
- `artifacts/sbom.cdx.json`.

These artifacts are local evidence. Do not publish them as proof of production
protection.

## 12. Advanced protected approval UI

Most users should skip this section initially. The protected approval UI is not a
fixture-only web page. It fails closed unless all trusted dependencies exist.

Start it with:

```powershell
npm run approval:serve:protected
```

It requires all of the following:

| Variable | Required value |
|---|---|
| `DATABASE_URL` | Reachable disposable PostgreSQL connection string |
| `APPROVAL_UI_ORIGIN` | Exact HTTPS origin, normally `https://127.0.0.1:4175` |
| `APPROVAL_UI_TLS_CERT_FILE` | Server certificate file |
| `APPROVAL_UI_TLS_KEY_FILE` | Server private-key file |
| `APPROVAL_UI_CLIENT_CA_FILE` | CA used to authenticate client certificates |
| `APPROVAL_UI_HUMAN_ID` | Trusted human identifier |
| `APPROVAL_UI_HUMAN_IDENTITY_REVISION` | Positive identity revision |
| `APPROVAL_UI_RUNTIME_KEY_ID` | Runtime encryption-key identifier |
| `APPROVAL_UI_RUNTIME_KEY_BASE64` | Base64-encoded 32-byte encryption key |
| `APPROVAL_UI_RUNTIME_MODULE` | Absolute path to a trusted runtime dependency module |

The runtime module must export
`createProtectedApprovalRuntimeDependenciesV1` and supply an exact credential-lease
issuer and downstream forwarder. The human certificate identity and allowed policy
scopes must already be registered in PostgreSQL.

Never copy example secrets into a real deployment. Use disposable certificates,
keys, PostgreSQL data, and downstream services for development.

## 13. Demonstrate the project

The project is best demonstrated through MCP tools and visible security decisions. It
does not currently include a free-form chat interface, so prompts are presented as the
user intent that an MCP agent host would translate into tool calls.

Allow about 8 to 10 minutes for the complete demonstration.

### Demo part 1: start the gateway and dashboard

Terminal 1:

```powershell
cd V:\agent-security
npm run gateway:serve
```

Terminal 2:

```powershell
cd V:\agent-security
npm run dashboard:serve
```

Open:

```text
http://127.0.0.1:4173/
```

Show the audience:

- all feature statuses;
- current validation counts;
- implemented security controls;
- release-gate status;
- `UNPROTECTED` coverage;
- gateway activity after requests occur.

Suggested introduction:

> This gateway is an external MCP security boundary. It authenticates clients,
> validates protocol state, resolves canonical effects, applies deterministic policy,
> requires exact approval where appropriate, governs results, and records durable
> evidence. This demonstration uses disposable local resources and does not claim
> production protection.

### Demo part 2: show MCP mediation

In Terminal 3, run:

```powershell
cd V:\agent-security
npm run gateway:smoke
```

The workflow demonstrates:

- invalid credentials return `401`;
- MCP initialization succeeds;
- the initialized notification is accepted;
- tool discovery succeeds;
- a protected tool call is rejected;
- coverage remains `UNPROTECTED`;
- downstream tool calls remain exactly zero.

Refresh the dashboard after the command finishes so the audience can see the sanitized
request activity.

Suggested narration:

> The gateway authenticates the client and negotiates MCP normally. Discovery succeeds,
> but an operational call is blocked because exclusive protection has not been
> established. Nothing reaches a downstream server.

Suggested prompt intent:

```text
Run the protected smoke-tool operation.
```

Expected result: the gateway denies the call under `UNPROTECTED` coverage and records
zero downstream calls.

### Demo part 3: show real open-source MCP tools

Run:

```powershell
npm run mcp-servers:verify:disposable
```

This launches two pinned real MCP implementations:

- Everything MCP calls `get-sum` with `19` and `23`;
- Microsoft Playwright MCP calls `browser_navigate` against an isolated local page;
- both servers reject `agent_security_unknown_tool`.

Prompt equivalent 1:

```text
Use the get-sum tool to add 19 and 23.
```

Expected result: `42`.

Prompt equivalent 2:

```text
Open the disposable local demonstration page using the browser tool.
```

Expected result: isolated local navigation succeeds.

Prompt equivalent 3:

```text
Call the tool named agent_security_unknown_tool.
```

Expected result: the server rejects the unknown tool.

The verification script invokes these tools directly through MCP. Do not imply that a
chat frontend is included or that the locally launched servers are independently
operated production evidence.

### Demo part 4: show exact human approval

The browser suite is configured to run visible Chromium. Run only the successful
approval workflow:

```powershell
npm run test:browser -- --grep "approves once through the Vault broker"
```

It demonstrates:

1. A live pending protected operation.
2. Canonical requester, route, target, risk, coverage, and recovery context.
3. The exact **Approve once** control.
4. Credential issuance only after approval.
5. One exact downstream attempt.
6. Governed result validation and display.
7. Durable PostgreSQL approval, outcome, and audit state.

Suggested prompt intent:

```text
Perform this protected operation exactly once.
```

Suggested narration:

> The prompt does not grant authority. The gateway constructs the canonical action,
> applies deterministic policy, and requires an independently authenticated human to
> approve this exact operation once.

Show the denial path separately:

```powershell
npm run test:browser -- --grep "keyboard denial"
```

Explain that denial creates no forwarding attempt and becomes durable audit evidence.

For a longer demo, run all four approval workflows:

```powershell
npm run test:browser
```

The complete matrix also shows reload and reconnect behavior, duplicate and multi-tab
decisions, expiry, stale authority and coverage, provider failure, and invalid-result
quarantine.

### Demo part 5: show hardened local deployment

Start Docker Desktop, confirm `docker version` reports a server, and run:

```powershell
npm run deploy:verify:non-production
```

Point out the final evidence:

- Docker network mode is `none`;
- no ports are published;
- the root filesystem is read-only;
- all Linux capabilities are dropped;
- `no-new-privileges` is enabled;
- the process uses a non-root user;
- coverage remains `UNPROTECTED`;
- downstream tool calls remain zero;
- the exact disposable container is removed afterward.

### Demo claims to use and avoid

Safe claim:

> This demonstrates fail-closed MCP mediation using disposable local resources.

Safe claim:

> Equivalent requests, approval state, results, and audit evidence are validated by
> deterministic controls outside the model.

Do not claim:

> This environment is production protected.

Do not claim that local open-source servers are independently operated, that disposable
credentials are production credentials, or that local Docker isolation proves
exclusive mediation in a production deployment.

### Demo checklist

Before presenting:

- [ ] `npm ci` and `npm run build` pass.
- [ ] Docker Desktop is healthy if the deployment step will be shown.
- [ ] Ports 4173 and 4174 are available.
- [ ] The gateway and dashboard are running in separate terminals.
- [ ] `npm run gateway:smoke` passes once as a rehearsal.
- [ ] The open-source MCP packages are available or already cached.
- [ ] Browser tests can start disposable PostgreSQL and Chromium.
- [ ] No real credentials, services, or production data are configured.
- [ ] The presenter says `UNPROTECTED` and explains what it means.

## 14. Stop the project

In each running terminal, press:

```text
Ctrl+C
```

Stop the gateway and dashboard separately. The disposable Docker deployment verifier
removes its exact temporary container automatically.

To see any leftover verifier containers without modifying them:

```powershell
docker ps --filter name=agent-security-gateway-smoke-
```

Do not run broad Docker deletion commands or reset Docker Desktop to factory defaults
just to stop this project.

## 15. Troubleshooting

### `npm ci` fails

1. Confirm `node --version` and `npm --version` work.
2. Use Node.js 24 or the current compatible LTS release.
3. Run the command from the repository root.
4. Keep `package-lock.json`; do not delete it to bypass dependency resolution.

### Port 4173 or 4174 is already in use

Stop the older project terminal with `Ctrl+C`, or choose another local port:

```powershell
$env:DASHBOARD_PORT = "4273"
npm run dashboard:serve
```

```powershell
$env:GATEWAY_PORT = "4274"
npm run gateway:serve
```

### The dashboard does not show gateway activity

1. Confirm `npm run gateway:serve` is still running.
2. Run `npm run gateway:smoke` to create safe lifecycle activity.
3. Refresh `http://127.0.0.1:4173/`.
4. Check `http://127.0.0.1:4173/api/status`.

### Integration tests cannot start PostgreSQL

The tests use disposable PostgreSQL infrastructure. Check for a blocked local port,
an antivirus or filesystem lock, and any stale test process. Rerun the exact failed
test after fixing the cause; do not reinterpret a failed test as passing evidence.

### Docker Desktop reports an inaccessible `.sock` file

Current Docker Desktop releases on Windows can leave broken AF_UNIX socket reparse
points after a crash, forced shutdown, or interrupted startup. Typical paths are:

```text
%LOCALAPPDATA%\Docker\run\sailor-ingest.sock
%LOCALAPPDATA%\docker-secrets-engine\engine.sock
```

Use this safe recovery:

1. Quit Docker Desktop completely.
2. In Task Manager, confirm `Docker Desktop` and `com.docker.backend` are stopped.
3. Preserve the affected parent directories by renaming them; do not reset Docker to
   factory defaults.
4. Recreate empty directories with the original names.
5. Disable Docker AI/Model Runner in Docker Desktop settings if it is not needed.
6. Start Docker Desktop and confirm `docker version` reports both client and server.

Example PowerShell, only after Docker is fully stopped:

```powershell
$repairStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dockerRunPath = Join-Path $env:LOCALAPPDATA "Docker\run"
$dockerSecretsPath = Join-Path $env:LOCALAPPDATA "docker-secrets-engine"

if (Test-Path -LiteralPath $dockerRunPath) {
  Rename-Item -LiteralPath $dockerRunPath -NewName "run.stale-$repairStamp"
}
New-Item -ItemType Directory -Path $dockerRunPath | Out-Null

if (Test-Path -LiteralPath $dockerSecretsPath) {
  Rename-Item -LiteralPath $dockerSecretsPath -NewName "docker-secrets-engine.stale-$repairStamp"
}
New-Item -ItemType Directory -Path $dockerSecretsPath | Out-Null
```

This preserves the broken runtime directories and does not remove images, containers,
volumes, or Docker data. A factory reset is not required for this error.

### `release:verify` reports a hash mismatch

The manifest is stale relative to the workspace. Regenerate and verify it:

```powershell
npm run release:manifest
npm run release:verify
```

Only do this after the intended source and documentation changes are complete.

## 16. Where to learn more

Read these in order when you need more detail:

1. `startup.md` — everyday setup and operation.
2. `handbook.md` — beginner-friendly architecture and security concepts.
3. `README.md` — repository overview and command summary.
4. `docs/progress.md` — current verified state and handoff.
5. `docs/featurelist.json` — machine-readable feature evidence.
6. `docs/technical-specification.md` — authoritative security specification.
7. `docs/plan.md` — delivery and release gates.
8. `docs/operations/recovery-and-rollback.md` — local recovery details.

## 17. Safety rules to remember

- Never use real production credentials or data in this repository.
- Never claim `ENFORCED` coverage from local disposable evidence.
- Never weaken a denial, approval rule, schema check, or test to make validation pass.
- Never treat discovery filtering as authorization.
- Never expose approval material or downstream credentials to the agent.
- Keep `phase-1` closed unless archival investigation is explicitly requested.
- Preserve existing workspace changes and generated evidence.
