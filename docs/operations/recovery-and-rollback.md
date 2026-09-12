# Recovery, Incident Response, and Rollback (Non-Production Harness)

This runbook applies only to the disposable local gateway and dashboard. It is not a
production incident-response plan and does not authorize deployment or publishing.

## Normal startup

```powershell
npm run dashboard:serve
npm run gateway:serve
```

The dashboard is at `http://127.0.0.1:4173/`; the gateway is at
`http://127.0.0.1:4174/mcp`. The gateway uses a fixture credential, accepts only
loopback traffic, and remains `UNPROTECTED` and non-forwarding.

## Detect and contain

1. Stop the affected local process with `Ctrl+C`.
2. If an automated disposable container is running, identify its exact UUID-suffixed
   name with `docker ps --filter name=agent-security-gateway-smoke-`.
3. Copy the exact returned name and remove only that container with
   `docker rm --force <exact-container-name>`. The automation performs this cleanup in
   a `finally` path on success and failure.
4. Preserve the dashboard `/api/status`, gateway `/status`, test output, image ID,
   SBOM, and release manifest before restarting if an incident needs investigation.
   When both local processes are running, `npm run evidence:capture` records this
   sanitized state as `artifacts/local-evidence.json`.

Do not use broad recursive deletion or remove unrelated containers, volumes, images,
or workspace files.

## Rollback

The harness has no production deployment history. Rollback means returning to a
previous local source revision and rebuilding the disposable image:

```powershell
npm ci
npm run build
npm run docker:build:non-production
npm run sbom:generate
npm run release:manifest
```

Verify the rebuilt image ID and manifest hashes before running the smoke test. Never
reuse a mutable `latest` tag as release evidence. A production rollback procedure
must add an immutable artifact registry, signed image verification, deployment-owner
approval, database recovery testing, and measured recovery objectives.

For the complete disposable preparation ladder, run
`npm run release:prepare:non-production`. It validates the repository, builds and
inspects the hardened no-network container, runs the MCP smoke inside it, removes it,
and regenerates/verifies unsigned local evidence. It never publishes an image.

## Incident evidence and unresolved production work

The local telemetry is sanitized and contains no arguments, results, credentials, or
approval tokens. It cannot prove exclusive mediation, production identity, direct
access blocking, or result governance. Production incident response remains pending
until those controls, owners, escalation paths, recovery objectives, and exercises
are approved and independently reviewed.
