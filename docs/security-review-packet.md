# Independent Security Review Packet

**Review status:** NOT PERFORMED  
**Requested scope:** Phase 2 Agent Security MCP Gateway, including the local
non-production service, dashboard telemetry, Docker packaging, release evidence, and
the claims recorded in `docs/technical-specification.md`. When `P2-F020` exists, the
scope must also include its human authentication, browser session, approval endpoints,
PostgreSQL transitions, and rendered pending-approval/outcome/audit views.  
**Current coverage:** `UNPROTECTED`

This packet prepares an independent reviewer; it is not a review report, approval,
or production authorization.

## Evidence to inspect

Run the following using disposable local resources only:

```powershell
npm ci
npm run build
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run validate:features
npm run gateway:serve
npm run gateway:smoke
npm run dashboard:serve
npm run evidence:capture
npm run sbom:generate
npm run docker:build:non-production
npm run release:manifest
npm run release:verify
npm run build:verify-reproducible
npm audit --audit-level=high
```

Review these artifacts and source boundaries:

- `src/transport/streamable-http-initialization-v1.ts`
- `src/policy-engine/`
- `src/approval/`
- `src/forwarding/`
- `src/persistence/`
- `src/coverage/`
- `apps/approval-ui/` or the final `P2-F020` frontend location (currently absent)
- `scripts/serve-gateway.mjs`
- `scripts/smoke-gateway.mjs`
- `artifacts/local-evidence.json`
- `artifacts/sbom.cdx.json`
- `artifacts/release-manifest.json`
- `docs/release-gate-audit.md`

## Required review questions

Review findings should be delivered using the V1 evidence boundary exported from
`src/evaluation/independent-security-review-v1.ts`. It binds the review to the exact
source, runtime, and configuration digests and requires evidence for remediation or
separate risk-owner authorization. Its `EVIDENCE_CONTRACT_ONLY` label is intentional:
the project must still verify reviewer independence and the authenticity of the
submitted evidence outside the schema.

1. Can any unauthenticated, alternate, encoded, replayed, or out-of-order request
   reach an operational downstream call?
2. Can policy, trust, supervisor output, or stale approval weaken an immutable deny?
3. Are credentials, arguments, results, approval material, and query strings absent
   from logs, telemetry, dashboard output, and artifacts?
4. Are PostgreSQL transactions, replay protection, concurrency, result mediation, and
   fail-safe dependency behavior sufficient for the stated test claims?
5. Does any path bypass the gateway's canonical resource/effect decision or result
   governance?
6. Which claims remain limited to disposable fixtures, and what independent evidence
   is required before production coverage can be raised above `UNPROTECTED`?
7. Can an unauthenticated or wrong-scope browser user view or decide another user's
   pending approval, and are CSRF, origin confusion, fixation, replay, stale state,
   reload, duplicate-click, and multi-tab races denied safely?
8. Does one visible `Approve once` action create at most one durable consumption and
   exact forwarding attempt, while `Deny`, expiry, revocation, or changed policy,
   route, schema, identity, or coverage creates none?
9. Does the approval UI display only canonical trusted context and governed outcomes,
   without credentials, approval secrets, raw hostile errors, or model-authored
   authority? Generated wireframes must not count as implementation evidence.

## Reviewer disposition

- Reviewer identity/organization: ______________________________
- Review date and source revision: _____________________________
- Critical findings: ___________________________________________
- High findings: ______________________________________________
- Required remediation: _______________________________________
- Accepted residual risk owner: ________________________________
- Independent review complete: `NO`
- Production authorization: `NO`
