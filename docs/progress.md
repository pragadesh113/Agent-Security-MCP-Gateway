# Agent Security MCP Gateway Progress

**Current phase:** Phase 2 - Production-Oriented MCP Gateway  
**Overall status:** Phase 2 local non-production deliverable complete; production assurance deferred
**Current feature:** none; all 21 tracked features are complete under the approved local-only scope
**Last updated:** 2026-10-01

### 2026-10-01 - P2-DOC-001 - Originality review and document visuals

- Result: revised report and manuscript prose for concrete project explanations,
  primary-source attribution, accurate related-work distinctions, and explicit dated
  evidence. Preserved pre-existing implementation and documentation changes.
- Originality checks: verified cited primary sources and sampled nine public-web
  phrase searches across both documents. A generic report opening was rewritten.
  Reproducible 12-token screening found zero matching windows against either of the
  two supplied source PDFs in both documents. This is not a proprietary similarity
  score, plagiarism certificate, universal pass, or automated-authorship verdict.
- Visuals: `images/` contains 24 original illustrations in PNG/SVG/PDF, nine editable
  CSV tables/charts, a gallery, captions, source hashes and reproducible generator.
  All 24 accompany the relevant report sections; three new full-width diagrams
  supplement the manuscript's existing three figures. Charts retain historical or
  candidate-inventory labels; no measured effectiveness results were invented.
- Document validation: the final eight-page IEEEtran PDF compiled with the existing
  cached Tectonic compiler and all eight rendered pages were visually inspected.
  Tables, figures, six bibliography entries and references resolve. The built-in
  editor remains open, but its compiler could not initialize platform directories.
  Underfull spacing/Fontconfig warnings remain; no overfull boxes remained.
- Repository validation: build, typecheck, 33 unit files/333 tests, 16 integration
  files/74 tests, and 21 feature records passed. Initial test startup was blocked by
  sandbox `spawn EPERM`; approved retries ran. The first integration retry failed
  on PostgreSQL startup timeout; the next complete invocation passed.
- Lint limitation: two pre-existing diagnostics remain in the uncommitted
  `src/evaluation/resolver-corpus-v1.ts` extension (deprecated finite at line 79,
  numeric template expression at line 110). That source was preserved outside this
  documentation task. The root validation ladder therefore is not wholly green.
- Not run: proprietary plagiarism services, authorship detectors, browser/Vault/
  container/release reruns, resolver experiments, or comparative research trials.
- Tracking: `P2-DOC-001` completion evidence updated; all 21 implementation feature
  statuses remain unchanged. Coverage is `UNPROTECTED`; forwarding stays disabled.
- Handoff: see `docs/document-originality-and-visuals.md`, both originality review
  notes, `report-assets/originality-local-audit.json`, and `images/manifest.json`.
  Submit the exact final documents to the institution's authorized similarity tool;
  inspect substantive matches. Respect the selected venue's page limit and complete
  author/disclosure details. Independently review resolver labels, create untouched
  held-out families, and resolve the existing lint diagnostics before claiming a new
  full repository validation pass. No production approval or research effectiveness
  is implied by the revised documents.

### 2026-09-27 - P2-DOC-001 - Research protocol deliverable completed

- Scope: completed the protocol and contribution-statement action from section 1 of
  `docs/addon-md.txt`; the research study and corpus remain unfinished
- Result: `docs/research-protocol.md` defines RQ1–RQ3, supported-operation boundaries,
  attacker capabilities and assumptions, independent labelling and family splits,
  six comparison conditions, metric denominators, paired analysis, execution faults,
  reproducibility inputs, and pilot/freeze/submission decision gates
- Prior work: `docs/research-related-work.md` compares primary Progent v3 and MCIP v7
  papers and links their official artifacts; neither baseline was installed or run,
  and novelty remains an open research question
- Implementation check: equivalence tests inject semantic findings; the analyzer
  registry is a validation boundary; approved-call loading uses stored authority.
  Fresh filesystem resolution and independent resolver ground truth remain work
- Validation: build, lint, typecheck, 32 unit files/295 tests, and 15 integration
  files/66 tests passed. Initial Vitest startup hit sandbox `spawn EPERM`; permitted
  retries passed with disposable resources. All 21 feature records and 12 local
  document links validated; scoped diff whitespace checks passed. Independent
  read-only review checked the protocol and primary-source comparison; its execution
  trust-boundary clarification was incorporated
- Not run: browser, container, interoperability, or research experiments; no runtime,
  browser, deployment, or corpus behavior changed. No empirical improvement claimed
- Coverage: `UNPROTECTED`; protected forwarding remains disabled; all 21 implementation
  feature statuses remain complete under the existing local-only scope
- Next action: create the candidate resolver corpus and pinned tool/grammar scope,
  assign complete families to development/held-out splits, and obtain independent
  label review. Do not present candidate labels as ground truth or reuse injected
  resolver expectations as independent evidence

### 2026-09-27 - P2-DOC-002 - Complete project reading guide added

- Status: `complete`; documentation-only deliverable with no runtime or coverage change
- Result: added `docs/project-guide.md` and the navigable `docs/project-guide.html`, a
  beginner-to-research guide covering MCP fundamentals, threat model, architecture,
  canonical actions, policy tiers, approval and recovery, credentials and result
  governance, PostgreSQL persistence, coverage, trust, repository layout, operation,
  validation evidence, paper position, research plan, code-reading route, glossary,
  and comprehension questions with answers
- Accuracy: the guide explicitly separates the local Phase 2 completion state from
  research effectiveness and production assurance; it records `UNPROTECTED` coverage,
  disabled protected forwarding, fixture-resolved semantic-equivalence evidence, the
  ordinary versus protected launchers, and the stored-authority revalidation limit
- Validation: `npm run validate:features` passed for all 21 Phase 2 records; build,
  lint, typecheck, 295 unit tests, and 66 integration tests passed during preparation;
  structural guide checks passed; browser visual QA was attempted but blocked by the
  Windows process policy (`spawn EPERM`) before Chromium could launch
- Coverage: unchanged at `UNPROTECTED`; protected forwarding remains disabled
- Next action: keep this guide synchronized when the runtime, feature evidence, or
  research claims change; rerun browser visual QA when the host permits Chromium
  launch

### 2026-09-21 - P2-DOC-001 - Beginner technical report refreshed

- Status: `complete`; documentation-only improvement with no runtime or coverage change
- Result: replaced the stale Semester VII snapshot in root `report.md` with a current,
  standalone technical onboarding report covering MCP fundamentals, threat model,
  architecture, request/result flow, every active source module, contracts, policy,
  approval, PostgreSQL migrations, coverage, runtime entrypoints, setup, testing,
  release evidence, limitations, troubleshooting, and glossary
- Reconciliation: the report now reflects all 21 locally complete Phase 2 features,
  the functional protected approval UI, current validation evidence, and the explicit
  distinction between local completion and deferred production assurance
- Validation: Markdown structure, internal repository references, feature tracker, and
  repository diff whitespace were checked; runtime tests were not rerun because no
  executable behavior changed
- Coverage: unchanged at `UNPROTECTED`; protected production forwarding remains disabled
- Next action: keep `report.md` synchronized with the authoritative specification,
  feature tracker, progress record, commands, and release gates

### 2026-09-20 - P2-DOC-001 - Startup and operation guide added

- Status: `complete`; documentation-only improvement with no runtime or coverage change
- Result: added root `startup.md` with step-by-step prerequisites, installation, basic
  gateway and dashboard startup, smoke verification, addresses and ports, development
  loop, validation commands, open-source MCP checks, Docker release preparation,
  evidence capture, advanced approval UI configuration, shutdown, troubleshooting,
  and an 8-to-10-minute presentation flow with prompt equivalents and expected results
- Docker recovery: documents the observed Windows AF_UNIX stale-socket failure and the
  recoverable parent-directory refresh without factory reset or Docker-data deletion
- Safety: distinguishes the beginner local workflow from the protected mutual-TLS UI,
  retains `UNPROTECTED` coverage, and forbids production credentials and claims
- Documentation integration: linked `startup.md` from the root README and recorded it
  in `P2-DOC-001` completion evidence
- Validation: all 19 referenced npm scripts resolve; `git diff --check`, build, lint,
  typecheck, 32 unit files/295 tests, 15 integration files/66 tests, and all 21 feature
  records pass; browser tests were not rerun because browser behavior did not change
- Coverage: unchanged at `UNPROTECTED`; protected production forwarding remains disabled
- Next action: use `startup.md` as the first operational guide and keep it synchronized
  with package scripts, ports, environment variables, and startup behavior

`P2-F020` is complete with disposable evidence. The protected mutual-TLS entrypoint composes
`ApprovalWebRuntimeBridgeV1` and the real `ClientApprovedCallExecutorV1`. PostgreSQL is
the trusted resolver for the approved human/session binding and the loader for the
exact approved call. Runtime request arguments are retained only as AES-256-GCM
ciphertext with an operator-supplied 32-byte key and key identifier; plaintext remains
excluded from ordinary trajectory and audit documents. Startup requires an absolute
trusted runtime module that supplies the credential lease and exact downstream
forwarder, and fails rather than exposing an approving endpoint when those dependencies
are absent or incomplete.

The approval decision boundary still accepts only the opaque approval id and the
independently authenticated human id. It reloads all agent authority from PostgreSQL,
checks active human scope authority, exact session digest, approval state and expiry,
then invokes the executor. Executor failures observed by the web process before durable
consumption transactionally change `APPROVED -> REVOKED` and append
`approval.execution_failed`; failures after consumption are represented by the
executor's terminal outcome path. The UI rereads durable records for outcome, recovery,
coverage, and audit rendering. The bridge test uses the real executor rather than a
casted fake.

PostgreSQL integration now proves authenticated web `APPROVE` through the real bridge,
trusted session resolution, approved-call decryption/loading, atomic consumption, one
forwarding attempt, and durable terminal outcomes. Credential issuance now receives the
executor-generated forwarding authorization, allowing the approved HashiCorp Vault
provider and non-exporting broker to bind the lease to the exact approval, action,
route, audience, endpoint, session, and durable forwarding attempt. The exact HTTP
forwarder then authenticates and governs the result before PostgreSQL persistence.
Chromium proves live keyboard denial, a successful governed `Approve once` workflow,
reload/reconnect, duplicate and two-tab concurrency, expiry, stale-human-authority
denial, coverage-driven revocation, provider failure, and invalid-result quarantine.
The browser now displays a bound non-content result disposition and schema verdict.
Current validation passes: build, typecheck, all 21 feature records, 32 unit files/295
tests, 15 integration files/66 tests, and 4 Playwright browser tests; lint also passes.

Approval now creates a durable dispatch in the same transaction as `APPROVED`. The
runtime claims it before session resolution. A bounded restart worker serializes stale
recovery with `FOR UPDATE SKIP LOCKED`: unconsumed approvals become `REVOKED` with zero
forwarding, while consumed attempts lacking an outcome become terminal `UNKNOWN` with
possible partial effects and are never retried. Claim timeout must exceed the finite
executor timeout.

Coverage remains `UNPROTECTED` and protected forwarding remains disabled. The repository
has production-shaped approved Vault/broker/exact-forwarder composition, but all browser
evidence is disposable. `P2-F018` is complete under the user-approved local open-source
interoperability scope. Independent hosts and external review remain deferred production
assurance. `P2-F019` is also complete with verified local packaging and release evidence.

### 2026-09-20 - P2-F019 - Local non-production release completed

- Status: `complete`; all 21 Phase 2 features are complete under the explicitly
  non-production scope
- Docker repair: Docker Desktop startup was restored without factory reset by
  preserving the inaccessible runtime-socket directories as dated backups and
  recreating only those ephemeral directories; Docker AI/Model Runner was disabled in
  the existing settings as recommended for this current Windows socket bug; images,
  containers, volumes, and other settings were not removed
- Disposable deployment: verified `network=none`, zero published ports, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`, and a non-root user;
  lifecycle smoke passed with `UNPROTECTED` coverage and zero downstream tool calls;
  the current Docker 29.7.2 engine passed a second post-repair deployment smoke
- Release evidence: package boundary verified 111 files; CycloneDX SBOM generated 277
  components; release manifest verified 138 file hashes and local image identity; 264
  generated files reproduced exactly; dependency audit reported zero vulnerabilities
- Full validation: build, lint, typecheck, 32 unit files/295 tests, 15 integration
  files/66 tests, all 21 feature records, dashboard generation, packaging, deployment,
  manifest verification, reproducible build, and dependency audit passed
- Artifact posture: unsigned, unpublished, not production-approved, and ineligible for
  `ENFORCED` coverage
- Coverage: `UNPROTECTED`; protected production forwarding remains disabled
- Deferred production assurance: independently operated hosts, external review,
  production credential custody, exclusive mediation, signing, and publication
- Next action: none for local Phase 2; open a separately approved production-assurance
  phase only if production use is requested

### 2026-09-20 - P2-F018 - Local open-source interoperability accepted

- Status: `complete` under the user's explicit local-only scope change; the prior
  independent-host and external-review requirements are deferred production gates
- Actual workflow: the pinned MCP Everything reference server `2026.8.31` advertised
  13 tools and completed `get-sum`; Microsoft Playwright MCP `0.0.81` advertised 26
  tools and completed an isolated loopback browser call; both rejected an unknown tool
- Evidence: `artifacts/open-source-mcp-smoke.json` binds package versions, registry
  integrity, observations, and an evidence digest
- Truthful limitation: the artifact remains `LOCAL_INTEROPERABILITY_ONLY`, records
  `independentlyOperated: false`, and reports `UNPROTECTED`; no external review or
  production-host claim is made
- Coverage: unchanged at `UNPROTECTED`; protected forwarding remains disabled
- Next action: complete `P2-F019` as non-production local release evidence, without
  signing, publishing, or claiming production approval

### 2026-09-20 - P2-F018 - External evidence blocker revalidated

- Status: `blocked`; none of the three acceptance criteria is complete
- Reconciliation: implementation, feature tracking, and the evidence contracts agree;
  no independently operated host configuration, retained operational trajectory, or
  completed independent review is present in the repository
- Focused validation: the independent-host, operational-trial, and independent-review
  unit suites passed 3 files/13 tests
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`
  (32 files/295 tests), `npm run test:integration` (15 files/66 tests), and
  `npm run validate:features` (21 records) passed
- Not run: the Chromium browser matrix and local open-source-server smoke were not
  rerun because no browser, protected-runtime, or interoperability behavior changed;
  independently operated host workflows and independent review remain unavailable
- Coverage: `UNPROTECTED`; protected forwarding remains disabled and no release claim
  changed
- Remaining risk: local fixtures, locally launched third-party servers, and project
  self-review cannot establish independent operation or reviewer independence
- Exact unblock action: provide connection and authentication details for two named,
  independently operated non-production MCP hosts plus an independent reviewer, then
  execute the prepared paired operational trials and review evidence workflow

Code-review follow-up checklist for the next session:

- [x] Compose the protected entrypoint with `ApprovalWebRuntimeBridgeV1`, PostgreSQL session/call authority, and the real `ClientApprovedCallExecutorV1`; fail startup when trusted runtime dependencies are absent.
- [x] Replace the casted bridge fake with the real executor and verify consume/outcome sequencing.
- [x] Prove PostgreSQL `APPROVE -> resolve -> consume -> forwarding attempt -> terminal outcome -> audit`, including durable pre-consumption reconciliation observed by the web process.
- [x] Run build, typecheck, lint, feature validation, full unit/integration suites, and the Chromium denial workflow.
- [x] Add an atomic durable dispatch/outbox claim and bounded recovery worker; prove restart and concurrent-worker recovery, zero forwarding for unconsumed approvals, and no retry for consumed ambiguous attempts.
- [x] Compose the approved HashiCorp Vault provider, non-exporting credential broker, and exact downstream forwarder; prove one disposable governed browser success without exposing credentials.
- [x] Complete browser/integration coverage for live APPROVE success, reload, duplicate click, multi-tab/concurrent consumption, reconnect, expiry, revocation, stale authority/coverage, and provider/result failures.
- [ ] Keep coverage `UNPROTECTED` and protected forwarding disabled until the production-provider, isolation, recovery, and full evidence gates pass.

The feature graph now contains 21 records. `P2-F020` explicitly tracks the functional
authenticated human approval and audit web application. The completed `P2-F010`
host-neutral interface model and generated report wireframes are not runnable approval
controls and cannot satisfy `P2-F020` or the production-candidate gate.

A dependency-free local status dashboard is now available at
`dashboard/index.html`. `npm run dashboard:build` derives its status JSON from the
authoritative feature tracker and progress record, showing verified controls,
validation counts, `UNPROTECTED` coverage, and blocked release gates. It is
informational only and does not expose authorization or forwarding.
The dashboard now also has a live local server: `npm run dashboard:serve` serves
`/` and recomputes `/api/status` from the current authoritative docs on every
request, avoiding stale generated data. Playwright verified HTTP 200, the expected
title, `COVERAGE: UNPROTECTED`, current feature status, and all three gate dispositions.
The live view now includes a security decision pipeline and background activity feed
with explicit accept/reject/not-required outcomes while preserving the truth that no
operational downstream call is simulated or forwarded.
The live dashboard now consumes loopback-only gateway telemetry from `/status`:
request counts, response classes, sanitized activity, coverage, and an explicit zero
downstream-tools-call counter. A real initialize/initialized/tools-call workflow was
observed by both processes; the tool call was rejected as non-forwarding and the
dashboard reflected the same request count and zero forwarded calls.
An executable non-production gateway entrypoint is now available via
`npm run gateway:serve`; it builds the TypeScript package, binds the existing
authenticated lifecycle adapter to loopback port 4174, and uses an explicit fixture
credential. It remains non-forwarding and `UNPROTECTED` by design.
Actual workflow validation passed against the live process: `initialize` returned
HTTP 200 with an MCP session, `notifications/initialized` returned HTTP 202, and a
real `tools/call` returned the explicit non-forwarding error with coverage
`UNPROTECTED`. The cumulative validation ladder also passed: build, lint, typecheck,
209 unit tests, 40 integration tests, feature validation, and package-boundary check.
The next packaging slice adds `Dockerfile.non-production` and `.dockerignore` for
the same fixture-only harness. The image is explicitly unreleased, binds to
container loopback, exposes no host port, and does not add production identity,
credentials, forwarding, or bypass controls.
The image built locally as `agent-security-gateway:non-production`; an ephemeral
container smoke test returned HTTP 200 for a real MCP `initialize` request and was
removed afterward. `compose.non-production.yml` additionally disables network
egress for disposable smoke runs. No image was published.
`npm run sbom:generate` now produces a local CycloneDX 1.5 SBOM from
`package-lock.json` at `artifacts/sbom.cdx.json`; it is unsigned local release
evidence and is excluded from runtime package contents. Signing and publication
remain pending approval and production release controls.
Latest validation after the SBOM slice passed build, lint, typecheck, 20 unit files/
209 tests, 10 integration files/40 tests, feature validation, package-boundary
verification, dashboard generation, SBOM generation, and high-severity dependency
audit (zero vulnerabilities).
The next safe release slice adds `docs/operations/recovery-and-rollback.md` and
`npm run release:manifest`. The manifest records hashes for package/config/SBOM
inputs plus the local non-production image ID, while explicitly marking the artifact
unsigned, unpublished, and not production-approved.
`npm run release:verify` now recomputes every manifest hash and checks the local
Docker image ID, preventing accidental use of changed local artifacts as if they
were the recorded build.
The latest full validation passed: build, lint, typecheck, 20 unit files/209 tests,
10 integration files/40 tests, feature validation, package-boundary verification,
dashboard generation, SBOM generation, release-manifest generation/verification,
and high-severity dependency audit with zero vulnerabilities.
The current evidence capture step is complete: `artifacts/local-evidence.json`
contains only sanitized gateway/dashboard telemetry and the verified manifest, and
the capture refused to proceed unless coverage was `UNPROTECTED`, forwarding was
disabled, and downstream call count was zero. Latest full validation passed all
checks, including 209 unit tests, 40 integration tests, gateway smoke, reproducible
build, manifest verification, and zero high-severity vulnerabilities.
The requested code review found and fixed two harness security issues: telemetry now
records only URL paths (never query strings), and the smoke test refuses non-loopback
targets before sending the fixture bearer token. The release manifest now also hashes
`scripts/serve-gateway.mjs`, which is copied into the runtime image. The rebuilt image
and manifest verify successfully; latest full validation passed all checks, including
209 unit tests, 40 integration tests, reproducible build, gateway smoke, and zero
high-severity audit findings.
The current safe evidence step adds `npm run evidence:capture`, which records a
sanitized local snapshot of gateway telemetry, dashboard gates, and the verified
release manifest only when the expected `UNPROTECTED`/zero-forwarding posture holds.
The next approval-ready artifact is `docs/security-review-packet.md`, which gives an
independent reviewer exact commands, source/artifact scope, security questions, and
an unsigned disposition template. It does not claim that review or production
authorization has occurred.
The dashboard now surfaces independent security review as an explicit `MISSING`
control until that packet is completed by an independent reviewer.
The next safe release slice adds `npm run build:verify-reproducible`, which performs
two clean TypeScript builds and compares every generated `dist` file hash before
reporting reproducibility evidence.
That reproducibility check now passes for 168 generated files. The latest full
validation also passed build, lint, typecheck, 209 unit tests, 40 integration tests,
feature validation, package-boundary verification, dashboard/SBOM generation,
release-manifest generation and verification, reproducible-build verification, and
high-severity dependency audit with zero vulnerabilities.
The live workflow is now repeatable with `npm run gateway:smoke`: it verifies invalid
credentials are rejected, lifecycle negotiation succeeds, `tools/call` is rejected,
and telemetry reports `UNPROTECTED`, forwarding disabled, and zero downstream calls.
The smoke parser now accepts the valid empty 202 notification response. Latest full
validation passed build, lint, typecheck, 209 unit tests, 40 integration tests,
feature validation, package-boundary verification, dashboard/SBOM generation,
release-manifest generation and verification, reproducible-build verification,
gateway smoke, and high-severity dependency audit with zero vulnerabilities.
The manifest was generated successfully; high-severity dependency audit remains at
zero vulnerabilities. The first cumulative integration invocation again encountered
the known Windows embedded-PostgreSQL `EBUSY` cleanup race after test execution; an
immediate rerun passed all 10 suites and 40 tests. Treat the cleanup race as an
environment limitation, not as passing evidence for a failed invocation.
The first cumulative integration run encountered a transient Windows `EBUSY` lock
while removing an embedded-PostgreSQL temp directory; an immediate rerun passed all
10 integration suites and 40 tests.

The documented one-command release preparation now passes with Docker available.
`npm run release:prepare:non-production` completed build, lint, typecheck, 210 unit
tests, 40 integration tests, feature and package validation, SBOM generation, a
hardened disposable container smoke workflow, manifest generation/verification,
reproducible-build verification, and a high-severity dependency audit with zero
vulnerabilities. `npm run evidence:capture` then refreshed sanitized local evidence
from loopback-only gateway and dashboard telemetry. Nothing was signed, published,
production-approved, or deployed to production, and coverage remains `UNPROTECTED`.

The release-gate audit is documented in `docs/release-gate-audit.md`. Development
validation passes, but the production-candidate gate remains blocked: Docker
packaging and a running service are absent, production identity/credential custody
and independent bypass controls are not configured, and independent review,
two-host/adaptive evidence, signed artifacts/SBOM, and exercised recovery/rollback
evidence are pending. No production deployment or publishing has occurred.
As safe release preparation, `npm run verify:package-boundary` now checks that
`npm pack --dry-run` excludes the archived Phase 1 tree, tests, and generated build
output; this verifies package contents only and does not publish anything.
The package check is Windows-compatible and passed alongside the latest cumulative
validation: 20 unit files/209 tests and 10 integration files/40 tests passed.

### 2026-09-06 - Release-gate audit - non-production deployment automation

- Status: implementation complete; actual container workflow blocked by the unavailable
  local Docker Linux engine
- Result: `npm run deploy:verify:non-production` builds a unique disposable image
  deployment, verifies no network or published ports, a read-only root filesystem,
  dropped capabilities, `no-new-privileges`, and a non-root user, runs the real
  authentication/lifecycle/tool-call smoke inside the container, asserts
  `UNPROTECTED`/zero-forwarding telemetry, and removes only its exact UUID-named
  container on success or failure. `npm run release:prepare:non-production` composes
  the complete local validation, package, SBOM, deployment, manifest,
  reproducibility, and high-severity audit ladder into one command.
- Focused validation: all release `.mjs` files passed `node --check`; the new release
  input enumeration test passed and binds source, TypeScript/container configuration,
  smoke, and release/deployment automation into the manifest input set.
- Cumulative validation: build, lint, typecheck, 21 unit files/210 tests, 10 integration
  files/40 tests, all 15 feature records, package-boundary verification (64 files),
  dashboard generation, CycloneDX 1.5 SBOM generation (274 components), reproducible
  build verification (171 files), and high-severity dependency audit (zero
  vulnerabilities) passed.
- Integration/actual deployment: `npm run release:prepare:non-production` reached the
  deployment step and failed before image creation because Docker Desktop's Linux
  engine pipe was unavailable. Docker Desktop is installed, but its service could not
  be started from this non-elevated session.
- Evidence: manifest verification now requires the exact release input set and a
  non-null matching local image ID; evidence capture verifies the manifest first. The
  currently stored release manifest and local evidence are stale and are not current
  release evidence.
- Coverage: `UNPROTECTED`; protected forwarding remains disabled and nothing was
  signed, published, deployed to production, or sent to a registry.
- Repository state: this workspace is not a Git repository, so exact source-revision
  attestation and revision-based rollback evidence are unavailable.
- Exact next action: start the Docker Desktop Linux engine, run
  `npm run release:prepare:non-production`, verify no UUID-suffixed smoke container
  remains, and only then regenerate/capture current local evidence.

#### Continuation diagnosis

- Docker Desktop startup was retried through both the desktop executable and
  `docker desktop start`; the backend still exited before exposing the Linux engine.
- The Docker backend log identifies the concrete cause: its inference manager cannot
  replace `C:/Users/radhi/AppData/Local/Docker/run/dockerInference`. Read-only
  inspection shows that exact entry is a zero-length reparse point. No Docker process
  remains active.
- An exact, non-recursive removal was prepared but the host policy denied changing
  that Docker runtime path. No file was removed.
- Exact unblocking action: with Docker Desktop stopped, manually remove only
  `C:/Users/radhi/AppData/Local/Docker/run/dockerInference`, restart Docker Desktop,
  confirm `docker info` succeeds, then run
  `npm run release:prepare:non-production`.

### 2026-09-06 - Disposable simulated-production database mount repaired

- Status: complete
- Root cause: `infra/simulation/init.sql` was an empty directory, while the retained
  Compose container configuration mounted that host path onto the file
  `/docker-entrypoint-initdb.d/001-seed.sql`. The original `infra/compose.yaml` was also
  absent, so Docker could not recreate the service from source configuration.
- Result: the empty mistaken directory was moved to the recoverable
  `init.sql.invalid-directory-backup`; `infra/compose.yaml` was reconstructed from the
  retained container configuration; and `infra/simulation/init.sql` was restored as an
  idempotent disposable schema/fixture seed matching the existing database.
- Data safety: the named PostgreSQL volume
  `agent-security-demo_simulated-production-data` was preserved and not recreated or
  deleted.
- Validation: `docker compose --file infra/compose.yaml config --quiet` passed; only
  `simulated-production-db` was force-recreated; it is healthy on
  `127.0.0.1:5433`; the seed is mounted read-only; authenticated `psql` returned
  database `simulated_production` and user `simulated_app`; the idempotent seed ran
  successfully and the database contains three disposable customers plus
  `simulated-api:healthy` deployment state.
- Coverage: `UNPROTECTED`; this is disposable local infrastructure and does not add
  production credentials, forwarding, isolation evidence, publication, or production
  deployment.
- Exact next action: run `npm run release:prepare:non-production` now that Docker is
  available, then refresh the release manifest and local evidence only if the complete
  command succeeds.

## Current snapshot

The repository contains a strict TypeScript protocol foundation that reports
`UNPROTECTED`, accepts loopback initialization, ping, and authenticated registry-backed
`tools/list`, and forwards no protected call. Strict client, session, downstream-server, and tool-route
V1 contracts validate initial boundary representations, integrity observations,
registration provenance, server/route and credential-audience binding, collision-safe
scoping, coverage, quotas, and UTC lifecycle timestamps.

Strict discovery, raw tool-call, raw tool-result, normalized gateway-error, and factual
awareness envelopes now bind untrusted protocol data, route and policy scope, payload
limits, call chains, result content types, coverage gaps, and evaluated alternatives.
One discriminated boundary dispatcher fails safely for unknown kinds, kind confusion,
unknown fields, and forward-incompatible versions across the completed payload types.

A pure MCP `2025-06-18` lifecycle state machine validates `initialize`, returns the
pinned supported version and either an empty capability set or discovery-only tools
capability according to trusted adapter configuration, waits for
`notifications/initialized`, permits `ping`, records bounded additional client
capabilities without negotiating them, rejects duplicate or out-of-order operation,
and enters a ready-but-non-forwarding state. A disposable loopback Streamable HTTP
adapter binds this state to opaque transport sessions, enforces Origin, media type,
body, session, and negotiated-version headers, and supports explicit termination. It
now requires an injected client authenticator before parsing MCP JSON and binds the
trusted user, agent, client, host, credential identifier, and identity revision to the
opaque session and a derived state namespace.

A disposable authenticated state repository now separates routes, downstream state,
approvals, quotas, results, and audit entries for every opaque session and clones
bounded JSON at its boundary. A disposable credential vault verifies credential
digests and issues metadata-only leases capped at five minutes and bound to an exact
profile revision, audience, route, session, and namespace. Same-subject credential or
identity-revision rotation quarantines the session, freezes shadow trust, clears active
state, retains result/audit accountability, and revokes its leases. These components
are automated-test infrastructure, not production identity or persistence fallbacks.

A disposable administrator-controlled downstream registry now authenticates server
observations outside discovery content, computes canonical registration, protocol,
capability, tool-set, and schema digests, and records allowlisted versioned audit
events. Healthy active routes are unique by ID and scope/environment/exposed name,
filtered per authenticated session, and reauthorized independently at call resolution.
Protocol, capability, tool-set, or schema drift latches quarantine until explicit
authorized review; unavailable, ambiguous, shadowed, and unauthorized routes fail
closed. The client-facing adapter now invokes this boundary through an injected
provider using the current authenticated session and a trusted configured scope,
revalidates the result, limits output, and marks returned metadata untrusted. A real
disposable HTTP MCP peer supplies integration discovery evidence.

A disposable host-neutral protocol guard now rejects stale or replayed request IDs and
nonces per authenticated session; applies atomic rate and concurrency quotas across
nine identity/route/effect dimensions; and bounds payloads, results, depth, delegation,
fan-out, redirects, retries, and deadlines at admission and runtime checkpoints. It
detects repeated ancestry effects, propagates cancellation and timeouts through abort
signals, denies unavailable dependencies before invocation, opens configurable
circuits, releases reservations on every terminal path, and emits versioned allowlisted
audit events. A real disposable HTTP operation supplies integration evidence.

A host-neutral canonical action normalizer now revalidates authenticated session,
current route, server, tool, schema, audience, policy scope, argument digest/size, and
call ancestry before selecting the resolver pinned by the registered route. It
normalizes bounded Windows/POSIX paths and URIs, hashes canonical resources, data flow,
parser evidence, and the complete action, and turns missing, failed, partial,
unsupported, or route-inconsistent analysis into an unresolved action rather than a
safe guess. Semantic aliases depend on a stable identity from the trusted resolver.

A deterministic policy engine now classifies fully parsed public reads, reversible
local writes, Tier 2 operations, and Tier 3 production, privileged, destructive,
credential, or difficult-to-reverse effects. It applies immutable and administrator
rules, coverage failure, trust, and supervisor evidence with most-restrictive-wins
composition. Unknown actions require approval or denial, non-enforced mutations deny,
advisories cannot lower a decision, and conflicting constraints or sandbox profiles
deny. This remains process-local test infrastructure with disposable resolvers and no
transactional persistence or forwarding.

A host-neutral exclusive-mediation monitor now computes exact-scope coverage from
trusted probe observations instead of a caller-provided label. It separately reports
gateway-mediated, native, and direct paths; requires all gateway and independent bypass
guarantees; rejects stale, future, mismatched, untrusted, ineligible, rolled-back, or
equivocating evidence; and times out failed probes. Disposable-test and deployment
assurance are distinct, so fixture evidence cannot establish production coverage. A
coverage-bound policy adapter and immediate pre-mutation recheck fail closed, while a
forward-only PostgreSQL migration durably stores append-only reports and evidence and
hash-chains non-enforced assessments as `BYPASS` events. No deployment probes are
configured, so the live runtime remains `UNPROTECTED` and non-forwarding.

A disposable host-neutral approval service now accepts only an exact action, policy
decision, and authenticated-session binding. It records one authenticated human
`APPROVE` or `DENY` decision, expires within five minutes, and synchronously
revalidates identity revision, current healthy route/schema, and fresh policy before
changing the record to `CONSUMED` and invoking one forwarding-start callback. Session
invalidation revokes live approvals; replay, parallel use, changed bindings, expiry,
human denial, revalidation failure, and callback failure cannot make an approval
reusable. Its allowlisted audit carries no arguments, credentials, or approval token.
The service is process-local test infrastructure, not a PostgreSQL or production human
approval boundary, and it is not wired into the client-facing gateway.

The trustworthy-interface builder supplies canonical data to an authenticated browser
application that loads live PostgreSQL approvals and submits exact `Approve once` or
`Deny` decisions. The protected mutual-TLS entrypoint has no fixture authentication
fallback and composes a durable dispatch bridge to the approved-call executor. The
browser matrix covers success, denial, reload/reconnect, concurrent use, expiry,
revocation, provider failure, and quarantined results, including a bound disposition
and schema verdict. `P2-F020` is complete with disposable evidence; protected
deployment evidence remains a separate `P2-F019` release gate.

A disposable exact-forwarding coordinator now revalidates the consumed authorization,
canonical action, authenticated session, current healthy route/schema, and recomputed
argument digest and byte length before allowing one process-local forwarding attempt.
The credential vault has a non-exporting HTTP sink that pins credentials to a lease,
route, audience, profile, and registered endpoint origin, injects them internally, and
refuses redirects. Authenticated downstream results are linked to request, action,
session, route, schema, server principal, and call-chain provenance; response bytes,
schema, secret redaction, egress disposition, error suppression, metadata, resource
content, and data-only instruction separation are mediated before release. This path
remains disposable test infrastructure and is not wired into the client-facing MCP
lifecycle adapter.

A PostgreSQL-only trajectory store now applies a checksummed forward-only migration
covering identities, clients, sessions, servers, schemas, routes, policies, requests,
canonical actions, decisions and reasons, approvals, forwarding attempts, provenance,
governed results, outcomes, hash-chained security events, shadow trust evidence,
coverage, protocol violations, supervisor assessments, and recovery records. Runtime
startup requires an explicit reachable PostgreSQL URL and has no in-memory fallback.
Transactions atomically persist request/decision state, approval decisions and runtime
dispatches, consume approvals under row locks, create unique forwarding attempts, link
result/outcome/trust state, and append tamper-evident events. Known configured secrets
are rejected before database work. Raw arguments are absent from ordinary records and
retained only as separately keyed AES-256-GCM runtime ciphertext; result content is not
stored. Immutable registry and dispatch conflicts fail the complete transaction. Real
PostgreSQL 18.4 remains disposable test evidence; production isolation and protected
forwarding authority are not established.

A host-neutral V1 dynamic-trust controller now starts in shadow mode and keeps the
effective and authoritative decision identical to deterministic policy. It validates
paired repeated-trial comparisons across static policy, policy plus awareness, and
bounded-trust counterfactuals; applies documented security, usability, latency,
coverage, approval, and trust-grinding promotion thresholds; and verifies evidence and
report digests. A passing report enables only a disposable counterfactual constrained
recommendation for an exact Tier 1 trust-eligible action and mature, independently
verified, scope-bound positive evidence. Tier 2/3, denial, invariant, unresolved,
production, non-enforced, and mismatched paths remain unchanged. Audit, identity,
route, schema, anomaly, and outcome freeze signals latch the controller in `FROZEN`.
No production authorization influence is enabled.

The request-to-outcome V1 trajectory now represents canonical actions, deterministic
decisions, exact five-minute approvals, downstream provenance and governed result
metadata, execution outcomes, and their cross-object bindings. It encodes fail-safe
Tier 3, ambiguity, degraded-mutation, result-quarantine, and unknown-outcome invariants
without enabling runtime policy or forwarding.

Authoritative Phase 2 governance is consolidated under `docs/`, with minimal root
entrypoints for agent discovery and repository navigation. The research thesis is now
explicitly MCP-only: representation-invariant, bidirectional mediation is the initial
contribution; native actions are coverage-relevant bypasses, and dynamic trust remains
a later bounded shadow-mode experiment.

The repository operating contract now supports a durable project goal across successive
features. The main task owns technical leadership and integration; architecture,
implementation, testing, review, and release-preparation roles may be delegated in
parallel only with collision-safe ownership. Routine repository work proceeds
autonomously, while material scope, architecture, security, production, destructive,
credential, spend, release, and external actions require a concrete user decision.
Verified checkpoints and an hourly quiet heartbeat provide interruption recovery without
treating usage exhaustion as completion.

Research requirements have been incorporated for request and response mediation,
discovery integrity, downstream identity and provenance, protocol abuse controls,
human approval security, exclusive mediation, repeated-trial evaluation, and a
shadow-mode gate for dynamic trust.

## Completed

### P2-DOC-001 - Phase 2 documentation and research baseline

- [x] Summarized both repository research papers.
- [x] Defined MCP-specific threats including replay, flooding, recursion, credential
  compromise, route poisoning, schema drift, malicious servers, and untrusted results.
- [x] Rewrote active governance and planning documents for Phase 2 only.
- [x] Created a Phase 2-only feature graph with stable dependencies.
- [x] Positioned dynamic trust as an experimental shadow-mode feature.
- [x] Defined bidirectional mediation and repeated-trial evaluation requirements.
- [x] Consolidated authoritative governance under `docs/` and recorded the final
  MCP-only research scope and related-work novelty boundary.

### P2-F001 - MCP protocol core and boundary contracts

- [x] Define all V1 client, session, server, route, request, result, provenance, error,
  awareness, approval, decision, and outcome boundary contracts.
- [x] Reject unknown and forward-incompatible versions and malformed boundary data.
- [x] Implement the pinned MCP `2025-06-18` initialization lifecycle and capability
  negotiation with no operational server capabilities.
- [x] Exercise a real disposable loopback Streamable HTTP handshake with opaque session
  binding and the required subsequent protocol-version header.
- [x] Prove that `tools/list` and `tools/call` remain unavailable and no protected call
  can be forwarded.

### P2-F002 - Authenticated identities and isolated sessions

- [x] Require a trusted transport authenticator before MCP payload parsing.
- [x] Bind authenticated user, agent, client, host, credential identifier, and identity
  revision to an opaque transport session and non-secret state namespace.
- [x] Reject cross-identity session access with an indistinguishable not-found response
  even when request parameters inject the owning identity's identifiers.
- [x] Bind gateway-held downstream credentials to exact audiences and routes without
  exposing credential material.
- [x] Namespace routes, downstream state, approvals, quotas, results, audit, and trust
  state by authenticated session.
- [x] Implement identity rotation invalidation and trust quarantine.

### P2-F003 - Integrity-checked downstream discovery and routing

- [x] Deterministically bind every visible tool to one authenticated server and route.
- [x] Compute and audit versioned registration, protocol, capability, tool-set, and
  tool-schema integrity evidence.
- [x] Latch unexpected drift in quarantine until explicit administrator review.
- [x] Reject duplicate, shadowed, ambiguous, unavailable, and unauthorized routes.
- [x] Reauthorize every route at call time independently of discovery filtering.

### P2-F004 - Protocol abuse and dependency controls

- [x] Reject stale/future timestamps and session-scoped request-ID or nonce replay.
- [x] Enforce rate and concurrency quotas for user, agent, client, session, server,
  tool, route, destination, and action family.
- [x] Bound payload/result size, depth, delegation, fan-out, concurrency, redirects,
  retries, and total execution time at admission and runtime.
- [x] Detect repeated request ancestry and equivalent route/destination/action cycles.
- [x] Propagate cancellation and deadlines, deny unavailable dependencies before work,
  open circuits, and audit all terminal outcomes.

### P2-F005 - Canonical normalization and immutable policy

- [x] Bind authenticated session, current route/schema/audience/scope, recomputed
  argument evidence, trusted resolver output, and call ancestry into canonical actions.
- [x] Keep unknown, partial, failed, unsupported, opaque, and dynamic actions on an
  approval-or-denial path without keyword-absence allows.
- [x] Classify production, privileged, destructive, credential-bearing, and difficult-
  to-reverse effects as Tier 3.
- [x] Compose deterministic policy, immutable denials, coverage, constraints, sandbox,
  trust, and supervisor evidence by most-restrictive-wins.
- [x] Prove equivalent effect treatment across tools, servers, aliases, paths,
  encodings, syntax, and transports.

### P2-F006 - Exact single-use human approval

- [x] Require one current explicit human approval for Tier 3 and reject persistent or
  always-allow decision shapes.
- [x] Bind approval to authenticated identity/session, canonical action, route, schema,
  audience, scope, resources, environment, data flow, and policy version.
- [x] Fail modified, expired, replayed, parallel, reordered, denied, invalidated, and
  concurrently consumed attempts without a second forwarding start.
- [x] Revalidate identity revision, route/schema/health, and current policy
  synchronously before process-local atomic consumption.
- [x] Keep tokens and credential material out of approval records, audit events,
  forwarding authorization metadata, and the disposable downstream request.

### P2-F007 - Exact forwarding and untrusted result mediation

- [x] Forward only the exact revalidated route, tool, and arguments once per consumed
  forwarding-attempt identifier.
- [x] Bind governed results to authenticated server, route, schema, request, action,
  session, and call-chain provenance.
- [x] Enforce response-byte limits, output-schema validation, secret redaction,
  data-egress disposition, and data-only treatment of untrusted content.
- [x] Suppress untrusted downstream errors and mark results, metadata, tool-derived
  instructions, and resource content as untrusted.
- [x] Deny or quarantine invalid, oversized, credential-classified, redirected,
  unauthenticated, and policy-disallowed results without positive trust eligibility.

### P2-F008 - PostgreSQL persistence and transactional audit

- [x] Apply checksummed forward-only migrations for every required Phase 2 trajectory,
  security, trust, coverage, supervisor, and recovery table with constraints and indexes.
- [x] Require an explicit reachable PostgreSQL dependency at startup without an
  in-memory runtime fallback.
- [x] Persist decisions, approval consumption and unique forwarding state, governed
  results, outcomes, and shadow trust evidence in database transactions.
- [x] Serialize cross-process approval consumption with row locks and preserve replay
  denial across store restart and multiple connections.
- [x] Hash-chain allowlisted correlated security events and reject event updates or
  deletion with a database trigger.
- [x] Reject configured known secrets before persistence, omit raw arguments/results,
  and verify no known secret across all persisted text, JSON, or array columns.

### P2-F015 - Authenticated client-facing tool discovery

- [x] Advertise the MCP tools capability only when a trusted discovery provider exists.
- [x] Invoke discovery only after authentication, session ownership, readiness, and
  negotiated protocol-version validation.
- [x] Use a gateway-generated discovery identifier and the current authenticated
  session binding; client parameters cannot choose policy scope or environment.
- [x] Revalidate `DiscoveryResultV1`, require the exact session and `UNPROTECTED`
  binding, cap output at one MiB, and emit gateway-owned untrusted-content markers.
- [x] Re-evaluate authorization on every list request and disclose no credential,
  audience, internal route, or schema-digest material.
- [x] Keep `tools/call` denied with protected forwarding disabled.

### P2-F016 - Client-facing tools/call composition

- [x] Traverse authenticated route resolution, protocol admission, canonicalization,
  deterministic policy, and PostgreSQL decision persistence.
- [x] Return canonical factual awareness for denied and approval-required calls with
  no downstream invocation.
- [x] Consume one exact approval durably before gateway credential use and forward once.
- [x] Govern and persist every downstream result or normalized terminal error before return.
- [x] Fail safely across dependency failure, cancellation, timeout, restart,
  route/schema drift, replay, concurrency, and non-ENFORCED coverage.

## Blocked

`P2-F018` cannot complete from repository fixtures or the existing local CLI smoke.
It requires authenticated connections to two named, independently operated
non-production MCP hosts that can each complete benign and adversarial operational
workflows, plus a genuinely independent reviewer. The prepared evidence contracts
reject fixture authentication, reused operators or authorities, incomplete workflow
classes, trajectory collisions, and self-authorized residual risk. No acceptance
criterion is complete yet.

## Next queued work

1. Complete `P2-F018` with two named independently operated non-production MCP hosts,
   adaptive repeated trials, and a genuinely independent reviewer.
2. Run named-host trials and independent review, then complete deployment and release
   evidence. Keep the runtime `UNPROTECTED` until every gate passes.
3. Preserve the advisory supervisor's default-disabled, fail-safe behavior.

## Current coverage

| Scope | State | Reason |
|---|---|---|
| MCP traffic | `UNPROTECTED` | Authenticated loopback lifecycle, request/result guards, and PostgreSQL trajectory storage exist, but the client-facing lifecycle is still non-forwarding and exclusive mediation is unverified |
| Client identity | `UNPROTECTED` | PostgreSQL can retain bound identity/session metadata, but authentication and rotation behavior still use disposable fixture providers and are not wired to a production runtime |
| Discovery and routes | `UNPROTECTED` | Client-facing discovery is authenticated and registry-backed, but the registry and provider configuration remain disposable and are not yet administered or persisted by the live runtime |
| Tool calls | `UNPROTECTED` | PostgreSQL transactions now preserve decisions, approval consumption, and unique forwarding state across connections/restart, but forwarding remains an unwired disposable flow and bypass controls are incomplete |
| Tool results | `UNPROTECTED` | Governed provenance/results/outcomes and shadow trust evidence are transactionally durable, but are not wired to a protected client-facing path and exclusive mediation is unverified |
| Human approval UI | `UNPROTECTED` | The functional authenticated browser application, durable PostgreSQL transitions, race/failure matrix, and production-shaped Vault/broker/exact-forwarder path are complete with disposable evidence, but deployment isolation is missing |
| Protected resources | `UNPROTECTED` | The monitor and disposable assurance workflow exist, but deployment network/IAM/sandbox/OS/downstream probes and production credential custody are not configured |

## Known risks

| Risk | Required response |
|---|---|
| Scaffold is mistaken for protection | Continue reporting `UNPROTECTED` and forward no protected traffic |
| Discovery metadata or results carry prompt injection | Treat both as untrusted and mediate the response path |
| Trusted resolver maps equivalent resources inconsistently | Keep resolver identity route-pinned, fail unresolved analysis closed, and expand category-specific alias tests before forwarding |
| Replay, flooding, or recursion exhausts the gateway | Complete `P2-F004` before downstream forwarding |
| Approval context is model-controlled | Generate summaries only from validated canonical data |
| Generated approval wireframe is mistaken for a working control | Track `P2-F020` separately and require authenticated browser-to-PostgreSQL end-to-end evidence |
| MCP is bypassed by native/direct access | Require gateway-held credentials and independent network/IAM/OS controls |
| Dynamic trust weakens policy | Keep trust in shadow mode until the promotion gate passes |

## Validation evidence

The current root scaffold must continue to pass:

- `npm run build`
- `npm run lint`
- `npm run typecheck`
- `npm test`
- `npm run test:integration`
- `npm run validate:features`

Validation is cumulative. Each progress entry must distinguish focused tests,
cumulative milestone tests, integration tests, actual workflow validation, full root
commands, and tests that could not be run.

## Progress update format

Add entries below in reverse chronological order:

```text
### YYYY-MM-DD - FEATURE-ID - Short result
- Status: planned | in_progress | blocked | complete
- Acceptance criteria addressed: exact criteria exercised by this work
- Focused tests: changed behavior and failure branches
- Cumulative tests: completed features/milestones revalidated
- Integration tests: real disposable component boundaries exercised
- Actual workflow: real protocol/UI workflow exercised, or "Not run" with reason
- Full validation: build, lint, typecheck, unit, integration, and feature validation
- Coverage: resulting ENFORCED/DEGRADED/OBSERVE_ONLY/UNPROTECTED scope and reason
- Remaining: exact unfinished work, or "None"
- Risks: new or changed risks, or "None"
- Next action: exact first task for a fresh session
```

## Update log

### 2026-09-18 - P2-F020 - Browser/PostgreSQL race and failure matrix revalidated

- Status: `complete`; all six acceptance criteria remain supported by disposable
  browser and PostgreSQL evidence
- Acceptance criteria addressed: reran the authenticated browser path for reload,
  duplicate/two-tab concurrent decisions, durable single consumption, expiry,
  coverage revocation, provider failure, governed-result quarantine, and durable
  outcome display; added explicit stale-human-authority browser evidence
- Focused tests: 5 approval-focused unit/integration files passed 33 tests; the final
  Chromium matrix passed 4 workflows. The first browser run after adding the stale-
  authority case failed only because the test expected the internal session wording;
  the boundary intentionally returned the safer normalized message `Approval decision
  is unavailable`. The assertion was corrected without changing runtime behavior, and
  the complete browser matrix reran successfully.
- Integration tests: the stale-authority workflow opens a live approval under an
  authorized PostgreSQL session, removes that exact scope grant, attempts `Approve
  once`, observes a normalized denial, and verifies the approval remains `PENDING`
  with zero forwarding attempts. Stale coverage separately produces durable
  `REVOKED`; expiry produces durable `EXPIRED`; concurrent tabs produce one downstream
  attempt; provider failure produces `UNKNOWN` with possible partial effects; invalid
  result schema produces a quarantined governed result.
- Actual workflow: real headless Chromium drove the HTTPS approval UI against
  disposable PostgreSQL, the approved Vault adapter, non-exporting broker, exact HTTP
  forwarder, downstream authenticator, and result guard
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`
  (32 files/295 tests), `npm run test:integration` (15 files/66 tests),
  `npm run test:browser` (4 workflows), and `npm run validate:features` (21 records)
  passed
- Coverage: `UNPROTECTED`; all evidence remains disposable, and no production
  isolation, independently operated host, credential-custody, or bypass-control proof
  was added. Protected deployment forwarding remains disabled.
- Remaining: none for `P2-F020`; `P2-F018` remains blocked on two independently
  operated hosts and an independent reviewer, and `P2-F019` remains dependency-blocked
- Risks: provider failure after consumption remains conservatively `UNKNOWN` with
  possible partial effects; result quarantine does not imply a failed downstream effect
- Next action: obtain connection/authentication details for two independently operated
  non-production MCP hosts plus an independent reviewer, then execute `P2-F018`

### 2026-09-16 - P2-DOC-001 - Beginner project handbook added

- Status: `complete`; documentation scope only, with no runtime or coverage change
- Result: added root `handbook.md` as a plain-English guide to MCP concepts, project
  goals and non-goals, threats, security invariants, request flow, risk tiers,
  canonicalization, identity, routing, approval, result mediation, PostgreSQL,
  coverage, trust, supervisor behavior, testing, repository layout, setup, commands,
  workflows, safe contribution, failure behavior, feature status, remaining work,
  troubleshooting, FAQ, glossary, and authoritative references
- Beginner safeguards: separates implementation evidence from production protection,
  explains why coverage remains `UNPROTECTED`, labels disposable workflows accurately,
  and warns against production credentials and resources
- Documentation integration: linked the handbook from the root and docs README files
  and recorded it in the completed documentation feature evidence
- Validation: all 24 handbook links resolved; build, lint, typecheck, 32 unit files/
  295 tests, 15 integration files/66 tests, dashboard generation, and all 21 feature
  records passed. Browser tests were not rerun because no browser behavior changed
- Coverage: `UNPROTECTED`; explanatory documentation creates no enforcement guarantee
- Remaining: none for the handbook request
- Risks: the handbook is intentionally introductory; the technical specification and
  live feature/progress records remain authoritative when implementation changes
- Next action: keep the handbook synchronized whenever architecture, commands, feature
  status, or production-readiness evidence changes

### 2026-09-16 - P2-F018 - Two open-source MCP servers exercised locally

- Status: `blocked`; the smoke improves interoperability evidence but completes none
  of the three acceptance criteria
- Acceptance criteria addressed: selected separately maintained open-source MCP
  implementations, pinned their registry versions and integrity hashes, and exercised
  real initialize, initialized, tools/list, harmless tools/call, and unknown-tool
  rejection over MCP stdio
- Implementation: `npm run mcp-servers:verify:disposable` launches the MIT-licensed
  MCP Everything reference server `2026.8.31` and Apache-2.0 Microsoft Playwright MCP
  `0.0.81` with a sanitized environment, bounded output and timeouts, disposable
  loopback content, exact package pins, and no production credentials
- Actual workflow: Everything advertised 13 tools and completed `get-sum`; Playwright
  advertised 26 tools and navigated isolated headless Chrome to a disposable loopback
  page; both rejected an unknown tool. A SHA-256-bound artifact was retained at
  `artifacts/open-source-mcp-smoke.json` with scope `LOCAL_INTEROPERABILITY_ONLY`,
  `independentlyOperated: false`, and coverage `UNPROTECTED`
- Focused validation: `node --check scripts/verify-open-source-mcp-servers.mjs` and the
  complete disposable smoke passed; package metadata was verified from the npm
  registry and official source repositories
- Cumulative validation: build, lint, typecheck, 32 unit files/295 tests, 15
  integration files/66 tests, and all 21 feature records passed; the prior `P2-F020`
  Chromium matrix remains current and was not rerun because this slice does not alter
  the browser UI or protected runtime
- Coverage: `UNPROTECTED`; these are locally launched downstream servers, not two
  independently operated MCP hosts, and the smoke does not traverse the protected runtime
- Remaining: all `P2-F018` criteria, including real independently operated host
  trajectories, adaptive paired trials through the runtime, and independent review
- Risks: package provenance and separate upstream maintainers do not establish
  independent operation; treating this local smoke as acceptance evidence would be a
  false readiness claim
- Next action: obtain two externally operated non-production host connections and an
  independent reviewer, then run the prepared operational evidence path

### 2026-09-16 - P2-F018 - External blocker reverified and dashboard handoff reconciled

- Status: `blocked`; none of the three acceptance criteria is complete
- Acceptance criteria addressed: verified that the named-host, paired adaptive-trial,
  and independent-review evidence contracts remain executable and fail safely, while
  confirming that no real host configuration, retained operational trajectory, or
  completed independent review has appeared in the repository
- Status correction: the live dashboard now reports completed `P2-F020` browser
  evidence as `TESTED`, removes the obsolete instruction to implement that feature,
  and points from blocked `P2-F018` to dependency-blocked `P2-F019`
- Focused tests: 4 files/18 tests passed for the dashboard evidence boundary and all
  three `P2-F018` evidence contracts; `node --check` also passed
- Cumulative tests: `npm run dashboard:build` and `npm run validate:features` passed
  for all 21 feature records; the full runtime ladder was not rerun because this slice
  changed status presentation only and the 2026-09-16 full validation remains current
- Actual workflow: not run; two authenticated independently operated non-production
  MCP hosts and an independent reviewer are still unavailable
- Coverage: `UNPROTECTED`; no forwarding, deployment, credential, or review claim changed
- Remaining: all `P2-F018` criteria
- Risks: local fixtures, Inspector/mcp-cli discovery smoke, or project self-review must
  not be relabelled as independent operational or review evidence
- Next action: provide connection and authentication details for two independently
  operated non-production MCP hosts plus the independent reviewer's identity/contact
  path, then execute the prepared evidence workflows

### 2026-09-16 - P2-F020 - Functional approval and audit browser workflow completed

- Status: `complete`; all six acceptance criteria pass with disposable browser,
  PostgreSQL, Vault-provider, and downstream evidence
- Acceptance criteria addressed: live canonical data; independent human/session/scope
  authority; same-origin, CSRF, ETag, and client-authority protection; exact controls;
  durable single transition/forwarding; outcome, recovery, coverage, audit, and result
  disposition display; complete positive and fail-closed automated workflows
- Implementation: browser sessions can be safely resumed across reloads and tabs by
  revalidating the existing HttpOnly session together with its exact CSRF binding;
  selected approval IDs are navigation state only and reload through the authorized
  server boundary. Stale-state reconciliation retains its visible warning. A strict
  result summary binds `resultId`, disposition, schema verdict, and processing time to
  the durable outcome without exposing raw result content.
- Focused tests: 4 affected Vitest files/19 tests passed for web boundary, protected
  runtime, PostgreSQL UI state, and approval execution; the complete unit suite passed
  32 files/295 tests
- Cumulative tests: all 15 integration files/66 tests passed against disposable HTTP,
  PostgreSQL, dispatch, result-mediation, and recovery boundaries
- Actual workflow: 4 Chromium workflows passed for keyboard denial; Vault-backed
  approval; reload/reconnect plus duplicate and two-tab concurrent approval with one
  downstream attempt; expiry and stale-coverage revocation with zero forwarding; and
  provider failure plus invalid-result quarantine
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, `npm run test:browser`, and
  `npm run validate:features` passed after correcting one pre-existing redundant
  approved-provider guard reported by lint
- Coverage: `UNPROTECTED`; the workflows use disposable authentication, Vault response,
  downstream server, PostgreSQL, and coverage evidence and do not establish production
  credential custody or exclusive mediation
- Remaining: none for `P2-F020`; `P2-F018` remains externally blocked and `P2-F019`
  retains deployment isolation, signing, SBOM, recovery, and production release gates
- Risks: provider failure after the non-exporting lease enters forwarding remains
  conservatively `UNKNOWN` with possible partial effects; quarantined result content is
  not released even though the downstream execution outcome itself is `COMPLETED`
- Next action: obtain two independently operated non-production MCP hosts and a
  genuinely independent reviewer, then execute the prepared `P2-F018` evidence path

### 2026-09-14 - P2-F020 - Vault-backed governed browser approval completed

- Status: `in_progress`; the first successful end-to-end browser `Approve once` path
  is complete
- Acceptance criteria addressed: exact approval authority reaches credential issuance;
  one non-exporting Vault-backed lease authorizes one exact downstream attempt; the
  authenticated result is schema checked, governed, persisted, and displayed
- Security correction: `issueCredentialLease` now receives the executor-generated
  `ApprovedForwardingAuthorizationV1`. A lease cannot be issued without the exact
  approval id, action hash, route, audience, endpoint, session, and durable forwarding
  attempt; route substitution is rejected before provider or downstream I/O
- Focused tests: 3 unit files/28 tests passed for executor ordering, credential broker
  binding, and protected runtime composition; the complete unit suite passed 32 files/
  295 tests
- Cumulative tests: all 15 integration files/66 tests passed against disposable HTTP
  and PostgreSQL boundaries
- Integration tests: the existing PostgreSQL approval, dispatch, restart, concurrency,
  and terminal-outcome suite remained green
- Actual workflow: two Chromium tests passed. The new workflow loaded live canonical
  PostgreSQL state, approved once, decrypted the stored request, consumed the approval,
  fetched one exact Vault revision through the approved provider boundary, sent one
  credentialed downstream request, governed the authenticated result, persisted a
  `COMPLETED` outcome, and displayed `Consumed`, `Completed`, and `Irreversible`
- Full validation: build, lint, typecheck, unit, integration, browser, and all 21
  feature records passed
- Coverage: `UNPROTECTED`; the browser, Vault response, human identity, downstream,
  and coverage evidence are disposable and do not prove deployment isolation or
  production credential custody
- Remaining: reload, duplicate-click, multi-tab/concurrent consumption, reconnect,
  expiry, revocation, stale authority/coverage, provider failure, result failure, and
  protected deployment-isolation evidence
- Risks: the exact forwarder relies on trusted current-route, downstream-authentication,
  output-schema, classification, and egress adapters supplied by the protected runtime;
  deployment configuration must bind those adapters to durable approved authorities
- Next action: add the browser/PostgreSQL reload and multi-tab/concurrent-consumption
  slice, then continue through expiry, revocation, stale authority, and provider/result
  failure behavior

### 2026-09-14 - P2-F020 - Durable approval dispatch and crash recovery completed

- Status: `in_progress`; the crash/restart portion of the fourth acceptance criterion is complete
- Acceptance criteria addressed: approval and dispatch commit atomically; the runtime
  claims before session resolution; concurrent workers recover one stale dispatch;
  unconsumed approvals revoke with zero forwarding; consumed ambiguous attempts become
  terminal `UNKNOWN` and are never retried
- Focused tests: 3 files/23 tests passed, including claim-before-resolution failure,
  migration constraints/triggers, restart-style recovery, two-worker serialization,
  durable audit, no forwarding for unclaimed approval, and no retry after consumption
- Cumulative tests: 32 unit files/294 tests and 15 integration files/66 tests passed
- Integration tests: disposable PostgreSQL applied migration `0010`; approval and
  outbox were committed together, and recovery persisted approval/dispatch/forwarding/
  outcome/recovery/audit state under real row locks
- Actual workflow: the Chromium live canonical keyboard-denial workflow passed; a full
  browser APPROVE success workflow remains outstanding
- Full validation: build, typecheck, lint, unit, integration, browser, and all 21
  feature records passed
- Coverage: `UNPROTECTED`; recovery correctness does not supply production credentials,
  downstream isolation, or protected forwarding authority
- Remaining: approved production credential/forwarder providers and the complete
  successful APPROVE, race, reconnect, expiry, revocation, stale-state, and failure
  browser/integration matrix
- Risks: recovery deliberately records consumed calls with missing outcomes as
  `UNKNOWN` and possible partial effects; it cannot prove whether the downstream effect
  occurred and therefore must not retry it
- Next action: compose the approved production-shaped credential broker and exact
  downstream forwarder, then exercise one governed APPROVE success through the browser

### 2026-09-12 - P2-F018 - External evidence blocker confirmed

- Status: `blocked`; none of the three acceptance criteria is complete
- Acceptance criteria addressed: audited the first criterion's executable prerequisites
  and the prepared contracts for named-host, repeated-trial, and independent-review
  evidence
- Focused tests: 3 evidence-boundary files/13 tests passed, covering independent host
  identities and operators, authenticated HTTPS adapters, benign/adversarial workflow
  completeness, trajectory uniqueness, paired baseline/defense trials, digest and
  authority substitution, reviewer independence, remediation, and residual-risk
  authorization
- Cumulative tests: full root validation passed after the status reconciliation: build,
  lint, typecheck, 31 unit files/283 tests, 13 integration files/60 tests, and all 21
  feature records
- Integration tests: the existing disposable HTTP and PostgreSQL integration suite
  passed; it does not constitute independently operated host or reviewer evidence
- Actual workflow: not run; the available Inspector and mcp-cli smoke reached only
  initialization and discovery against the fixture gateway, while the criterion
  requires authenticated benign and adversarial operational trajectories from two
  independently operated hosts
- Coverage: `UNPROTECTED`; no forwarding, approval, deployment, or protection claim
  changed
- Remaining: all `P2-F018` criteria—two-host operational workflows, adaptive paired
  trials with retained trajectories, and genuine independent review with remediation
  or separately authorized residual-risk disposition
- Risks: treating local fixture/CLI smoke or self-review as independent evidence would
  create a false production-readiness claim
- Next action: provide connection and authentication details for two independently
  operated non-production MCP hosts and the identity/contact path of an independent
  reviewer, then run the prepared evidence workflows

### 2026-09-12 - P2-F017 - HashiCorp Vault provider completed

- Status: `complete`; all four acceptance criteria are now supported
- Provider decision: the project owner approved the recommended HashiCorp Vault
  default for protected downstream credentials
- Implementation: the KV v2 adapter accepts a canonical field-bound reference,
  requires HTTPS outside explicit disposable loopback tests, requests one exact
  revision, checks the returned revision, rejects redirects and malformed/substituted
  responses, bounds response bytes, and zeroizes provider token buffers
- Focused tests: `test/unit/hashicorp-vault-provider-v1.test.ts` passed 3 tests covering
  exact retrieval, missing versions/fields, revision substitution, redirects,
  malformed references, remote plaintext rejection, and token zeroization
- Actual workflow: checksum-verified HashiCorp Vault 1.21.1 ran in in-memory dev mode
  on loopback; `npm run vault:verify:disposable` seeded a random KV v2 value, retrieved
  version 1 through the adapter and non-exporting broker, and delivered it only to one
  exact disposable route/audience/origin-bound HTTP request
- Full validation: build, lint, typecheck, 31 unit files/283 tests, 13 integration
  files/60 tests, and all 21 feature records passed
- Coverage: `UNPROTECTED`; Vault dev mode is intentionally insecure and disposable and
  does not prove production TLS, policies, token custody, HA, isolation, or bypass control
- Remaining: none for `P2-F017`; production deployment assurance remains in `P2-F019`
- Next action: continue `P2-F018` with two independently operated local MCP host
  products and retain real repeated-trial trajectories; independent review remains a
  later human evidence gate

### 2026-09-12 - P2-F018 - Independent-review evidence boundary prepared

- Status: `in_progress`; no acceptance criterion is complete because external host and
  reviewer evidence has not been produced
- Slice implemented: a strict V1 review report binds the reviewer and organization,
  independence declaration, source revision, source/runtime/configuration digests,
  reviewed scopes, findings, remediation evidence, disposition, and separately owned
  residual-risk authorization into a canonical digest
- Fail-safe behavior: open material findings force `REJECTED`; accepted risk requires
  an authorization record whose owner is not the reviewer; remediation cannot be
  claimed without evidence; forged report fields fail digest validation
- Focused tests: `test/unit/independent-security-review-v1.test.ts` passed 3 tests
- Full validation: build, lint, typecheck, 30 unit files/280 tests, 13 integration
  files/60 tests, and all 21 feature records passed. The first integration run shared
  the host with five parallel validation commands and hit the existing protocol-guard
  timing bound; the isolated full integration rerun passed.
- Actual workflow: not run; no two named independently operated MCP hosts or independent
  reviewer were supplied, and disposable fixtures cannot be relabelled as that evidence
- Host interoperability smoke: after the owner authorized recommended local defaults,
  the official `@modelcontextprotocol/inspector` CLI and independently maintained
  `@wong2/mcp-cli` both initialized and listed tools through the real loopback gateway.
  Attempts to call an absent tool were rejected by the clients, so this does not count
  as the required benign/adversarial operational-runtime criterion.
- Coverage: `UNPROTECTED`; the slice validates evidence shape only and enables no
  forwarding, deployment, approval, or production claim
- Remaining: execute benign and adversarial workflows through two named independent
  hosts; retain adaptive paired trial trajectories; obtain and remediate or formally
  disposition a genuine independent review
- Next action: obtain authorization and connection details for two non-production MCP
  hosts and the identity of an independent reviewer, then run the prepared evidence path

### 2026-09-12 - P2-F020 - Functional approval UI added to the feature graph

- Status: `planned`
- Reconciliation: `P2-F010` is now explicitly the completed host-neutral interface
  model, not a rendered production UI; the architecture, plan, README files, report,
  release dependency graph, and dashboard evidence are being aligned to that boundary
- Acceptance criteria added: live canonical pending-approval data; independent human
  authentication and scope authorization; CSRF/origin/session/replay protection; exact
  `Approve once` and `Deny` only; durable reload/expiry/revocation/multi-tab/concurrency
  semantics; governed outcome/recovery/audit display; accessibility; and automated
  browser plus complete end-to-end execution evidence
- Dependency graph: `P2-F020` depends on `P2-F010`, `P2-F016`, and `P2-F017`;
  production-candidate feature `P2-F019` now also depends on `P2-F020`
- Full validation after reconciliation: build, lint, typecheck, 29 unit files/277
  tests, 13 integration files/60 tests, and all 21 feature records passed
- Tracker after reconciliation: 17 of 21 features complete; 87 of 101 acceptance
  criteria complete; one feature is blocked and three are planned
- Coverage: `UNPROTECTED`; this change creates requirements only and enables no UI,
  approval, forwarding, credential, or deployment path
- Remaining: all six `P2-F020` acceptance criteria
- Risk: until the feature is implemented, only the informational dashboard is runnable;
  report approval screens remain wireframes
- Next action: finish the `P2-F017` secret-manager adapter, then implement the smallest
  authenticated pending-approval list/detail/decision slice for `P2-F020`

### 2026-09-11 - P2-F017 - Three production-provider criteria completed

- Status: `blocked`; 3 of 4 acceptance criteria complete
- Acceptance criteria completed: protected runtime identity with durable rotation and
  revocation; authenticated durable versioned audited server/route/schema/policy
  administration; fail-safe required analyzer activation and unknown-syntax handling
- Identity evidence: the Streamable HTTP boundary now awaits async authenticators and
  derives normalized certificate facts only from `TLSSocket`; the mutual-TLS provider
  checks TLS 1.2/1.3, client-auth EKU, certificate validity, fingerprint binding, and
  a fresh active PostgreSQL credential revision on every request
- Durability evidence: migrations `0005` and `0006` add append-only protected identity,
  administration-version, and audit records; embedded PostgreSQL tests prove atomic
  registration/rotation/revocation, stale and concurrent rejection, exact versioning,
  authenticated authorization, and cross-kind integrity
- Runtime evidence: `npm run gateway:serve:protected` uses HTTPS with mandatory client
  certificates and CA validation, requires PostgreSQL, contains no fixture/bearer
  fallback, and was observed refusing startup when required TLS configuration was absent
- Credential foundation: the protected broker requires an explicitly `APPROVED`
  provider descriptor, retrieves one exact revision only at use time, binds short
  leases to session/audience/route/origin, never returns material, and zeroizes buffers
- Analyzer evidence: all eleven mandated categories are explicit; production activation
  refuses an incomplete set, while missing/mismatched analyzers, unknown operation,
  syntax/version, failure, partial output, or substitution are quarantined with unknown
  effect
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  and `npm run test:integration` passed; 27 unit files/263 tests and 13 integration
  files/58 tests passed
- Tracker at that checkpoint: 17 of 20 features complete; 87 of 95 acceptance criteria
  complete; the later `P2-F020` reconciliation increases the active graph to 21
  features and 101 criteria
- Coverage: `UNPROTECTED`; protected forwarding remains disabled
- Remaining blocker: select, approve, configure, and exercise one concrete external
  secret manager. The provider-neutral broker and mock tests do not constitute that
  external operational evidence.
- Next action: obtain the operator's secret-manager choice and configuration, implement
  its adapter, and exercise exact-revision retrieval through the protected runtime;
  P2-F018 then requires two named independent MCP hosts and an independent review

### 2026-09-11 - P2-F017 - Protected identity profile decision required

- Status: blocked on a material identity-authority choice; no criterion is complete.
- Reconciliation: `docs/plan.md` now identifies `P2-F017` instead of completed
  `P2-F016` as the current feature.
- Observed state: the live non-production entrypoint hardcodes TEST_FIXTURE bearer
  authentication; transport/session invalidation is process-local; existing identity
  rows are trajectory snapshots rather than an authoritative revocation registry.
- Recommended profile: mutual TLS with an operator-owned CA. The TLS boundary validates
  chain, EKU, validity, and peer identity; a SHA-256 certificate fingerprint maps to a
  durable PostgreSQL identity revision. Rotation inserts revision N+1, revokes the old
  revision and active sessions/approvals, freezes trust, and remains effective across
  processes and restart.
- Alternatives: signed token/OIDC requires selecting and trusting an external issuer;
  Windows process/SID peer identity alone is not a sufficiently portable Node/Express
  boundary for the current architecture.
- Validation: `npm run validate:features` passed for all 20 records; runtime commands
  were not rerun because no implementation changed.
- Coverage: `UNPROTECTED`; no production identity claim is made.
- Next action: obtain the provider-profile decision, then implement migration 0005,
  protected identity/store adapters, async transport authentication, real TLS and
  PostgreSQL restart/rotation tests, and fail-closed runtime configuration.

### 2026-09-11 - P2-F016 - Client-facing call composition completed

- Status: complete; all five acceptance criteria pass with disposable evidence.
- Acceptance criteria addressed: dependency failure, cancellation, timeout, restart,
  route/schema drift, and non-ENFORCED coverage fail safely across the composed path.
- Focused tests: coordinator/executor tests cover cancellation and timeout during
  asynchronous coverage without late persistence, trusted continuation aborts,
  consumption-before-credential ordering, lease failure, transport uncertainty, and
  safe terminal outcomes.
- Integration tests: real Streamable HTTP propagates client disconnect cancellation;
  client-facing dependency failure returns only generic admission failure and persists
  no decision; PostgreSQL restart/concurrency/replay and newest-assessment coverage
  tests deny additional forwarding; real registry drift tests quarantine changed schema.
- Actual workflow: disposable MCP initialization and `tools/call` prove UNPROTECTED
  denial and dependency failure; a separate trusted approval continuation consumes one
  synthetic exact-scope approval, sends one vault-credentialed HTTP call, mediates and
  persists its result, and rejects replay.
- Cumulative/full validation: `npm run build`, `npm run lint`, `npm run typecheck`,
  23 unit files/229 tests, 11 integration files/50 tests, and validation of all 20
  feature records passed.
- Coverage: `UNPROTECTED`; synthetic DISPOSABLE_TEST enforcement cannot establish
  deployment identity, credential custody, isolation, or bypass prevention.
- Remaining: None for `P2-F016`.
- Risks: the production runtime still needs protected identity, secret-manager,
  administration, and category-resolver adapters; approval continuation is a trusted
  host-neutral boundary rather than a production human UI transport.
- Next action: start `P2-F017` with the protected runtime identity-provider boundary
  and durable rotation/revocation state.

### 2026-09-11 - P2-F016 - Governed result and error persistence completed

- Status: in_progress; four of five acceptance criteria are complete.
- Acceptance criteria addressed: every downstream result or normalized error is bound,
  governed, persisted, and only then safely released or withheld.
- Focused tests: 7 coordinator/executor tests passed, including a partial-effect
  transport failure that persisted an `UNKNOWN` terminal outcome before returning no
  downstream content.
- Integration/actual workflow: the approved disposable HTTP workflow now runs through
  ClientApprovedCallExecutorV1, transactionally persists provenance/result/completed
  outcome after mediation, returns only DATA_ONLY untrusted content, and denies replay.
- Cumulative/full validation: `npm run build`, `npm run lint`, `npm run typecheck`,
  23 unit files/224 tests, 11 integration files/49 tests, and validation of all 20
  feature records passed.
- Coverage: globally `UNPROTECTED`; the end-to-end execution uses only synthetic
  disposable exact-scope enforcing evidence.
- Remaining: actual client-facing failure workflows for dependency failure,
  cancellation, timeout, restart, route/schema drift, and non-ENFORCED coverage.
- Risks: persistence failure after a downstream effect intentionally withholds the
  result and leaves the consumed approval non-reusable; operational reconciliation is
  required in the final failure slice.
- Next action: implement the final failure-workflow matrix and complete `P2-F016` only
  if the full root ladder and actual disposable workflows pass.

### 2026-09-11 - P2-F016 - Exact durable approved forwarding completed

- Status: in_progress; three of five acceptance criteria are complete.
- Acceptance criteria addressed: one exact approved request is consumed and forwarded
  once through gateway-held credentials, with durable replay and concurrent-use denial.
- Focused tests: 6 coordinator/executor tests passed for canonical admission,
  consumption-before-credential ordering, losing-consumption denial, persistence
  failure, authority substitution, and non-allow awareness.
- Integration tests: 14 PostgreSQL tests passed, including cross-connection single
  consumption, restart replay denial, a real credential-vault-to-HTTP execution, and
  newest-coverage-assessment revalidation.
- Actual workflow: a disposable approved request was loaded by approval ID and
  authenticated session, consumed under PostgreSQL row lock, issued one non-exporting
  route lease, and caused exactly one downstream HTTP request; replay caused none.
- Security correction: coverage consumption now selects the newest exact-scope record
  before checking `ENFORCED` freshness. A regression test proves a newer UNPROTECTED
  assessment blocks forwarding despite an older still-valid ENFORCED record.
- Cumulative/full validation: `npm run build`, `npm run lint`, `npm run typecheck`,
  23 unit files/223 tests, 11 integration files/49 tests, and validation of all 20
  feature records passed.
- Coverage: globally `UNPROTECTED`; only synthetic disposable exact-scope ENFORCED
  evidence permits the test workflow, and no production provider or bypass proof exists.
- Remaining: persist and return/withhold governed results and errors; actual workflow
  failure evidence for dependency failure, cancellation, timeout, restart, drift, and
  non-ENFORCED coverage.
- Risks: approved state is loaded through an injected trusted provider; production
  approval UI/authentication and durable provider adapters remain future work.
- Next action: compose governed result/error and outcome persistence into the approved
  continuation before any downstream content is returned.

### 2026-09-11 - P2-F016 - Canonical non-allow awareness completed

- Status: in_progress; two of five acceptance criteria are complete.
- Acceptance criteria addressed: denied and approval-required client-facing calls
  return factual awareness without invoking a downstream tool.
- Focused tests: 4 coordinator unit tests passed for durable denial, persistence
  failure, authority substitution, and synthetic enforced exact-approval awareness.
- Integration tests: the PostgreSQL persistence file passed 13 tests, including the
  real loopback initialize/initialized/tools-call denial with canonical awareness.
- Actual workflow: a disposable MCP HTTP client received a canonical `DENY` summary,
  exact `UNPROTECTED` coverage gap, safe no-effect alternative, and zero downstream
  invocation after decision persistence.
- Cumulative/full validation: `npm run build`, `npm run lint`, `npm run typecheck`,
  23 unit files/221 tests, 11 integration files/48 tests, and validation of all 20
  feature records passed.
- Coverage: `UNPROTECTED`; this slice adds explanation only and never forwards or
  exposes approval or credential material.
- Remaining: exact durable approval and one-time forwarding; governed result/error
  persistence; dependency failure, cancellation, timeout, restart, drift, and
  non-ENFORCED actual-workflow evidence.
- Risks: the runtime still requires injected coverage assessment and other disposable
  providers; production adapters and exclusive-mediation evidence do not exist.
- Next action: compose exact PostgreSQL-backed approval consumption and one-time
  forwarding, retaining replay/concurrency denial and `UNPROTECTED` fail-closed state.

### 2026-09-08 - P2-F016 - Durable client-facing decision admission completed

- Status: in_progress; the first of five acceptance criteria is complete.
- Acceptance criteria addressed: every client-facing `tools/call` traverses
  authenticated current-route/schema resolution, protocol admission, canonicalization,
  deterministic policy, and PostgreSQL decision persistence.
- Focused tests: 3 coordinator tests passed for the full ordered decision path,
  fail-closed persistence failure with protocol reservation release, and rejection of
  a route that does not match server-configured scope/name authority.
- Integration tests: the PostgreSQL persistence suite passed 13 tests, including a
  real loopback initialize/initialized/tools-call workflow that persisted the exact
  Tier 3 `UNPROTECTED` denial before response.
- Actual workflow: a disposable MCP HTTP client completed the client-facing workflow;
  the response reported `DENY`, `UNPROTECTED`, and `downstreamInvoked: false`.
- Cumulative tests: 23 unit files/220 tests and 11 integration files/48 tests passed;
  all 20 Phase 2 feature records validated.
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed.
- Coverage: `UNPROTECTED`; the slice invokes no downstream tool and adds no production
  identity, credential custody, route administration, or exclusive-mediation evidence.
- Remaining: canonical awareness, exact approval, one-time forwarding, governed result
  and error persistence, cancellation/timeout/restart/drift failure workflows.
- Risks: dependency health is injected into the process-local protocol guard; production
  adapters and durable protocol state remain required.
- Next action: build the denied/approval-required response from canonical
  `TrustworthyInterfaceBuilderV1` awareness and prove zero downstream invocation.

### 2026-09-07 - P2-F016 - Strict tools/call admission seam added

- Status: in_progress
- Acceptance criteria addressed: strict client-facing request parsing and authenticated
  current-session binding before adapter dispatch; no downstream forwarding.
- Focused tests: real HTTP tests cover valid authenticated calls, rejection of client-
  selected scope fields, and preservation of the existing denied-call behavior when
  no adapter is configured.
- Cumulative tests: `npm run build`, `npm run lint`, `npm run typecheck`, and the
  discovery/call integration file passed.
- Actual workflow: not rerun after this transport-only seam; the live service remains
  non-forwarding and its smoke contract is unchanged.
- Full validation: full unit/integration suites and feature validation remain to be
  rerun after durable orchestration is added.
- Coverage: `UNPROTECTED`; no credentials are forwarded and no protected path is
  enabled.
- Remaining: compose route resolution, protocol guard, canonical policy, PostgreSQL
  denial persistence, approval, forwarding, result mediation, and outcomes.
- Risks: an adapter must implement durable admission/policy checks; the transport
  intentionally does not infer them.
- Next action: implement the adapter against `DisposableProtocolGuardV1`,
  `CanonicalActionNormalizerV1`, `DeterministicPolicyEngineV1`, and
  `PostgresTrajectoryStoreV1`, keeping all non-ENFORCED decisions denied.

### 2026-09-07 - P2-F015 - Authenticated client-facing discovery completed

- Status: complete; `P2-F016` is the next dependency-ready operational feature
- Result: the Streamable HTTP adapter conditionally advertises `tools/list`, invokes an
  injected discovery provider only after current authentication/session/readiness/
  protocol checks, validates the exact session and `UNPROTECTED` result binding, limits
  serialized discovery output to one MiB, and emits only MCP tool fields plus
  gateway-owned untrusted-content and call-time-authorization markers. The live
  non-production service uses the existing registry with a fixed empty test scope.
- Focused validation: 4 focused files and 64 tests passed for lifecycle negotiation,
  adversarial ordering, authenticated HTTP discovery, per-request authorization
  revocation, strict parameter rejection, safe provider failure, output limits,
  metadata isolation, and continued call denial.
- Cumulative validation: build, lint, typecheck, 22 unit files/217 tests, 11 integration
  files/46 tests, and all 20 Phase 2 feature records passed.
- Actual workflow: `npm run gateway:serve` plus `npm run gateway:smoke` completed invalid
  authentication, initialize, initialized notification, registry-backed `tools/list`
  (HTTP 200), denied `tools/call`, and verified zero downstream calls.
- Coverage: `UNPROTECTED`; discovery is real but uses fixture authentication and an
  empty disposable registry. The client-facing call, approval, forwarding, result,
  and PostgreSQL orchestration remains unwired.
- Not run: non-production release preparation, Docker deployment verification, SBOM,
  manifest regeneration, signing, publication, and production deployment were outside
  this feature and remain release-gated.
- Repository state: this workspace is not a Git repository, so no commit or source
  revision attestation is available.
- Exact next action: implement `P2-F016` beginning with strict client-facing
  `tools/call` parsing, current route resolution, deterministic policy evaluation, and
  transactional persistence of every denial before response.

### 2026-09-06 - Release-gate audit - non-production release preparation verified

- Status: complete for the automated local release-preparation slice; production-
  candidate release gates remain blocked
- Acceptance criteria addressed: one-command cumulative validation; hardened
  disposable container deployment; real authentication/lifecycle/tool-call smoke;
  manifest and local-image identity verification; reproducible output; sanitized
  local evidence refresh
- Focused tests: the deployment verifier built and inspected a uniquely named
  disposable container with `network=none`, zero published ports, read-only root
  filesystem, dropped capabilities, `no-new-privileges`, and a non-root user
- Cumulative tests: build, lint, typecheck, 21 unit files/210 tests, 10 integration
  files/40 tests, all 15 feature records, a 66-file package boundary, a 274-component
  CycloneDX 1.5 SBOM, and high-severity dependency audit with zero vulnerabilities
  passed
- Integration tests: the complete 40-test suite passed against disposable HTTP and
  PostgreSQL boundaries; the hardened Docker image built successfully
- Actual workflow: the container smoke rejected invalid credentials, completed MCP
  initialize/initialized, rejected `tools/call` on the non-forwarding path, and
  reported `UNPROTECTED` with zero downstream calls; the exact smoke container was
  removed by the verifier
- Full validation: `npm run release:prepare:non-production` passed; the generated
  release manifest verified 40 file hashes plus local image identity; two clean builds
  matched across 171 generated files; `npm run evidence:capture` refreshed sanitized
  loopback telemetry and manifest evidence
- Coverage: `UNPROTECTED`; the image and evidence are disposable local artifacts and
  do not establish production identity, credential custody, exclusive mediation, or
  independent bypass controls
- Remaining: independent review, production identity and gateway-held credential
  custody, deployment isolation evidence, named-host/adaptive repeated trials, signed
  artifacts/SBOM, and exercised production recovery/rollback evidence
- Risks: the repository is not a Git checkout, so revision-based source attestation
  and rollback evidence remain unavailable; npm reported a deprecation warning for the
  installed ESLint version during image construction, although the audit found no
  vulnerabilities
- Packaging reconciliation: `.npmignore` now excludes `paper/` and local `tmp/`
  rendering scratch; the package verifier rejects either class in the runtime tarball;
  and the release manifest binds both `.npmignore` and
  `scripts/verify-package-boundary.mjs`. The focused release-input test and the complete
  release-preparation ladder passed after this change.
- Research artifact: `paper/main.tex` and `paper/references.bib` provide a four-page
  IEEEtran manuscript preview compiled to `paper/main.pdf` with Tectonic 0.17.0 and
  visually inspected page by page. It reports only disposable-fixture evidence,
  synthetic adapters, non-forwarding runtime behavior, and `UNPROTECTED` production
  coverage; author, venue, anonymity, and stronger publication-grade experiments remain
  required before submission.
- Next action: have an independent reviewer execute
  `docs/security-review-packet.md` and record a disposition; do not sign, publish,
  change coverage, or deploy to production without the remaining evidence and explicit
  approval

#### Post-validation Docker recurrence

- The complete release-preparation command passed, including Docker build, hardened
  container inspection, real MCP smoke, manifest verification, and container cleanup.
- A later final `npm run evidence:capture` attempt failed because the Docker Linux
  engine had stopped. Read-only inspection confirmed that
  `C:/Users/radhi/AppData/Local/Docker/run/dockerInference` is again a zero-length
  `ReparsePoint` with no reported target.
- Current Docker Desktop 4.69.0 backend logs repeatedly show the inference manager
  failing while removing that exact Unix-socket entry, followed by a backend crash.
  This is the immediate startup cause; WSL or virtualization failure was not indicated
  by the observed error path.
- The stored `artifacts/local-evidence.json` is stale relative to the final manifest
  because the post-change capture did not succeed. Do not use it as current evidence.
- Exact next action: with Docker Desktop fully stopped, remove only the malformed
  `dockerInference` runtime entry, restart Docker, confirm `docker version` has a server
  response, then rerun `npm run release:verify` and `npm run evidence:capture`. Factory
  reset is not required for this diagnosis and risks deleting Docker state.
- Authorized repair attempt: Docker Desktop and `com.docker.backend` were confirmed
  stopped, and the exact target was revalidated as a non-directory, zero-byte reparse
  point with no reported target. Non-elevated `Remove-Item` was blocked by host policy;
  `fsutil reparsepoint delete` and a recoverable `Move-Item` both failed because Windows
  returned error 1920; and `chkdsk C: /scan` required elevation. Nothing was deleted or
  renamed, Docker remains stopped, and images, volumes, and the simulated database were
  not changed.
- Updated unblocking action: reboot with Docker auto-start disabled, then use an
  elevated PowerShell prompt to remove only the exact `dockerInference` entry before
  starting Docker. If error 1920 persists, run elevated `chkdsk C: /scan` and follow
  its repair recommendation before retrying. Do not use factory reset unless Docker
  data is backed up and the targeted filesystem repair has failed.
- Resolution: elevated `chkdsk C: /scan` completed with no filesystem errors or bad
  sectors. With Docker stopped, the user removed the stale `dockerInference`,
  `userAnalyticsOtlpHttp.sock`, and `docker-secrets-engine/engine.sock` AF_UNIX socket
  entries; all three then tested absent. `docker desktop start` succeeded,
  `docker desktop status` reported `running`, and `docker version` reported both Client
  and Server 29.4.0. `npm run release:verify` again verified 40 file hashes plus local
  image identity, and `npm run evidence:capture` refreshed sanitized local evidence.
  No factory reset occurred and existing Docker images, volumes, and the simulated
  database were preserved.

### 2026-09-05 - P2-F014 - Provider-neutral advisory supervisor completed

- Status: complete
- Acceptance criteria addressed: minimal redacted/delimited inputs; strict versioned
  advisory output and append-only audit; deterministic fail-safe fallback on timeout,
  invalid output, low confidence, provider failure, and audit failure; global and exact
  policy-scope external-submission disablement
- Focused tests: 4 unit tests passed for redaction and delimiter injection, strict
  output/input binding, no-authorization advisory behavior, all fallback statuses,
  disabled precedence, resolved-action skip, and audit failure; 2 HTTP integration
  tests passed for valid and malformed disposable providers
- Cumulative tests: all 209 unit tests across 20 files passed
- Integration tests: all 40 integration tests across 10 files passed, including the
  PostgreSQL migration, exact supervisor audit binding, restart readback, duplicate
  denial, append-only trigger, and known-secret scan
- Actual workflow: a loopback HTTP provider received one redacted unresolved-action
  request, returned a strict advisory, and produced no downstream tool call; malformed
  and globally disabled paths retained deterministic denial
- Full validation: build, lint, typecheck, unit, integration, feature validation, and
  dependency audit passed; all 15 feature records validated and zero vulnerabilities
  were reported
- Release preparation: `npm pack --dry-run` now contains only the active Phase 2
  package (41 files); the archived `phase-1/` tree, tests, generated output, and source
  PDFs are excluded by `.npmignore`. Nothing was published.
- Coverage: `UNPROTECTED`; supervisor output is advisory-only, external submission is
  disabled by default, client-facing MCP remains non-forwarding, and no deployment
  protection claim is made
- Remaining: all tracked Phase 2 features are complete; production-candidate release
  gates still lack client-facing exclusive mediation, independent deployment controls,
  signed artifacts/SBOM, and operational recovery evidence
- Risks: provider adapters and verifier/audit sinks are disposable or caller-supplied;
  digests detect mutation but cannot establish provider honesty or production isolation
- Next action: perform the release-gate audit and prepare only approval-gated, disposable
  evidence; do not connect production resources or change coverage without explicit user
  approval

### 2026-09-05 - P2-F013 - Dynamic-trust shadow experiment completed

- Status: complete
- Acceptance criteria addressed: shadow-only baseline authorization; paired repeated
  comparison of static policy, policy plus awareness, and bounded trust; immutable
  Tier 2/3, denial, unknown, production, and degraded-coverage exclusions; latched
  audit-gap, identity, route, schema, anomaly, and missing-outcome freezes; predefined
  attack, false-allow, completion, approval, latency, coverage, and grinding thresholds
- Focused tests: 6 dynamic-trust tests passed for 90 paired observations across three
  arms, evidence/report integrity, passing and failing promotion gates, shadow decision
  immutability, mature scope-bound positive evidence, every required freeze, runtime
  disposable-only enforcement, and action/decision trajectory substitution denial
- Cumulative tests: all 205 unit tests across 19 files passed
- Integration tests: all 37 integration tests across 9 files passed against the
  existing disposable HTTP and PostgreSQL boundaries; no new external trust provider
  or production authorization integration was claimed
- Actual workflow: the disposable host-neutral experiment evaluated 30 paired trials
  per arm, promoted only the passing counterfactual profile, retained deterministic
  policy as authoritative, and rejected security, coverage, grinding, utility, and
  boundary-integrity failures
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; all 15 Phase 2
  feature records validated
- Coverage: `UNPROTECTED`; dynamic trust is a host-neutral research component, its
  promoted output is counterfactual and disposable-only, and it creates no production
  authorization or exclusive-mediation claim
- Remaining: None for `P2-F013`
- Risks: supplied trial observations and verifier assertions remain trusted evaluation
  inputs whose digests detect mutation rather than dishonest evidence; production
  trust influence remains intentionally disabled
- Next action: implement `P2-F014` provider-neutral redacted advisory supervisor with
  strict schema validation, audit evidence, fail-safe fallback, and a global/scope
  external-submission disable switch

### 2026-09-04 - P2-F012 - Multi-host concurrency validation completed

- Status: complete
- Acceptance criteria addressed: two distinct host adapters completed equivalent
  policy-controlled workflows; concurrent and historical session, identity, route,
  quota, approval, trust, result, and audit isolation; per-host failure, latency,
  completion, approval/error, policy-violation, and coverage metrics; separate native
  and direct bypass inventories structurally prohibited from claiming gateway protection
- Focused tests: 2 multi-host integration tests passed for three concurrent repetitions,
  canonical policy equivalence, exact metric aggregation, evidence/report digest
  integrity, and deliberate cross-host compartment collision rejection
- Cumulative tests: all 199 unit tests across 18 files passed
- Integration tests: all 37 integration tests across 9 files passed
- Actual workflow: two distinct disposable host adapters issued six real MCP
  `initialize` requests to an ephemeral loopback HTTP peer across three concurrent
  repetitions and returned equivalent approval-required observations with isolated
  compartment evidence
- Full validation: build, lint, typecheck, unit, integration, feature validation, and
  dependency audit passed; all 15 feature records validated and zero vulnerabilities
  were reported
- Coverage: `UNPROTECTED`; disposable host adapters and evidence validation do not prove
  production-host interoperability, exclusive deployment mediation, or native/direct
  bypass prevention
- Remaining: None for the scoped `P2-F012` validation harness; named production-host
  certification remains deployment evidence, not a gateway-protection claim
- Risks: adapters can report fabricated state unless their evidence producers are bound
  to trusted host instrumentation; digest integrity detects mutation, not dishonesty
- Next action: implement `P2-F013` dynamic trust in shadow mode with repeated comparison,
  immutable exclusions, anomaly freezes, and explicit promotion thresholds

### 2026-09-04 - P2-F011 - Seeded adversarial evaluation harness completed

- Status: complete
- Acceptance criteria addressed: complete protocol, policy-invariance, content, and
  human/trust attack-class catalogs; deterministic repeated trials; evidence-bound
  observations; prevention, attack/baseline success, risk ratio, safe completion,
  false allow/denial, latency distribution, cost, approval, re-planning, and coverage
  metrics
- Focused tests: 3 harness tests passed across all 30 required attack classes for
  catalog completeness, missing-class rejection, deterministic seeds/results/digests,
  repeated trials, exact metric aggregation, and contradictory observation rejection
- Cumulative tests: all 199 unit tests across 18 files passed; the existing focused
  component tests retain concrete coverage of the cataloged protocol, canonicalization,
  content, approval, identity, audit, coverage, concurrency, and TOCTOU controls
- Integration tests: all 35 integration tests across 8 files passed against disposable
  HTTP peers and PostgreSQL; no new external benchmark integration was claimed
- Actual workflow: the seeded runner executed 93 evidence-bound trials in two identical
  runs and produced byte-equivalent trial sequences and report digests
- Full validation: build, lint, typecheck, unit, integration, feature validation, and
  dependency audit passed; all 15 feature records validated and zero vulnerabilities
  were reported
- Coverage: `UNPROTECTED`; an evaluation harness measures evidence but does not establish
  deployment mediation or isolation
- Remaining: None for `P2-F011`
- Risks: deterministic assertion evidence is lower fidelity than disposable workflow or
  human-validated evidence and must remain distinguishable in published results
- Next action: implement `P2-F012` two-host equivalent workflows and concurrent isolated
  session metrics with separate native/direct bypass inventories

### 2026-09-04 - P2-F010 - Trustworthy approval, awareness, audit, and recovery completed

- Status: complete
- Acceptance criteria addressed: canonical-data-only approval context; requester,
  server/tool/route, targets, data flow, parser provenance, risk, reversibility, blast
  radius, related attempts, coverage, missing guarantees, and partial-effect display;
  factual structured awareness and evaluated no-effect/exact-approval alternatives;
  recovery classification; strict rejection of bulk/always-allow fields; scoped
  approval-fatigue counters and latency
- Focused tests: 4 interface tests passed for complete canonical presentation,
  action/coverage/outcome substitution denial, degraded-coverage awareness, recovery
  context, approval metrics, and strict bulk/persistent control rejection
- Cumulative tests: all 196 unit tests across 17 files passed
- Integration tests: all 35 integration tests across 8 files passed; real PostgreSQL
  applied the third migration, retained interface/fatigue/recovery records across store
  restart, and enforced append-only storage
- Actual workflow: the disposable exclusive-mediation workflow produced a canonical
  Tier 3 approval view and factual awareness, recorded presentation, one-second human
  response latency and a related attempt, then completed one mediated request; its next
  degraded assessment still denied any additional request
- Full validation: build, lint, typecheck, unit, integration, and feature validation
  passed; all 15 Phase 2 feature records validated
- Coverage: `UNPROTECTED`; interface presentation does not expand authorization or
  establish production mediation
- Remaining: None for `P2-F010`
- Risks: the host-neutral view is not a rendered production UI; canonical references
  are displayed by design and a deployment may require additional role-based redaction;
  the client-facing runtime remains non-forwarding
- Next action: start `P2-F011` with seeded protocol, policy-invariance, prompt/content,
  and human/trust evaluation suites

### 2026-09-04 - P2-DOC-001 - Autonomous project execution configured

- Status: complete
- Acceptance criteria addressed: durable project execution across dependency-ready
  features; accountable technical-lead integration; architecture, development, test,
  review, and release roles; collision-safe parallel delegation; material-decision
  approval gates; interruption recovery; verifiable project-level completion
- Focused tests: an independent read-only agent reviewed instruction and feature-tracking
  consistency; its two completion-loop ambiguities were corrected, and it found no
  security-invariant or `P2-F009` handoff conflict; no runtime code changed
- Cumulative tests: not rerun because this change affects agent operating documentation,
  not gateway behavior
- Integration tests: not applicable to the documentation-only operating contract
- Actual workflow: created one active durable goal for Phase 2 completion and one hourly
  task heartbeat that resumes incomplete work, stays quiet without meaningful change,
  and does not bypass pending human approval
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed after the final
  operating-contract and completion-loop reconciliation; 173 unit and 32 integration
  tests passed, and all 15 Phase 2 feature records validated
- Coverage: `UNPROTECTED`; agent workflow configuration does not establish gateway
  mediation or bypass controls
- Remaining: None for the autonomous operating contract
- Risks: work cannot execute while usage is unavailable; the heartbeat retries after
  availability but does not create compute during an exhausted usage window; parallel
  agents consume additional usage and therefore remain limited to useful independent work
- Next action: resume `P2-F009` at independent bypass-control evidence and scoped
  fail-closed coverage diagnostics

### 2026-09-04 - P2-F009 - Exclusive mediation and truthful coverage completed

- Status: complete
- Acceptance criteria addressed: gateway-only credential-consuming boundary; explicit
  independent network, IAM, sandbox, OS, and downstream-authorization guarantees;
  separate gateway-mediated, native, and direct path states; immediate fail-closed
  mutation recheck; exact missing-guarantee diagnostics
- Focused tests: 19 unit tests passed for complete evidence, every path state, missing,
  stale, failed, untrusted, future, rolled-back, equivocating, throwing, and timed-out
  evidence, deterministic ordering/digest, deployment rejection of fixture evidence,
  action/scope substitution, policy denial, and time-of-check/time-of-use degradation
- Cumulative tests: all 192 unit tests across 16 files passed, retaining every completed
  protocol, identity, routing, policy, approval, forwarding, result, and persistence path
- Integration tests: a disposable loopback peer denied an unauthenticated direct
  `tools/call` with zero mutations, accepted one exact internally credentialed and
  mediated gateway request under explicitly `DISPOSABLE_TEST` evidence, then observed
  zero additional mutations after a direct-network probe became `REACHABLE`; real
  PostgreSQL 18.4 tests persisted and reloaded a scoped report across store restart,
  rejected report mutation, and hash-chained the degradation as `BYPASS`
- Actual workflow: the coverage-bound evaluator produced `ENFORCED` only from the full
  disposable evidence set, the pre-mutation guard re-collected the same evidence before
  credential use, and the next changed evidence revision produced `DEGRADED`, an exact
  `coverage.network_isolation.reachable` diagnostic, policy `DENY`, and no second call
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 192 unit and 34
  integration tests passed, all 15 Phase 2 feature records validated, and `npm audit`
  reported zero known vulnerabilities
- Coverage: `UNPROTECTED`; test-fixture evidence is explicitly barred from deployment
  assurance, and the current runtime has no production network/IAM/sandbox/OS probes,
  production credential custody, or client-facing protected forwarding
- Remaining: None for the host-neutral `P2-F009` capability; operators must supply real
  deployment probes and isolation before any scope may truthfully become `ENFORCED`
- Risks: authority names and proof digests are correlation/integrity fields, not a
  substitute for authenticated deployment adapters; evidence revision watermarks are
  process-local in the monitor and durable recovery must use the PostgreSQL records;
  the only safe credential-consuming integration is the immediate recheck wrapper
- Next action: implement `P2-F010` canonical approval/awareness/audit/recovery interfaces

### 2026-09-04 - P2-F008 - PostgreSQL persistence and transactional audit completed

- Status: complete
- Acceptance criteria addressed: checksummed forward-only schema with all required
  tables, constraints, indexes, and append-only trigger; explicit fail-closed PostgreSQL
  startup; transactional request/decision, approval/forwarding, result/outcome/trust
  linkage; cross-connection and restart-safe single consumption; hash-chained correlated
  security events; centralized known-secret persistence denial
- Focused tests: 2 new persistence unit tests and 8 real-PostgreSQL integration tests
  passed for missing/invalid/unreachable database configuration, migration idempotency,
  required schema/index/trigger inventory, atomic decision persistence, raw-argument
  omission, digest and stored-approval binding revalidation, immutable-conflict rollback,
  known-secret rejection and catalog-wide scan,
  parallel approval consumption, restart replay, result/outcome/trust linkage rollback,
  complete HTTP trajectory storage, audit correlation, chain verification, and mutation
  rejection
- Cumulative tests: all 173 unit tests across 15 files passed, retaining all completed
  request, policy, approval, forwarding, and result-mediation behavior
- Integration tests: all 32 tests across 7 files passed; PostgreSQL tests launched a
  real disposable PostgreSQL 18.4 engine, and the complete workflow also used a real
  ephemeral HTTP downstream peer
- Actual workflow: a synthetic `ENFORCED` fixture persisted its authenticated identity,
  route/schema, request, canonical action, and decision; stored one human approval;
  atomically consumed it into one forwarding attempt; sent one exact credentialed HTTP
  `tools/call`; mediated the authenticated result; and transactionally linked provenance,
  result, completed outcome, shadow-only trust evidence, and hash-chained audit. A second
  connection and a restarted store could not consume the approval again.
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; `npm audit` also
  reports zero known vulnerabilities after updating the transitive `qs` resolution
- Coverage: `UNPROTECTED`; durable storage is now evidenced, but authentication,
  registries, policy dependencies, and downstream verification remain disposable
  fixtures, the client-facing lifecycle is non-forwarding, and independent network/IAM/
  sandbox/OS/downstream controls have not established exclusive mediation
- Remaining: None for `P2-F008`
- Risks: production PostgreSQL still requires operational TLS, roles, backup, retention,
  monitoring, and deployment hardening; the embedded PostgreSQL package and binaries are
  development-only test dependencies; application-level hash chaining detects mutation
  but production key anchoring or external transparency remains future hardening
- Next action: start `P2-F009` by modeling independent bypass-control evidence and
  computing scoped fail-closed coverage diagnostics for protected resources

### 2026-09-04 - P2-F007 - Exact forwarding and untrusted result mediation completed

- Status: complete
- Acceptance criteria addressed: exact revalidated route/tool/argument forwarding once;
  authenticated server, request, action, session, route, schema, and call-chain
  provenance; response-size and output-schema enforcement; centralized secret
  redaction and egress disposition; explicit data-only handling for untrusted results,
  metadata, descriptions, errors, and resource content; deny/quarantine outcomes made
  ineligible for positive trust evidence
- Focused tests: 11 new forwarding/result integration tests passed for exact request
  shape and route-scoped credential injection, duplicate attempt denial, modified-
  argument pre-forward denial, malicious instruction and metadata marking, nested
  secret redaction, invalid-schema quarantine, tool-error suppression, egress denial,
  unredacted credential quarantine, authenticated-server mismatch, redirect refusal,
  response-size enforcement, and cancellation
- Cumulative tests: all 171 unit tests across 14 files passed; the existing exact-
  approval integration was upgraded to pass its consumed authorization through the
  new forwarding and result-mediation boundary
- Integration tests: all 24 tests across 6 files passed against real ephemeral loopback
  HTTP servers
- Actual workflow: using a synthetic `ENFORCED` disposable fixture—not current gateway
  coverage—one authenticated human approval was atomically consumed, one exact
  `tools/call` was sent with a route/audience/profile/origin-bound vault credential,
  the server result was authenticated and governed, and only an explicitly untrusted
  data-only result was released; replay generated no second downstream request
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records
- Coverage: `UNPROTECTED`; forwarding state is process-local, PostgreSQL transactions
  are absent, downstream authentication and schema checks are injected disposable
  fixtures, independent bypass controls are absent, and the client-facing lifecycle
  still advertises no operational tools and forwards no protected traffic
- Remaining: None for the disposable `P2-F007` boundary; durable exactly-once state,
  transactional audit/outcomes, and restart or multi-process guarantees belong to
  `P2-F008`
- Risks: the injected route resolver, downstream authenticator, schema validator, and
  egress classifier must be production-grade trusted dependencies; origin pinning does
  not establish exclusive mediation; process-local forwarding-attempt state cannot
  prevent replay after restart or across gateway processes
- Next action: start `P2-F008` with forward-only PostgreSQL migrations and transactional
  request-to-outcome linkage, failing startup when durable persistence is unavailable

### 2026-09-04 - P2-F006 - Exact single-use human approval completed

- Status: complete
- Acceptance criteria addressed: mandatory current approval for Tier 3 without an
  always-allow shape; exact identity/session/action/route/schema/resource/environment/
  data-flow/policy binding; safe modified, expired, replayed, parallel, reordered, and
  concurrent handling; immediate policy/route/identity revalidation; no approval
  material exposed to the model, client, or downstream fixture
- Focused tests: 14 new approval unit tests passed for exact proposal binding,
  authenticated human approval and denial, forbidden persistent controls, consumption
  ordering, expiry before and after approval, modified action/decision/session denial,
  16-way parallel consumption, identity/route/policy revalidation, session-invalidation
  revocation, failed-start non-reusability, protected audit reads, redacted allowlisted
  audit, enforced-coverage gating, lifetime bounds, and invalid contract states; all
  17 affected trajectory tests also passed
- Cumulative tests: all 171 unit tests across 14 files passed, retaining all completed
  Milestone 1 and `P2-F005` evidence
- Integration tests: all 13 tests across 5 files passed; the new approval integration
  test exercised one process-atomic consumption against a real ephemeral loopback HTTP
  server
- Actual workflow: using a synthetic `ENFORCED` disposable fixture—not current gateway
  coverage—one authenticated human approval was consumed before exactly one real HTTP
  `tools/call`; replay produced no second request, and captured downstream headers/body
  contained no approval identifier or approval metadata. The result was discarded by
  the test because governed result mediation belongs to `P2-F007`.
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records
- Coverage: `UNPROTECTED`; synchronous consumption is atomic only inside one process,
  the client-facing gateway is not wired to the approval service, PostgreSQL durability
  and a production human authenticator are absent, results are not governed, and
  protected forwarding remains disabled
- Remaining: None for the disposable `P2-F006` boundary; production-grade transaction
  and restart/multi-process guarantees remain explicitly assigned to `P2-F008`
- Risks: an injected human authenticator must verify the exact decision assertion;
  in-memory state cannot prevent replay across restart or multiple gateway processes;
  the forwarding-start callback must remain internal so approval metadata is never
  serialized downstream; a consumed record intentionally remains consumed after start
  failure, requiring a new human approval
- Next action: start `P2-F007` by connecting one consumed authorization to exact
  route-scoped fixture forwarding, then govern the complete untrusted result/error path
  before anything is returned to a client

### 2026-09-04 - P2-F005 - Canonical normalization and immutable policy completed

- Status: complete
- Acceptance criteria addressed: no keyword-absence allow path; approval or denial for
  unknown, partial, failed, unsupported, opaque, and dynamic actions; Tier 3 treatment
  for production, privileged, destructive, credential, and difficult-to-reverse
  effects; equivalent decisions across tools, servers, aliases, paths, encodings,
  syntax, and transports; immutable denial and Tier 3 resistance to trust/supervisor
  allow advice
- Focused tests: 11 new canonical-policy unit tests passed for authenticated route and
  call-chain binding, forged session/route/schema/digest/size denial, resolver failure,
  reference normalization, safe-read and unknown fallback, all Tier 3 classes,
  most-restrictive composition, immutable/advisory bypass resistance, representation
  equivalence, conflicting sandbox denial, and non-enforced mutation denial; all 17
  affected trajectory-contract tests also passed
- Cumulative tests: all 157 unit tests across 13 files passed, retaining all completed
  Milestone 1 evidence
- Integration tests: all 12 tests across 4 files passed; the authenticated downstream
  registry workflow now carries a real HTTP-discovered route through canonicalization
  and policy evaluation
- Actual workflow: a disposable authenticated HTTP MCP peer was initialized and
  discovered, its verified route was resolved at call time, a request was normalized,
  current `UNPROTECTED` coverage produced `DENY`, and the peer observed zero
  `tools/call` requests
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records
- Coverage: `UNPROTECTED`; category resolvers and policy state are process-local test
  infrastructure, no decision transaction exists, exact approval is absent, results
  are not mediated, and protected forwarding remains disabled
- Remaining: None for `P2-F005`
- Risks: semantic alias identity and category semantics depend on trusted resolver
  correctness; path case-folding assumes ordinary Windows case-insensitive behavior;
  canonical JSON byte evidence must be supplied from the trusted protocol adapter;
  policy decisions have no restart, concurrency, or tamper-evidence guarantee until
  PostgreSQL persistence is implemented
- Next action: start `P2-F006` by creating an exact action-bound approval proposal and
  atomic five-minute single-use consumption with immediate policy and route
  revalidation

### 2026-09-03 - P2-F004 - Protocol abuse and dependency controls completed

- Status: complete
- Acceptance criteria addressed: timestamp/request-ID/nonce freshness and replay;
  user, agent, client, session, server, tool, route, destination, and action-family
  quotas; payload/result/concurrency/depth/delegation/fan-out/redirect/retry/deadline
  bounds; recursive/cyclic ancestry denial; aborting cancellation, timeouts, dependency
  failure, circuit opening/recovery, and normalized audit evidence
- Focused tests: 24 new unit tests passed for stale and future timestamps, request and
  nonce replay, cross-session isolation, all nine rate dimensions, concurrency release,
  every admission/runtime bound, malformed checkpoint cleanup, effect recursion,
  cancellation, timeout, circuit denial/recovery, audit events, and legitimate success
- Cumulative tests: all 146 Milestone 1 unit tests across 12 files passed
- Integration tests: all 12 tests across 4 files passed; the added protocol-guard test
  wrapped real ephemeral loopback HTTP requests and exercised bounded success,
  concurrent denial, propagated cancellation, deadline abort, and pre-network circuit
  denial
- Actual workflow: a disposable HTTP operation completed under the guard; a concurrent
  request was denied without exceeding configured capacity, cancelled and timed-out
  requests aborted their fetches, and an open downstream circuit produced zero HTTP
  requests while recording dependency denial
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records after final documentation reconciliation
- Coverage: `UNPROTECTED`; guard state and audit are disposable and process-local,
  trusted adapters do not yet feed protected operations, canonical authorization and
  PostgreSQL are absent, results are not mediated, and forwarding remains disabled
- Remaining: None for `P2-F004`; Milestone 1 criteria are complete
- Risks: redirect/retry/fan-out/result counters depend on trusted adapter checkpoints;
  in-memory replay, quota, circuit, and audit state cannot provide restart or
  multi-process guarantees; production must fail without durable coordinated state
- Next action: start `P2-F005` by canonicalizing resources, effects, environment, data
  flow, and route evidence, then implement immutable Tier 3 rules and deterministic
  most-restrictive policy with representation-equivalence tests

### 2026-09-03 - P2-F003 - Downstream discovery and routing integrity completed

- Status: complete
- Acceptance criteria addressed: deterministic authenticated server/route resolution;
  versioned and audited server identity, protocol, capability, tool-set, schema, and
  hash evidence; review-latched drift quarantine; safe duplicate, shadowed, ambiguous,
  unavailable, and unauthorized route failure; independent call-time authorization
- Focused tests: 7 new unit tests passed for administrator denial, computed evidence,
  authenticated observation, legitimate discovery and resolution, protocol/capability/
  tool/schema drift, cross-server and route collisions, atomic rejection, authorization
  revocation, unavailable servers, quarantine latching, and authorized review
- Cumulative tests: all 122 unit tests across 11 files passed
- Integration tests: all 11 tests across 3 files passed; the added registry integration
  test used an ephemeral authenticated loopback HTTP MCP peer and exercised initialize,
  tools/list, integrity verification, filtered discovery, resolution, call-time denial,
  live schema drift, and route removal
- Actual workflow: a disposable administrator registered one real HTTP MCP peer; its
  authenticated initialize and tools/list responses activated exactly one route, a
  later authorization revocation denied resolution despite prior visibility, and a
  changed live input schema latched quarantine and removed the route from discovery
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records after the final documentation reconciliation
- Coverage: `UNPROTECTED`; registry identity, state, audit, and downstream evidence are
  disposable and process-local, client-facing discovery remains disabled, and protocol
  guards, canonical policy, PostgreSQL, result mediation, protected forwarding, and
  independent bypass controls do not exist
- Remaining: None for `P2-F003`
- Risks: canonical digests prove equality only for the registry's bounded JSON
  representation; downstream descriptions and annotations remain untrusted; the
  injected authorizers/authenticators and in-memory audit are test boundaries, not
  production guarantees
- Next action: start `P2-F004` by implementing trusted request IDs, timestamps, nonces,
  bounded clock skew, and session-scoped replay caches before adding layered quotas,
  recursion, cancellation, deadlines, and circuit breakers

### 2026-09-03 - P2-F002 - Authenticated identity and session isolation completed

- Status: complete
- Acceptance criteria addressed: completed audience/route/session-bound short-lived
  credential handling without secret return; complete session compartment isolation;
  identity-rotation quarantine, trust freeze, active-state invalidation, and lease
  revocation; revalidated identity derivation outside untrusted MCP arguments
- Focused tests: 6 new unit tests passed across credential-vault and session-isolation
  suites, covering digest mismatch, audience/route/session mismatch, expiry, revocation,
  reference isolation, cross-session denial, state invalidation, accountability
  retention, trust freeze, and permanent quarantine
- Cumulative tests: all 115 unit tests across 10 files passed
- Integration tests: all 10 tests across 2 files passed against real ephemeral loopback
  HTTP servers; the added workflow exercised same-subject identity rotation through the
  authenticated transport and verified state quarantine plus credential-lease revocation
- Actual workflow: a disposable authenticated client initialized a real HTTP session,
  populated all six isolated compartments, and obtained a metadata-only credential
  lease; a rotated credential received 404, quarantined the session, cleared active
  state, retained results/audit, revoked the lease, and prevented the old credential
  from resuming the session
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records
- Coverage: `UNPROTECTED`; all identity, state, and credential evidence is disposable
  and process-local, and there is still no production identity provider, durable
  PostgreSQL repository, downstream route registry, authorization, forwarding, result
  mediation, or independent exclusive-mediation proof
- Remaining: None for `P2-F002`
- Risks: the vault deliberately has no credential-consuming forwarding sink; the
  administrative snapshot exposes only namespaces, reason codes, and compartment
  counts; process-local repositories must never become production persistence fallbacks
- Next action: start `P2-F003` by implementing an administrator-controlled authenticated
  downstream-server registry with pinned protocol versions and computed discovery
  integrity evidence, while protected forwarding remains disabled

### 2026-09-03 - P2-F002 - Authenticated session ownership boundary implemented

- Status: in_progress
- Acceptance criteria addressed: completed "Untrusted arguments cannot select or
  override identity" for the currently supported lifecycle transport; began session
  isolation and rotation-safe identity binding
- Focused tests: 5 identity unit tests passed for strict principal validation,
  credential-field rejection, opaque namespace derivation, reauthentication, identity,
  credential, and revision mismatch, and malformed session IDs; 8 HTTP integration
  tests passed for authentication-before-JSON, safe dependency failure, no identity or
  credential response disclosure, and cross-identity session denial
- Cumulative tests: all 109 Milestone 1 unit tests across 8 files passed
- Integration tests: all 9 tests across 2 files passed against real ephemeral loopback
  HTTP servers, including two authenticated fixture principals and isolated opaque
  sessions
- Actual workflow: a disposable authenticated client initialized a real HTTP session;
  a second identity copied its session ID and injected the owner's identifiers in MCP
  parameters but received the same 404 as an unknown session, while the owner remained
  active
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed after the final
  documentation reconciliation; feature validation confirmed 15 Phase 2 records
- Coverage: `UNPROTECTED`; the boundary uses injected `TEST_FIXTURE` authenticators and
  has no production identity provider, PostgreSQL repository, credential registry,
  route policy, result mediation, forwarding, or exclusive-access proof
- Remaining: audience/route-scoped credential profiles; complete per-session state
  repositories; identity-rotation invalidation and trust quarantine
- Risks: authentication output is trusted configuration input and therefore fails
  closed on schema drift or provider exceptions; fixture authentication must never be
  enabled as a production identity method; the current in-memory map is disposable and
  not a runtime persistence fallback
- Next action: implement a non-secret gateway credential-profile registry that binds
  profile IDs to one audience, an explicit route set, authenticated session ownership,
  and expiry without exposing credential values or enabling forwarding

### 2026-09-03 - P2-F001 - Disposable HTTP lifecycle workflow completed

- Status: complete
- Acceptance criteria addressed: MCP `2025-06-18` initialization and capability
  negotiation correctness; continued `UNPROTECTED`, non-forwarding behavior
- Focused tests: 13 lifecycle and posture unit tests passed; 5 disposable HTTP and
  posture integration tests passed, including the newly explicit missing negotiated
  protocol-version header rejection
- Cumulative tests: all 104 Milestone 1 unit tests across 7 files passed
- Integration tests: all 5 tests across 2 files passed against a real ephemeral
  loopback HTTP server; exercised initialization, initialized notification, ping,
  opaque session isolation, Origin/media/body/header rejection, GET 405, DELETE
  termination, and post-termination 404
- Actual workflow: a disposable MCP client completed the real Streamable HTTP
  lifecycle and verified that `tools/list` and `tools/call` return fail-closed
  unavailable-method errors without downstream forwarding
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; feature validation
  confirmed 15 Phase 2 records. The first cumulative run exposed four stale
  pre-transport posture assertions; they were corrected and the full ladder reran
  successfully.
- Coverage: `UNPROTECTED`; lifecycle traffic is accepted on the disposable loopback
  adapter, but client authentication, policy, persistence, result mediation,
  downstream credentials, forwarding, and exclusive-mediation controls do not exist
- Remaining: None for `P2-F001`
- Risks: the in-memory transport-session map is disposable lifecycle state, not an
  authenticated or durable session boundary; it must not be reused as the runtime
  identity repository or represented as protection
- Next action: start `P2-F002` by defining a trusted client-authentication boundary and
  binding its user, agent, client, and host identity to an isolated gateway session
  namespace outside model-controlled MCP arguments

### 2026-09-01 - P2-F001 - Non-forwarding MCP lifecycle core implemented

- Status: in_progress
- Acceptance criteria addressed: partial initialization and capability-negotiation
  correctness for MCP `2025-06-18`; protocol ordering, alternate-version selection,
  bounded open client capability handling, empty server capability advertisement,
  ping, duplicate initialization, non-forwarding operation, and shutdown
- Focused tests: 12 tests passed for official request/notification shapes, bounded
  additional capabilities, pre-normalization dangerous-key rejection, JSON-RPC version
  validation, ordered initialize/initialized transitions, alternate-version response,
  ping before initialization, pre-initialization operation denial, out-of-order
  notification silence, acknowledgement gating, duplicate initialization, empty
  capability advertisement, `tools/list` denial, closed state, and unchanged repository
  posture
- Cumulative tests: complete unit suite passed, 65 tests across 6 files
- Integration tests: repository security-posture suite passed, 1 test; the lifecycle
  reducer has no network transport or authenticated session boundary yet
- Actual workflow: Not run because no MCP transport is connected to the lifecycle core
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2
  feature records validated
- Coverage: `UNPROTECTED`; the pure reducer negotiates no operational capability,
  accepts no network traffic, holds no downstream credentials, and forwards nothing
- Remaining: disposable Streamable HTTP initialization adapter, session/header binding,
  actual client handshake, and negative proof that tool discovery/calls cannot forward
- Risks: lifecycle state is not yet transport/session isolated; payload timestamps,
  nonces, replay, quotas, authentication, and persistence remain future features;
  additional client capabilities are recorded as untrusted declarations and must never
  create authority
- Next action: connect the reducer to a disposable loopback-only Streamable HTTP
  initialization adapter without advertising or forwarding tools

### 2026-09-01 - P2-F001 - Protocol boundary envelopes and dispatch implemented

- Status: in_progress
- Acceptance criteria addressed: versioned discovery, raw tool-call, raw tool-result,
  provenance-adjacent result, normalized error, and awareness boundary validation;
  centralized unknown-kind, kind-confusion, unknown-field, and forward-incompatible
  version rejection; continued non-forwarding posture
- Focused tests: 14 tests passed for safe untrusted discovery, cross-scope and duplicate
  route rejection, pre-normalization prototype-key rejection, JSON depth bounds,
  credential-free tool-call shape, call-chain bounds, supported untrusted raw results,
  empty/unknown/falsely trusted result rejection, suppressed normalized errors, partial
  effect request binding, safe display text, factual non-allow awareness, coverage-gap
  disclosure, alternative uniqueness, centralized dispatch, kind confusion, version
  rejection, and unchanged `UNPROTECTED` posture
- Cumulative tests: complete unit suite passed, 53 tests across 5 files
- Integration tests: repository security-posture suite passed, 1 test; no real MCP
  transport, authenticated session, discovery registry, result guard, or persistence
  boundary exists yet
- Actual workflow: Not run because initialization, capability negotiation, and MCP
  transport are not implemented
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2
  feature records validated
- Coverage: `UNPROTECTED`; contracts accept and reject representations but do not
  authenticate, resolve routes, compute digests, enforce byte counts, authorize,
  mediate results, accept traffic, or forward calls
- Remaining: initialization, capability negotiation, and protocol conformance tests
- Risks: payload byte lengths and digests are asserted fields until trusted transport
  code computes them; text and structured content can still contain secrets or prompt
  injection and must not be released before result-guard processing; supported content
  types will need review against the negotiated MCP protocol version
- Next action: implement a non-forwarding MCP initialization state machine and strict
  capability negotiation with fail-safe ordering and version tests

### 2026-09-01 - P2-F001 - Request-to-outcome trajectory contracts implemented

- Status: in_progress
- Acceptance criteria addressed: canonical action, policy decision, exact approval,
  downstream provenance, governed result metadata, execution outcome, and complete
  trajectory portions of versioned schema validation; unknown-version rejection;
  continued non-forwarding posture
- Focused tests: 17 tests passed for safe read and exact Tier 3 trajectories, unresolved
  denial, Tier 3 invariants, degraded mutation denial, constrained and sandbox decision
  usability, action/route/schema mismatch, five-minute approval lifecycle, identity,
  resource, route, policy and forwarding-attempt tampering, prior atomic-consumption
  ordering, result quarantine/redaction, provenance and chronology, denied forwarding,
  unknown partial effects, version rejection, call-chain/data-flow/resource/influence
  integrity, secret removal, and unchanged `UNPROTECTED` posture
- Cumulative tests: complete unit suite passed, 39 tests across 4 files
- Integration tests: repository security-posture suite passed, 1 test; no real MCP,
  canonicalization, policy, approval, forwarding, result-guard, or persistence boundary
  exists yet
- Actual workflow: Not run because canonicalization, policy, approval persistence,
  forwarding, raw result mediation, and MCP transport are not implemented
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2 feature
  records validated
- Coverage: `UNPROTECTED`; contracts encode future security state but do not authenticate,
  authorize, persist, mediate, forward, or establish exclusive coverage
- Remaining: awareness, discovery, raw tool-call/result, and error envelopes;
  centralized version dispatch; initialization; capability negotiation; protocol
  conformance tests
- Risks: all hashes and trusted classifications are presently asserted contract fields,
  not values computed by trusted components. Schema lifecycle rules do not provide
  database atomicity, replay protection, current-time expiry enforcement, or downstream
  result filtering. Raw content remains outside this governed metadata contract.
- Next action: define strict discovery, tool-call, raw tool-result, gateway-error, and
  awareness envelopes, then route every boundary kind through centralized fail-safe
  schema-version dispatch

### 2026-09-01 - P2-F001 - Downstream server and route contracts implemented

- Status: in_progress
- Acceptance criteria addressed: `DownstreamServerV1` and `ToolRouteV1` portions of
  versioned boundary-schema validation; unknown-version rejection; capability and
  schema-drift quarantine; server, route, health, and credential-audience binding;
  scoped route-collision rejection; continued non-forwarding posture
- Focused tests: 13 tests passed for valid registration and binding, credential-field
  rejection, endpoint restrictions, unknown versions, capability/schema drift, missing
  observations, observation ordering, unknown mappings, server/audience mismatch,
  unhealthy-server activation, duplicate routes, ambiguous exposed names, independent
  scope usability, and unchanged `UNPROTECTED` posture
- Cumulative tests: complete unit suite passed, 22 tests across 3 files
- Integration tests: repository security-posture suite passed, 1 test; no real MCP,
  route-registry, authenticated-server, or persistence boundary exists yet
- Actual workflow: Not run because server registration, route registry, MCP transport,
  and initialization are not implemented
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2 feature
  records validated
- Coverage: `UNPROTECTED`; contracts represent registration and quarantine state but do
  not authenticate servers, compute trusted digests, select routes, authorize, or
  forward MCP traffic
- Remaining: action, decision, approval, result, provenance, outcome, awareness,
  discovery, call, and error contracts; centralized version dispatch; initialization;
  capability negotiation; protocol conformance tests
- Risks: URL shape validation is not SSRF policy; trusted registry code must resolve and
  constrain destinations. Schema and capability digests are recorded but not yet
  computed from authenticated discovery. Test-fixture authentication must never be
  accepted in production runtime configuration.
- Next action: define the remaining core action/decision/approval and
  result/provenance/outcome contracts as a coherent request-to-outcome trajectory

### 2026-09-01 - P2-DOC-001/P2-F001 - Governance consolidated and first contracts implemented

- Status: `P2-DOC-001` complete; `P2-F001` in_progress
- Acceptance criteria addressed: authoritative documentation consolidation; final
  MCP-only research direction; `GatewayClientV1` and `GatewaySessionV1` portions of
  versioned boundary-schema validation; unknown-version rejection for those contracts;
  continued non-forwarding `UNPROTECTED` posture
- Focused tests: 8 contract tests passed for valid clients/sessions, unknown versions,
  unknown fields, duplicate and malformed capabilities, invalid coverage, quota
  bounds, UTC timestamps, timestamp ordering, and non-forwarding posture
- Cumulative tests: complete unit suite passed, 9 tests across 2 files
- Integration tests: repository security-posture suite passed, 1 test; no real MCP or
  persistence boundary exists yet
- Actual workflow: Not run because MCP initialization and transport are not implemented
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2 feature
  records validated
- Coverage: `UNPROTECTED`; contracts validate data but do not authenticate, authorize,
  mediate, or forward MCP traffic
- Remaining: all other `P2-F001` schemas, global version-dispatch behavior, MCP
  initialization, capability negotiation, and protocol conformance tests
- Risks: schema parsing must not be mistaken for identity authentication; native local
  actions remain outside the gateway and invalidate exclusive-mediation claims when
  they can reproduce a protected effect
- Next action: implement strict `DownstreamServerV1` and `ToolRouteV1` contracts and
  their schema-drift, route-binding, credential-audience, and unknown-version tests

### 2026-08-29 - P2-DOC-001 - Cross-session execution loop standardized

- Status: complete
- Acceptance criteria addressed: fresh-session state reconstruction, dependency-aware
  work selection, cumulative testing, actual workflow validation, tracking, and handoff
- Focused tests: documentation structure and feature-schema validation
- Cumulative tests: active Phase 2 feature graph revalidated
- Integration tests: Not applicable to documentation-only behavior
- Actual workflow: reviewed the "continue work" path against current progress,
  features, milestones, and required commands
- Full validation: `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` passed; 15 Phase 2
  feature records validated
- Coverage: `UNPROTECTED`; documentation changes do not create runtime enforcement
- Remaining: None
- Risks: agents must still execute the documented loop; written instructions do not
  substitute for runtime controls or test infrastructure
- Next action: continue `P2-F001` at `GatewayClientV1` and `GatewaySessionV1`

### 2026-08-29 - P2-DOC-001 - Agent operating style standardized

- Status: complete
- Evidence: `docs/AGENTS.md` now defines the agent's security-engineering character,
  evidence-first decision model, standard task workflow, communication expectations,
  usability discipline, and session-independent use of active project documents
- Remaining: None
- Risks: Behavioral guidance improves consistency but cannot replace technical policy,
  tests, isolation, or runtime enforcement

### 2026-08-29 - P2-DOC-001/P2-F001 - Phase 2 security baseline established

- Status: `P2-DOC-001` complete; `P2-F001` in_progress
- Evidence: Phase 2-only technical specification, feature list, progress tracker,
  implementation plan, repository instructions, README, and research synthesis;
  `npm run build`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run test:integration`, and `npm run validate:features` pass; feature validation
  confirms 15 Phase 2 records with valid dependencies
- Remaining: implement all `P2-F001` contracts, protocol negotiation, and tests
- Risks: the gateway remains a non-forwarding `UNPROTECTED` scaffold
