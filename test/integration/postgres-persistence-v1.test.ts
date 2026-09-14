import { createHash } from "node:crypto";
import { createServer as createHttpServer, type IncomingMessage } from "node:http";
import { createServer as createNetServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import EmbeddedPostgres from "embedded-postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  AdvisorySupervisorV1,
  CanonicalActionNormalizerV1,
  ClientApprovedCallExecutorV1,
  ClientToolCallCoordinatorV1,
  PersistenceDeniedV1,
  DisposableCredentialVaultV1,
  DisposableExactForwarderV1,
  DisposableProtocolGuardV1,
  DeterministicPolicyEngineV1,
  PostgresTrajectoryStoreV1,
  SecretPersistenceDeniedV1,
  TrustworthyInterfaceBuilderV1,
  createInitializationHttpAppV1,
  computeCanonicalDigestV1,
  type CoveragePathKindV1,
  type MediationGuaranteeV1,
  type PostgresPersistenceConfigV1
} from "../../src/index.js";
import { DisposableMcpHttpClientV1 } from "../fixtures/disposable-mcp-http-client-v1.js";
import {
  createPostgresTrajectoryFixtureV1,
  type PostgresTrajectoryFixtureV1
} from "../fixtures/postgres-trajectory-v1.js";

const knownSecret = "known-database-secret-value";
let postgres: EmbeddedPostgres;
let store: PostgresTrajectoryStoreV1;
let config: PostgresPersistenceConfigV1;

const requiredCoverageGuarantees = {
  GATEWAY_MEDIATED: [
    "CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT",
    "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS",
    "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"
  ],
  NATIVE: ["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"],
  DIRECT: [
    "CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION",
    "DOWNSTREAM_AUTHORIZATION"
  ]
} as const satisfies Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>>;

async function persistEnforcedCoverage(
  target: PostgresTrajectoryStoreV1,
  candidate: PostgresTrajectoryFixtureV1
): Promise<void> {
  const resource = candidate.action.resources[0];
  if (resource === undefined) throw new Error("Coverage fixture requires a resource");
  const observedAt = new Date();
  const scope = {
    ...candidate.action.identity,
    stateNamespace: candidate.action.sessionId,
    ...candidate.action.route,
    credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
    environment: candidate.action.environment,
    resourceClass: resource.resourceClass,
    resourceId: resource.resourceId,
    resourcesDigest: candidate.action.resourcesDigest
  };
  const evidence = (Object.entries(requiredCoverageGuarantees) as Array<
    [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
  >).flatMap(([pathKind, guarantees]) => guarantees.map((guarantee) => ({
    schemaVersion: "1.0.0" as const,
    evidenceId: `persist-${candidate.action.actionId}-${pathKind}-${guarantee}`,
    guarantee,
    pathKind,
    verifierId: `persist-verifier-${pathKind}-${guarantee}`,
    authority: "postgres-test-authority",
    verifierClass: "TEST_FIXTURE" as const,
    assurance: "DISPOSABLE_TEST" as const,
    scope,
    status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
    revision: 1,
    observedAt: observedAt.toISOString(),
    expiresAt: new Date(observedAt.getTime() + 60_000).toISOString(),
    proofDigest: computeCanonicalDigestV1({ actionId: candidate.action.actionId, pathKind, guarantee })
  })));
  const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
    pathKind, coverage: "ENFORCED" as const, reasonCodes: []
  }));
  await target.persistCoverageAssessment({
    schemaVersion: "1.0.0",
    assessmentId: `persist-coverage-${candidate.action.actionId}`,
    revision: 1,
    assurance: "DISPOSABLE_TEST",
    scope,
    coverage: "ENFORCED",
    mutationAllowed: true,
    paths,
    missingGuarantees: [],
    evidence,
    evidenceDigest: computeCanonicalDigestV1({
      assurance: "DISPOSABLE_TEST", scope, coverage: "ENFORCED", paths,
      missingGuarantees: [], evidence
    }),
    assessedAt: observedAt.toISOString(),
    expiresAt: new Date(observedAt.getTime() + 60_000).toISOString()
  });
}

async function persistNewerUnprotectedCoverage(
  target: PostgresTrajectoryStoreV1,
  candidate: PostgresTrajectoryFixtureV1
): Promise<void> {
  const resource = candidate.action.resources[0];
  if (resource === undefined) throw new Error("Coverage fixture requires a resource");
  const assessedAt = new Date(Date.now() + 1_000);
  const scope = {
    ...candidate.action.identity,
    stateNamespace: candidate.action.sessionId,
    ...candidate.action.route,
    credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
    environment: candidate.action.environment,
    resourceClass: resource.resourceClass,
    resourceId: resource.resourceId,
    resourcesDigest: candidate.action.resourcesDigest
  };
  const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
    pathKind, coverage: "UNPROTECTED" as const,
    reasonCodes: ["coverage.network_isolation.reachable"]
  }));
  const missingGuarantees = [{
    guarantee: "NETWORK_ISOLATION" as const,
    pathKind: "DIRECT" as const,
    reasonCode: "coverage.network_isolation.reachable",
    verifierId: null
  }];
  await target.persistCoverageAssessment({
    schemaVersion: "1.0.0",
    assessmentId: `degraded-coverage-${candidate.action.actionId}`,
    revision: 2,
    assurance: "DISPOSABLE_TEST",
    scope,
    coverage: "UNPROTECTED",
    mutationAllowed: false,
    paths,
    missingGuarantees,
    evidence: [],
    evidenceDigest: computeCanonicalDigestV1({
      assurance: "DISPOSABLE_TEST", scope, coverage: "UNPROTECTED", paths,
      missingGuarantees, evidence: []
    }),
    assessedAt: assessedAt.toISOString(),
    expiresAt: new Date(assessedAt.getTime() + 60_000).toISOString()
  });
}

async function availablePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
  if (address === null || typeof address === "string") throw new Error("Port allocation failed");
  return address.port;
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

beforeAll(async () => {
  const port = await availablePort();
  const databaseDir = await mkdtemp(join(tmpdir(), "agent-security-postgres-"));
  postgres = new EmbeddedPostgres({
    databaseDir,
    user: "postgres",
    password: "disposable-postgres-password",
    port,
    persistent: false,
    onLog: () => undefined,
    onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  config = {
    connectionString: `postgresql://postgres:disposable-postgres-password@127.0.0.1:${String(port)}/postgres`,
    knownSecretValues: [knownSecret]
  };
  store = await PostgresTrajectoryStoreV1.connect(config);
}, 30_000);

afterAll(async () => {
  await store.close();
  await postgres.stop();
}, 30_000);

describe("PostgreSQL trajectory persistence", () => {
  it("persists a client-facing call decision after route, protocol, and canonical admission", async () => {
    const base = new Date();
    const candidate = createPostgresTrajectoryFixtureV1("client-runtime-integration", base);
    const guard = new DisposableProtocolGuardV1({
      limits: {
        schemaVersion: "1.0.0", maxClockSkewMs: 30_000, replayTtlMs: 60_000,
        rateWindowMs: 60_000, callsPerWindow: 10, concurrentCalls: 2,
        payloadBytes: 64 * 1024, resultBytes: 1024 * 1024, callDepth: 4,
        delegationDepth: 2, fanOut: 2, redirects: 0, retries: 0,
        executionMs: 5_000, circuitFailureThreshold: 2
      }
    });
    for (const dependency of ["route-registry", "canonicalizer", "policy", "postgres"]) {
      guard.recordDependencySuccess(dependency);
    }
    const resolverId = candidate.binding.route.resourceMapping.resolverId;
    const coordinator = new ClientToolCallCoordinatorV1({
      policyScopeId: candidate.binding.route.policyScopeId,
      environment: "PRODUCTION",
      policyDigest: candidate.policyDigest,
      resolveRoute: () => ({
        binding: candidate.binding,
        inputSchema: candidate.inputSchema,
        outputSchema: candidate.outputSchema
      }),
      protocolGuard: guard,
      normalizer: new CanonicalActionNormalizerV1({
        resolvers: new Map([[resolverId, ({ arguments: args }) => {
          const recordId = args["record_id"];
          if (typeof recordId !== "string") throw new Error("record_id is required");
          return {
            schemaVersion: "1.0.0", parserId: resolverId, parserVersion: "1.0.0",
            status: "FULL",
            resources: [{
              resourceId: recordId, resourceClass: "DATABASE",
              reference: `postgres://disposable/orders/${recordId}`,
              referencePlatform: "URI", classification: "CONFIDENTIAL"
            }],
            effect: "DELETE", environment: "PRODUCTION",
            dataFlow: { direction: "NONE", classifications: ["CONFIDENTIAL"], externalDestination: false, destinationId: null },
            reversibility: "IRREVERSIBLE", influences: ["USER_INPUT"]
          };
        }]])
      }),
      policy: new DeterministicPolicyEngineV1({
        policyVersion: candidate.decision.policyVersion
      }),
      assessCoverage: (action) => {
        const resource = action.resources[0];
        if (resource === undefined) throw new Error("A canonical resource is required");
        const scope = {
          ...action.identity,
          stateNamespace: action.sessionId,
          ...action.route,
          credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
          environment: action.environment,
          resourceId: resource.resourceId,
          resourceClass: resource.resourceClass,
          resourcesDigest: action.resourcesDigest
        };
        const pathKinds = ["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const;
        const paths = pathKinds.map((pathKind) => ({
          pathKind, coverage: "UNPROTECTED" as const,
          reasonCodes: ["coverage.runtime.not_configured"]
        }));
        const missingGuarantees = [{
          guarantee: "CLIENT_AUTHENTICATION" as const,
          pathKind: "GATEWAY_MEDIATED" as const,
          reasonCode: "coverage.runtime.not_configured",
          verifierId: null
        }];
        return {
          schemaVersion: "1.0.0" as const,
          assessmentId: "assessment-client-runtime-integration",
          revision: 1,
          assurance: "DISPOSABLE_TEST" as const,
          scope,
          coverage: "UNPROTECTED" as const,
          mutationAllowed: false,
          paths,
          missingGuarantees,
          evidence: [],
          evidenceDigest: computeCanonicalDigestV1({
            assurance: "DISPOSABLE_TEST", scope, coverage: "UNPROTECTED", paths,
            missingGuarantees, evidence: []
          }),
          assessedAt: base.toISOString(),
          expiresAt: new Date(base.getTime() + 30_000).toISOString()
        };
      },
      interfaceBuilder: new TrustworthyInterfaceBuilderV1({ clock: () => base }),
      store
    });
    const app = createInitializationHttpAppV1({
      clientAuthenticator: (attempt) => attempt.authorizationHeader === "Bearer client-runtime-integration"
        ? {
            schemaVersion: "1.0.0", userId: "user-client-runtime-integration",
            agentId: "agent-client-runtime-integration", clientId: "client-client-runtime-integration",
            host: { hostId: "host-client-runtime-integration", name: "Integration host", version: "1.0.0" },
            authentication: {
              method: "TEST_FIXTURE", credentialId: "credential-client-runtime-integration",
              identityRevision: 1, authenticatedAt: base.toISOString()
            }
          }
        : undefined,
      toolCall: { provider: (request) => coordinator.handle(request) }
    });
    const server = createHttpServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("HTTP port unavailable");
    try {
      const client = new DisposableMcpHttpClientV1(
        `http://127.0.0.1:${String(address.port)}/mcp`,
        { authorizationHeader: "Bearer client-runtime-integration" }
      );
      await client.initialize({
        protocolVersion: "2025-06-18", capabilities: {},
        clientInfo: { name: "PostgreSQL call host", version: "1.0.0" }
      });
      await client.sendInitialized();
      const response = await client.sendRequest("tools/call", {
        name: candidate.binding.route.exposedName,
        arguments: { record_id: "row-client-runtime-integration" }
      }, "protocol-client-runtime-integration");
      expect(response.status).toBe(200);
      expect(response.json).toMatchObject({ result: { structuredContent: {
        decision: "DENY", coverage: "UNPROTECTED", downstreamInvoked: false,
        awareness: {
          decision: "DENY",
          generatedFromCanonicalData: true,
          missingGuarantees: ["coverage.runtime.not_configured"]
        }
      } } });
      const events = await store.readSecurityEvents();
      expect(events.some((event) =>
        event.eventType === "DENIED" &&
        event.stateNamespace !== null &&
        event.reasonCodes.includes("invariant.tier3_approval")
      )).toBe(true);
      const beforeDependencyFailure = await store.tableCounts();
      guard.recordDependencyFailure("postgres");
      const deniedByDependency = await client.sendRequest("tools/call", {
        name: candidate.binding.route.exposedName,
        arguments: { record_id: "row-client-runtime-dependency-failure" }
      }, "protocol-client-runtime-dependency-failure");
      expect(deniedByDependency.status).toBe(503);
      expect(deniedByDependency.json).toMatchObject({
        error: { code: -32006, message: "Tool call admission is unavailable" }
      });
      expect(await store.tableCounts()).toEqual(beforeDependencyFailure);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => {
        if (error === undefined) resolve(); else reject(error);
      }));
    }
  });

  it("applies the forward-only migration once with all required tables, constraints, indexes, and append-only trigger", async () => {
    const second = await PostgresTrajectoryStoreV1.connect(config);
    await second.close();
    const client = postgres.getPgClient();
    await client.connect();
    try {
      const migrations = await client.query("SELECT version, filename FROM schema_migrations");
      expect(migrations.rows).toEqual([
        { version: "0001", filename: "0001_phase2_core.sql" },
        { version: "0002", filename: "0002_exclusive_mediation_coverage.sql" },
        { version: "0003", filename: "0003_trustworthy_interfaces.sql" },
        { version: "0004", filename: "0004_advisory_supervisor.sql" },
        { version: "0005", filename: "0005_protected_identity.sql" },
        { version: "0006", filename: "0006_protected_administration.sql" },
        { version: "0007", filename: "0007_approval_web_ui.sql" }
      ]);
      const tables = await client.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public' ORDER BY table_name`
      );
      const names = tables.rows.map((row) => row.table_name);
      expect(names).toEqual(expect.arrayContaining([
        "identities", "clients", "sessions", "servers", "schema_versions", "routes",
        "policies", "requests", "canonical_actions", "decisions", "decision_reasons",
        "approvals", "forwarding_attempts", "result_provenance", "results", "outcomes",
        "security_events", "trust_evidence", "coverage_events", "coverage_control_evidence", "protocol_violations",
        "supervisor_assessments", "recovery_records", "trustworthy_interface_views",
        "approval_fatigue_events", "protected_admin_resources", "protected_admin_versions",
        "protected_admin_audit_events", "protected_client_identity_revisions",
        "protected_client_identity_audit_events", "approval_ui_humans",
        "approval_ui_scope_grants", "approval_ui_sessions", "approval_ui_security_events",
        "schema_migrations"
      ]));
      const indexes = await client.query<{ indexname: string }>(
        "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'"
      );
      expect(indexes.rows.map((row) => row.indexname)).toEqual(expect.arrayContaining([
        "requests_session_time_idx", "approvals_state_expiry_idx",
        "security_events_request_idx", "trust_evidence_scope_idx", "coverage_events_scope_time_idx",
        "trustworthy_interface_scope_time_idx", "approval_fatigue_scope_time_idx",
        "supervisor_assessments_scope_time_idx", "approvals_scope_state_time_idx",
        "approval_ui_sessions_human_expiry_idx", "approval_ui_security_events_approval_idx"
      ]));
      const trigger = await client.query(
        "SELECT 1 FROM pg_trigger WHERE tgname = 'security_events_append_only' AND NOT tgisinternal"
      );
      expect(trigger.rowCount).toBe(1);
      const coverageTriggers = await client.query(
        `SELECT tgname FROM pg_trigger
         WHERE tgname IN ('coverage_events_append_only', 'coverage_control_evidence_append_only')
         AND NOT tgisinternal ORDER BY tgname`
      );
      expect(coverageTriggers.rows).toHaveLength(2);
      const supervisorTrigger = await client.query(
        "SELECT 1 FROM pg_trigger WHERE tgname = 'supervisor_assessments_append_only' AND NOT tgisinternal"
      );
      expect(supervisorTrigger.rowCount).toBe(1);
    } finally {
      await client.end();
    }
  });

  it("persists an allowlisted advisory supervisor audit with exact trajectory bindings", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("supervisor-audit");
    await store.persistDecisionTrajectory(candidate);
    const supervisor = new AdvisorySupervisorV1({
      provider: { providerId: "provider-postgres-fixture", modelId: "model-postgres-fixture", assess: () => ({}) },
      auditSink: { record: () => undefined }, globallyEnabled: false,
      assessmentIdFactory: () => "assessment-postgres-fixture",
      knownSecretValues: [knownSecret]
    });
    const result = await supervisor.assess({ action: candidate.action, deterministicDecision: candidate.decision });
    expect(result.audit.status).toBe("NOT_REQUIRED");
    await store.persistSupervisorAssessment(result.audit);
    await expect(store.persistSupervisorAssessment(result.audit)).rejects.toBeDefined();
    const persisted = await store.readSupervisorAssessments();
    expect(persisted).toContainEqual(result.audit);
    const client = postgres.getPgClient();
    await client.connect();
    try {
      await expect(client.query(
        "UPDATE supervisor_assessments SET status = 'DISABLED' WHERE assessment_id = $1",
        [result.audit.assessmentId]
      )).rejects.toBeDefined();
      expect(JSON.stringify(persisted)).not.toContain(knownSecret);
    } finally {
      await client.end();
    }
  });

  it("durably records scoped coverage diagnostics and hash-chains degradation", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("coverage-persistence");
    await store.persistDecisionTrajectory(candidate);
    const resource = candidate.action.resources[0];
    if (resource === undefined) throw new Error("Coverage fixture requires one resource");
    const scope = {
      userId: candidate.action.identity.userId,
      agentId: candidate.action.identity.agentId,
      clientId: candidate.action.identity.clientId,
      hostId: candidate.action.identity.hostId,
      stateNamespace: candidate.action.sessionId,
      serverId: candidate.action.route.serverId,
      routeId: candidate.action.route.routeId,
      toolName: candidate.action.route.toolName,
      schemaDigest: candidate.action.route.schemaDigest,
      policyScopeId: candidate.action.route.policyScopeId,
      environment: candidate.action.environment,
      credentialAudienceId: candidate.action.route.credentialAudienceId,
      credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
      resourceClass: resource.resourceClass,
      resourceId: resource.resourceId,
      resourcesDigest: candidate.action.resourcesDigest
    };
    const paths = [
      { pathKind: "GATEWAY_MEDIATED" as const, coverage: "UNPROTECTED" as const,
        reasonCodes: ["coverage.client_authentication.missing"] },
      { pathKind: "NATIVE" as const, coverage: "DEGRADED" as const, reasonCodes: [] },
      { pathKind: "DIRECT" as const, coverage: "DEGRADED" as const, reasonCodes: [] }
    ];
    const missingGuarantees = [{
      guarantee: "CLIENT_AUTHENTICATION" as const,
      pathKind: "GATEWAY_MEDIATED" as const,
      reasonCode: "coverage.client_authentication.missing",
      verifierId: null
    }];
    const evidence: never[] = [];
    const coverage = "UNPROTECTED" as const;
    const assurance = "DISPOSABLE_TEST" as const;
    const evidenceDigest = computeCanonicalDigestV1({
      assurance, scope, coverage, paths, missingGuarantees, evidence
    });
    const assessment = {
      schemaVersion: "1.0.0" as const,
      assessmentId: "coverage-assessment-persistence",
      revision: 1,
      assurance,
      scope,
      coverage,
      mutationAllowed: false,
      paths,
      missingGuarantees,
      evidence,
      evidenceDigest,
      assessedAt: candidate.decision.decidedAt,
      expiresAt: new Date(Date.parse(candidate.decision.decidedAt) + 1_000).toISOString()
    };

    const before = await store.tableCounts();
    await store.persistCoverageAssessment(assessment);
    expect(await store.readLatestCoverageAssessment(scope)).toEqual(assessment);
    const after = await store.tableCounts();
    expect(after["coverage_events"]).toBe((before["coverage_events"] ?? 0) + 1);
    expect(after["security_events"]).toBe((before["security_events"] ?? 0) + 1);
    expect((await store.readSecurityEvents()).at(-1)).toMatchObject({
      eventType: "BYPASS",
      evidenceDigest
    });

    const restarted = await PostgresTrajectoryStoreV1.connect(config);
    try {
      expect(await restarted.readLatestCoverageAssessment(scope)).toEqual(assessment);
    } finally {
      await restarted.close();
    }
    const client = postgres.getPgClient();
    await client.connect();
    try {
      await expect(client.query(
        "UPDATE coverage_events SET coverage = 'ENFORCED' WHERE coverage_event_id = $1",
        [assessment.assessmentId]
      )).rejects.toThrow(/append-only/u);
    } finally {
      await client.end();
    }
  });

  it("persists canonical awareness, fatigue events, and mutation recovery across restart", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("interface-audit");
    const decision = new DeterministicPolicyEngineV1({
      policyVersion: candidate.decision.policyVersion,
      clock: () => new Date(candidate.decision.decidedAt),
      decisionIdFactory: () => "decision-interface-audit"
    }).evaluate({ action: candidate.action, coverage: "UNPROTECTED" });
    await store.persistDecisionTrajectory({ ...candidate, decision });
    const resource = candidate.action.resources[0];
    if (resource === undefined) throw new Error("Interface audit requires a resource");
    const scope = {
      ...candidate.action.identity,
      stateNamespace: candidate.action.sessionId,
      ...candidate.action.route,
      credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
      environment: candidate.action.environment,
      resourceClass: resource.resourceClass,
      resourceId: resource.resourceId,
      resourcesDigest: candidate.action.resourcesDigest
    };
    const paths = [
      { pathKind: "GATEWAY_MEDIATED" as const, coverage: "UNPROTECTED" as const,
        reasonCodes: ["coverage.client_authentication.missing"] },
      { pathKind: "NATIVE" as const, coverage: "DEGRADED" as const,
        reasonCodes: ["coverage.os_isolation.missing"] },
      { pathKind: "DIRECT" as const, coverage: "DEGRADED" as const,
        reasonCodes: ["coverage.network_isolation.missing"] }
    ];
    const missingGuarantees = [
      { guarantee: "CLIENT_AUTHENTICATION" as const, pathKind: "GATEWAY_MEDIATED" as const,
        reasonCode: "coverage.client_authentication.missing", verifierId: null },
      { guarantee: "OS_ISOLATION" as const, pathKind: "NATIVE" as const,
        reasonCode: "coverage.os_isolation.missing", verifierId: null },
      { guarantee: "NETWORK_ISOLATION" as const, pathKind: "DIRECT" as const,
        reasonCode: "coverage.network_isolation.missing", verifierId: null }
    ];
    const assurance = "DISPOSABLE_TEST" as const;
    const coverage = "UNPROTECTED" as const;
    const evidence: never[] = [];
    const assessment = {
      schemaVersion: "1.0.0" as const,
      assessmentId: "coverage-interface-audit",
      revision: 1,
      assurance,
      scope,
      coverage,
      mutationAllowed: false,
      paths,
      missingGuarantees,
      evidence,
      evidenceDigest: computeCanonicalDigestV1({
        assurance, scope, coverage, paths, missingGuarantees, evidence
      }),
      assessedAt: decision.decidedAt,
      expiresAt: new Date(Date.parse(decision.decidedAt) + 1_000).toISOString()
    };
    await store.persistCoverageAssessment(assessment);
    const { view, awareness } = new TrustworthyInterfaceBuilderV1({
      clock: () => new Date(decision.decidedAt),
      interfaceIdFactory: () => "interface-audit",
      awarenessIdFactory: () => "awareness-interface-audit"
    }).build({ action: candidate.action, decision, coverage: assessment,
      relatedAttemptIds: ["attempt-interface-earlier"] });
    await store.persistTrustworthyInterface({
      view,
      awareness,
      presentedEvent: {
        schemaVersion: "1.0.0",
        eventId: "fatigue-presented-interface",
        interfaceId: view.interfaceId,
        policyScopeId: view.route.policyScopeId,
        eventType: "PRESENTED",
        decisionLatencyMs: null,
        relatedAttemptCount: 1,
        occurredAt: view.generatedAt
      }
    });
    await store.persistApprovalFatigueEvent({
      schemaVersion: "1.0.0",
      eventId: "fatigue-error-interface",
      interfaceId: view.interfaceId,
      policyScopeId: view.route.policyScopeId,
      eventType: "ERROR",
      decisionLatencyMs: null,
      relatedAttemptCount: 0,
      occurredAt: new Date(Date.parse(view.generatedAt) + 1).toISOString()
    });
    const outcome = {
      schemaVersion: "1.0.0" as const,
      outcomeId: "outcome-interface-audit",
      requestId: candidate.action.requestId,
      actionId: candidate.action.actionId,
      sessionId: candidate.action.sessionId,
      decisionId: decision.decisionId,
      approvalId: null,
      forwardingAttemptId: null,
      resultId: null,
      provenanceId: null,
      status: "NOT_FORWARDED" as const,
      forwardedAt: null,
      finishedAt: null,
      possiblePartialEffects: false,
      recoveryClass: candidate.action.reversibility,
      trustEvidenceEligible: false,
      observedAt: new Date(Date.parse(view.generatedAt) + 2).toISOString()
    };
    await store.recordTerminalOutcome(outcome);
    expect(await store.readApprovalFatigueMetrics(view.route.policyScopeId, view.generatedAt))
      .toMatchObject({ presentations: 1, approvalErrors: 1, repeatedRelatedAttempts: 1 });

    const restarted = await PostgresTrajectoryStoreV1.connect(config);
    try {
      expect(await restarted.readApprovalFatigueMetrics(view.route.policyScopeId, view.generatedAt))
        .toMatchObject({ presentations: 1, approvalErrors: 1, repeatedRelatedAttempts: 1 });
      const counts = await restarted.tableCounts();
      expect(counts["trustworthy_interface_views"]).toBeGreaterThanOrEqual(1);
      expect(counts["approval_fatigue_events"]).toBeGreaterThanOrEqual(2);
      expect(counts["recovery_records"]).toBeGreaterThanOrEqual(1);
    } finally {
      await restarted.close();
    }
  });

  it("persists request metadata, canonical action, decision, and audit atomically without raw arguments", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("decision");
    const before = await store.tableCounts();
    await store.persistDecisionTrajectory(candidate);
    const after = await store.tableCounts();
    expect(after["requests"]).toBe((before["requests"] ?? 0) + 1);
    expect(after["canonical_actions"]).toBe((before["canonical_actions"] ?? 0) + 1);
    expect(after["decisions"]).toBe((before["decisions"] ?? 0) + 1);
    expect(after["security_events"]).toBe((before["security_events"] ?? 0) + 1);

    const client = postgres.getPgClient();
    await client.connect();
    try {
      const columns = await client.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns
         WHERE table_name = 'requests' ORDER BY ordinal_position`
      );
      expect(columns.rows.map((row) => row.column_name)).not.toContain("arguments");
      const request = await client.query<{ arguments_digest: string }>(
        "SELECT arguments_digest FROM requests WHERE request_id = $1",
        [candidate.request.requestId]
      );
      expect(request.rows[0]?.arguments_digest).toBe(candidate.request.argumentsDigest);
    } finally {
      await client.end();
    }
  });

  it("rejects an immutable server or route conflict and rolls back the whole trajectory", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("immutable");
    await store.persistDecisionTrajectory(candidate);
    const before = await store.tableCounts();
    await expect(store.persistDecisionTrajectory({
      ...candidate,
      binding: {
        ...candidate.binding,
        server: { ...candidate.binding.server, displayName: "Conflicting server identity" }
      }
    })).rejects.toBeInstanceOf(PersistenceDeniedV1);
    expect(await store.tableCounts()).toEqual(before);
  });

  it("revalidates request and approval bindings at the persistence boundary", async () => {
    const tamperedRequest = createPostgresTrajectoryFixtureV1("tampered-request");
    const beforeRequest = await store.tableCounts();
    await expect(store.persistDecisionTrajectory({
      ...tamperedRequest,
      request: {
        ...tamperedRequest.request,
        arguments: { ...tamperedRequest.request.arguments, injected: true }
      }
    })).rejects.toBeInstanceOf(PersistenceDeniedV1);
    expect(await store.tableCounts()).toEqual(beforeRequest);

    const candidate = createPostgresTrajectoryFixtureV1("tampered-approval");
    await store.persistDecisionTrajectory(candidate);
    const beforeApproval = await store.tableCounts();
    await expect(store.persistApproval({
      ...candidate.approval,
      route: { ...candidate.approval.route, toolName: "wrong-tool" }
    })).rejects.toBeInstanceOf(PersistenceDeniedV1);
    expect(await store.tableCounts()).toEqual(beforeApproval);
  });

  it("rejects known secrets before the transaction and persists no partial row", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("secret");
    const poisoned = {
      ...candidate,
      binding: {
        ...candidate.binding,
        server: { ...candidate.binding.server, displayName: `Server ${knownSecret}` }
      }
    };
    const before = await store.tableCounts();
    await expect(store.persistDecisionTrajectory(poisoned))
      .rejects.toBeInstanceOf(SecretPersistenceDeniedV1);
    expect(await store.tableCounts()).toEqual(before);
    await expect(store.appendSecurityEvent({
      eventId: "secret-event",
      eventType: "BYPASS",
      requestId: null,
      stateNamespace: null,
      forwardingAttemptId: null,
      actorId: "security-test",
      reasonCodes: [knownSecret],
      evidenceDigest: computeCanonicalDigestV1("secret-test"),
      occurredAt: new Date().toISOString()
    })).rejects.toBeInstanceOf(SecretPersistenceDeniedV1);

    const client = postgres.getPgClient();
    await client.connect();
    try {
      const columns = await client.query<{ table_name: string; column_name: string }>(
        `SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = 'public'
           AND data_type IN ('text', 'character varying', 'character', 'jsonb', 'ARRAY')`
      );
      for (const column of columns.rows) {
        if (!/^[a-z0-9_]+$/u.test(column.table_name) || !/^[a-z0-9_]+$/u.test(column.column_name)) {
          throw new Error("Unexpected PostgreSQL identifier");
        }
        const match = await client.query<{ count: string }>(
          `SELECT count(*) AS count FROM "${column.table_name}"
           WHERE "${column.column_name}"::text LIKE $1`,
          [`%${knownSecret}%`]
        );
        expect(Number(match.rows[0]?.count ?? 0)).toBe(0);
      }
    } finally {
      await client.end();
    }
  });

  it("denies approval consumption when no fresh exact-scope ENFORCED coverage is persisted", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("missing-current-coverage");
    await store.persistDecisionTrajectory(candidate);
    await store.persistApproval(candidate.approval);
    await expect(store.consumeApprovalAndStartForwarding(candidate.authorization))
      .rejects.toBeInstanceOf(PersistenceDeniedV1);
    const client = postgres.getPgClient();
    await client.connect();
    try {
      const approval = await client.query<{ state: string }>(
        "SELECT state FROM approvals WHERE approval_id = $1",
        [candidate.approval.approvalId]
      );
      expect(approval.rows[0]?.state).toBe("APPROVED");
      const attempts = await client.query<{ count: string }>(
        "SELECT count(*) AS count FROM forwarding_attempts WHERE approval_id = $1",
        [candidate.approval.approvalId]
      );
      expect(Number(attempts.rows[0]?.count ?? 0)).toBe(0);
    } finally {
      await client.end();
    }
  });

  it("consumes approval and creates forwarding state exactly once across connections and restart", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("concurrent");
    await store.persistDecisionTrajectory(candidate);
    await store.persistApproval(candidate.approval);
    await persistEnforcedCoverage(store, candidate);
    const peer = await PostgresTrajectoryStoreV1.connect(config);
    const attempts = await Promise.allSettled([
      store.consumeApprovalAndStartForwarding(candidate.authorization),
      peer.consumeApprovalAndStartForwarding(candidate.authorization)
    ]);
    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(1);
    await peer.close();

    const restarted = await PostgresTrajectoryStoreV1.connect(config);
    await expect(restarted.consumeApprovalAndStartForwarding(candidate.authorization))
      .rejects.toBeInstanceOf(PersistenceDeniedV1);
    const counts = await restarted.tableCounts();
    expect(counts["forwarding_attempts"]).toBe(1);

    const beforeResult = await restarted.tableCounts();
    await restarted.recordResultAndOutcome({
      authorization: candidate.authorization,
      provenance: candidate.provenance,
      result: candidate.result,
      outcome: candidate.outcome,
      trustEvidenceId: "trust-evidence-concurrent"
    });
    const completed = await restarted.tableCounts();
    expect(completed["result_provenance"]).toBe((beforeResult["result_provenance"] ?? 0) + 1);
    expect(completed["results"]).toBe((beforeResult["results"] ?? 0) + 1);
    expect(completed["outcomes"]).toBe((beforeResult["outcomes"] ?? 0) + 1);
    expect(completed["trust_evidence"]).toBe((beforeResult["trust_evidence"] ?? 0) + 1);

    const beforeRetry = await restarted.tableCounts();
    const secondProvenance = { ...candidate.provenance, provenanceId: "provenance-retry" };
    const secondResult = {
      ...candidate.result,
      resultId: "result-retry",
      provenanceId: secondProvenance.provenanceId
    };
    const secondOutcome = {
      ...candidate.outcome,
      outcomeId: "outcome-retry",
      resultId: secondResult.resultId,
      provenanceId: secondProvenance.provenanceId
    };
    await expect(restarted.recordResultAndOutcome({
      authorization: candidate.authorization,
      provenance: secondProvenance,
      result: secondResult,
      outcome: secondOutcome,
      trustEvidenceId: "trust-evidence-retry"
    })).rejects.toBeDefined();
    expect(await restarted.tableCounts()).toEqual(beforeRetry);
    await restarted.close();
  });

  it("does not fall back to older ENFORCED evidence after a newer coverage degradation", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("coverage-degraded-before-consume");
    await store.persistDecisionTrajectory(candidate);
    await store.persistApproval(candidate.approval);
    await persistEnforcedCoverage(store, candidate);
    await persistNewerUnprotectedCoverage(store, candidate);
    await expect(store.consumeApprovalAndStartForwarding(candidate.authorization))
      .rejects.toBeInstanceOf(PersistenceDeniedV1);
    const counts = await store.tableCounts();
    const client = postgres.getPgClient();
    await client.connect();
    try {
      const attempts = await client.query<{ count: string }>(
        "SELECT count(*) AS count FROM forwarding_attempts WHERE approval_id = $1",
        [candidate.approval.approvalId]
      );
      expect(Number(attempts.rows[0]?.count ?? 0)).toBe(0);
      expect(counts["coverage_events"]).toBeGreaterThanOrEqual(2);
    } finally {
      await client.end();
    }
  });

  it("persists a complete approval-to-HTTP-result trajectory against disposable PostgreSQL", async () => {
    let downstreamCalls = 0;
    let downstreamAuthorization: string | undefined;
    const downstream = createHttpServer((request, response) => {
      void (async () => {
        downstreamCalls += 1;
        downstreamAuthorization = request.headers.authorization;
        const body = await readJsonBody(request);
        response.statusCode = 200;
        response.setHeader("Content-Type", "application/json");
        response.setHeader("Mcp-Server-Authorization", "postgres-workflow-proof");
        response.end(JSON.stringify({
          jsonrpc: "2.0",
          id: body["id"],
          result: {
            content: [{ type: "text", text: "completed disposable operation" }],
            structuredContent: { ok: true }
          }
        }));
      })();
    });
    await new Promise<void>((resolve, reject) => {
      downstream.once("error", reject);
      downstream.listen(0, "127.0.0.1", () => {
        downstream.off("error", reject);
        resolve();
      });
    });
    try {
      const address = downstream.address();
      if (address === null || typeof address === "string") throw new Error("HTTP fixture failed");
      const origin = `http://127.0.0.1:${String(address.port)}`;
      const candidate = createPostgresTrajectoryFixtureV1(
        "workflow",
        new Date(Date.now() - 10_000)
      );
      const binding = {
        ...candidate.binding,
        server: {
          ...candidate.binding.server,
          transport: {
            kind: "STREAMABLE_HTTP" as const,
            endpoint: `${origin}/mcp`,
            authenticationProfileId: "server-auth-workflow"
          }
        }
      };
      await store.persistDecisionTrajectory({ ...candidate, binding });
      await store.persistApproval(candidate.approval);
      await persistEnforcedCoverage(store, { ...candidate, binding });

      const credentialMaterial = Buffer.from("workflow-route-credential", "utf8");
      const vault = new DisposableCredentialVaultV1({
        leaseIdFactory: () => "workflow-lease"
      });
      vault.registerCredential({
        schemaVersion: "1.0.0",
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        credentialRevision: 1,
        credentialKind: "BEARER_TOKEN",
        audienceId: binding.route.credentialAudienceId,
        allowedRouteIds: [binding.route.routeId],
        allowedEndpointOrigins: [origin],
        materialDigest: createHash("sha256").update(credentialMaterial).digest("hex"),
        status: "ACTIVE",
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 60_000).toISOString()
      }, credentialMaterial);
      const forwarder = new DisposableExactForwarderV1({
        credentialVault: vault,
        resolveCurrentRoute: () => binding,
        authenticateDownstream: () => ({
          schemaVersion: "1.0.0",
          serverId: binding.server.serverId,
          principalId: binding.server.authenticatedPrincipalId,
          authenticationMethod: "TEST_FIXTURE",
          credentialId: "workflow-server-credential",
          identityRevision: 1,
          authenticatedAt: new Date().toISOString()
        }),
        validateOutputSchema: ({ structuredContent }) => structuredContent?.["ok"] === true,
        classifyResult: () => ["PUBLIC"],
        evaluateEgress: () => "ALLOW",
        resultIdFactory: () => candidate.result.resultId,
        provenanceIdFactory: () => candidate.provenance.provenanceId,
        errorIdFactory: () => "workflow-result-error"
      });
      const executor = new ClientApprovedCallExecutorV1({
        loadApprovedCall: ({ approvalId, session }) => {
          expect(approvalId).toBe(candidate.approval.approvalId);
          expect(session.stateNamespace).toBe(candidate.session.stateNamespace);
          return {
            session: candidate.session, request: candidate.request, action: candidate.action,
            decision: candidate.decision, approval: candidate.approval
          };
        },
        store,
        issueCredentialLease: ({ session }) => vault.issueLease(session, {
          credentialProfileId: binding.server.credentialAudience.credentialProfileId,
          audienceId: binding.route.credentialAudienceId,
          routeId: binding.route.routeId
        }).leaseId,
        forwarder,
        clock: () => new Date(candidate.authorization.authorizedAt),
        forwardingAttemptIdFactory: () => candidate.authorization.forwardingAttemptId,
        outcomeIdFactory: () => candidate.outcome.outcomeId,
        trustEvidenceIdFactory: () => "trust-evidence-workflow"
      });
      const mediated = await executor.execute({
        approvalId: candidate.approval.approvalId,
        session: candidate.session
      });
      await expect(executor.execute({
        approvalId: candidate.approval.approvalId,
        session: candidate.session
      })).rejects.toBeInstanceOf(PersistenceDeniedV1);
      if (mediated.provenance === null || mediated.result === null) {
        throw new Error("Disposable workflow result was unexpectedly withheld");
      }
      expect(downstreamCalls).toBe(1);
      expect(downstreamAuthorization).toBe("Bearer workflow-route-credential");
      expect(mediated.release?.instructionPolicy).toBe("DATA_ONLY");
      expect(await store.verifySecurityEventChain()).toBe(true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        downstream.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
      });
    }
  });

  it("hash-chains all security event classes and rejects update or deletion", async () => {
    const eventTypes = ["DENIED", "MODIFIED", "ALTERNATE_ROUTE", "REPLAYED", "BYPASS"] as const;
    for (const [index, eventType] of eventTypes.entries()) {
      await store.appendSecurityEvent({
        eventId: `audit-class-${String(index)}`,
        eventType,
        requestId: `correlated-request-${String(index)}`,
        stateNamespace: `correlated-session-${String(index)}`,
        forwardingAttemptId: `correlated-forward-${String(index)}`,
        actorId: "audit-fixture",
        reasonCodes: [`audit.${eventType.toLowerCase()}`],
        evidenceDigest: computeCanonicalDigestV1({ eventType, index }),
        occurredAt: new Date(Date.now() + index).toISOString()
      });
    }
    expect(await store.verifySecurityEventChain()).toBe(true);
    const correlated = (await store.readSecurityEvents())
      .filter((event) => event.eventId.startsWith("audit-class-"));
    expect(correlated).toHaveLength(eventTypes.length);
    expect(correlated.every((event) => event.requestId !== null &&
      event.stateNamespace !== null && event.forwardingAttemptId !== null)).toBe(true);
    const client = postgres.getPgClient();
    await client.connect();
    try {
      await expect(client.query(
        "UPDATE security_events SET actor_id = 'tampered' WHERE sequence_id = 1"
      )).rejects.toThrow(/append-only/u);
    } finally {
      await client.end();
    }
    expect(await store.verifySecurityEventChain()).toBe(true);
  });
});
