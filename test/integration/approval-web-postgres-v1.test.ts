import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import EmbeddedPostgres from "embedded-postgres";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import type {
  CoveragePathKindV1,
  MediationGuaranteeV1
} from "../../src/coverage/exclusive-mediation-v1.js";
import { createApprovalWebAppV1 } from "../../src/interfaces/approval-web-v1.js";
import { TrustworthyInterfaceBuilderV1 } from "../../src/interfaces/trustworthy-interface-v1.js";
import { PostgresApprovalUiStoreV1 } from "../../src/persistence/postgres-approval-ui-store-v1.js";
import { PostgresTrajectoryStoreV1 } from "../../src/persistence/postgres-trajectory-store-v1.js";
import { ApprovalWebRuntimeBridgeV1 } from "../../src/runtime/approval-web-runtime-v1.js";
import { ClientApprovedCallExecutorV1 } from "../../src/runtime/client-tool-call-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

const approvalOrigin = "https://approval.test.local";

let postgres: EmbeddedPostgres;
let trajectory: PostgresTrajectoryStoreV1;
let ui: PostgresApprovalUiStoreV1;
let httpServer: Server;
let connectionString: string;
let baseUrl: string;
let eventNumber = 0;

async function availablePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => { resolve(); }));
  if (address === null || typeof address === "string") throw new Error("Port unavailable");
  return address.port;
}

const guarantees = {
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

const humanPrincipal = {
  schemaVersion: "1.0.0" as const,
  humanId: "human-approval-web",
  authenticationMethod: "OIDC" as const,
  credentialId: "opaque-idp-subject",
  identityRevision: 1,
  authenticatedAt: new Date(Date.now() - 30_000).toISOString()
};

const otherPrincipal = {
  ...humanPrincipal,
  humanId: "other-approval-human",
  credentialId: "other-opaque-idp-subject"
};

beforeAll(async () => {
  const postgresPort = await availablePort();
  postgres = new EmbeddedPostgres({
    databaseDir: await mkdtemp(join(tmpdir(), "agent-security-web-postgres-")),
    user: "postgres",
    password: "disposable-password",
    port: postgresPort,
    persistent: false,
    onLog: () => undefined,
    onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  connectionString =
    `postgresql://postgres:disposable-password@127.0.0.1:${String(postgresPort)}/postgres`;
  trajectory = await PostgresTrajectoryStoreV1.connect({
    connectionString,
    approvalRuntimePayloadEncryption: {
      keyId: "approval-web-runtime-key",
      key: Buffer.alloc(32, 11)
    }
  });
  ui = await PostgresApprovalUiStoreV1.connect({
    connectionString,
    expectedOrigin: approvalOrigin,
    administratorAuthorizer: (authority) => authority.administratorId === "approval-admin",
    eventIdFactory: () => `approval-web-event-${String(++eventNumber)}`
  });

  const executor = new ClientApprovedCallExecutorV1({
    loadApprovedCall: (input) => trajectory.loadApprovedCall(input),
    store: trajectory,
    issueCredentialLease: () => "approval-web-disposable-lease",
    forwarder: {
      execute: ({ authorization }) => Promise.resolve({
        schemaVersion: "1.0.0",
        forwardingAttemptId: authorization.forwardingAttemptId,
        provenance: null,
        result: null,
        release: null,
        error: null,
        trustEvidenceEligible: false
      })
    }
  });
  const bridge = new ApprovalWebRuntimeBridgeV1({
    sessions: trajectory,
    executor,
    dispatches: trajectory
  });
  const app = createApprovalWebAppV1({
    origin: approvalOrigin,
    store: ui.asApprovalWebStore(),
    authenticateHuman: (request) => {
      if (request.get("x-test-human") === humanPrincipal.humanId) return humanPrincipal;
      if (request.get("x-test-human") === otherPrincipal.humanId) return otherPrincipal;
      return null;
    },
    executeApprovedCall: (input) => bridge.executeApprovedCall(input),
    readStaticAsset: () => null
  });
  httpServer = createHttpServer(app);
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (address === null || typeof address === "string") throw new Error("HTTP address unavailable");
  baseUrl = `http://127.0.0.1:${String(address.port)}`;
}, 30_000);

afterAll(async () => {
  await new Promise<void>((resolve) => httpServer.close(() => { resolve(); }));
  await ui.close();
  await trajectory.close();
  await postgres.stop();
}, 30_000);

async function seedPendingApproval(suffix: string) {
  const candidate = createPostgresTrajectoryFixtureV1(suffix, new Date(Date.now() - 20_000));
  await trajectory.persistDecisionTrajectory(candidate);
  const pending = {
    ...candidate.approval,
    state: "PENDING" as const,
    decidedAt: null,
    decidedByHumanId: null
  };
  await trajectory.persistApproval(pending);
  const resource = candidate.action.resources[0];
  if (resource === undefined) throw new Error("Resource fixture missing");
  const now = new Date();
  const scope = {
    ...candidate.action.identity,
    stateNamespace: candidate.action.sessionId,
    ...candidate.action.route,
    credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
    environment: candidate.action.environment,
    resourceId: resource.resourceId,
    resourceClass: resource.resourceClass,
    resourcesDigest: candidate.action.resourcesDigest
  };
  const evidence = (Object.entries(guarantees) as Array<
    [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
  >).flatMap(([pathKind, values]) => values.map((guarantee) => ({
    schemaVersion: "1.0.0" as const,
    evidenceId: `${suffix}-${pathKind}-${guarantee}`,
    guarantee,
    pathKind,
    verifierId: `${suffix}-verifier-${pathKind}-${guarantee}`,
    authority: "web-integration-test",
    verifierClass: "TEST_FIXTURE" as const,
    assurance: "DISPOSABLE_TEST" as const,
    scope,
    status: pathKind === "GATEWAY_MEDIATED"
      ? "VERIFIED_ENFORCING" as const
      : "VERIFIED_BLOCKED" as const,
    revision: 1,
    observedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString(),
    proofDigest: computeCanonicalDigestV1({ suffix, pathKind, guarantee })
  })));
  const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
    pathKind,
    coverage: "ENFORCED" as const,
    reasonCodes: []
  }));
  const assessment = {
    schemaVersion: "1.0.0" as const,
    assessmentId: `coverage-${suffix}`,
    revision: 1,
    assurance: "DISPOSABLE_TEST" as const,
    scope,
    coverage: "ENFORCED" as const,
    mutationAllowed: true,
    paths,
    missingGuarantees: [],
    evidence,
    evidenceDigest: computeCanonicalDigestV1({
      assurance: "DISPOSABLE_TEST", scope, coverage: "ENFORCED", paths,
      missingGuarantees: [], evidence
    }),
    assessedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString()
  };
  await trajectory.persistCoverageAssessment(assessment);
  const { view, awareness } = new TrustworthyInterfaceBuilderV1({
    interfaceIdFactory: () => `interface-${suffix}`,
    awarenessIdFactory: () => `awareness-${suffix}`
  }).build({ action: candidate.action, decision: candidate.decision, coverage: assessment });
  await trajectory.persistTrustworthyInterface({
    view,
    awareness,
    presentedEvent: {
      schemaVersion: "1.0.0",
      eventId: `presented-${suffix}`,
      interfaceId: view.interfaceId,
      policyScopeId: view.route.policyScopeId,
      eventType: "PRESENTED",
      decisionLatencyMs: null,
      relatedAttemptCount: 0,
      occurredAt: now.toISOString()
    }
  });
  await ui.configureHuman({
    authority: {
      schemaVersion: "1.0.0",
      administratorId: "approval-admin",
      authenticatedAt: now.toISOString()
    },
    human: {
      schemaVersion: "1.0.0",
      humanId: humanPrincipal.humanId,
      credentialId: humanPrincipal.credentialId,
      authenticationMethod: humanPrincipal.authenticationMethod,
      authenticationRevision: humanPrincipal.identityRevision,
      authenticatedAt: humanPrincipal.authenticatedAt
    },
    policyScopeIds: [candidate.action.route.policyScopeId]
  });
  return { candidate, pending, view };
}

async function approveWithoutRuntimeDispatch(suffix: string) {
  const seeded = await seedPendingApproval(suffix);
  const now = new Date();
  const webStore = ui.asApprovalWebStore();
  const session = await webStore.createSession({
    sessionIdDigest: computeCanonicalDigestV1({ suffix, kind: "session" }),
    csrfTokenDigest: computeCanonicalDigestV1({ suffix, kind: "csrf" }),
    principal: humanPrincipal,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString()
  });
  await webStore.decide({
    session,
    approvalId: seeded.pending.approvalId,
    decision: "APPROVE",
    expectedRevision: 1,
    decidedAt: now.toISOString()
  });
  return seeded;
}

describe("approval web application with PostgreSQL", () => {
  it("loads a live pending record and durably denies it through the authenticated HTTP boundary", async () => {
    const fixtureTime = new Date(Date.now() - 20_000);
    const candidate = createPostgresTrajectoryFixtureV1("approval-web-postgres", fixtureTime);
    await trajectory.persistDecisionTrajectory(candidate);
    const pending = {
      ...candidate.approval,
      state: "PENDING" as const,
      decidedAt: null,
      decidedByHumanId: null
    };
    await trajectory.persistApproval(pending);

    const resource = candidate.action.resources[0];
    if (resource === undefined) throw new Error("Resource fixture missing");
    const now = new Date();
    const scope = {
      ...candidate.action.identity,
      stateNamespace: candidate.action.sessionId,
      ...candidate.action.route,
      credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
      environment: candidate.action.environment,
      resourceId: resource.resourceId,
      resourceClass: resource.resourceClass,
      resourcesDigest: candidate.action.resourcesDigest
    };
    const evidence = (Object.entries(guarantees) as Array<
      [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
    >).flatMap(([pathKind, values]) => values.map((guarantee) => ({
      schemaVersion: "1.0.0" as const,
      evidenceId: `web-${pathKind}-${guarantee}`,
      guarantee,
      pathKind,
      verifierId: `web-verifier-${pathKind}-${guarantee}`,
      authority: "web-integration-test",
      verifierClass: "TEST_FIXTURE" as const,
      assurance: "DISPOSABLE_TEST" as const,
      scope,
      status: pathKind === "GATEWAY_MEDIATED"
        ? "VERIFIED_ENFORCING" as const
        : "VERIFIED_BLOCKED" as const,
      revision: 1,
      observedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      proofDigest: computeCanonicalDigestV1({ pathKind, guarantee })
    })));
    const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
      pathKind,
      coverage: "ENFORCED" as const,
      reasonCodes: []
    }));
    const assessment = {
      schemaVersion: "1.0.0" as const,
      assessmentId: "coverage-approval-web-postgres",
      revision: 1,
      assurance: "DISPOSABLE_TEST" as const,
      scope,
      coverage: "ENFORCED" as const,
      mutationAllowed: true,
      paths,
      missingGuarantees: [],
      evidence,
      evidenceDigest: computeCanonicalDigestV1({
        assurance: "DISPOSABLE_TEST", scope, coverage: "ENFORCED", paths,
        missingGuarantees: [], evidence
      }),
      assessedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString()
    };
    await trajectory.persistCoverageAssessment(assessment);
    const { view, awareness } = new TrustworthyInterfaceBuilderV1({
      interfaceIdFactory: () => "interface-approval-web-postgres",
      awarenessIdFactory: () => "awareness-approval-web-postgres"
    }).build({ action: candidate.action, decision: candidate.decision, coverage: assessment });
    await trajectory.persistTrustworthyInterface({
      view,
      awareness,
      presentedEvent: {
        schemaVersion: "1.0.0",
        eventId: "presented-approval-web-postgres",
        interfaceId: view.interfaceId,
        policyScopeId: view.route.policyScopeId,
        eventType: "PRESENTED",
        decisionLatencyMs: null,
        relatedAttemptCount: 0,
        occurredAt: now.toISOString()
      }
    });
    await ui.configureHuman({
      authority: {
        schemaVersion: "1.0.0",
        administratorId: "approval-admin",
        authenticatedAt: now.toISOString()
      },
      human: {
        schemaVersion: "1.0.0",
        humanId: humanPrincipal.humanId,
        credentialId: humanPrincipal.credentialId,
        authenticationMethod: humanPrincipal.authenticationMethod,
        authenticationRevision: humanPrincipal.identityRevision,
        authenticatedAt: humanPrincipal.authenticatedAt
      },
      policyScopeIds: [candidate.action.route.policyScopeId]
    });

    const sessionResponse = await fetch(`${baseUrl}/approval/api/session`, {
      method: "POST",
      headers: {
        Origin: approvalOrigin,
        "Sec-Fetch-Site": "same-origin",
        "X-Test-Human": humanPrincipal.humanId
      }
    });
    expect(sessionResponse.status).toBe(201);
    const sessionBody = await sessionResponse.json() as {
      csrfToken: string;
      human: { humanId: string };
    };
    expect(sessionBody.human.humanId).toBe(humanPrincipal.humanId);
    const setCookie = sessionResponse.headers.get("set-cookie");
    if (setCookie === null) throw new Error("Approval session cookie missing");
    const cookie = setCookie.split(";", 1)[0];
    if (cookie === undefined) throw new Error("Approval session cookie malformed");

    const authenticatedHeaders = {
      Cookie: cookie,
      "Sec-Fetch-Site": "same-origin",
      "X-Test-Human": humanPrincipal.humanId
    };
    const pendingResponse = await fetch(`${baseUrl}/approval/api/pending`, {
      headers: authenticatedHeaders
    });
    expect(pendingResponse.status).toBe(200);
    const pendingBody = await pendingResponse.json() as {
      approvals: Array<{ approvalId: string; state: string; policyScopeId: string }>;
    };
    expect(pendingBody.approvals).toEqual([
      expect.objectContaining({
        approvalId: pending.approvalId,
        state: "PENDING",
        policyScopeId: candidate.action.route.policyScopeId
      })
    ]);

    const detailResponse = await fetch(
      `${baseUrl}/approval/api/approvals/${encodeURIComponent(pending.approvalId)}`,
      { headers: authenticatedHeaders }
    );
    expect(detailResponse.status).toBe(200);
    const etag = detailResponse.headers.get("etag");
    expect(etag).toMatch(/^"[1-9][0-9]*"$/u);
    const detail = await detailResponse.json() as {
      approval: { approvalId: string; state: string };
      view: { interfaceId: string };
      outcome: unknown;
    };
    expect(detail).toMatchObject({
      approval: { approvalId: pending.approvalId, state: "PENDING" },
      view: { interfaceId: view.interfaceId },
      outcome: null
    });

    const crossUserResponse = await fetch(
      `${baseUrl}/approval/api/approvals/${encodeURIComponent(pending.approvalId)}`,
      {
        headers: {
          ...authenticatedHeaders,
          "X-Test-Human": otherPrincipal.humanId
        }
      }
    );
    expect(crossUserResponse.status).toBe(401);

    const decisionUrl =
      `${baseUrl}/approval/api/approvals/${encodeURIComponent(pending.approvalId)}/decision`;
    const crossOriginResponse = await fetch(decisionUrl, {
      method: "POST",
      headers: {
        ...authenticatedHeaders,
        Origin: "https://attacker.example",
        "Content-Type": "application/json",
        "If-Match": etag ?? "",
        "X-CSRF-Token": sessionBody.csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "DENY" })
    });
    expect(crossOriginResponse.status).toBe(403);

    const denyResponse = await fetch(decisionUrl, {
      method: "POST",
      headers: {
        ...authenticatedHeaders,
        Origin: approvalOrigin,
        "Content-Type": "application/json",
        "If-Match": etag ?? "",
        "X-CSRF-Token": sessionBody.csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "DENY" })
    });
    expect(denyResponse.status).toBe(200);
    expect(await denyResponse.json()).toMatchObject({
      approval: {
        approvalId: pending.approvalId,
        state: "DENIED",
        decidedByHumanId: humanPrincipal.humanId
      },
      audit: [
        expect.objectContaining({
          eventType: "DECISION_RECORDED",
          humanId: humanPrincipal.humanId,
          approvalId: pending.approvalId
        })
      ]
    });

    const duplicateResponse = await fetch(decisionUrl, {
      method: "POST",
      headers: {
        ...authenticatedHeaders,
        Origin: approvalOrigin,
        "Content-Type": "application/json",
        "If-Match": etag ?? "",
        "X-CSRF-Token": sessionBody.csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "DENY" })
    });
    expect(duplicateResponse.status).toBe(409);
    expect(await duplicateResponse.json()).toMatchObject({
      error: { code: "approval.stale" }
    });

    const verifier = new Pool({ connectionString, application_name: "approval-web-audit-verifier" });
    try {
      const audit = await verifier.query<{
        event_type: string;
        human_id: string;
        reason_codes: string[];
      }>(
        `SELECT event_type,human_id,reason_codes FROM approval_ui_security_events
         WHERE approval_id=$1 ORDER BY sequence_id`,
        [pending.approvalId]
      );
      expect(audit.rows).toEqual([
        {
          event_type: "DECISION_RECORDED",
          human_id: humanPrincipal.humanId,
          reason_codes: ["approval_ui.denied"]
        }
      ]);
    } finally {
      await verifier.end();
    }
  });

  it("approves through the PostgreSQL resolver, real executor, consumption, and terminal outcome path", async () => {
    const { pending } = await seedPendingApproval("approval-web-runtime");
    const sessionResponse = await fetch(`${baseUrl}/approval/api/session`, {
      method: "POST",
      headers: {
        Origin: approvalOrigin,
        "Sec-Fetch-Site": "same-origin",
        "X-Test-Human": humanPrincipal.humanId
      }
    });
    expect(sessionResponse.status).toBe(201);
    const sessionBody = await sessionResponse.json() as { csrfToken: string };
    const setCookie = sessionResponse.headers.get("set-cookie");
    if (setCookie === null) throw new Error("Approval session cookie missing");
    const cookie = setCookie.split(";", 1)[0];
    if (cookie === undefined) throw new Error("Approval session cookie malformed");
    const headers = {
      Cookie: cookie,
      "Sec-Fetch-Site": "same-origin",
      "X-Test-Human": humanPrincipal.humanId
    };
    const detailResponse = await fetch(
      `${baseUrl}/approval/api/approvals/${encodeURIComponent(pending.approvalId)}`,
      { headers }
    );
    const etag = detailResponse.headers.get("etag");
    expect(detailResponse.status).toBe(200);
    expect(etag).toMatch(/^"[1-9][0-9]*"$/u);

    const decisionUrl =
      `${baseUrl}/approval/api/approvals/${encodeURIComponent(pending.approvalId)}/decision`;
    const approve = await fetch(decisionUrl, {
      method: "POST",
      headers: {
        ...headers,
        Origin: approvalOrigin,
        "Content-Type": "application/json",
        "If-Match": etag ?? "",
        "X-CSRF-Token": sessionBody.csrfToken
      },
      body: JSON.stringify({ schemaVersion: "1.0.0", decision: "APPROVE" })
    });
    expect(approve.status).toBe(200);
    expect(await approve.json()).toMatchObject({
      approval: { approvalId: pending.approvalId, state: "CONSUMED" },
      outcome: {
        approvalId: pending.approvalId,
        status: "FAILED",
        possiblePartialEffects: false
      },
      audit: [expect.objectContaining({
        eventType: "DECISION_RECORDED",
        reasonCodes: ["approval_ui.approved_once"]
      })]
    });

    const verifier = new Pool({ connectionString, application_name: "approval-runtime-verifier" });
    try {
      const trajectoryRows = await verifier.query<{
        approval_state: string;
        forwarding_state: string;
        outcome_status: string;
      }>(
        `SELECT a.state AS approval_state,f.state AS forwarding_state,o.status AS outcome_status
           FROM approvals a
           JOIN forwarding_attempts f ON f.approval_id=a.approval_id
           JOIN outcomes o ON o.forwarding_attempt_id=f.forwarding_attempt_id
          WHERE a.approval_id=$1`,
        [pending.approvalId]
      );
      expect(trajectoryRows.rows).toEqual([{
        approval_state: "CONSUMED",
        forwarding_state: "FAILED",
        outcome_status: "FAILED"
      }]);
      const dispatch = await verifier.query<{ state: string; failure_reason_code: string | null }>(
        "SELECT state,failure_reason_code FROM approval_runtime_dispatches WHERE approval_id=$1",
        [pending.approvalId]
      );
      expect(dispatch.rows).toEqual([{ state: "COMPLETED", failure_reason_code: null }]);
    } finally {
      await verifier.end();
    }
  });

  it("recovers one unclaimed approval after restart without a forwarding attempt", async () => {
    const { pending } = await approveWithoutRuntimeDispatch("approval-dispatch-unclaimed");
    const peer = await PostgresTrajectoryStoreV1.connect({
      connectionString,
      approvalRuntimePayloadEncryption: {
        keyId: "approval-web-runtime-key",
        key: Buffer.alloc(32, 11)
      }
    });
    const recoveredAt = new Date(Date.now() + 120_000);
    try {
      const results = await Promise.all([
        trajectory.recoverStaleApprovalDispatches({
          staleBefore: new Date(recoveredAt.getTime() - 1_000).toISOString(),
          recoveredAt: recoveredAt.toISOString()
        }),
        peer.recoverStaleApprovalDispatches({
          staleBefore: new Date(recoveredAt.getTime() - 1_000).toISOString(),
          recoveredAt: recoveredAt.toISOString()
        })
      ]);
      expect(results.reduce((sum, value) => sum + value, 0)).toBe(1);
    } finally {
      await peer.close();
    }
    const verifier = new Pool({ connectionString, application_name: "approval-recovery-verifier" });
    try {
      const state = await verifier.query<{
        approval_state: string;
        dispatch_state: string;
        attempt_count: string;
      }>(
        `SELECT a.state AS approval_state,d.state AS dispatch_state,
           (SELECT count(*) FROM forwarding_attempts f WHERE f.approval_id=a.approval_id) AS attempt_count
         FROM approvals a JOIN approval_runtime_dispatches d ON d.approval_id=a.approval_id
         WHERE a.approval_id=$1`,
        [pending.approvalId]
      );
      expect(state.rows).toEqual([{
        approval_state: "REVOKED",
        dispatch_state: "FAILED",
        attempt_count: "0"
      }]);
      const audit = await verifier.query<{ reason_codes: string[] }>(
        `SELECT reason_codes FROM approval_ui_security_events
         WHERE approval_id=$1 AND reason_codes @> ARRAY['approval.runtime_dispatch.recovered']::text[]`,
        [pending.approvalId]
      );
      expect(audit.rowCount).toBe(1);
    } finally {
      await verifier.end();
    }
  });

  it("revokes a claimed approval when protected session resolution fails", async () => {
    const { pending } = await approveWithoutRuntimeDispatch("approval-dispatch-resolution-failure");
    const failedAt = new Date();
    await trajectory.claimApprovalDispatch({
      approvalId: pending.approvalId,
      humanId: humanPrincipal.humanId,
      claimId: "claim-approval-dispatch-resolution-failure",
      claimedAt: failedAt.toISOString()
    });
    await trajectory.failApprovalDispatch({
      approvalId: pending.approvalId,
      humanId: humanPrincipal.humanId,
      claimId: "claim-approval-dispatch-resolution-failure",
      failedAt: new Date(failedAt.getTime() + 1).toISOString()
    });
    const verifier = new Pool({ connectionString, application_name: "approval-resolution-failure-verifier" });
    try {
      const state = await verifier.query<{
        approval_state: string;
        dispatch_state: string;
        failure_reason_code: string;
        attempt_count: string;
      }>(
        `SELECT a.state AS approval_state,d.state AS dispatch_state,d.failure_reason_code,
           (SELECT count(*) FROM forwarding_attempts f WHERE f.approval_id=a.approval_id) AS attempt_count
         FROM approvals a JOIN approval_runtime_dispatches d ON d.approval_id=a.approval_id
         WHERE a.approval_id=$1`,
        [pending.approvalId]
      );
      expect(state.rows).toEqual([{
        approval_state: "REVOKED",
        dispatch_state: "FAILED",
        failure_reason_code: "approval.runtime_dispatch.failed",
        attempt_count: "0"
      }]);
    } finally {
      await verifier.end();
    }
  });

  it("records an UNKNOWN terminal outcome for a stale consumed dispatch and never retries it", async () => {
    const { candidate, pending } = await approveWithoutRuntimeDispatch("approval-dispatch-consumed");
    const claimedAt = new Date();
    const authorization = {
      ...candidate.authorization,
      forwardingAttemptId: "forward-approval-dispatch-consumed-recovery",
      authorizedAt: claimedAt.toISOString()
    };
    await trajectory.claimApprovalDispatch({
      approvalId: pending.approvalId,
      humanId: humanPrincipal.humanId,
      claimId: "claim-approval-dispatch-consumed-recovery",
      claimedAt: claimedAt.toISOString()
    });
    await trajectory.consumeApprovalAndStartForwarding(authorization);
    const recoveredAt = new Date(claimedAt.getTime() + 120_000);
    expect(await trajectory.recoverStaleApprovalDispatches({
      staleBefore: new Date(recoveredAt.getTime() - 1_000).toISOString(),
      recoveredAt: recoveredAt.toISOString()
    })).toBe(1);

    const verifier = new Pool({ connectionString, application_name: "approval-unknown-verifier" });
    try {
      const state = await verifier.query<{
        approval_state: string;
        dispatch_state: string;
        forwarding_state: string;
        outcome_status: string;
        possible_partial_effects: boolean;
      }>(
        `SELECT a.state AS approval_state,d.state AS dispatch_state,
           f.state AS forwarding_state,o.status AS outcome_status,o.possible_partial_effects
         FROM approvals a JOIN approval_runtime_dispatches d ON d.approval_id=a.approval_id
         JOIN forwarding_attempts f ON f.approval_id=a.approval_id
         JOIN outcomes o ON o.approval_id=a.approval_id
         WHERE a.approval_id=$1`,
        [pending.approvalId]
      );
      expect(state.rows).toEqual([{
        approval_state: "CONSUMED",
        dispatch_state: "FAILED",
        forwarding_state: "UNKNOWN",
        outcome_status: "UNKNOWN",
        possible_partial_effects: true
      }]);
    } finally {
      await verifier.end();
    }
    await expect(trajectory.claimApprovalDispatch({
      approvalId: pending.approvalId,
      humanId: humanPrincipal.humanId,
      claimId: "claim-approval-dispatch-consumed-retry",
      claimedAt: recoveredAt.toISOString()
    })).rejects.toBeDefined();
  });
});
