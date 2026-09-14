import { createServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import EmbeddedPostgres from "embedded-postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import { TrustworthyInterfaceBuilderV1 } from "../../src/interfaces/trustworthy-interface-v1.js";
import {
  ApprovalUiPersistenceDeniedV1,
  PostgresApprovalUiStoreV1
} from "../../src/persistence/postgres-approval-ui-store-v1.js";
import { PostgresTrajectoryStoreV1 } from "../../src/persistence/postgres-trajectory-store-v1.js";
import type {
  CoveragePathKindV1,
  MediationGuaranteeV1
} from "../../src/coverage/exclusive-mediation-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

let postgres: EmbeddedPostgres;
let trajectory: PostgresTrajectoryStoreV1;
let ui: PostgresApprovalUiStoreV1;
let connectionString: string;
let eventNumber = 0;

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { resolve(); });
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
  DIRECT: ["CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION", "DOWNSTREAM_AUTHORIZATION"]
} as const satisfies Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>>;

beforeAll(async () => {
  const port = await availablePort();
  postgres = new EmbeddedPostgres({
    databaseDir: await mkdtemp(join(tmpdir(), "agent-security-approval-ui-")),
    user: "postgres", password: "disposable-password", port, persistent: false,
    onLog: () => undefined, onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  connectionString = `postgresql://postgres:disposable-password@127.0.0.1:${String(port)}/postgres`;
  trajectory = await PostgresTrajectoryStoreV1.connect({ connectionString });
  ui = await PostgresApprovalUiStoreV1.connect({
    connectionString,
    expectedOrigin: "http://127.0.0.1:4175",
    administratorAuthorizer: (authority) => authority.administratorId === "approval-admin",
    eventIdFactory: () => `approval-ui-event-${String(++eventNumber)}`
  });
}, 30_000);

afterAll(async () => {
  await ui.close();
  await trajectory.close();
  await postgres.stop();
}, 30_000);

describe("PostgreSQL approval UI boundary", () => {
  it("authenticates a scoped human and records one exact denial across concurrent tabs", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("approval-ui", new Date(Date.now() - 10_000));
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
      ...candidate.action.identity, stateNamespace: candidate.action.sessionId,
      ...candidate.action.route,
      credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
      environment: candidate.action.environment, resourceId: resource.resourceId,
      resourceClass: resource.resourceClass, resourcesDigest: candidate.action.resourcesDigest
    };
    const evidence = (Object.entries(guarantees) as Array<
      [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
    >).flatMap(([pathKind, values]) => values.map((guarantee) => ({
      schemaVersion: "1.0.0" as const,
      evidenceId: `ui-${pathKind}-${guarantee}`, guarantee, pathKind,
      verifierId: `ui-verifier-${pathKind}-${guarantee}`, authority: "ui-test",
      verifierClass: "TEST_FIXTURE" as const, assurance: "DISPOSABLE_TEST" as const,
      scope,
      status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
      revision: 1, observedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60_000).toISOString(),
      proofDigest: computeCanonicalDigestV1({ pathKind, guarantee })
    })));
    const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
      pathKind, coverage: "ENFORCED" as const, reasonCodes: []
    }));
    const assessment = {
      schemaVersion: "1.0.0" as const, assessmentId: "coverage-approval-ui", revision: 1,
      assurance: "DISPOSABLE_TEST" as const, scope, coverage: "ENFORCED" as const,
      mutationAllowed: true, paths, missingGuarantees: [], evidence,
      evidenceDigest: computeCanonicalDigestV1({ assurance: "DISPOSABLE_TEST", scope,
        coverage: "ENFORCED", paths, missingGuarantees: [], evidence }),
      assessedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 60_000).toISOString()
    };
    await trajectory.persistCoverageAssessment(assessment);
    const { view, awareness } = new TrustworthyInterfaceBuilderV1({
      interfaceIdFactory: () => "interface-approval-ui",
      awarenessIdFactory: () => "awareness-approval-ui"
    }).build({ action: candidate.action, decision: candidate.decision, coverage: assessment });
    await trajectory.persistTrustworthyInterface({
      view, awareness,
      presentedEvent: {
        schemaVersion: "1.0.0", eventId: "presented-approval-ui",
        interfaceId: view.interfaceId, policyScopeId: view.route.policyScopeId,
        eventType: "PRESENTED", decisionLatencyMs: null, relatedAttemptCount: 0,
        occurredAt: now.toISOString()
      }
    });

    const authority = {
      schemaVersion: "1.0.0" as const, administratorId: "approval-admin",
      authenticatedAt: now.toISOString()
    };
    const human = {
      schemaVersion: "1.0.0" as const, humanId: "human-approval-ui",
      subjectId: "opaque-idp-subject", authenticationMethod: "OIDC" as const,
      authenticationRevision: 1, authenticatedAt: now.toISOString()
    };
    await ui.configureHuman({ authority, human, policyScopeIds: [candidate.action.route.policyScopeId] });
    const browser = await ui.createBrowserSession(human);
    const pendingItems = await ui.listPending(browser.sessionToken);
    expect(pendingItems).toHaveLength(1);
    expect(pendingItems[0]).toMatchObject({
      approvalId: pending.approvalId, actionHash: pending.actionHash,
      policyScopeId: candidate.action.route.policyScopeId, state: "PENDING"
    });
    expect(JSON.stringify(pendingItems)).not.toContain(human.subjectId);
    expect((await ui.readDetail(browser.sessionToken, pending.approvalId)).outcome).toBeNull();

    const decision = {
      schemaVersion: "1.0.0" as const, approvalId: pending.approvalId,
      expectedActionHash: pending.actionHash, decision: "DENY" as const,
      sessionToken: browser.sessionToken, csrfToken: browser.csrfToken,
      origin: "http://127.0.0.1:4175"
    };
    const races = await Promise.allSettled([ui.recordDecision(decision), ui.recordDecision(decision)]);
    expect(races.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(races.filter((item) => item.status === "rejected")).toHaveLength(1);
    const decided = await ui.readDetail(browser.sessionToken, pending.approvalId);
    expect(decided.approval).toMatchObject({ state: "DENIED", decidedByHumanId: human.humanId });
    expect(decided.audit).toHaveLength(1);
    await expect(ui.recordDecision({ ...decision, origin: "https://attacker.example" }))
      .rejects.toBeInstanceOf(ApprovalUiPersistenceDeniedV1);
  });
});
