import { createHash } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer, type Server } from "node:https";
import { createServer as createNetServer } from "node:net";
import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { expect, test } from "@playwright/test";
import EmbeddedPostgres from "embedded-postgres";
import { Pool } from "pg";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import type {
  CoveragePathKindV1,
  MediationGuaranteeV1
} from "../../src/coverage/exclusive-mediation-v1.js";
import {
  createApprovalWebAppV1,
  type ApprovalWebStaticAssetV1
} from "../../src/interfaces/approval-web-v1.js";
import { TrustworthyInterfaceBuilderV1 } from "../../src/interfaces/trustworthy-interface-v1.js";
import { PostgresApprovalUiStoreV1 } from "../../src/persistence/postgres-approval-ui-store-v1.js";
import { PostgresTrajectoryStoreV1 } from "../../src/persistence/postgres-trajectory-store-v1.js";
import { ApprovalWebRuntimeBridgeV1 } from "../../src/runtime/approval-web-runtime-v1.js";
import { ClientApprovedCallExecutorV1 } from "../../src/runtime/client-tool-call-v1.js";
import { createHashiCorpVaultApprovalRuntimeV1 } from "../../src/runtime/protected-approval-runtime-v1.js";
import { HashiCorpVaultKvV2ProviderV1 } from "../../src/identity/hashicorp-vault-provider-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

let approvalOrigin: string;
const humanPrincipal = {
  schemaVersion: "1.0.0" as const,
  humanId: "human-approval-browser",
  authenticationMethod: "OIDC" as const,
  credentialId: "opaque-browser-idp-subject",
  identityRevision: 1,
  authenticatedAt: new Date(Date.now() - 30_000).toISOString()
};

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

let postgres: EmbeddedPostgres;
let trajectory: PostgresTrajectoryStoreV1;
let ui: PostgresApprovalUiStoreV1;
let httpServer: Server | null = null;
let connectionString: string;
let baseUrl: string;
let eventNumber = 0;
let activeRuntimeBridge: ApprovalWebRuntimeBridgeV1 | null = null;

async function availablePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolvePort, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePort);
  });
  const address = server.address();
  await new Promise<void>((resolveClose) => server.close(() => { resolveClose(); }));
  if (address === null || typeof address === "string") throw new Error("Port unavailable");
  return address.port;
}

async function readApprovalAsset(path: "/index.html" | `/assets/${string}`): Promise<ApprovalWebStaticAssetV1 | null> {
  const names: Readonly<Record<string, readonly [string, ApprovalWebStaticAssetV1["contentType"]]>> = {
    "/index.html": ["index.html", "text/html; charset=utf-8"],
    "/assets/app.css": ["app.css", "text/css; charset=utf-8"],
    "/assets/app.js": ["app.js", "application/javascript; charset=utf-8"]
  };
  const asset = names[path];
  if (asset === undefined) return null;
  return { contentType: asset[1], body: await readFile(join(resolve("approval-ui"), asset[0]), "utf8") };
}

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  const postgresPort = await availablePort();
  const webPort = await availablePort();
  baseUrl = `https://127.0.0.1:${String(webPort)}`;
  approvalOrigin = baseUrl;
  postgres = new EmbeddedPostgres({
    databaseDir: await mkdtemp(join(tmpdir(), "agent-security-browser-postgres-")),
    user: "postgres",
    password: "disposable-password",
    port: postgresPort,
    persistent: false,
    onLog: () => undefined,
    onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  connectionString = `postgresql://postgres:disposable-password@127.0.0.1:${String(postgresPort)}/postgres`;
  trajectory = await PostgresTrajectoryStoreV1.connect({
    connectionString,
    approvalRuntimePayloadEncryption: {
      keyId: "approval-browser-runtime-key",
      key: Buffer.alloc(32, 17)
    }
  });
  ui = await PostgresApprovalUiStoreV1.connect({
    connectionString,
    expectedOrigin: approvalOrigin,
    administratorAuthorizer: (authority) => authority.administratorId === "approval-admin",
    eventIdFactory: () => `approval-browser-event-${String(++eventNumber)}`
  });
  const app = createApprovalWebAppV1({
    origin: approvalOrigin,
    store: ui.asApprovalWebStore(),
    authenticateHuman: (request) => request.get("x-test-human") === humanPrincipal.humanId
      ? humanPrincipal
      : null,
    executeApprovedCall: (input) => {
      if (activeRuntimeBridge === null) throw new Error("Protected runtime is unavailable");
      return activeRuntimeBridge.executeApprovedCall(input);
    },
    readStaticAsset: readApprovalAsset
  });
  const [certificate, privateKey] = await Promise.all([
    readFile(resolve("test", "fixtures", "localhost-test-cert.pem")),
    readFile(resolve("test", "fixtures", "localhost-test-key.pem"))
  ]);
  const server = createHttpsServer({ cert: certificate, key: privateKey }, app);
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(webPort, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("HTTP address unavailable");
  if (address.port !== webPort) throw new Error("HTTP port binding changed unexpectedly");
  httpServer = server;
});

test.afterAll(async () => {
  const server = httpServer;
  if (server !== null) {
    await new Promise<void>((resolveClose) => server.close(() => { resolveClose(); }));
  }
  await ui.close();
  await trajectory.close();
  await postgres.stop();
});

async function seedLiveApproval(
  candidate: ReturnType<typeof createPostgresTrajectoryFixtureV1>,
  binding = candidate.binding,
  expiresAt = candidate.approval.expiresAt
) {
  await trajectory.persistDecisionTrajectory({ ...candidate, binding });
  const pending = {
    ...candidate.approval,
    state: "PENDING" as const,
    decidedAt: null,
    decidedByHumanId: null,
    expiresAt
  };
  await trajectory.persistApproval(pending);
  const resource = candidate.action.resources[0];
  if (resource === undefined) throw new Error("Resource fixture missing");
  const now = new Date();
  const scope = {
    ...candidate.action.identity,
    stateNamespace: candidate.action.sessionId,
    ...candidate.action.route,
    credentialProfileId: binding.server.credentialAudience.credentialProfileId,
    environment: candidate.action.environment,
    resourceId: resource.resourceId,
    resourceClass: resource.resourceClass,
    resourcesDigest: candidate.action.resourcesDigest
  };
  const evidence = (Object.entries(guarantees) as Array<
    [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
  >).flatMap(([pathKind, values]) => values.map((guarantee) => ({
    schemaVersion: "1.0.0" as const,
    evidenceId: `${candidate.approval.approvalId}-${pathKind}-${guarantee}`,
    guarantee,
    pathKind,
    verifierId: `browser-verifier-${pathKind}-${guarantee}`,
    authority: "browser-integration-test",
    verifierClass: "TEST_FIXTURE" as const,
    assurance: "DISPOSABLE_TEST" as const,
    scope,
    status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
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
    assessmentId: `coverage-${candidate.approval.approvalId}`,
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
    interfaceIdFactory: () => `interface-${candidate.approval.approvalId}`,
    awarenessIdFactory: () => `awareness-${candidate.approval.approvalId}`
  }).build({ action: candidate.action, decision: candidate.decision, coverage: assessment });
  await trajectory.persistTrustworthyInterface({
    view,
    awareness,
    presentedEvent: {
      schemaVersion: "1.0.0",
      eventId: `presented-${candidate.approval.approvalId}`,
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
  return { pending, resource, scope };
}

async function persistDegradedCoverage(
  candidate: ReturnType<typeof createPostgresTrajectoryFixtureV1>,
  scope: Awaited<ReturnType<typeof seedLiveApproval>>["scope"]
) {
  const now = new Date();
  const paths = (["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const).map((pathKind) => ({
    pathKind,
    coverage: "UNPROTECTED" as const,
    reasonCodes: ["coverage.network_isolation.reachable"]
  }));
  const missingGuarantees = [{
    guarantee: "NETWORK_ISOLATION" as const,
    pathKind: "DIRECT" as const,
    reasonCode: "coverage.network_isolation.reachable",
    verifierId: null
  }];
  const evidence: never[] = [];
  await trajectory.persistCoverageAssessment({
    schemaVersion: "1.0.0",
    assessmentId: `degraded-${candidate.approval.approvalId}`,
    revision: 2,
    assurance: "DISPOSABLE_TEST",
    scope,
    coverage: "UNPROTECTED",
    mutationAllowed: false,
    paths,
    missingGuarantees,
    evidence,
    evidenceDigest: computeCanonicalDigestV1({
      assurance: "DISPOSABLE_TEST", scope, coverage: "UNPROTECTED", paths,
      missingGuarantees, evidence
    }),
    assessedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString()
  });
}

function activateVaultRuntime(input: {
  readonly candidate: ReturnType<typeof createPostgresTrajectoryFixtureV1>;
  readonly binding: ReturnType<typeof createPostgresTrajectoryFixtureV1>["binding"];
  readonly downstreamSecret: string;
  readonly fetchImplementation: typeof fetch;
  readonly validateOutputSchema?: (input: { readonly structuredContent: Readonly<Record<string, unknown>> | null }) => boolean;
}) {
  if (input.binding.server.transport.kind === "STDIO") {
    throw new Error("Browser runtime requires an HTTP route");
  }
  const now = new Date();
  const downstreamOrigin = new URL(input.binding.server.transport.endpoint).origin;
  const provider = new HashiCorpVaultKvV2ProviderV1({
    descriptor: {
      schemaVersion: "1.0.0",
      providerId: `approved-vault-${input.candidate.approval.approvalId}`,
      providerType: "HASHICORP_VAULT",
      approval: {
        status: "APPROVED",
        approvedBy: "project-owner",
        approvedAt: now.toISOString(),
        configurationDigest: computeCanonicalDigestV1({ approvalId: input.candidate.approval.approvalId })
      }
    },
    endpointOrigin: "https://vault.browser.test",
    tokenProvider: () => Promise.resolve(Buffer.from("browser-vault-token", "utf8")),
    fetchImplementation: input.fetchImplementation
  });
  const runtime = createHashiCorpVaultApprovalRuntimeV1({
    secretManager: provider,
    credentialBindings: [{
      schemaVersion: "1.0.0",
      secretManagerProviderId: provider.descriptor.providerId,
      secretReference: "kv-v2://secret/browser/downstream#token",
      profile: {
        schemaVersion: "1.0.0",
        credentialProfileId: input.binding.server.credentialAudience.credentialProfileId,
        credentialRevision: 1,
        credentialKind: "BEARER_TOKEN",
        audienceId: input.binding.route.credentialAudienceId,
        allowedRouteIds: [input.binding.route.routeId],
        allowedEndpointOrigins: [downstreamOrigin],
        materialDigest: createHash("sha256").update(input.downstreamSecret).digest("hex"),
        status: "ACTIVE",
        issuedAt: new Date(now.getTime() - 60_000).toISOString(),
        expiresAt: new Date(now.getTime() + 60_000).toISOString()
      }
    }],
    resolveCurrentRoute: () => input.binding,
    authenticateDownstream: () => ({
      schemaVersion: "1.0.0",
      serverId: input.binding.server.serverId,
      principalId: input.binding.server.authenticatedPrincipalId,
      authenticationMethod: "TEST_FIXTURE",
      credentialId: "browser-downstream-credential",
      identityRevision: 1,
      authenticatedAt: now.toISOString()
    }),
    validateOutputSchema: input.validateOutputSchema ??
      ((result) => result.structuredContent?.["ok"] === true),
    classifyResult: () => ["PUBLIC"],
    evaluateEgress: () => "ALLOW"
  });
  activeRuntimeBridge = new ApprovalWebRuntimeBridgeV1({
    sessions: trajectory,
    executor: new ClientApprovedCallExecutorV1({
      loadApprovedCall: (loadInput) => trajectory.loadApprovedCall(loadInput),
      store: trajectory,
      issueCredentialLease: runtime.issueCredentialLease,
      forwarder: runtime.forwarder
    }),
    dispatches: trajectory
  });
}

test("loads canonical context and records an exact keyboard denial durably", async ({ browser }) => {
  const fixtureTime = new Date(Date.now() - 20_000);
  const candidate = createPostgresTrajectoryFixtureV1("approval-browser", fixtureTime);
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
    evidenceId: `browser-${pathKind}-${guarantee}`,
    guarantee,
    pathKind,
    verifierId: `browser-verifier-${pathKind}-${guarantee}`,
    authority: "browser-integration-test",
    verifierClass: "TEST_FIXTURE" as const,
    assurance: "DISPOSABLE_TEST" as const,
    scope,
    status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
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
    assessmentId: "coverage-approval-browser",
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
    interfaceIdFactory: () => "interface-approval-browser",
    awarenessIdFactory: () => "awareness-approval-browser"
  }).build({ action: candidate.action, decision: candidate.decision, coverage: assessment });
  await trajectory.persistTrustworthyInterface({
    view,
    awareness,
    presentedEvent: {
      schemaVersion: "1.0.0",
      eventId: "presented-approval-browser",
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

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: {
      "X-Test-Human": humanPrincipal.humanId
    }
  });
  const page = await context.newPage();
  await page.goto(`${baseUrl}/approval`, { waitUntil: "networkidle" });

  await expect(page.getByText("Protected session active")).toBeVisible();
  const pendingButton = page.locator(`[data-approval-id="${pending.approvalId}"]`);
  await expect(pendingButton).toBeVisible();
  await pendingButton.click();
  await expect(page.getByRole("heading", { name: "Authenticated requester" })).toBeVisible();
  await expect(page.getByText(candidate.action.identity.userId, { exact: true })).toBeVisible();
  await expect(page.locator("#route-fields").getByText(
    candidate.action.route.toolName,
    { exact: true }
  )).toBeVisible();
  await expect(page.locator("#target-list").getByText(
    resource.canonicalReference,
    { exact: true }
  )).toBeVisible();
  await expect(page.getByText(/Enforced coverage/u)).toBeVisible();

  const deny = page.getByRole("button", { name: "Deny", exact: true });
  await deny.focus();
  await expect(deny).toBeFocused();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Deny this action?", exact: true })).toBeVisible();
  await expect(dialog.getByText("This prevents this approval request from being used.", { exact: true })).toBeVisible();
  const confirm = dialog.getByRole("button", { name: "Deny", exact: true });
  await confirm.focus();
  await page.keyboard.press("Enter");

  await expect(page.locator("#approval-state")).toHaveText("Denied");
  await expect(page.getByText("Decision recorded", { exact: true })).toBeVisible();
  await expect(page.getByText("Reasons: approval_ui.denied", { exact: true })).toBeVisible();

  const verifier = new Pool({ connectionString, application_name: "approval-browser-verifier" });
  try {
    const approvalRow = await verifier.query<{ state: string; decided_by_human_id: string }>(
      "SELECT state,decided_by_human_id FROM approvals WHERE approval_id=$1",
      [pending.approvalId]
    );
    expect(approvalRow.rows).toEqual([{
      state: "DENIED",
      decided_by_human_id: humanPrincipal.humanId
    }]);
    const audit = await verifier.query<{ event_type: string; reason_codes: string[] }>(
      `SELECT event_type,reason_codes FROM approval_ui_security_events
       WHERE approval_id=$1 ORDER BY sequence_id`,
      [pending.approvalId]
    );
    expect(audit.rows).toEqual([{
      event_type: "DECISION_RECORDED",
      reason_codes: ["approval_ui.denied"]
    }]);
  } finally {
    await verifier.end();
    await context.close();
  }
});

test("approves once through the Vault broker and displays the governed durable result", async ({ browser }) => {
  const downstreamSecret = "browser-approved-downstream-secret";
  let downstreamCalls = 0;
  const downstream = createHttpServer((request, response) => {
    downstreamCalls += 1;
    expect(request.headers.authorization).toBe(`Bearer ${downstreamSecret}`);
    response.setHeader("Content-Type", "application/json");
    response.setHeader("Mcp-Server-Authorization", "browser-downstream-proof");
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: "protocol-approval-browser-success",
      result: {
        content: [{ type: "text", text: "The protected operation completed." }],
        structuredContent: { ok: true }
      }
    }));
  });
  const downstreamPort = await availablePort();
  await new Promise<void>((resolveListen, reject) => {
    downstream.once("error", reject);
    downstream.listen(downstreamPort, "127.0.0.1", resolveListen);
  });
  const downstreamOrigin = `http://127.0.0.1:${String(downstreamPort)}`;
  const candidate = createPostgresTrajectoryFixtureV1(
    "approval-browser-success",
    new Date(Date.now() - 20_000)
  );
  const binding = {
    ...candidate.binding,
    server: {
      ...candidate.binding.server,
      transport: {
        kind: "STREAMABLE_HTTP" as const,
        endpoint: `${downstreamOrigin}/mcp`,
        authenticationProfileId: candidate.binding.server.transport.kind === "STDIO"
          ? "browser-downstream-auth"
          : candidate.binding.server.transport.authenticationProfileId
      }
    }
  };
  await seedLiveApproval(candidate, binding);
  const now = new Date();
  const provider = new HashiCorpVaultKvV2ProviderV1({
    descriptor: {
      schemaVersion: "1.0.0",
      providerId: "approved-browser-vault",
      providerType: "HASHICORP_VAULT",
      approval: {
        status: "APPROVED",
        approvedBy: "project-owner",
        approvedAt: now.toISOString(),
        configurationDigest: computeCanonicalDigestV1({ provider: "approved-browser-vault" })
      }
    },
    endpointOrigin: "https://vault.browser.test",
    tokenProvider: () => Promise.resolve(Buffer.from("browser-vault-token", "utf8")),
    fetchImplementation: () => Promise.resolve(new Response(JSON.stringify({
      data: { data: { token: downstreamSecret }, metadata: { version: 1 } }
    }), { status: 200, headers: { "Content-Type": "application/json" } }))
  });
  const runtime = createHashiCorpVaultApprovalRuntimeV1({
    secretManager: provider,
    credentialBindings: [{
      schemaVersion: "1.0.0",
      secretManagerProviderId: provider.descriptor.providerId,
      secretReference: "kv-v2://secret/browser/downstream#token",
      profile: {
        schemaVersion: "1.0.0",
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        credentialRevision: 1,
        credentialKind: "BEARER_TOKEN",
        audienceId: binding.route.credentialAudienceId,
        allowedRouteIds: [binding.route.routeId],
        allowedEndpointOrigins: [downstreamOrigin],
        materialDigest: createHash("sha256").update(downstreamSecret).digest("hex"),
        status: "ACTIVE",
        issuedAt: new Date(now.getTime() - 60_000).toISOString(),
        expiresAt: new Date(now.getTime() + 60_000).toISOString()
      }
    }],
    resolveCurrentRoute: () => binding,
    authenticateDownstream: () => ({
      schemaVersion: "1.0.0",
      serverId: binding.server.serverId,
      principalId: binding.server.authenticatedPrincipalId,
      authenticationMethod: "TEST_FIXTURE",
      credentialId: "browser-downstream-credential",
      identityRevision: 1,
      authenticatedAt: now.toISOString()
    }),
    validateOutputSchema: ({ structuredContent }) => structuredContent?.["ok"] === true,
    classifyResult: () => ["PUBLIC"],
    evaluateEgress: () => "ALLOW"
  });
  const executor = new ClientApprovedCallExecutorV1({
    loadApprovedCall: (input) => trajectory.loadApprovedCall(input),
    store: trajectory,
    issueCredentialLease: runtime.issueCredentialLease,
    forwarder: runtime.forwarder
  });
  activeRuntimeBridge = new ApprovalWebRuntimeBridgeV1({
    sessions: trajectory,
    executor,
    dispatches: trajectory
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { "X-Test-Human": humanPrincipal.humanId }
  });
  try {
    const firstPage = await context.newPage();
    await firstPage.goto(`${baseUrl}/approval`, { waitUntil: "networkidle" });
    await firstPage.locator(`[data-approval-id="${candidate.approval.approvalId}"]`).click();
    await expect(firstPage).toHaveURL(new RegExp(`approval=${candidate.approval.approvalId}$`, "u"));
    await firstPage.reload({ waitUntil: "networkidle" });
    await expect(firstPage.locator("#approval-state")).toHaveText("Pending");

    const secondPage = await context.newPage();
    await secondPage.goto(`${baseUrl}/approval`, { waitUntil: "networkidle" });
    await secondPage.locator(`[data-approval-id="${candidate.approval.approvalId}"]`).click();

    await Promise.all([firstPage, secondPage].map(async (page) => {
      await page.getByRole("button", { name: "Approve once", exact: true }).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog.getByRole("heading", { name: "Approve this action once?" })).toBeVisible();
    }));
    await Promise.all([firstPage, secondPage].map(async (page) => {
      await page.getByRole("dialog").getByRole("button", { name: "Approve once", exact: true }).click();
    }));

    for (const page of [firstPage, secondPage]) {
      await expect(page.locator("#approval-state")).toHaveText("Consumed");
      await expect(page.locator("#outcome-fields")).toContainText("Completed");
      await expect(page.locator("#outcome-fields")).toContainText("Irreversible");
      await expect(page.getByText("Decision recorded", { exact: true })).toBeVisible();
      await expect(page.locator("#decision-actions")).toBeHidden();
    }
    expect(downstreamCalls).toBe(1);

    await firstPage.reload({ waitUntil: "networkidle" });
    await expect(firstPage.locator("#approval-state")).toHaveText("Consumed");
    await expect(firstPage.locator("#outcome-fields")).toContainText("Completed");

    const verifier = new Pool({ connectionString, application_name: "approval-browser-success-verifier" });
    try {
      const rows = await verifier.query<{ state: string; status: string; disposition: string }>(
        `SELECT a.state,o.status,r.disposition FROM approvals a
         JOIN outcomes o ON o.approval_id=a.approval_id
         JOIN results r ON r.result_id=o.result_id WHERE a.approval_id=$1`,
        [candidate.approval.approvalId]
      );
      expect(rows.rows).toEqual([{ state: "CONSUMED", status: "COMPLETED", disposition: "ALLOW" }]);
    } finally {
      await verifier.end();
    }
  } finally {
    activeRuntimeBridge = null;
    await context.close();
    await new Promise<void>((resolveClose, reject) => downstream.close((error) => {
      if (error === undefined) resolveClose();
      else reject(error);
    }));
  }
});

test("shows durable expiry and denies stale human authority or coverage", async ({ browser }) => {
  const expiredCandidate = createPostgresTrajectoryFixtureV1(
    "approval-browser-expired",
    new Date(Date.now() - 20_000)
  );
  await seedLiveApproval(
    expiredCandidate,
    expiredCandidate.binding,
    new Date(Date.now() + 750).toISOString()
  );
  const staleCandidate = createPostgresTrajectoryFixtureV1(
    "approval-browser-stale-coverage",
    new Date(Date.now() - 20_000)
  );
  const stale = await seedLiveApproval(staleCandidate);
  await persistDegradedCoverage(staleCandidate, stale.scope);
  const staleAuthorityCandidate = createPostgresTrajectoryFixtureV1(
    "approval-browser-stale-authority",
    new Date(Date.now() - 20_000)
  );
  await seedLiveApproval(staleAuthorityCandidate);
  await ui.configureHuman({
    authority: {
      schemaVersion: "1.0.0",
      administratorId: "approval-admin",
      authenticatedAt: new Date().toISOString()
    },
    human: {
      schemaVersion: "1.0.0",
      humanId: humanPrincipal.humanId,
      credentialId: humanPrincipal.credentialId,
      authenticationMethod: humanPrincipal.authenticationMethod,
      authenticationRevision: humanPrincipal.identityRevision,
      authenticatedAt: humanPrincipal.authenticatedAt
    },
    policyScopeIds: [
      expiredCandidate.action.route.policyScopeId,
      staleCandidate.action.route.policyScopeId,
      staleAuthorityCandidate.action.route.policyScopeId
    ]
  });

  const verifier = new Pool({ connectionString, application_name: "approval-browser-negative-verifier" });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { "X-Test-Human": humanPrincipal.humanId }
  });
  try {
    await new Promise((resolveWait) => setTimeout(resolveWait, 900));
    const page = await context.newPage();
    await page.goto(
      `${baseUrl}/approval?approval=${encodeURIComponent(expiredCandidate.approval.approvalId)}`,
      { waitUntil: "networkidle" }
    );
    await expect(page.locator("#approval-state")).toHaveText("Expired");
    await expect(page.locator("#decision-actions")).toBeHidden();
    await expect(page.getByText("Reasons: approval.expired", { exact: true })).toBeVisible();

    await page.goto(
      `${baseUrl}/approval?approval=${encodeURIComponent(staleCandidate.approval.approvalId)}`,
      { waitUntil: "networkidle" }
    );
    await expect(page.locator("#approval-state")).toHaveText("Pending");
    await page.getByRole("button", { name: "Approve once", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve once", exact: true }).click();
    await expect(page.locator("#approval-state")).toHaveText("Revoked");
    await expect(page.locator("#decision-alert")).toContainText("changed or was already decided");
    await expect(page.getByText("Reasons: approval_ui.revalidation_failed", { exact: true })).toBeVisible();
    await expect(page.locator("#decision-actions")).toBeHidden();

    await page.goto(
      `${baseUrl}/approval?approval=${encodeURIComponent(staleAuthorityCandidate.approval.approvalId)}`,
      { waitUntil: "networkidle" }
    );
    await expect(page.locator("#approval-state")).toHaveText("Pending");
    await ui.configureHuman({
      authority: {
        schemaVersion: "1.0.0",
        administratorId: "approval-admin",
        authenticatedAt: new Date().toISOString()
      },
      human: {
        schemaVersion: "1.0.0",
        humanId: humanPrincipal.humanId,
        credentialId: humanPrincipal.credentialId,
        authenticationMethod: humanPrincipal.authenticationMethod,
        authenticationRevision: humanPrincipal.identityRevision,
        authenticatedAt: humanPrincipal.authenticatedAt
      },
      policyScopeIds: ["policy-scope-without-approval-authority"]
    });
    await page.getByRole("button", { name: "Approve once", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve once", exact: true }).click();
    await expect(page.locator("#decision-alert")).toContainText("Approval decision is unavailable");

    const rows = await verifier.query<{ approval_id: string; state: string }>(
      `SELECT approval_id,state FROM approvals WHERE approval_id=ANY($1::text[]) ORDER BY approval_id`,
      [[expiredCandidate.approval.approvalId, staleCandidate.approval.approvalId,
        staleAuthorityCandidate.approval.approvalId]]
    );
    expect(rows.rows).toEqual([
      { approval_id: expiredCandidate.approval.approvalId, state: "EXPIRED" },
      { approval_id: staleCandidate.approval.approvalId, state: "REVOKED" },
      { approval_id: staleAuthorityCandidate.approval.approvalId, state: "PENDING" }
    ].sort((left, right) => left.approval_id.localeCompare(right.approval_id)));
    expect((await verifier.query(
      "SELECT count(*)::int AS count FROM forwarding_attempts WHERE approval_id=ANY($1::text[])",
      [[expiredCandidate.approval.approvalId, staleCandidate.approval.approvalId,
        staleAuthorityCandidate.approval.approvalId]]
    )).rows[0]).toEqual({ count: 0 });
  } finally {
    await verifier.end();
    await context.close();
  }
});

test("persists and displays provider and governed-result failures after consumption", async ({ browser }) => {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { "X-Test-Human": humanPrincipal.humanId }
  });
  const verifier = new Pool({ connectionString, application_name: "approval-browser-failure-verifier" });
  let downstream: ReturnType<typeof createHttpServer> | null = null;
  try {
    const providerCandidate = createPostgresTrajectoryFixtureV1(
      "approval-browser-provider-failure",
      new Date(Date.now() - 20_000)
    );
    await seedLiveApproval(providerCandidate);
    let providerCalls = 0;
    activateVaultRuntime({
      candidate: providerCandidate,
      binding: providerCandidate.binding,
      downstreamSecret: "unavailable-provider-secret",
      fetchImplementation: () => {
        providerCalls += 1;
        return Promise.reject(new Error("Disposable provider unavailable"));
      }
    });
    const page = await context.newPage();
    await page.goto(`${baseUrl}/approval?approval=${providerCandidate.approval.approvalId}`, {
      waitUntil: "networkidle"
    });
    await page.getByRole("button", { name: "Approve once", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve once", exact: true }).click();
    await expect(page.locator("#approval-state")).toHaveText("Consumed");
    await expect(page.locator("#outcome-fields")).toContainText("Unknown");
    await expect(page.locator("#outcome-fields")).toContainText("Possible partial effectsYes");
    expect(providerCalls).toBe(1);

    const resultSecret = "browser-result-failure-secret";
    let downstreamCalls = 0;
    downstream = createHttpServer((request, response) => {
      downstreamCalls += 1;
      expect(request.headers.authorization).toBe(`Bearer ${resultSecret}`);
      response.setHeader("Content-Type", "application/json");
      response.setHeader("Mcp-Server-Authorization", "browser-downstream-proof");
      response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: "protocol-approval-browser-result-failure",
        result: {
          content: [{ type: "text", text: "Invalid governed result" }],
          structuredContent: { ok: false }
        }
      }));
    });
    const downstreamPort = await availablePort();
    await new Promise<void>((resolveListen, reject) => {
      downstream?.once("error", reject);
      downstream?.listen(downstreamPort, "127.0.0.1", resolveListen);
    });
    const resultCandidate = createPostgresTrajectoryFixtureV1(
      "approval-browser-result-failure",
      new Date(Date.now() - 20_000)
    );
    const endpoint = `http://127.0.0.1:${String(downstreamPort)}/mcp`;
    const resultBinding = {
      ...resultCandidate.binding,
      server: {
        ...resultCandidate.binding.server,
        transport: {
          kind: "STREAMABLE_HTTP" as const,
          endpoint,
          authenticationProfileId: "browser-result-failure-auth"
        }
      }
    };
    await seedLiveApproval(resultCandidate, resultBinding);
    activateVaultRuntime({
      candidate: resultCandidate,
      binding: resultBinding,
      downstreamSecret: resultSecret,
      fetchImplementation: () => Promise.resolve(new Response(JSON.stringify({
        data: { data: { token: resultSecret }, metadata: { version: 1 } }
      }), { status: 200, headers: { "Content-Type": "application/json" } })),
      validateOutputSchema: () => false
    });
    await page.goto(`${baseUrl}/approval?approval=${resultCandidate.approval.approvalId}`, {
      waitUntil: "networkidle"
    });
    await page.getByRole("button", { name: "Approve once", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Approve once", exact: true }).click();
    await expect(page.locator("#approval-state")).toHaveText("Consumed");
    await expect(page.locator("#outcome-fields")).toContainText("Completed");
    await expect(page.locator("#outcome-fields")).toContainText("Result dispositionQuarantine");
    await expect(page.locator("#outcome-fields")).toContainText("Result schemaInvalid");
    expect(downstreamCalls).toBe(1);

    const outcomes = await verifier.query<{ approval_id: string; status: string }>(
      `SELECT approval_id,status FROM outcomes WHERE approval_id=ANY($1::text[]) ORDER BY approval_id`,
      [[providerCandidate.approval.approvalId, resultCandidate.approval.approvalId]]
    );
    expect(outcomes.rows).toEqual([
      { approval_id: providerCandidate.approval.approvalId, status: "UNKNOWN" },
      { approval_id: resultCandidate.approval.approvalId, status: "COMPLETED" }
    ].sort((left, right) => left.approval_id.localeCompare(right.approval_id)));
  } finally {
    activeRuntimeBridge = null;
    await verifier.end();
    await context.close();
    if (downstream !== null) {
      await new Promise<void>((resolveClose, reject) => downstream?.close((error) => {
        if (error === undefined) resolveClose();
        else reject(error);
      }));
    }
  }
});
