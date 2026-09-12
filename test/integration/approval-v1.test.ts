import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  ApprovalDeniedV1,
  DeterministicPolicyEngineV1,
  DisposableApprovalServiceV1,
  DisposableCredentialVaultV1,
  DisposableExactForwarderV1,
  bindAuthenticatedIdentityToSessionV1,
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  type CanonicalActionV1,
  type DownstreamServerRouteBindingV1
} from "../../src/index.js";

const openServers = new Set<ReturnType<typeof createServer>>();
const timestamp = "2026-09-04T11:00:00.000Z";

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function sendJson(response: ServerResponse, body: unknown): void {
  response.statusCode = 200;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(body));
}

afterEach(async () => {
  await Promise.all([...openServers].map(async (server) => new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  })));
  openServers.clear();
});

describe("exact approval disposable forwarding boundary", () => {
  it("consumes one approval before one HTTP call and exposes no approval material downstream", async () => {
    let calls = 0;
    let received: Record<string, unknown> | null = null;
    let receivedHeaders: IncomingMessage["headers"] | null = null;
    let downstreamAuthorization: string | undefined;
    const downstream = createServer((request, response) => {
      void (async () => {
        calls += 1;
        receivedHeaders = request.headers;
        downstreamAuthorization = request.headers.authorization;
        received = await readBody(request);
        sendJson(response, {
          jsonrpc: "2.0",
          id: received["id"],
          result: {
            content: [{ type: "text", text: "deleted disposable row" }],
            structuredContent: { ok: true }
          }
        });
      })().catch(() => {
        response.statusCode = 500;
        response.end();
      });
    });
    openServers.add(downstream);
    await new Promise<void>((resolve, reject) => {
      downstream.once("error", reject);
      downstream.listen(0, "127.0.0.1", () => {
        downstream.off("error", reject);
        resolve();
      });
    });
    const address = downstream.address();
    if (address === null || typeof address === "string") throw new Error("Disposable server did not bind");
    const endpoint = `http://127.0.0.1:${String(address.port)}/mcp`;
    const schemaDigest = "a".repeat(64);
    const binding: DownstreamServerRouteBindingV1 = {
      server: {
        schemaVersion: "1.0.0",
        serverId: "server-approval-http",
        displayName: "Approval HTTP fixture",
        authenticatedPrincipalId: "principal-approval-http",
        authenticationMethod: "TEST_FIXTURE",
        mcpProtocolVersion: "2025-06-18",
        transport: { kind: "STREAMABLE_HTTP", endpoint, authenticationProfileId: "auth-approval-http" },
        credentialAudience: { audienceId: "audience-approval-http", credentialProfileId: "credential-approval-http" },
        capabilities: ["tools"],
        capabilityIntegrity: { registeredDigest: "b".repeat(64), observedDigest: "b".repeat(64), state: "VERIFIED", observedAt: timestamp },
        health: { state: "HEALTHY", checkedAt: timestamp, reasonCodes: [] },
        registration: { source: "TEST_FIXTURE", registeredBy: "admin-approval-http", registeredAt: timestamp, revision: 1, evidenceDigest: "c".repeat(64) }
      },
      route: {
        schemaVersion: "1.0.0",
        routeId: "route-approval-http",
        serverId: "server-approval-http",
        toolName: "database.delete_row",
        exposedName: "database.delete_row",
        credentialAudienceId: "audience-approval-http",
        policyScopeId: "scope-approval-http",
        environment: "PRODUCTION",
        resourceMapping: { resourceClass: "DATABASE", resolverId: "database-v1", scope: "disposable" },
        schemaIntegrity: { registeredDigest: schemaDigest, observedDigest: schemaDigest, state: "VERIFIED", observedAt: timestamp },
        status: "ACTIVE",
        registeredAt: timestamp
      }
    };
    const principal = {
      schemaVersion: "1.0.0" as const,
      userId: "user-approval-http",
      agentId: "agent-approval-http",
      clientId: "client-approval-http",
      host: { hostId: "host-approval-http", name: "HTTP approval fixture", version: "1.0.0" },
      authentication: { method: "TEST_FIXTURE" as const, credentialId: "client-auth-http", identityRevision: 1, authenticatedAt: timestamp }
    };
    const session = bindAuthenticatedIdentityToSessionV1(principal, "transport-approval-http");
    const resources = [{ resourceId: "row-disposable-42", resourceClass: "DATABASE" as const, canonicalReference: "postgres://disposable/orders/42", classification: "CONFIDENTIAL" as const }];
    const dataFlow = { direction: "NONE" as const, classifications: ["CONFIDENTIAL" as const], externalDestination: false, destinationId: null };
    const argumentsValue = { record_id: 42 };
    const actionInput = {
      schemaVersion: "1.0.0" as const,
      requestId: "request-approval-http",
      actionId: "action-approval-http",
      sessionId: session.stateNamespace,
      identity: { userId: principal.userId, agentId: principal.agentId, clientId: principal.clientId, hostId: principal.host.hostId },
      route: { serverId: binding.server.serverId, routeId: binding.route.routeId, toolName: binding.route.toolName, schemaDigest, credentialAudienceId: binding.route.credentialAudienceId, policyScopeId: binding.route.policyScopeId },
      arguments: { digest: computeCanonicalDigestV1(argumentsValue), keys: ["record_id"], secretValuesRemoved: true as const },
      resources,
      resourcesDigest: computeCanonicalDigestV1(resources),
      effect: "DELETE" as const,
      environment: "PRODUCTION" as const,
      dataFlow,
      dataFlowDigest: computeCanonicalDigestV1(dataFlow),
      parsingEvidence: { parserId: "database-v1", parserVersion: "1.0.0", status: "FULL" as const, evidenceDigest: "e".repeat(64) },
      reversibility: "IRREVERSIBLE" as const,
      callChain: { callChainId: "chain-approval-http", parentActionId: null, ancestorActionIds: [], depth: 0, delegationDepth: 0 },
      influences: ["USER_INPUT" as const],
      createdAt: timestamp
    };
    const action: CanonicalActionV1 = { ...actionInput, actionHash: computeCanonicalDigestV1(actionInput) };
    const policy = new DeterministicPolicyEngineV1({
      policyVersion: "policy-1.0.0",
      clock: () => new Date(timestamp),
      decisionIdFactory: () => "decision-approval-http"
    });
    const decision = policy.evaluate({ action, coverage: "ENFORCED" });
    let event = 0;
    const approvals = new DisposableApprovalServiceV1({
      humanAuthorizer: (candidate) => candidate.humanId === "human-approval-http",
      auditAuthorizer: () => true,
      identityRevalidator: () => true,
      routeRevalidator: () => binding,
      policyRevalidator: () => policy.evaluate({ action, coverage: "ENFORCED" }),
      clock: () => new Date(timestamp),
      approvalIdFactory: () => "approval-http",
      consumptionIdFactory: () => "consumption-http",
      forwardingAttemptIdFactory: () => "forwarding-http",
      eventIdFactory: () => `approval-http-event-${String(++event)}`
    });
    const approval = approvals.requestApproval({ action, decision, session });
    approvals.recordHumanDecision({
      schemaVersion: "1.0.0",
      approvalId: approval.approvalId,
      actionHash: action.actionHash,
      humanId: "human-approval-http",
      authenticationMethod: "TEST_FIXTURE",
      decision: "APPROVE",
      authenticatedAt: timestamp
    });
    const downstreamSecret = Buffer.from("route-scoped-secret-material", "utf8");
    const vault = new DisposableCredentialVaultV1({
      clock: () => new Date(timestamp),
      leaseIdFactory: () => "approval-http-lease"
    });
    vault.registerCredential({
      schemaVersion: "1.0.0",
      credentialProfileId: binding.server.credentialAudience.credentialProfileId,
      credentialRevision: 1,
      credentialKind: "BEARER_TOKEN",
      audienceId: binding.route.credentialAudienceId,
      allowedRouteIds: [binding.route.routeId],
      allowedEndpointOrigins: [new URL(endpoint).origin],
      materialDigest: createHash("sha256").update(downstreamSecret).digest("hex"),
      status: "ACTIVE",
      issuedAt: timestamp,
      expiresAt: "2026-09-04T11:30:00.000Z"
    }, downstreamSecret);
    const lease = vault.issueLease(session, {
      credentialProfileId: binding.server.credentialAudience.credentialProfileId,
      audienceId: binding.route.credentialAudienceId,
      routeId: binding.route.routeId
    });
    const forwarder = new DisposableExactForwarderV1({
      credentialVault: vault,
      resolveCurrentRoute: () => binding,
      authenticateDownstream: () => ({
        schemaVersion: "1.0.0",
        serverId: binding.server.serverId,
        principalId: binding.server.authenticatedPrincipalId,
        authenticationMethod: "TEST_FIXTURE",
        credentialId: "approval-http-server-auth",
        identityRevision: 1,
        authenticatedAt: timestamp
      }),
      validateOutputSchema: ({ structuredContent }) => structuredContent?.["ok"] === true,
      classifyResult: () => ["PUBLIC"],
      evaluateEgress: () => "ALLOW",
      clock: () => new Date(timestamp),
      resultIdFactory: () => "approval-http-result",
      provenanceIdFactory: () => "approval-http-provenance",
      errorIdFactory: () => "approval-http-error"
    });
    const toolRequest = {
      schemaVersion: "1.0.0" as const,
      requestId: action.requestId,
      protocolRequestId: 1,
      sessionId: action.sessionId,
      route: {
        serverId: binding.server.serverId,
        routeId: binding.route.routeId,
        toolName: binding.route.toolName,
        exposedName: binding.route.exposedName,
        schemaDigest,
        credentialAudienceId: binding.route.credentialAudienceId,
        policyScopeId: binding.route.policyScopeId
      },
      arguments: argumentsValue,
      argumentsDigest: computeCanonicalDigestV1(argumentsValue),
      payloadBytes: computeCanonicalJsonByteLengthV1(argumentsValue),
      nonce: "approval-http-nonce",
      requestedAt: timestamp,
      callChain: {
        callChainId: action.callChain.callChainId,
        parentRequestId: null,
        depth: 0,
        delegationDepth: 0
      },
      contentTrust: "UNTRUSTED" as const,
      credentialsExcluded: true as const
    };
    const response = await approvals.consumeAndBeginForwarding(
      { approvalId: approval.approvalId, action, decision, session },
      async (authorization) => forwarder.execute({
        authorization,
        action,
        request: toolRequest,
        session,
        credentialLeaseId: lease.leaseId
      })
    );
    expect(response.result?.disposition).toBe("ALLOW");
    expect(response.release?.contentTrust).toBe("UNTRUSTED");
    expect(calls).toBe(1);
    expect(received).toMatchObject({ method: "tools/call", params: { name: "database.delete_row" } });
    expect(downstreamAuthorization).toBe(`Bearer ${downstreamSecret.toString("utf8")}`);
    expect(JSON.stringify({ received, receivedHeaders })).not.toContain("approval-http");
    expect(() => { approvals.consumeAndBeginForwarding({ approvalId: approval.approvalId, action, decision, session }, () => "replayed"); }).toThrow(ApprovalDeniedV1);
    expect(calls).toBe(1);
  });
});
