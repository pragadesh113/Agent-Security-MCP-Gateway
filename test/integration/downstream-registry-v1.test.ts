import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  CanonicalActionNormalizerV1,
  DeterministicPolicyEngineV1,
  DisposableDownstreamRegistryV1,
  bindAuthenticatedIdentityToSessionV1,
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  type AuthenticatedClientPrincipalV1,
  type DownstreamRegistrationV1,
  type RouteAdministratorAuthorityV1
} from "../../src/index.js";

const openServers = new Set<ReturnType<typeof createServer>>();
const timestamp = "2026-09-03T12:00:00.000Z";
const authority: RouteAdministratorAuthorityV1 = {
  schemaVersion: "1.0.0",
  administratorId: "admin-integration",
  role: "ROUTE_REGISTRAR",
  authenticatedAt: timestamp
};
const clientPrincipal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-integration",
  agentId: "agent-integration",
  clientId: "client-integration",
  host: { hostId: "host-integration", name: "Integration host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "client-integration-credential",
    identityRevision: 1,
    authenticatedAt: timestamp
  }
};

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
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
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  })));
  openServers.clear();
});

describe("authenticated downstream MCP discovery workflow", () => {
  it("registers, verifies, exposes, reauthorizes, and quarantines a real HTTP peer", async () => {
    let drifted = false;
    let toolCalls = 0;
    const server = createServer((request, response) => {
      void (async () => {
      if (request.headers.authorization !== "Bearer disposable-downstream") {
        response.statusCode = 401;
        response.end();
        return;
      }
      const message = await readJson(request);
      if (message["method"] === "initialize") {
        sendJson(response, {
          jsonrpc: "2.0",
          id: message["id"],
          result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "disposable-calendar", version: "1.0.0" }
          }
        });
        return;
      }
      if (message["method"] === "tools/call") {
        toolCalls += 1;
        sendJson(response, { jsonrpc: "2.0", id: message["id"], result: { content: [{ type: "text", text: "unexpected" }] } });
        return;
      }
      sendJson(response, {
        jsonrpc: "2.0",
        id: message["id"],
        result: {
          tools: [{
            name: "calendar.read",
            title: "Read calendar",
            description: "Untrusted downstream metadata",
            inputSchema: drifted ? { type: "array" } : { type: "object" },
            outputSchema: { type: "object" },
            annotations: { readOnlyHint: true }
          }]
        }
      });
      })().catch(() => {
        response.statusCode = 500;
        response.end();
      });
    });
    openServers.add(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Disposable server did not bind a TCP address");
    }
    const endpoint = `http://127.0.0.1:${String(address.port)}/mcp`;
    const registration: DownstreamRegistrationV1 = {
      schemaVersion: "1.0.0",
      server: {
        schemaVersion: "1.0.0",
        serverId: "server-calendar-http",
        displayName: "Disposable HTTP calendar server",
        authenticatedPrincipalId: "principal-calendar-http",
        authenticationMethod: "TEST_FIXTURE",
        mcpProtocolVersion: "2025-06-18",
        transport: {
          kind: "STREAMABLE_HTTP",
          endpoint,
          authenticationProfileId: "server-http-auth"
        },
        credentialAudience: {
          audienceId: "audience-calendar-http",
          credentialProfileId: "credential-calendar-http"
        },
        capabilities: ["tools"]
      },
      routes: [{
        schemaVersion: "1.0.0",
        routeId: "route-calendar-http-read",
        serverId: "server-calendar-http",
        toolName: "calendar.read",
        exposedName: "calendar.read",
        credentialAudienceId: "audience-calendar-http",
        policyScopeId: "scope-calendar-http",
        environment: "TEST",
        resourceMapping: {
          resourceClass: "NETWORK",
          resolverId: "calendar-http-v1",
          scope: "calendar:http:test"
        },
        inputSchema: { type: "object" },
        outputSchema: { type: "object" }
      }],
      registrationRevision: 1
    };
    let callAllowed = true;
    const registry = new DisposableDownstreamRegistryV1({
      administratorAuthorizer: (candidate) =>
        candidate.administratorId === authority.administratorId,
      downstreamAuthenticator: (attempt) =>
        attempt.authorizationHeader === "Bearer disposable-downstream"
          ? {
              schemaVersion: "1.0.0",
              serverId: attempt.serverId,
              principalId: "principal-calendar-http",
              authenticationMethod: "TEST_FIXTURE",
              credentialId: "server-http-credential",
              identityRevision: 1,
              authenticatedAt: timestamp
            }
          : null,
      routeAuthorizer: ({ stage }) => stage === "DISCOVERY" || callAllowed,
      clock: () => new Date(timestamp)
    });
    registry.register(authority, registration);

    const invoke = async (method: string, id: number) => fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: "Bearer disposable-downstream",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params: {} })
    }).then(async (response) => response.json() as Promise<Record<string, unknown>>);
    const initialized = await invoke("initialize", 1);
    const listed = await invoke("tools/list", 2);
    const initializeResult = initialized["result"] as Record<string, unknown>;
    const listResult = listed["result"] as Record<string, unknown>;
    registry.observeDiscovery({
      serverId: "server-calendar-http",
      authorizationHeader: "Bearer disposable-downstream"
    }, {
      schemaVersion: "1.0.0",
      mcpProtocolVersion: initializeResult["protocolVersion"] as string,
      capabilities: Object.keys(initializeResult["capabilities"] as object),
      tools: listResult["tools"] as never,
      observedAt: timestamp
    });
    const session = bindAuthenticatedIdentityToSessionV1(clientPrincipal, "session-http");
    expect(registry.discover({
      requestId: "discovery-http",
      session,
      policyScopeId: "scope-calendar-http",
      environment: "TEST"
    }).tools).toHaveLength(1);
    const resolved = registry.resolveCall({
      session,
      policyScopeId: "scope-calendar-http",
      environment: "TEST",
      exposedName: "calendar.read"
    });
    expect(resolved.route.routeId).toBe("route-calendar-http-read");

    const argumentsValue = { calendarId: "disposable-calendar" };
    const action = new CanonicalActionNormalizerV1({
      resolvers: new Map([["calendar-http-v1", () => ({
        schemaVersion: "1.0.0",
        parserId: "calendar-http-v1",
        parserVersion: "1.0.0",
        status: "FULL",
        resources: [{
          resourceId: "calendar-disposable",
          resourceClass: "NETWORK",
          reference: "https://calendar.invalid/calendars/disposable-calendar",
          referencePlatform: "URI",
          classification: "PUBLIC"
        }],
        effect: "READ",
        environment: "TEST",
        dataFlow: { direction: "INGRESS", classifications: ["PUBLIC"], externalDestination: false, destinationId: null },
        reversibility: "NOT_APPLICABLE",
        influences: ["USER_INPUT"]
      })]]),
      clock: () => new Date(timestamp),
      actionIdFactory: () => "action-calendar-http"
    }).normalize({
      request: {
        schemaVersion: "1.0.0",
        requestId: "call-calendar-http",
        protocolRequestId: 4,
        sessionId: session.stateNamespace,
        route: {
          serverId: resolved.server.serverId,
          routeId: resolved.route.routeId,
          toolName: resolved.route.toolName,
          exposedName: resolved.route.exposedName,
          schemaDigest: resolved.route.schemaIntegrity.registeredDigest,
          credentialAudienceId: resolved.route.credentialAudienceId,
          policyScopeId: resolved.route.policyScopeId
        },
        arguments: argumentsValue,
        argumentsDigest: computeCanonicalDigestV1(argumentsValue),
        payloadBytes: computeCanonicalJsonByteLengthV1(argumentsValue),
        nonce: "nonce-calendar-http",
        requestedAt: timestamp,
        callChain: { callChainId: "chain-calendar-http", parentRequestId: null, depth: 0, delegationDepth: 0 },
        contentTrust: "UNTRUSTED",
        credentialsExcluded: true
      },
      session,
      binding: resolved
    });
    const decision = new DeterministicPolicyEngineV1({
      policyVersion: "policy-1.0.0",
      clock: () => new Date(timestamp),
      decisionIdFactory: () => "decision-calendar-http"
    }).evaluate({ action, coverage: "UNPROTECTED" });
    expect(decision).toMatchObject({ decision: "DENY", tier: 0, coverage: "UNPROTECTED" });
    expect(toolCalls).toBe(0);

    callAllowed = false;
    expect(() => registry.resolveCall({
      session,
      policyScopeId: "scope-calendar-http",
      environment: "TEST",
      exposedName: "calendar.read"
    })).toThrow("denied");
    callAllowed = true;
    drifted = true;
    const driftedList = await invoke("tools/list", 3);
    registry.observeDiscovery({
      serverId: "server-calendar-http",
      authorizationHeader: "Bearer disposable-downstream"
    }, {
      schemaVersion: "1.0.0",
      mcpProtocolVersion: "2025-06-18",
      capabilities: ["tools"],
      tools: (driftedList["result"] as Record<string, unknown>)["tools"] as never,
      observedAt: timestamp
    });
    expect(registry.discover({
      requestId: "discovery-after-drift",
      session,
      policyScopeId: "scope-calendar-http",
      environment: "TEST"
    }).tools).toEqual([]);
  });
});
