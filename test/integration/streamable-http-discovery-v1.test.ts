import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  DisposableDownstreamRegistryV1,
  createInitializationHttpAppV1,
  type AuthenticatedClientPrincipalV1,
  type ClientAuthenticatorV1,
  type DownstreamRegistrationV1,
  type RouteAdministratorAuthorityV1
} from "../../src/index.js";
import { DisposableMcpHttpClientV1 } from "../fixtures/disposable-mcp-http-client-v1.js";

const timestamp = "2026-09-07T08:00:00.000Z";
const openServers = new Set<Server>();
const authority: RouteAdministratorAuthorityV1 = {
  schemaVersion: "1.0.0",
  administratorId: "admin-discovery-runtime",
  role: "ROUTE_REGISTRAR",
  authenticatedAt: timestamp
};
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-discovery-runtime",
  agentId: "agent-discovery-runtime",
  clientId: "client-discovery-runtime",
  host: { hostId: "host-discovery-runtime", name: "Discovery host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-discovery-runtime",
    identityRevision: 1,
    authenticatedAt: timestamp
  }
};
const authenticator: ClientAuthenticatorV1 = (attempt) =>
  attempt.authorizationHeader === "Bearer discovery-runtime" ? principal : undefined;
const registration: DownstreamRegistrationV1 = {
  schemaVersion: "1.0.0",
  server: {
    schemaVersion: "1.0.0",
    serverId: "server-discovery-runtime",
    displayName: "Runtime discovery fixture",
    authenticatedPrincipalId: "principal-discovery-runtime",
    authenticationMethod: "TEST_FIXTURE",
    mcpProtocolVersion: "2025-06-18",
    transport: {
      kind: "STREAMABLE_HTTP",
      endpoint: "http://127.0.0.1:4199/mcp",
      authenticationProfileId: "auth-discovery-runtime"
    },
    credentialAudience: {
      audienceId: "audience-discovery-runtime",
      credentialProfileId: "profile-discovery-runtime"
    },
    capabilities: ["tools"]
  },
  routes: [{
    schemaVersion: "1.0.0",
    routeId: "route-discovery-runtime",
    serverId: "server-discovery-runtime",
    toolName: "fixture.read",
    exposedName: "fixture.read",
    credentialAudienceId: "audience-discovery-runtime",
    policyScopeId: "scope-discovery-runtime",
    environment: "TEST",
    resourceMapping: {
      resourceClass: "NETWORK",
      resolverId: "fixture-read-v1",
      scope: "fixture:read:test"
    },
    inputSchema: { type: "object", additionalProperties: false },
    outputSchema: { type: "object" }
  }],
  registrationRevision: 1
};

function createRegistry(authorization: { allowed: boolean }) {
  const registry = new DisposableDownstreamRegistryV1({
    administratorAuthorizer: (candidate) => candidate.administratorId === authority.administratorId,
    downstreamAuthenticator: (attempt) =>
      attempt.authorizationHeader === "Bearer downstream-discovery-runtime"
        ? {
            schemaVersion: "1.0.0",
            serverId: attempt.serverId,
            principalId: "principal-discovery-runtime",
            authenticationMethod: "TEST_FIXTURE",
            credentialId: "downstream-credential-discovery-runtime",
            identityRevision: 1,
            authenticatedAt: timestamp
          }
        : undefined,
    routeAuthorizer: ({ stage, session }) =>
      stage === "DISCOVERY" && authorization.allowed &&
      session.identity.userId === principal.userId,
    clock: () => new Date(timestamp)
  });
  registry.register(authority, registration);
  registry.observeDiscovery({
    serverId: registration.server.serverId,
    authorizationHeader: "Bearer downstream-discovery-runtime"
  }, {
    schemaVersion: "1.0.0",
    mcpProtocolVersion: "2025-06-18",
    capabilities: ["tools"],
    tools: [{
      name: "fixture.read",
      title: "Fixture read",
      description: "Untrusted downstream description",
      inputSchema: { type: "object", additionalProperties: false },
      outputSchema: { type: "object" },
      annotations: { readOnlyHint: true, contentTrust: "TRUSTED" }
    }],
    observedAt: timestamp
  });
  return registry;
}

async function listen(app: ReturnType<typeof createInitializationHttpAppV1>) {
  const server = createServer(app);
  openServers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${String(address.port)}/mcp` };
}

afterEach(async () => {
  await Promise.all([...openServers].map(async (server) => new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  })));
  openServers.clear();
});

describe("authenticated client-facing registry discovery", () => {
  it("lists current authorized routes with gateway-owned trust markers and keeps calls denied", async () => {
    const authorization = { allowed: true };
    const registry = createRegistry(authorization);
    const { server, url } = await listen(createInitializationHttpAppV1({
      clientAuthenticator: authenticator,
      discovery: {
        provider: ({ requestId, session }) => registry.discover({
          requestId,
          session,
          policyScopeId: "scope-discovery-runtime",
          environment: "TEST"
        }),
        requestIdFactory: () => "discovery-runtime-request"
      }
    }));
    const client = new DisposableMcpHttpClientV1(url, {
      authorizationHeader: "Bearer discovery-runtime"
    });

    const initialized = await client.initialize({
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "discovery-runtime-client", version: "1.0.0" }
    });
    expect(initialized.json).toMatchObject({
      result: { capabilities: { tools: { listChanged: false } } }
    });
    await client.sendInitialized();

    const listed = await client.sendRequest("tools/list", {}, "list-runtime");
    expect(listed.status).toBe(200);
    expect(listed.json).toEqual({
      jsonrpc: "2.0",
      id: "list-runtime",
      result: {
        tools: [{
          name: "fixture.read",
          title: "Fixture read",
          description: "Untrusted downstream description",
          inputSchema: { type: "object", additionalProperties: false },
          outputSchema: { type: "object" },
          annotations: { readOnlyHint: true },
          _meta: {
            gateway: {
              contentTrust: "UNTRUSTED",
              callTimeAuthorizationRequired: true,
              coverage: "UNPROTECTED"
            }
          }
        }]
      }
    });
    expect(JSON.stringify(listed.json)).not.toContain("credentialProfileId");
    expect(JSON.stringify(listed.json)).not.toContain("audience-discovery-runtime");
    expect(JSON.stringify(listed.json)).not.toContain("route-discovery-runtime");

    authorization.allowed = false;
    expect((await client.sendRequest("tools/list", {}, "list-revoked")).json).toMatchObject({
      result: { tools: [] }
    });
    expect((await client.sendRequest("tools/call", {
      name: "fixture.read",
      arguments: {}
    }, "call-still-denied")).json).toMatchObject({
      error: { code: -32601, data: { coverage: "UNPROTECTED" } }
    });

    openServers.delete(server);
    await new Promise<void>((resolve) => server.close(() => {
      resolve();
    }));
  });

  it("rejects client-selected discovery scope and unsupported pagination", async () => {
    const registry = createRegistry({ allowed: true });
    const { server, url } = await listen(createInitializationHttpAppV1({
      clientAuthenticator: authenticator,
      discovery: {
        provider: ({ requestId, session }) => registry.discover({
          requestId,
          session,
          policyScopeId: "scope-discovery-runtime",
          environment: "TEST"
        })
      }
    }));
    const client = new DisposableMcpHttpClientV1(url, {
      authorizationHeader: "Bearer discovery-runtime"
    });
    await client.initialize({
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "discovery-runtime-client", version: "1.0.0" }
    });
    await client.sendInitialized();

    for (const params of [
      { policyScopeId: "attacker-scope", environment: "PRODUCTION" },
      { cursor: "attacker-cursor" }
    ]) {
      const denied = await client.sendRequest("tools/list", params);
      expect(denied.status).toBe(200);
      expect(denied.json).toMatchObject({
        error: { code: -32602, message: "Invalid tools/list request" }
      });
    }

    openServers.delete(server);
    await new Promise<void>((resolve) => server.close(() => {
      resolve();
    }));
  });

  it("fails provider errors and oversized discovery output without exposing details", async () => {
    let mode: "THROW" | "OVERSIZED" = "THROW";
    const { server, url } = await listen(createInitializationHttpAppV1({
      clientAuthenticator: authenticator,
      discovery: {
        provider: ({ requestId, session }) => {
          if (mode === "THROW") {
            throw new Error("sensitive discovery provider detail");
          }
          return {
            schemaVersion: "1.0.0",
            requestId,
            sessionId: session.stateNamespace,
            policyScopeId: "scope-discovery-runtime",
            environment: "TEST",
            tools: Array.from({ length: 600 }, (_, index) => ({
              route: {
                serverId: "server-discovery-runtime",
                routeId: `route-oversized-${String(index)}`,
                toolName: `fixture.tool.${String(index)}`,
                exposedName: `fixture.tool.${String(index)}`,
                schemaDigest: "a".repeat(64),
                credentialAudienceId: "audience-discovery-runtime",
                policyScopeId: "scope-discovery-runtime"
              },
              title: null,
              description: "x".repeat(2_048),
              inputSchema: { type: "object" },
              outputSchema: null,
              annotations: null,
              availability: "AVAILABLE",
              contentTrust: "UNTRUSTED",
              callTimeAuthorizationRequired: true
            })),
            coverage: "UNPROTECTED",
            generatedAt: timestamp
          };
        }
      }
    }));
    const client = new DisposableMcpHttpClientV1(url, {
      authorizationHeader: "Bearer discovery-runtime"
    });
    await client.initialize({
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "discovery-runtime-client", version: "1.0.0" }
    });
    await client.sendInitialized();

    const providerFailure = await client.sendRequest("tools/list", {}, "provider-failure");
    expect(providerFailure.status).toBe(503);
    expect(providerFailure.json).toMatchObject({
      error: { code: -32005, message: "Tool discovery is unavailable" }
    });
    expect(JSON.stringify(providerFailure.json)).not.toContain("sensitive");

    mode = "OVERSIZED";
    const oversized = await client.sendRequest("tools/list", {}, "oversized-discovery");
    expect(oversized.status).toBe(503);
    expect(oversized.json).toMatchObject({
      error: { code: -32005, message: "Tool discovery is unavailable" }
    });

    openServers.delete(server);
    await new Promise<void>((resolve) => server.close(() => {
      resolve();
    }));
  });
});

describe("authenticated client-facing tool call admission", () => {
  it("admits only strict call shapes and delegates the authenticated session context", async () => {
    const calls: Array<{ name: string; sessionId: string; arguments: Record<string, unknown> }> = [];
    const { url } = await listen(createInitializationHttpAppV1({
      clientAuthenticator: authenticator,
      toolCall: {
        provider: ({ session, name, arguments: args }) => {
          calls.push({ name, sessionId: session.stateNamespace, arguments: args });
          return { isError: true, content: [{ type: "text", text: "Denied by policy" }] };
        }
      }
    }));
    const client = new DisposableMcpHttpClientV1(url, {
      authorizationHeader: "Bearer discovery-runtime"
    });
    await client.initialize({
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "call-runtime-client", version: "1.0.0" }
    });
    await client.sendInitialized();
    const result = await client.sendRequest("tools/call", {
      name: "fixture.read",
      arguments: { query: "safe" }
    }, "call-runtime");
    expect(result.status).toBe(200);
    expect(result.json).toMatchObject({
      jsonrpc: "2.0",
      id: "call-runtime",
      result: { isError: true }
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ name: "fixture.read", arguments: { query: "safe" } });

    const invalid = await client.sendRequest("tools/call", {
      name: "fixture.read",
      arguments: {},
      scope: "client-selected-scope"
    }, "invalid-call");
    expect(invalid.status).toBe(200);
    expect(invalid.json).toMatchObject({ error: { code: -32602 } });
    expect(calls).toHaveLength(1);
  });

  it("propagates an actual client disconnect to in-flight call admission", async () => {
    let markStarted: (() => void) | undefined;
    let markAborted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const aborted = new Promise<void>((resolve) => { markAborted = resolve; });
    const { url } = await listen(createInitializationHttpAppV1({
      clientAuthenticator: authenticator,
      toolCall: {
        provider: ({ signal }) => new Promise((_resolve, reject) => {
          markStarted?.();
          signal.addEventListener("abort", () => {
            markAborted?.();
            reject(new Error("client disconnected"));
          }, { once: true });
        })
      }
    }));
    const client = new DisposableMcpHttpClientV1(url, {
      authorizationHeader: "Bearer discovery-runtime"
    });
    await client.initialize({
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "call-cancellation-client", version: "1.0.0" }
    });
    await client.sendInitialized();
    if (client.sessionId === undefined || client.negotiatedProtocolVersion === undefined) {
      throw new Error("Cancellation workflow requires an initialized session");
    }
    const controller = new AbortController();
    const pending = fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer discovery-runtime",
        "Content-Type": "application/json",
        "Mcp-Session-Id": client.sessionId,
        "MCP-Protocol-Version": client.negotiatedProtocolVersion
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: "cancel-call-runtime", method: "tools/call",
        params: { name: "fixture.read", arguments: { query: "safe" } }
      }),
      signal: controller.signal
    });
    await started;
    controller.abort();
    await expect(pending).rejects.toThrow();
    await aborted;
  });
});
