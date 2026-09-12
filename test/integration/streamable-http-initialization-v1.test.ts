import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  CredentialAccessDeniedV1,
  DisposableCredentialVaultV1,
  DisposableSessionStateRepositoryV1,
  bindAuthenticatedIdentityToSessionV1,
  createInitializationHttpAppV1
} from "../../src/index.js";
import type {
  AuthenticatedClientPrincipalV1,
  ClientAuthenticatorV1
} from "../../src/index.js";
import { DisposableMcpHttpClientV1 } from "../fixtures/disposable-mcp-http-client-v1.js";

const openServers = new Set<Server>();

async function listenDisposable(
  app: ReturnType<typeof createInitializationHttpAppV1>
): Promise<{ server: Server; url: string }> {
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

async function closeServer(server: Server): Promise<void> {
  openServers.delete(server);
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}

const initializeParams = {
  protocolVersion: "2025-06-18",
  capabilities: { roots: { listChanged: true } },
  clientInfo: { name: "disposable-http-client", version: "1.0.0" }
} as const;

const firstPrincipal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-first",
  agentId: "agent-first",
  clientId: "client-first",
  host: { hostId: "host-first", name: "Disposable host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-first",
    identityRevision: 1,
    authenticatedAt: "2026-09-03T10:00:00.000Z"
  }
};

const secondPrincipal: AuthenticatedClientPrincipalV1 = {
  ...firstPrincipal,
  userId: "user-second",
  agentId: "agent-second",
  clientId: "client-second",
  host: { ...firstPrincipal.host, hostId: "host-second" },
  authentication: {
    ...firstPrincipal.authentication,
    credentialId: "credential-second"
  }
};

const rotatedFirstPrincipal: AuthenticatedClientPrincipalV1 = {
  ...firstPrincipal,
  authentication: {
    ...firstPrincipal.authentication,
    credentialId: "credential-first-rotated",
    identityRevision: 2,
    authenticatedAt: "2026-09-03T10:05:00.000Z"
  }
};

const fixtureAuthenticator: ClientAuthenticatorV1 = (attempt) => {
  if (attempt.authorizationHeader === "Bearer fixture-first") {
    return firstPrincipal;
  }
  if (attempt.authorizationHeader === "Bearer fixture-second") {
    return secondPrincipal;
  }
  if (attempt.authorizationHeader === "Bearer fixture-first-rotated") {
    return rotatedFirstPrincipal;
  }
  return null;
};

function createTestApp(
  options: Omit<Parameters<typeof createInitializationHttpAppV1>[0], "clientAuthenticator"> = {}
) {
  return createInitializationHttpAppV1({
    clientAuthenticator: fixtureAuthenticator,
    ...options
  });
}

function createTestClient(url: string, authorizationHeader = "Bearer fixture-first") {
  return new DisposableMcpHttpClientV1(url, { authorizationHeader });
}

afterEach(async () => {
  await Promise.all([...openServers].map(async (server) => closeServer(server)));
});

describe("disposable Streamable HTTP initialization workflow", () => {
  it("completes the actual handshake while tool discovery and calls stay unavailable", async () => {
    const { server, url } = await listenDisposable(createTestApp());
    const client = createTestClient(url);

    const initialize = await client.initialize(initializeParams, "initialize-001");
    expect(initialize.status).toBe(200);
    expect(client.sessionId).toMatch(/^[A-Za-z0-9._~-]{1,128}$/u);
    expect(client.negotiatedProtocolVersion).toBe("2025-06-18");
    expect(initialize.json).toMatchObject({
      jsonrpc: "2.0",
      id: "initialize-001",
      result: { protocolVersion: "2025-06-18", capabilities: {} }
    });

    const initialized = await client.sendInitialized();
    expect(initialized.status).toBe(202);
    expect(initialized.text).toBe("");

    const ping = await client.ping("ping-ready");
    expect(ping.status).toBe(200);
    expect(ping.json).toEqual({ jsonrpc: "2.0", id: "ping-ready", result: {} });

    for (const method of ["tools/list", "tools/call"] as const) {
      const denied = await client.sendRequest(method);
      expect(denied.status).toBe(200);
      expect(denied.json).toMatchObject({
        error: {
          code: -32601,
          data: { method, coverage: "UNPROTECTED" }
        }
      });
    }

    expect((await client.terminate()).status).toBe(204);
    expect((await client.ping("ping-after-close")).status).toBe(404);
    await closeServer(server);
  });

  it("keeps two initialized transport sessions isolated", async () => {
    let sessionNumber = 0;
    const { server, url } = await listenDisposable(
      createTestApp({
        sessionIdFactory: () => `disposable-session-${String(++sessionNumber)}`
      })
    );
    const first = createTestClient(url);
    const second = createTestClient(url);

    await first.initialize(initializeParams, "initialize-first");
    await second.initialize(initializeParams, "initialize-second");
    expect(first.sessionId).not.toBe(second.sessionId);
    expect((await first.sendInitialized()).status).toBe(202);
    expect((await second.sendInitialized()).status).toBe(202);

    expect((await first.terminate()).status).toBe(204);
    expect((await first.ping("first-closed")).status).toBe(404);
    expect((await second.ping("second-active")).json).toEqual({
      jsonrpc: "2.0",
      id: "second-active",
      result: {}
    });

    await closeServer(server);
  });

  it("enforces transport headers, Origin, body bounds, and session binding", async () => {
    const { server, url } = await listenDisposable(
      createTestApp({ maxJsonBodyBytes: 1_024 })
    );

    const missingAccept = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
    });
    expect(missingAccept.status).toBe(406);

    const remoteOrigin = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        Origin: "https://attacker.example"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
    });
    expect(remoteOrigin.status).toBe(403);

    const missingSession = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
    });
    expect(missingSession.status).toBe(400);

    const oversized = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "initialize",
        params: { ...initializeParams, padding: "x".repeat(2_048) }
      })
    });
    expect(oversized.status).toBe(413);

    const unknownSession = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json",
        "Mcp-Session-Id": "unknown-session",
        "MCP-Protocol-Version": "2025-06-18"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" })
    });
    expect(unknownSession.status).toBe(404);

    const client = createTestClient(url);
    await client.initialize(initializeParams);
    const missingVersion = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json",
        "Mcp-Session-Id": client.sessionId ?? "missing"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "ping" })
    });
    expect(missingVersion.status).toBe(400);
    expect((await client.sendInitialized()).status).toBe(202);

    const get = await fetch(url, {
      headers: {
        Accept: "text/event-stream",
        Authorization: "Bearer fixture-first"
      }
    });
    expect(get.status).toBe(405);
    await closeServer(server);
  });

  it("rejects a wrong negotiated-version header without changing the session", async () => {
    const { server, url } = await listenDisposable(createTestApp());
    const client = createTestClient(url);
    await client.initialize(initializeParams);
    const sessionId = client.sessionId;
    expect(sessionId).toBeDefined();

    const wrongVersion = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer fixture-first",
        "Content-Type": "application/json",
        "Mcp-Session-Id": sessionId ?? "missing",
        "MCP-Protocol-Version": "2025-03-26"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "ping" })
    });
    expect(wrongVersion.status).toBe(400);
    expect((await client.sendInitialized()).status).toBe(202);
    expect((await client.ping("still-active")).status).toBe(200);
    await closeServer(server);
  });

  it("authenticates before parsing MCP input and exposes no identity material", async () => {
    const { server, url } = await listenDisposable(createTestApp());

    const unauthenticated = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json"
      },
      body: "not-json"
    });
    expect(unauthenticated.status).toBe(401);
    expect(await unauthenticated.json()).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32004, message: "Client authentication is required" }
    });

    const client = createTestClient(url);
    const initialized = await client.initialize({
      ...initializeParams,
      clientInfo: { name: "claims-user-second", version: "999.0.0" }
    });
    expect(initialized.status).toBe(200);
    expect(JSON.stringify(initialized.json)).not.toContain("user-first");
    expect(JSON.stringify(initialized.json)).not.toContain("credential-first");
    await closeServer(server);
  });

  it.each([
    {
      name: "throws",
      authenticator: () => {
        throw new Error("sensitive provider detail");
      },
      message: "Client authentication is unavailable"
    },
    {
      name: "rejects asynchronously",
      authenticator: async () => Promise.reject(new Error("async sensitive provider detail")),
      message: "Client authentication is unavailable"
    },
    {
      name: "returns invalid identity",
      authenticator: () => ({ ...firstPrincipal, credential: "must-not-leak" }),
      message: "Client authentication returned invalid identity"
    }
  ])("fails closed with a safe error when authentication $name", async ({
    authenticator,
    message
  }) => {
    const { server, url } = await listenDisposable(
      createInitializationHttpAppV1({ clientAuthenticator: authenticator })
    );
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer must-not-leak",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
    });
    const body: unknown = await response.json();

    expect(response.status).toBe(503);
    expect(body).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32004, message }
    });
    expect(JSON.stringify(body)).not.toContain("must-not-leak");
    expect(JSON.stringify(body)).not.toContain("sensitive provider detail");
    await closeServer(server);
  });

  it("passes only transport-derived TLS facts to an asynchronous authenticator", async () => {
    let observedAttempt: Parameters<ClientAuthenticatorV1>[0] | undefined;
    const { server, url } = await listenDisposable(createInitializationHttpAppV1({
      clientAuthenticator: (attempt) => {
        observedAttempt = attempt;
        return Promise.resolve(firstPrincipal);
      }
    }));
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
        "X-Forwarded-Client-Cert": "untrusted"
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })
    });

    expect(response.status).toBe(200);
    expect(observedAttempt?.trustedTlsPeer).toBeNull();
    await closeServer(server);
  });

  it("hides and rejects a session when a different identity presents its ID", async () => {
    const { server, url } = await listenDisposable(createTestApp());
    const owner = createTestClient(url, "Bearer fixture-first");
    const attacker = createTestClient(url, "Bearer fixture-second");

    await owner.initialize(initializeParams);
    await owner.sendInitialized();
    attacker.sessionId = owner.sessionId;
    attacker.negotiatedProtocolVersion = owner.negotiatedProtocolVersion;

    const denied = await attacker.sendRequest("ping", {
      userId: "user-first",
      agentId: "agent-first",
      clientId: "client-first",
      hostId: "host-first"
    });
    expect(denied.status).toBe(404);
    expect(denied.json).toMatchObject({
      error: { code: -32001, message: "MCP session was not found" }
    });
    expect((await owner.ping("owner-still-active")).status).toBe(200);
    await closeServer(server);
  });

  it("quarantines an active session and invalidates its credential lease on identity rotation", async () => {
    const secret = Buffer.from("disposable-downstream-secret", "utf8");
    const vault = new DisposableCredentialVaultV1({
      clock: () => new Date("2026-09-03T10:01:00.000Z"),
      leaseIdFactory: () => "rotation-lease"
    });
    vault.registerCredential({
      schemaVersion: "1.0.0",
      credentialProfileId: "profile-calendar",
      credentialRevision: 1,
      credentialKind: "BEARER_TOKEN",
      audienceId: "audience-calendar",
      allowedRouteIds: ["route-calendar-read"],
      allowedEndpointOrigins: ["https://calendar.example.test"],
      materialDigest: createHash("sha256").update(secret).digest("hex"),
      status: "ACTIVE",
      issuedAt: "2026-09-03T10:00:00.000Z",
      expiresAt: "2026-09-03T10:30:00.000Z"
    }, secret);
    const repository = new DisposableSessionStateRepositoryV1([vault]);
    const { server, url } = await listenDisposable(createTestApp({
      sessionIdFactory: () => "rotation-session",
      sessionStateRepository: repository
    }));
    const owner = createTestClient(url);
    await owner.initialize(initializeParams);
    await owner.sendInitialized();
    const binding = bindAuthenticatedIdentityToSessionV1(firstPrincipal, "rotation-session");
    for (const compartment of [
      "ROUTES", "DOWNSTREAM_STATE", "APPROVALS", "QUOTAS", "RESULTS", "AUDIT"
    ] as const) {
      repository.put(firstPrincipal, "rotation-session", compartment, `entry-${compartment}`, {
        retainedForTest: true
      });
    }
    const lease = vault.issueLease(binding, {
      credentialProfileId: "profile-calendar",
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    });
    const rotated = createTestClient(url, "Bearer fixture-first-rotated");
    rotated.sessionId = owner.sessionId;
    rotated.negotiatedProtocolVersion = owner.negotiatedProtocolVersion;

    expect((await rotated.ping("rotation-attempt")).status).toBe(404);
    expect(repository.inspectSession("rotation-session")).toMatchObject({
      status: "QUARANTINED",
      trustState: "FROZEN",
      compartmentEntryCounts: {
        ROUTES: 0,
        DOWNSTREAM_STATE: 0,
        APPROVALS: 0,
        QUOTAS: 0,
        RESULTS: 1,
        AUDIT: 1
      }
    });
    expect((await owner.ping("old-identity-after-rotation")).status).toBe(404);
    expect(() => vault.validateLease(binding, {
      leaseId: lease.leaseId,
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    })).toThrow(expect.objectContaining({
      name: CredentialAccessDeniedV1.name,
      reason: "LEASE_REVOKED"
    }));
    await closeServer(server);
  });
});
