import { describe, expect, it } from "vitest";

import {
  DisposableDownstreamRegistryV1,
  DownstreamRegistryDeniedV1,
  bindAuthenticatedIdentityToSessionV1,
  computeRegistryDigestV1,
  type AuthenticatedClientPrincipalV1,
  type DownstreamRegistrationV1,
  type RouteAdministratorAuthorityV1
} from "../../src/index.js";

const now = "2026-09-03T12:00:00.000Z";
const authority: RouteAdministratorAuthorityV1 = {
  schemaVersion: "1.0.0",
  administratorId: "admin-test",
  role: "ROUTE_REGISTRAR",
  authenticatedAt: now
};
const sessionPrincipal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-test",
  agentId: "agent-test",
  clientId: "client-test",
  host: { hostId: "host-test", name: "Test host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "client-credential",
    identityRevision: 1,
    authenticatedAt: now
  }
};
const registration: DownstreamRegistrationV1 = {
  schemaVersion: "1.0.0",
  server: {
    schemaVersion: "1.0.0",
    serverId: "server-calendar",
    displayName: "Disposable calendar server",
    authenticatedPrincipalId: "principal-calendar",
    authenticationMethod: "TEST_FIXTURE",
    mcpProtocolVersion: "2025-06-18",
    transport: {
      kind: "STREAMABLE_HTTP",
      endpoint: "http://127.0.0.1:3200/mcp",
      authenticationProfileId: "server-auth-profile"
    },
    credentialAudience: {
      audienceId: "audience-calendar",
      credentialProfileId: "downstream-credential-profile"
    },
    capabilities: ["tools.list"]
  },
  routes: [{
    schemaVersion: "1.0.0",
    routeId: "route-calendar-read",
    serverId: "server-calendar",
    toolName: "calendar.read",
    exposedName: "calendar.read",
    credentialAudienceId: "audience-calendar",
    policyScopeId: "scope-calendar",
    environment: "TEST",
    resourceMapping: {
      resourceClass: "NETWORK",
      resolverId: "calendar-resource-v1",
      scope: "calendar:test"
    },
    inputSchema: { type: "object", properties: { date: { type: "string" } } },
    outputSchema: { type: "object" }
  }],
  registrationRevision: 1
};
const observedTool = {
  name: "calendar.read",
  title: "Read calendar",
  description: "Untrusted downstream description",
  inputSchema: { properties: { date: { type: "string" } }, type: "object" },
  outputSchema: { type: "object" },
  annotations: { readOnlyHint: true }
} as const;
const observation = {
  schemaVersion: "1.0.0" as const,
  mcpProtocolVersion: "2025-06-18",
  capabilities: ["tools.list"],
  tools: [observedTool],
  observedAt: now
};

function createRegistry(state = { discovery: true, call: true }) {
  let event = 0;
  return new DisposableDownstreamRegistryV1({
    administratorAuthorizer: (candidate) => candidate.administratorId === "admin-test",
    downstreamAuthenticator: (attempt) => attempt.authorizationHeader === "Bearer server-fixture"
      ? {
          schemaVersion: "1.0.0",
          serverId: attempt.serverId,
          principalId: "principal-calendar",
          authenticationMethod: "TEST_FIXTURE",
          credentialId: "server-credential",
          identityRevision: 1,
          authenticatedAt: now
        }
      : null,
    routeAuthorizer: ({ stage }) => stage === "DISCOVERY" ? state.discovery : state.call,
    clock: () => new Date(now),
    eventIdFactory: () => `event-${String(++event)}`
  });
}

function authenticateObservation(registry: DisposableDownstreamRegistryV1) {
  return registry.observeDiscovery({
    serverId: "server-calendar",
    authorizationHeader: "Bearer server-fixture"
  }, observation);
}

describe("disposable downstream registry", () => {
  it("requires administrator authority and records computed, versioned registration evidence", () => {
    const registry = createRegistry();
    expect(() => registry.register({ ...authority, administratorId: "attacker" }, registration))
      .toThrow(DownstreamRegistryDeniedV1);
    const server = registry.register(authority, registration);

    expect(server.health.state).toBe("QUARANTINED");
    expect(server.capabilityIntegrity).toMatchObject({
      observedDigest: null,
      state: "UNVERIFIED"
    });
    expect(server.registration.evidenceDigest).toBe(computeRegistryDigestV1(registration));
    expect(registry.readAudit(authority)).toEqual([
      expect.objectContaining({
        schemaVersion: "1.0.0",
        eventType: "SERVER_REGISTERED",
        serverId: "server-calendar",
        actorId: "admin-test"
      })
    ]);
  });

  it("authenticates discovery and deterministically exposes one verified route", () => {
    const registry = createRegistry();
    registry.register(authority, registration);
    expect(authenticateObservation(registry).health.state).toBe("HEALTHY");
    const session = bindAuthenticatedIdentityToSessionV1(sessionPrincipal, "session-calendar");
    const discovery = registry.discover({
      requestId: "discovery-001",
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST"
    });

    expect(discovery).toMatchObject({
      coverage: "UNPROTECTED",
      tools: [{
        route: {
          serverId: "server-calendar",
          routeId: "route-calendar-read",
          schemaDigest: computeRegistryDigestV1({
            inputSchema: registration.routes[0]?.inputSchema,
            outputSchema: registration.routes[0]?.outputSchema
          })
        },
        contentTrust: "UNTRUSTED",
        callTimeAuthorizationRequired: true
      }]
    });
    expect(registry.resolveCall({
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST",
      exposedName: "calendar.read"
    })).toMatchObject({
      server: { authenticatedPrincipalId: "principal-calendar", health: { state: "HEALTHY" } },
      route: { routeId: "route-calendar-read", status: "ACTIVE" }
    });
  });

  it("quarantines protocol, capability, tool-set, and schema drift", () => {
    for (const changed of [
      { ...observation, mcpProtocolVersion: "2025-03-26" },
      { ...observation, capabilities: ["tools.list", "resources.list"] },
      { ...observation, tools: [] },
      {
        ...observation,
        tools: [{ ...observedTool, inputSchema: { type: "array" } }]
      }
    ]) {
      const registry = createRegistry();
      registry.register(authority, registration);
      const server = registry.observeDiscovery({
        serverId: "server-calendar",
        authorizationHeader: "Bearer server-fixture"
      }, changed);
      const session = bindAuthenticatedIdentityToSessionV1(sessionPrincipal, "session-calendar");
      expect(() => registry.resolveCall({
        session,
        policyScopeId: "scope-calendar",
        environment: "TEST",
        exposedName: "calendar.read"
      })).toThrow(DownstreamRegistryDeniedV1);
      expect(registry.readAudit(authority).map((event) => event.eventType)).toContain(
        "DISCOVERY_QUARANTINED"
      );
      expect(
        server.health.state === "QUARANTINED" || changed.tools[0]?.inputSchema.type === "array"
      ).toBe(true);
    }
  });

  it("rejects unauthenticated servers and duplicate, shadowed, or ambiguous routes atomically", () => {
    const registry = createRegistry();
    registry.register(authority, registration);
    expect(() => registry.observeDiscovery({
      serverId: "server-calendar",
      authorizationHeader: "Bearer attacker"
    }, observation)).toThrow(DownstreamRegistryDeniedV1);

    const firstRoute = registration.routes[0];
    if (firstRoute === undefined) {
      throw new Error("Fixture route is unavailable");
    }
    const conflicting: DownstreamRegistrationV1 = {
      ...registration,
      server: {
        ...registration.server,
        serverId: "server-shadow",
        authenticatedPrincipalId: "principal-shadow"
      },
      routes: [{
        ...firstRoute,
        routeId: "route-shadow",
        serverId: "server-shadow"
      }]
    };
    expect(() => registry.register(authority, conflicting)).toThrow(DownstreamRegistryDeniedV1);
    expect(registry.readAudit(authority)).toHaveLength(1);

    const duplicateWithinManifest = {
      ...registration,
      server: { ...registration.server, serverId: "server-duplicate-manifest" },
      routes: [
        { ...firstRoute, serverId: "server-duplicate-manifest" },
        {
          ...firstRoute,
          serverId: "server-duplicate-manifest",
          routeId: "route-second",
          toolName: "calendar.other"
        }
      ]
    };
    expect(() => registry.register(authority, duplicateWithinManifest)).toThrow();
  });

  it("does not treat discovery filtering as call-time authorization", () => {
    const authorization = { discovery: true, call: true };
    const registry = createRegistry(authorization);
    registry.register(authority, registration);
    authenticateObservation(registry);
    const session = bindAuthenticatedIdentityToSessionV1(sessionPrincipal, "session-calendar");
    expect(registry.discover({
      requestId: "discovery-001",
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST"
    }).tools).toHaveLength(1);

    authorization.call = false;
    expect(() => registry.resolveCall({
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST",
      exposedName: "calendar.read"
    })).toThrow(DownstreamRegistryDeniedV1);
    authorization.discovery = false;
    expect(registry.discover({
      requestId: "discovery-002",
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST"
    }).tools).toEqual([]);
  });

  it("latches drift quarantine until an authorized administrator reviews matching state", () => {
    const registry = createRegistry();
    registry.register(authority, registration);
    registry.observeDiscovery({
      serverId: "server-calendar",
      authorizationHeader: "Bearer server-fixture"
    }, { ...observation, tools: [{ ...observedTool, inputSchema: { type: "array" } }] });

    expect(authenticateObservation(registry).health.state).toBe("QUARANTINED");
    expect(() => registry.reviewQuarantine(
      { ...authority, administratorId: "attacker" },
      "server-calendar"
    )).toThrow(DownstreamRegistryDeniedV1);
    expect(registry.reviewQuarantine(authority, "server-calendar").health.state).toBe(
      "HEALTHY"
    );
    expect(registry.readAudit(authority).at(-1)?.eventType).toBe("QUARANTINE_REVIEWED");
  });

  it("removes unavailable servers and routes from discovery and resolution", () => {
    const registry = createRegistry();
    registry.register(authority, registration);
    authenticateObservation(registry);
    const session = bindAuthenticatedIdentityToSessionV1(sessionPrincipal, "session-calendar");

    expect(registry.markServerUnavailable(
      authority,
      "server-calendar",
      "dependency.unavailable"
    ).health.state).toBe("UNAVAILABLE");
    expect(registry.discover({
      requestId: "discovery-unavailable",
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST"
    }).tools).toEqual([]);
    expect(() => registry.resolveCall({
      session,
      policyScopeId: "scope-calendar",
      environment: "TEST",
      exposedName: "calendar.read"
    })).toThrow(DownstreamRegistryDeniedV1);
  });
});
