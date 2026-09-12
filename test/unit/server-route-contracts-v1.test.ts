import { describe, expect, it } from "vitest";

import {
  downstreamServerRouteBindingV1Schema,
  downstreamServerV1Schema,
  gatewayScaffoldStatus,
  toolRouteSetV1Schema,
  toolRouteV1Schema
} from "../../src/index.js";

const registeredDigest = "a".repeat(64);

const validServer = {
  schemaVersion: "1.0.0",
  serverId: "server-001",
  displayName: "Disposable filesystem MCP server",
  authenticatedPrincipalId: "principal-server-001",
  authenticationMethod: "TEST_FIXTURE",
  mcpProtocolVersion: "2025-06-18",
  transport: {
    kind: "STREAMABLE_HTTP",
    endpoint: "http://127.0.0.1:3100/mcp",
    authenticationProfileId: "auth-profile-001"
  },
  credentialAudience: {
    audienceId: "audience-filesystem-test",
    credentialProfileId: "credential-profile-001"
  },
  capabilities: ["tools", "resources.read"],
  capabilityIntegrity: {
    registeredDigest,
    observedDigest: registeredDigest,
    state: "VERIFIED",
    observedAt: "2026-09-01T12:00:00.000Z"
  },
  health: {
    state: "HEALTHY",
    checkedAt: "2026-09-01T12:00:01.000Z",
    reasonCodes: []
  },
  registration: {
    source: "TEST_FIXTURE",
    registeredBy: "admin-test-001",
    registeredAt: "2026-09-01T11:59:00.000Z",
    revision: 1,
    evidenceDigest: "b".repeat(64)
  }
} as const;

const validRoute = {
  schemaVersion: "1.0.0",
  routeId: "route-001",
  serverId: "server-001",
  toolName: "filesystem.read_file",
  exposedName: "filesystem.read_file",
  credentialAudienceId: "audience-filesystem-test",
  policyScopeId: "scope-disposable-repository",
  environment: "TEST",
  resourceMapping: {
    resourceClass: "FILESYSTEM",
    resolverId: "filesystem-path-v1",
    scope: "V:/disposable/repository"
  },
  schemaIntegrity: {
    registeredDigest,
    observedDigest: registeredDigest,
    state: "VERIFIED",
    observedAt: "2026-09-01T12:00:00.000Z"
  },
  status: "ACTIVE",
  registeredAt: "2026-09-01T11:59:30.000Z"
} as const;

describe("DownstreamServerV1", () => {
  it("accepts a bounded authenticated server registration without credential values", () => {
    expect(downstreamServerV1Schema.parse(validServer)).toEqual(validServer);
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        credentialAudience: {
          ...validServer.credentialAudience,
          credentialValue: "must-not-enter-the-contract"
        }
      }).success
    ).toBe(false);
  });

  it("rejects unknown versions, embedded endpoint credentials, and remote plaintext HTTP", () => {
    expect(
      downstreamServerV1Schema.safeParse({ ...validServer, schemaVersion: "2.0.0" })
        .success
    ).toBe(false);
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        transport: {
          ...validServer.transport,
          endpoint: "https://user:secret@example.test/mcp"
        }
      }).success
    ).toBe(false);
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        transport: {
          ...validServer.transport,
          endpoint: "http://example.test/mcp"
        }
      }).success
    ).toBe(false);
  });

  it("requires capability drift or missing observations to quarantine the server", () => {
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        capabilityIntegrity: {
          ...validServer.capabilityIntegrity,
          observedDigest: "c".repeat(64),
          state: "DRIFTED"
        }
      }).success
    ).toBe(false);

    const quarantined = {
      ...validServer,
      capabilityIntegrity: {
        ...validServer.capabilityIntegrity,
        observedDigest: "c".repeat(64),
        state: "DRIFTED"
      },
      health: { ...validServer.health, state: "QUARANTINED" }
    } as const;
    expect(downstreamServerV1Schema.safeParse(quarantined).success).toBe(true);

    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        capabilityIntegrity: {
          ...validServer.capabilityIntegrity,
          observedDigest: null,
          observedAt: null,
          state: "UNVERIFIED"
        }
      }).success
    ).toBe(false);
  });

  it("rejects capability or health observations that predate registration", () => {
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        health: { ...validServer.health, checkedAt: "2026-09-01T11:58:00.000Z" }
      }).success
    ).toBe(false);
    expect(
      downstreamServerV1Schema.safeParse({
        ...validServer,
        capabilityIntegrity: {
          ...validServer.capabilityIntegrity,
          observedAt: "2026-09-01T11:58:00.000Z"
        }
      }).success
    ).toBe(false);
  });
});

describe("ToolRouteV1", () => {
  it("accepts one verified route with canonical environment and resource mapping", () => {
    expect(toolRouteV1Schema.parse(validRoute)).toEqual(validRoute);
    expect(
      downstreamServerRouteBindingV1Schema.safeParse({
        server: validServer,
        route: validRoute
      }).success
    ).toBe(true);
  });

  it("rejects unknown versions and active unknown mappings", () => {
    expect(
      toolRouteV1Schema.safeParse({ ...validRoute, schemaVersion: "1.1.0" }).success
    ).toBe(false);
    expect(
      toolRouteV1Schema.safeParse({ ...validRoute, environment: "UNKNOWN" }).success
    ).toBe(false);
    expect(
      toolRouteV1Schema.safeParse({
        ...validRoute,
        resourceMapping: { ...validRoute.resourceMapping, resourceClass: "UNKNOWN" }
      }).success
    ).toBe(false);
  });

  it("requires schema drift or missing observations to quarantine the route", () => {
    expect(
      toolRouteV1Schema.safeParse({
        ...validRoute,
        schemaIntegrity: {
          ...validRoute.schemaIntegrity,
          observedDigest: "d".repeat(64),
          state: "DRIFTED"
        }
      }).success
    ).toBe(false);

    const quarantined = {
      ...validRoute,
      schemaIntegrity: {
        ...validRoute.schemaIntegrity,
        observedDigest: null,
        observedAt: null,
        state: "UNVERIFIED"
      },
      status: "QUARANTINED"
    } as const;
    expect(toolRouteV1Schema.safeParse(quarantined).success).toBe(true);
  });

  it("rejects schema observations that predate route registration", () => {
    expect(
      toolRouteV1Schema.safeParse({
        ...validRoute,
        schemaIntegrity: {
          ...validRoute.schemaIntegrity,
          observedAt: "2026-09-01T11:58:00.000Z"
        }
      }).success
    ).toBe(false);
  });

  it("rejects server and credential-audience binding mismatches", () => {
    expect(
      downstreamServerRouteBindingV1Schema.safeParse({
        server: validServer,
        route: { ...validRoute, serverId: "server-attacker" }
      }).success
    ).toBe(false);
    expect(
      downstreamServerRouteBindingV1Schema.safeParse({
        server: validServer,
        route: { ...validRoute, credentialAudienceId: "audience-attacker" }
      }).success
    ).toBe(false);
  });

  it("rejects active routes to unhealthy servers", () => {
    expect(
      downstreamServerRouteBindingV1Schema.safeParse({
        server: {
          ...validServer,
          health: { ...validServer.health, state: "UNAVAILABLE" }
        },
        route: validRoute
      }).success
    ).toBe(false);
  });

  it("rejects duplicate IDs and shadowed exposed names within one scope", () => {
    expect(
      toolRouteSetV1Schema.safeParse([
        validRoute,
        { ...validRoute, exposedName: "filesystem.read_other" }
      ]).success
    ).toBe(false);
    expect(
      toolRouteSetV1Schema.safeParse([
        validRoute,
        {
          ...validRoute,
          routeId: "route-002",
          serverId: "server-002",
          exposedName: validRoute.exposedName
        }
      ]).success
    ).toBe(false);
  });

  it("allows the same exposed name in independently scoped route namespaces", () => {
    expect(
      toolRouteSetV1Schema.safeParse([
        validRoute,
        {
          ...validRoute,
          routeId: "route-002",
          serverId: "server-002",
          policyScopeId: "scope-other-disposable-repository"
        }
      ]).success
    ).toBe(true);
  });

  it("keeps the gateway non-forwarding and unprotected", () => {
    expect(gatewayScaffoldStatus).toMatchObject({
      coverage: "UNPROTECTED",
      acceptsLifecycleTraffic: true,
      protectedForwardingEnabled: false
    });
  });
});
