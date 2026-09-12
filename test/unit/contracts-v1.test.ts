import { describe, expect, it } from "vitest";

import {
  gatewayClientV1Schema,
  gatewayScaffoldStatus,
  gatewaySessionV1Schema
} from "../../src/index.js";

const validClient = {
  schemaVersion: "1.0.0",
  userId: "user-001",
  agentId: "agent-001",
  clientId: "client-001",
  host: {
    hostId: "host-001",
    name: "Disposable MCP test host",
    version: "0.1.0"
  },
  mcpProtocolVersion: "2025-06-18",
  capabilities: ["tools", "resources.read"],
  issuedAt: "2026-09-01T10:00:00.000Z"
} as const;

const validSession = {
  schemaVersion: "1.0.0",
  sessionId: "session-001",
  identity: {
    userId: "user-001",
    agentId: "agent-001",
    clientId: "client-001",
    hostId: "host-001"
  },
  stateNamespace: "session:session-001",
  status: "ACTIVE",
  coverage: "UNPROTECTED",
  quotaLimits: {
    callsPerMinute: 60,
    concurrentCalls: 4,
    payloadBytes: 1_048_576,
    callDepth: 8,
    delegationDepth: 4
  },
  createdAt: "2026-09-01T10:00:00.000Z",
  lastActivityAt: "2026-09-01T10:01:00.000Z",
  expiresAt: "2026-09-01T11:00:00.000Z"
} as const;

describe("GatewayClientV1", () => {
  it("accepts a bounded versioned client resolved by a trusted boundary", () => {
    expect(gatewayClientV1Schema.parse(validClient)).toEqual(validClient);
  });

  it("fails safely for an unknown schema version", () => {
    expect(
      gatewayClientV1Schema.safeParse({ ...validClient, schemaVersion: "2.0.0" }).success
    ).toBe(false);
  });

  it("rejects duplicate or malformed capability identifiers", () => {
    expect(
      gatewayClientV1Schema.safeParse({
        ...validClient,
        capabilities: ["tools", "tools"]
      }).success
    ).toBe(false);
    expect(
      gatewayClientV1Schema.safeParse({
        ...validClient,
        capabilities: ["TOOLS WITH SPACES"]
      }).success
    ).toBe(false);
  });

  it("rejects unknown fields instead of silently trusting them", () => {
    expect(
      gatewayClientV1Schema.safeParse({ ...validClient, isAdministrator: true }).success
    ).toBe(false);
  });
});

describe("GatewaySessionV1", () => {
  it("accepts an isolated session with bounded quotas and UTC timestamps", () => {
    expect(gatewaySessionV1Schema.parse(validSession)).toEqual(validSession);
  });

  it("fails safely for unknown versions and invalid coverage claims", () => {
    expect(
      gatewaySessionV1Schema.safeParse({ ...validSession, schemaVersion: "1.1.0" }).success
    ).toBe(false);
    expect(
      gatewaySessionV1Schema.safeParse({ ...validSession, coverage: "PROTECTED" }).success
    ).toBe(false);
  });

  it("rejects invalid quota and timestamp boundaries", () => {
    expect(
      gatewaySessionV1Schema.safeParse({
        ...validSession,
        quotaLimits: { ...validSession.quotaLimits, concurrentCalls: 0 }
      }).success
    ).toBe(false);
    expect(
      gatewaySessionV1Schema.safeParse({
        ...validSession,
        expiresAt: "2026-09-01T09:59:59.000Z"
      }).success
    ).toBe(false);
    expect(
      gatewaySessionV1Schema.safeParse({
        ...validSession,
        createdAt: "2026-09-01T15:30:00+05:30"
      }).success
    ).toBe(false);
  });

  it("does not enable traffic or claim protection", () => {
    expect(gatewayScaffoldStatus).toMatchObject({
      coverage: "UNPROTECTED",
      acceptsLifecycleTraffic: true,
      protectedForwardingEnabled: false
    });
  });
});
