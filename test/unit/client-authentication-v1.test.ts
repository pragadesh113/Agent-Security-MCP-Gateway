import { describe, expect, it } from "vitest";

import {
  authenticatedClientPrincipalV1Schema,
  authenticatedSessionIdentityBindingV1Schema,
  bindAuthenticatedIdentityToSessionV1,
  principalMatchesSessionBindingV1
} from "../../src/index.js";

const principal = {
  schemaVersion: "1.0.0",
  userId: "user-001",
  agentId: "agent-001",
  clientId: "client-001",
  host: {
    hostId: "host-001",
    name: "Disposable MCP host",
    version: "1.0.0"
  },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-001",
    identityRevision: 1,
    authenticatedAt: "2026-09-03T10:00:00.000Z"
  }
} as const;

describe("authenticated client identity boundary", () => {
  it("accepts trusted identity metadata without credential material", () => {
    expect(authenticatedClientPrincipalV1Schema.parse(principal)).toEqual(principal);
  });

  it("rejects unknown versions, fields, and credential-bearing output", () => {
    expect(
      authenticatedClientPrincipalV1Schema.safeParse({
        ...principal,
        schemaVersion: "2.0.0"
      }).success
    ).toBe(false);
    expect(
      authenticatedClientPrincipalV1Schema.safeParse({
        ...principal,
        authentication: {
          ...principal.authentication,
          token: "must-not-cross-the-boundary"
        }
      }).success
    ).toBe(false);
    expect(
      authenticatedClientPrincipalV1Schema.safeParse({
        ...principal,
        isAdministrator: true
      }).success
    ).toBe(false);
  });

  it("binds an opaque transport session to a non-secret state namespace", () => {
    const binding = bindAuthenticatedIdentityToSessionV1(
      principal,
      "transport-session-001"
    );

    expect(authenticatedSessionIdentityBindingV1Schema.parse(binding)).toEqual(binding);
    expect(binding.transportSessionId).toBe("transport-session-001");
    expect(binding.stateNamespace).toMatch(/^session:[a-f0-9]{64}$/u);
    expect(binding.identity).toMatchObject({
      userId: principal.userId,
      agentId: principal.agentId,
      clientId: principal.clientId,
      hostId: principal.host.hostId,
      credentialId: principal.authentication.credentialId,
      identityRevision: 1
    });
    expect(JSON.stringify(binding)).not.toContain("must-not-cross-the-boundary");
  });

  it("matches reauthentication time changes but rejects identity or credential changes", () => {
    const binding = bindAuthenticatedIdentityToSessionV1(
      principal,
      "transport-session-001"
    );
    expect(
      principalMatchesSessionBindingV1(
        {
          ...principal,
          authentication: {
            ...principal.authentication,
            authenticatedAt: "2026-09-03T10:01:00.000Z"
          }
        },
        binding
      )
    ).toBe(true);

    const changedPrincipals = [
      { ...principal, userId: "user-002" },
      { ...principal, agentId: "agent-002" },
      { ...principal, clientId: "client-002" },
      { ...principal, host: { ...principal.host, hostId: "host-002" } },
      {
        ...principal,
        authentication: { ...principal.authentication, credentialId: "credential-002" }
      },
      {
        ...principal,
        authentication: { ...principal.authentication, identityRevision: 2 }
      }
    ];

    for (const changedPrincipal of changedPrincipals) {
      expect(principalMatchesSessionBindingV1(changedPrincipal, binding)).toBe(false);
    }
  });

  it("rejects malformed session identifiers before deriving a namespace", () => {
    expect(() => bindAuthenticatedIdentityToSessionV1(principal, "contains space")).toThrow();
    expect(() => bindAuthenticatedIdentityToSessionV1(principal, "x".repeat(129))).toThrow();
  });
});
