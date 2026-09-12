import { describe, expect, it } from "vitest";

import {
  DisposableSessionStateRepositoryV1,
  SessionAccessDeniedV1,
  bindAuthenticatedIdentityToSessionV1,
  type AuthenticatedClientPrincipalV1
} from "../../src/index.js";

const owner: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-owner",
  agentId: "agent-owner",
  clientId: "client-owner",
  host: { hostId: "host-owner", name: "Disposable host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-001",
    identityRevision: 1,
    authenticatedAt: "2026-09-03T10:00:00.000Z"
  }
};

describe("session state isolation", () => {
  it("isolates every state compartment and prevents reference-based mutation", () => {
    const repository = new DisposableSessionStateRepositoryV1();
    repository.createSession(bindAuthenticatedIdentityToSessionV1(owner, "session-owner"));
    const attacker = {
      ...owner,
      userId: "user-attacker",
      agentId: "agent-attacker",
      clientId: "client-attacker",
      host: { ...owner.host, hostId: "host-attacker" }
    };
    repository.createSession(bindAuthenticatedIdentityToSessionV1(attacker, "session-attacker"));
    const value = { allowed: true };
    repository.put(owner, "session-owner", "ROUTES", "route-001", value);
    value.allowed = false;

    expect(repository.get(owner, "session-owner", "ROUTES", "route-001")).toEqual({
      allowed: true
    });
    expect(() => repository.get(attacker, "session-owner", "ROUTES", "route-001"))
      .toThrow(SessionAccessDeniedV1);
    expect(repository.inspectSession("session-owner")?.compartmentEntryCounts.ROUTES).toBe(1);
  });

  it("quarantines rotation, clears active state, retains accountability, and invalidates leases", () => {
    const invalidated: string[] = [];
    const repository = new DisposableSessionStateRepositoryV1([
      { invalidateSession: (sessionId) => invalidated.push(sessionId) }
    ]);
    repository.createSession(bindAuthenticatedIdentityToSessionV1(owner, "session-owner"));
    for (const compartment of [
      "ROUTES", "DOWNSTREAM_STATE", "APPROVALS", "QUOTAS", "RESULTS", "AUDIT"
    ] as const) {
      repository.put(owner, "session-owner", compartment, `entry-${compartment}`, { n: 1 });
    }
    const rotated = {
      ...owner,
      authentication: {
        ...owner.authentication,
        credentialId: "credential-002",
        identityRevision: 2
      }
    };

    expect(() => repository.authorizeSession(rotated, "session-owner"))
      .toThrow(SessionAccessDeniedV1);
    expect(repository.inspectSession("session-owner")).toMatchObject({
      status: "QUARANTINED",
      trustState: "FROZEN",
      reasonCodes: ["identity.credential_rotated"],
      compartmentEntryCounts: {
        ROUTES: 0,
        DOWNSTREAM_STATE: 0,
        APPROVALS: 0,
        QUOTAS: 0,
        RESULTS: 1,
        AUDIT: 1
      }
    });
    expect(invalidated).toEqual(["session-owner"]);
    expect(() => repository.authorizeSession(owner, "session-owner"))
      .toThrow(SessionAccessDeniedV1);
  });
});
