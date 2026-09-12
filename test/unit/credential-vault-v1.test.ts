import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  CredentialAccessDeniedV1,
  DisposableCredentialVaultV1,
  bindAuthenticatedIdentityToSessionV1,
  type AuthenticatedClientPrincipalV1
} from "../../src/index.js";

const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-001",
  agentId: "agent-001",
  clientId: "client-001",
  host: { hostId: "host-001", name: "Disposable host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "client-credential-001",
    identityRevision: 1,
    authenticatedAt: "2026-09-03T10:00:00.000Z"
  }
};

const secret = Buffer.from("disposable-secret-material", "utf8");

function profile() {
  return {
    schemaVersion: "1.0.0" as const,
    credentialProfileId: "downstream-credential-001",
    credentialRevision: 1,
    credentialKind: "BEARER_TOKEN" as const,
    audienceId: "audience-calendar",
    allowedRouteIds: ["route-calendar-read"],
    allowedEndpointOrigins: ["https://calendar.example.test"],
    materialDigest: createHash("sha256").update(secret).digest("hex"),
    status: "ACTIVE" as const,
    issuedAt: "2026-09-03T10:00:00.000Z",
    expiresAt: "2026-09-03T10:30:00.000Z"
  };
}

describe("disposable credential vault", () => {
  it("issues short-lived audience-, route-, and session-bound leases without returning secrets", () => {
    const vault = new DisposableCredentialVaultV1({
      clock: () => new Date("2026-09-03T10:01:00.000Z"),
      leaseIdFactory: () => "lease-001"
    });
    vault.registerCredential(profile(), secret);
    const binding = bindAuthenticatedIdentityToSessionV1(principal, "session-001");
    const lease = vault.issueLease(binding, {
      credentialProfileId: "downstream-credential-001",
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    });

    expect(lease.expiresAt).toBe("2026-09-03T10:06:00.000Z");
    expect(vault.validateLease(binding, {
      leaseId: lease.leaseId,
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    })).toEqual(lease);
    expect(JSON.stringify(lease)).not.toContain(secret.toString("utf8"));
    expect("credentialMaterial" in lease).toBe(false);
  });

  it.each([
    ["audience-other", "route-calendar-read", "AUDIENCE_MISMATCH"],
    ["audience-calendar", "route-calendar-write", "ROUTE_MISMATCH"]
  ] as const)("rejects use outside the registered audience or route", (audienceId, routeId, reason) => {
    const vault = new DisposableCredentialVaultV1({
      clock: () => new Date("2026-09-03T10:01:00.000Z")
    });
    vault.registerCredential(profile(), secret);
    expect(() => vault.issueLease(
      bindAuthenticatedIdentityToSessionV1(principal, "session-001"),
      { credentialProfileId: "downstream-credential-001", audienceId, routeId }
    )).toThrow(expect.objectContaining({ reason }));
  });

  it("rejects digest mismatches, cross-session use, expiration, and invalidation", () => {
    let now = new Date("2026-09-03T10:01:00.000Z");
    const vault = new DisposableCredentialVaultV1({
      clock: () => now,
      leaseIdFactory: () => "lease-001"
    });
    expect(() => {
      vault.registerCredential(
        { ...profile(), materialDigest: "0".repeat(64) },
        secret
      );
    }).toThrow("digest");
    vault.registerCredential(profile(), secret);
    const first = bindAuthenticatedIdentityToSessionV1(principal, "session-001");
    const lease = vault.issueLease(first, {
      credentialProfileId: "downstream-credential-001",
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    });
    const request = {
      leaseId: lease.leaseId,
      audienceId: "audience-calendar",
      routeId: "route-calendar-read"
    };
    expect(() => vault.validateLease(
      bindAuthenticatedIdentityToSessionV1(principal, "session-002"), request
    )).toThrow(expect.objectContaining({ reason: "SESSION_MISMATCH" }));

    now = new Date("2026-09-03T10:06:00.000Z");
    expect(() => vault.validateLease(first, request)).toThrow(
      expect.objectContaining({ reason: "LEASE_EXPIRED" })
    );
    now = new Date("2026-09-03T10:02:00.000Z");
    vault.invalidateSession("session-001");
    expect(() => vault.validateLease(first, request)).toThrow(CredentialAccessDeniedV1);
    expect(() => vault.validateLease(first, request)).toThrow(
      expect.objectContaining({ reason: "LEASE_REVOKED" })
    );
  });
});
