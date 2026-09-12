import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { bindAuthenticatedIdentityToSessionV1 } from "../../src/identity/client-authentication-v1.js";
import {
  ProtectedCredentialBrokerV1,
  ProtectedCredentialDeniedV1,
  type ApprovedSecretManagerProviderV1,
  type ProtectedCredentialBindingV1
} from "../../src/identity/protected-credential-broker-v1.js";

const now = new Date("2026-09-11T10:00:00.000Z");
const secretBytes = Buffer.from("approved-manager-secret", "utf8");
const descriptor = {
  schemaVersion: "1.0.0" as const,
  providerId: "approved-secret-manager",
  providerType: "CUSTOM_APPROVED" as const,
  approval: {
    status: "APPROVED" as const,
    approvedBy: "security-administrator",
    approvedAt: "2026-09-11T09:00:00.000Z",
    configurationDigest: "a".repeat(64)
  }
};
const binding: ProtectedCredentialBindingV1 = {
  schemaVersion: "1.0.0",
  secretManagerProviderId: descriptor.providerId,
  secretReference: "secret/downstream/calendar/versions/7",
  profile: {
    schemaVersion: "1.0.0",
    credentialProfileId: "profile-calendar",
    credentialRevision: 7,
    credentialKind: "BEARER_TOKEN",
    audienceId: "audience-calendar",
    allowedRouteIds: ["route-calendar"],
    allowedEndpointOrigins: ["https://calendar.example.test"],
    materialDigest: createHash("sha256").update(secretBytes).digest("hex"),
    status: "ACTIVE",
    issuedAt: "2026-09-11T09:30:00.000Z",
    expiresAt: "2026-09-11T10:30:00.000Z"
  }
};
const session = bindAuthenticatedIdentityToSessionV1({
  schemaVersion: "1.0.0",
  userId: "user-001",
  agentId: "agent-001",
  clientId: "client-001",
  host: { hostId: "host-001", name: "Protected host", version: "1.0.0" },
  authentication: {
    method: "MUTUAL_TLS",
    credentialId: "client-mtls-001",
    identityRevision: 1,
    authenticatedAt: now.toISOString()
  }
}, "transport-session-001");
const exactAuthorization = {
  approvalId: "approval-001",
  actionHash: "b".repeat(64),
  forwardingAttemptId: "forwarding-attempt-001"
};

function createBroker(overrides: {
  provider?: ApprovedSecretManagerProviderV1;
  fetchImplementation?: typeof fetch;
} = {}) {
  const material = Buffer.from(secretBytes);
  const fetchExactRevision = vi.fn(() => Promise.resolve({
    providerId: descriptor.providerId,
    secretReference: binding.secretReference,
    credentialProfileId: binding.profile.credentialProfileId,
    credentialRevision: binding.profile.credentialRevision,
    material
  }));
  const provider: ApprovedSecretManagerProviderV1 = overrides.provider ?? {
    descriptor,
    fetchExactRevision
  };
  const fetchImplementation = overrides.fetchImplementation ?? vi.fn(() => Promise.resolve(
    new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), {
      status: 200,
      headers: { "content-type": "application/json" }
    })
  ));
  const broker = new ProtectedCredentialBrokerV1({
    secretManager: provider,
    bindings: [binding],
    clock: () => now,
    leaseIdFactory: () => "protected-lease-001",
    fetchImplementation
  });
  return { broker, fetchExactRevision, fetchImplementation, material };
}

function issueLease(broker: ProtectedCredentialBrokerV1) {
  return broker.issueLease(session, {
    credentialProfileId: binding.profile.credentialProfileId,
    audienceId: binding.profile.audienceId,
    routeId: binding.profile.allowedRouteIds[0] ?? "missing",
    endpointOrigin: binding.profile.allowedEndpointOrigins[0] ?? "missing",
    ...exactAuthorization
  });
}

function requestFor(leaseId: string, signal?: AbortSignal) {
  return {
    leaseId,
    credentialProfileId: binding.profile.credentialProfileId,
    credentialRevision: binding.profile.credentialRevision,
    audienceId: binding.profile.audienceId,
    routeId: binding.profile.allowedRouteIds[0] ?? "missing",
    ...exactAuthorization,
    endpoint: `${binding.profile.allowedEndpointOrigins[0] ?? "missing"}/mcp`,
    body: Buffer.from("{}", "utf8"),
    maxResponseBytes: 1_024,
    ...(signal === undefined ? {} : { signal })
  };
}

describe("protected credential broker", () => {
  it("fetches the exact approved revision only at use and returns no credential material", async () => {
    let observedAuthorization: string | null = null;
    let observedRedirect: RequestRedirect | undefined;
    const fetchImplementation = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      observedAuthorization = new Headers(init?.headers).get("authorization");
      observedRedirect = init?.redirect;
      return Promise.resolve(new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" }
      }));
    }) as typeof fetch;
    const { broker, fetchExactRevision, material } = createBroker({ fetchImplementation });
    const lease = issueLease(broker);

    expect(JSON.stringify(lease)).not.toContain(secretBytes.toString("utf8"));
    const response = await broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId));

    expect(fetchExactRevision).toHaveBeenCalledWith({
      secretReference: binding.secretReference,
      credentialProfileId: binding.profile.credentialProfileId,
      credentialRevision: 7
    });
    expect(observedAuthorization).toBe(`Bearer ${secretBytes.toString("utf8")}`);
    expect(observedRedirect).toBe("manual");
    expect(response.status).toBe(200);
    expect(JSON.stringify(response)).not.toContain(secretBytes.toString("utf8"));
    expect([...material]).toEqual(new Array(material.length).fill(0));
  });

  it.each([
    ["audience", { audienceId: "audience-other" }, "AUDIENCE_MISMATCH"],
    ["route", { routeId: "route-other" }, "ROUTE_MISMATCH"],
    ["endpoint", { endpointOrigin: "https://other.example.test" }, "ENDPOINT_MISMATCH"]
  ] as const)("rejects a mismatched %s before issuing a lease", (_name, change, reason) => {
    const { broker } = createBroker();
    expect(() => broker.issueLease(session, {
      credentialProfileId: binding.profile.credentialProfileId,
      audienceId: binding.profile.audienceId,
      routeId: binding.profile.allowedRouteIds[0] ?? "missing",
      endpointOrigin: binding.profile.allowedEndpointOrigins[0] ?? "missing",
      ...exactAuthorization,
      ...change
    })).toThrow(expect.objectContaining({ reason }));
  });

  it("denies provider, secret reference, profile, revision, and digest substitution", async () => {
    for (const secretChange of [
      { providerId: "other-provider" },
      { secretReference: "secret/other" },
      { credentialProfileId: "profile-other" },
      { credentialRevision: 8 },
      { material: Buffer.from("wrong-secret-material", "utf8") }
    ]) {
      const provider: ApprovedSecretManagerProviderV1 = {
        descriptor,
        fetchExactRevision: () => Promise.resolve({
          providerId: descriptor.providerId,
          secretReference: binding.secretReference,
          credentialProfileId: binding.profile.credentialProfileId,
          credentialRevision: binding.profile.credentialRevision,
          material: Buffer.from(secretBytes),
          ...secretChange
        })
      };
      const { broker } = createBroker({ provider });
      const lease = issueLease(broker);
      await expect(broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId)))
        .rejects.toBeInstanceOf(ProtectedCredentialDeniedV1);
    }
  });

  it("binds one lease to one exact approval, action, and forwarding attempt and rejects replay before I/O", async () => {
    const created = createBroker();
    const lease = issueLease(created.broker);
    await expect(created.broker.sendMcpJsonWithLease(session, {
      ...requestFor(lease.leaseId), actionHash: "c".repeat(64)
    })).rejects.toMatchObject({ reason: "AUTHORIZATION_MISMATCH" });
    expect(created.fetchExactRevision).not.toHaveBeenCalled();

    await created.broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId));
    await expect(created.broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId)))
      .rejects.toMatchObject({ reason: "LEASE_REPLAYED" });
    expect(created.fetchExactRevision).toHaveBeenCalledTimes(1);
    expect(created.fetchImplementation).toHaveBeenCalledTimes(1);
  });

  it("streams chunked responses and cancels as soon as the result exceeds the cap", async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(700));
        controller.enqueue(new Uint8Array(325));
      },
      cancel() { cancelled = true; }
    });
    const created = createBroker({
      fetchImplementation: vi.fn(() => Promise.resolve(new Response(stream, {
        status: 200, headers: { "content-type": "application/json" }
      })))
    });
    const lease = issueLease(created.broker);
    await expect(created.broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId)))
      .rejects.toThrow("exceeds the result limit");
    expect(cancelled).toBe(true);
  });

  it.each(["1025", "not-a-number"])("rejects invalid Content-Length %s before reading", async (contentLength) => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
    const created = createBroker({ fetchImplementation: vi.fn(() => Promise.resolve(
      new Response(stream, { status: 200, headers: { "content-length": contentLength } })
    )) });
    const lease = issueLease(created.broker);
    await expect(created.broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId))).rejects.toBeInstanceOf(RangeError);
    expect(cancelled).toBe(true);
  });

  it("fails closed on provider error, unknown revision, cancellation, and redirect", async () => {
    const cases: Array<{ provider: ApprovedSecretManagerProviderV1; signal?: AbortSignal }> = [
      { provider: { descriptor, fetchExactRevision: () => Promise.reject(new Error("provider detail")) } },
      { provider: { descriptor, fetchExactRevision: () => Promise.resolve(null) } }
    ];
    for (const item of cases) {
      const { broker } = createBroker({ provider: item.provider });
      const lease = issueLease(broker);
      await expect(broker.sendMcpJsonWithLease(session, requestFor(lease.leaseId, item.signal)))
        .rejects.toBeInstanceOf(ProtectedCredentialDeniedV1);
    }

    const controller = new AbortController();
    controller.abort();
    const cancelled = createBroker();
    const cancelledLease = issueLease(cancelled.broker);
    await expect(cancelled.broker.sendMcpJsonWithLease(
      session,
      requestFor(cancelledLease.leaseId, controller.signal)
    )).rejects.toMatchObject({ reason: "CANCELLED" });
    expect(cancelled.fetchExactRevision).not.toHaveBeenCalled();

    const redirected = createBroker({
      fetchImplementation: vi.fn(() => Promise.resolve(new Response(null, {
        status: 302,
        headers: { location: "https://other.example.test" }
      })))
    });
    const redirectLease = issueLease(redirected.broker);
    await expect(redirected.broker.sendMcpJsonWithLease(
      session,
      requestFor(redirectLease.leaseId)
    )).rejects.toMatchObject({ reason: "ENDPOINT_MISMATCH" });
  });

  it("requires an explicitly approved provider and keeps bindings strict", () => {
    expect(() => createBroker({
      provider: {
        descriptor: { ...descriptor, approval: { ...descriptor.approval, status: "PENDING" } } as never,
        fetchExactRevision: () => Promise.resolve(null)
      }
    })).toThrow();
    expect(() => new ProtectedCredentialBrokerV1({
      secretManager: { descriptor, fetchExactRevision: () => Promise.resolve(null) },
      bindings: [{ ...binding, secretManagerProviderId: "other-provider" }],
      clock: () => now
    })).toThrow(expect.objectContaining({ reason: "PROVIDER_UNAVAILABLE" }));
  });
});
