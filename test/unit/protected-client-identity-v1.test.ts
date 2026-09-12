import { describe, expect, it, vi } from "vitest";

import {
  ProtectedClientIdentityProviderV1,
  ProtectedClientIdentityUnavailableV1,
  TLS_CLIENT_AUTH_EKU_OID_V1,
  normalizeTlsCertificateFingerprintSha256V1,
  protectedClientCredentialRecordV1Schema,
  trustedTlsPeerFactsV1Schema,
  type ProtectedClientCredentialRecordV1,
  type ProtectedClientCredentialStoreV1
} from "../../src/identity/protected-client-identity-v1.js";

const now = new Date("2026-09-11T10:00:00.000Z");
const fingerprint = "ab".repeat(32);

const attempt = {
  transport: "STREAMABLE_HTTP",
  remoteAddress: "127.0.0.1",
  authorizationHeader: undefined,
  trustedTlsPeer: {
    schemaVersion: "1.0.0",
    authorized: true,
    authorizationError: null,
    protocol: "TLSv1.3",
    certificate: {
      fingerprintSha256: fingerprint,
      validFrom: "2026-09-11T09:00:00.000Z",
      validTo: "2026-09-11T11:00:00.000Z",
      extendedKeyUsageOids: [TLS_CLIENT_AUTH_EKU_OID_V1]
    }
  }
} as const;

const record: ProtectedClientCredentialRecordV1 = {
  schemaVersion: "1.0.0",
  fingerprintSha256: fingerprint,
  credentialId: "mtls-client-credential-001",
  identityRevision: 4,
  status: "ACTIVE",
  userId: "user-001",
  agentId: "agent-001",
  clientId: "client-001",
  host: { hostId: "host-001", name: "Protected host", version: "1.2.3" },
  validFrom: "2026-09-11T08:00:00.000Z",
  validTo: "2026-09-11T12:00:00.000Z",
  activatedAt: "2026-09-11T08:30:00.000Z",
  revokedAt: null
};

const defaultStored = Symbol("default-stored");

function providerFor(
  stored: unknown = defaultStored,
  clock: () => Date = () => now
): {
  provider: ProtectedClientIdentityProviderV1;
  resolveActiveCredential: ReturnType<typeof vi.fn>;
} {
  const resolveActiveCredential = vi.fn(() => Promise.resolve(
    (stored === defaultStored ? record : stored) as ProtectedClientCredentialRecordV1 | null
  ));
  const store: ProtectedClientCredentialStoreV1 = {
    resolveActiveCredential
  };
  return {
    provider: new ProtectedClientIdentityProviderV1({ credentialStore: store, clock }),
    resolveActiveCredential
  };
}

describe("protected mutual-TLS client identity", () => {
  it("normalizes the Node TLS SHA-256 fingerprint form and rejects non-SHA-256 input", () => {
    expect(normalizeTlsCertificateFingerprintSha256V1(
      Array.from({ length: 32 }, () => "AB").join(":")
    )).toBe(fingerprint);
    expect(() => normalizeTlsCertificateFingerprintSha256V1("AA:BB")).toThrow();
    expect(() => normalizeTlsCertificateFingerprintSha256V1("g".repeat(64))).toThrow();
  });

  it("returns a strict MUTUAL_TLS principal from current TLS and registry evidence", async () => {
    const { provider, resolveActiveCredential } = providerFor();

    await expect(provider.authenticate(attempt)).resolves.toEqual({
      schemaVersion: "1.0.0",
      userId: "user-001",
      agentId: "agent-001",
      clientId: "client-001",
      host: { hostId: "host-001", name: "Protected host", version: "1.2.3" },
      authentication: {
        method: "MUTUAL_TLS",
        credentialId: "mtls-client-credential-001",
        identityRevision: 4,
        authenticatedAt: now.toISOString()
      }
    });
    expect(resolveActiveCredential).toHaveBeenCalledWith(fingerprint, now);
  });

  it.each([
    ["TLS authorization failure", { ...attempt, trustedTlsPeer: { ...attempt.trustedTlsPeer, authorized: false, authorizationError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" } }],
    ["missing client-auth EKU", { ...attempt, trustedTlsPeer: { ...attempt.trustedTlsPeer, certificate: { ...attempt.trustedTlsPeer.certificate, extendedKeyUsageOids: ["1.3.6.1.5.5.7.3.1"] } } }],
    ["not-yet-valid peer certificate", { ...attempt, trustedTlsPeer: { ...attempt.trustedTlsPeer, certificate: { ...attempt.trustedTlsPeer.certificate, validFrom: "2026-09-11T10:01:00.000Z" } } }],
    ["expired peer certificate", { ...attempt, trustedTlsPeer: { ...attempt.trustedTlsPeer, certificate: { ...attempt.trustedTlsPeer.certificate, validTo: "2026-09-11T09:59:59.000Z" } } }]
  ])("denies %s without trusting the registry", async (_name, candidate) => {
    const { provider, resolveActiveCredential } = providerFor();
    await expect(provider.authenticate(candidate))
      .resolves.toBeUndefined();
    expect(resolveActiveCredential).not.toHaveBeenCalled();
  });

  it.each([
    ["unknown credential", null],
    ["revoked credential", { ...record, status: "REVOKED", revokedAt: "2026-09-11T09:30:00.000Z" }],
    ["expired registry record", { ...record, validTo: "2026-09-11T09:59:59.000Z" }],
    ["future activation", { ...record, activatedAt: "2026-09-11T10:01:00.000Z" }]
  ])("denies a %s", async (_name, stored) => {
    const { provider } = providerFor(stored);
    await expect(provider.authenticate(attempt)).resolves.toBeUndefined();
  });

  it("fails closed when the store fails or returns malformed or substituted state", async () => {
    const failingStore: ProtectedClientCredentialStoreV1 = {
      resolveActiveCredential: () => Promise.reject(new Error("database detail"))
    };
    const failingProvider = new ProtectedClientIdentityProviderV1({
      credentialStore: failingStore,
      clock: () => now
    });
    await expect(failingProvider.authenticate(attempt)).rejects.toBeInstanceOf(
      ProtectedClientIdentityUnavailableV1
    );

    for (const stored of [
      { ...record, unexpected: true },
      { ...record, fingerprintSha256: "cd".repeat(32) }
    ]) {
      const { provider } = providerFor(stored);
      await expect(provider.authenticate(attempt)).rejects.toBeInstanceOf(
        ProtectedClientIdentityUnavailableV1
      );
    }
  });

  it("keeps trusted TLS facts and credential records strict and internally consistent", () => {
    expect(trustedTlsPeerFactsV1Schema.safeParse({
      ...attempt.trustedTlsPeer,
      certificatePem: "must-not-cross-the-boundary"
    }).success).toBe(false);
    expect(protectedClientCredentialRecordV1Schema.safeParse({
      ...record,
      status: "ACTIVE",
      revokedAt: "2026-09-11T09:30:00.000Z"
    }).success).toBe(false);
    expect(protectedClientCredentialRecordV1Schema.safeParse({
      ...record,
      status: "REVOKED",
      revokedAt: null
    }).success).toBe(false);
  });
});
