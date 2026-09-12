import { describe, expect, it, vi } from "vitest";

import { HashiCorpVaultKvV2ProviderV1 } from "../../src/identity/hashicorp-vault-provider-v1.js";

const descriptor = {
  schemaVersion: "1.0.0" as const,
  providerId: "hashicorp-vault-local",
  providerType: "HASHICORP_VAULT" as const,
  approval: { status: "APPROVED" as const, approvedBy: "project-owner",
    approvedAt: "2026-09-12T12:00:00.000Z", configurationDigest: "a".repeat(64) }
};

function provider(fetchImplementation: typeof fetch, token = Buffer.from("dev-only-token")) {
  return { instance: new HashiCorpVaultKvV2ProviderV1({
    descriptor, endpointOrigin: "http://127.0.0.1:8200",
    allowInsecureLoopbackForDisposableTests: true,
    tokenProvider: () => Promise.resolve(token), fetchImplementation
  }), token };
}

describe("HashiCorp Vault KV v2 provider", () => {
  it("fetches one exact version, binds the field, disables redirects, and zeroizes its token", async () => {
    let requested = "";
    let redirect: RequestRedirect | undefined;
    let header: string | null = null;
    const created = provider(vi.fn((url: URL | RequestInfo, init?: RequestInit) => {
      requested = url instanceof URL ? url.href : typeof url === "string" ? url : url.url;
      redirect = init?.redirect;
      header = new Headers(init?.headers).get("x-vault-token");
      return Promise.resolve(new Response(JSON.stringify({
        data: { data: { token: "downstream-secret-value" }, metadata: { version: 7 } }
      }), { status: 200 }));
    }));
    const result = await created.instance.fetchExactRevision({
      secretReference: "kv-v2://secret/downstream/calendar#token",
      credentialProfileId: "profile-calendar", credentialRevision: 7
    });
    expect(requested).toBe("http://127.0.0.1:8200/v1/secret/data/downstream/calendar?version=7");
    expect(redirect).toBe("manual");
    expect(header).toBe("dev-only-token");
    expect(result?.material.toString()).toBe("downstream-secret-value");
    expect([...created.token]).toEqual(new Array(created.token.length).fill(0));
  });

  it("fails closed on revision substitution, malformed references, plaintext remote origins, and redirects", async () => {
    const substituted = provider(vi.fn(() => Promise.resolve(new Response(JSON.stringify({
      data: { data: { token: "downstream-secret-value" }, metadata: { version: 8 } }
    }), { status: 200 })))).instance;
    await expect(substituted.fetchExactRevision({ secretReference: "kv-v2://secret/a#token",
      credentialProfileId: "profile", credentialRevision: 7 })).rejects.toThrow(/substituted/u);

    expect(() => new HashiCorpVaultKvV2ProviderV1({ descriptor,
      endpointOrigin: "http://vault.example.test", tokenProvider: () => Promise.resolve(Buffer.from("token-value"))
    })).toThrow(/HTTPS/u);
    await expect(provider(vi.fn(() => Promise.resolve(new Response(null, { status: 302 }))))
      .instance.fetchExactRevision({ secretReference: "kv-v2://secret/a#token",
        credentialProfileId: "profile", credentialRevision: 1 })).rejects.toThrow(/failed/u);
    await expect(provider(vi.fn()) .instance.fetchExactRevision({
      secretReference: "kv-v2://secret/../escape#token", credentialProfileId: "profile",
      credentialRevision: 1 })).rejects.toThrow(/invalid/u);
  });

  it("returns null for a missing version or field without exposing token material", async () => {
    const missingVersion = provider(vi.fn(() => Promise.resolve(new Response(null, { status: 404 }))));
    await expect(missingVersion.instance.fetchExactRevision({ secretReference: "kv-v2://secret/a#token",
      credentialProfileId: "profile", credentialRevision: 1 })).resolves.toBeNull();
    const missingField = provider(vi.fn(() => Promise.resolve(new Response(JSON.stringify({
      data: { data: { other: "value" }, metadata: { version: 1 } }
    }), { status: 200 }))));
    await expect(missingField.instance.fetchExactRevision({ secretReference: "kv-v2://secret/a#token",
      credentialProfileId: "profile", credentialRevision: 1 })).resolves.toBeNull();
  });
});
