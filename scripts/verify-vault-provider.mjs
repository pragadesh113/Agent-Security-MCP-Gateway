import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

import {
  HashiCorpVaultKvV2ProviderV1,
  ProtectedCredentialBrokerV1,
  bindAuthenticatedIdentityToSessionV1,
  computeCanonicalDigestV1
} from "../dist/src/index.js";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing disposable Vault setting: ${name}`);
  return value;
}

const vaultOrigin = required("VAULT_ADDR");
const vaultToken = required("VAULT_TOKEN");
const downstreamSecret = randomBytes(24).toString("base64url");
const secretReference = "kv-v2://secret/agent-security/downstream#token";

const seedResponse = await fetch(`${vaultOrigin}/v1/secret/data/agent-security/downstream`, {
  method: "POST",
  redirect: "manual",
  headers: { "Content-Type": "application/json", "X-Vault-Token": vaultToken },
  body: JSON.stringify({ data: { token: downstreamSecret } })
});
if (!seedResponse.ok) throw new Error(`Disposable Vault seed failed with ${seedResponse.status}`);
const seedBody = await seedResponse.json();
const revision = seedBody?.data?.version;
if (!Number.isSafeInteger(revision) || revision <= 0) {
  throw new Error("Disposable Vault did not return an exact KV v2 revision");
}

let authorizationObserved = false;
const downstream = createServer((request, response) => {
  authorizationObserved = request.headers.authorization === `Bearer ${downstreamSecret}`;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { verified: authorizationObserved } }));
});
await new Promise((resolve) => downstream.listen(0, "127.0.0.1", resolve));
const address = downstream.address();
if (address === null || typeof address === "string") throw new Error("Disposable downstream did not bind");
const downstreamOrigin = `http://127.0.0.1:${String(address.port)}`;

try {
  const descriptor = {
    schemaVersion: "1.0.0",
    providerId: "hashicorp-vault-disposable",
    providerType: "HASHICORP_VAULT",
    approval: {
      status: "APPROVED",
      approvedBy: "project-owner",
      approvedAt: new Date().toISOString(),
      configurationDigest: computeCanonicalDigestV1({ vaultOrigin, mode: "DISPOSABLE_DEV" })
    }
  };
  const provider = new HashiCorpVaultKvV2ProviderV1({
    descriptor,
    endpointOrigin: vaultOrigin,
    allowInsecureLoopbackForDisposableTests: true,
    tokenProvider: () => Promise.resolve(Buffer.from(vaultToken, "utf8"))
  });
  const now = new Date();
  const broker = new ProtectedCredentialBrokerV1({
    secretManager: provider,
    bindings: [{
      schemaVersion: "1.0.0",
      secretManagerProviderId: descriptor.providerId,
      secretReference,
      profile: {
        schemaVersion: "1.0.0",
        credentialProfileId: "profile-vault-disposable",
        credentialRevision: revision,
        credentialKind: "BEARER_TOKEN",
        audienceId: "audience-vault-disposable",
        allowedRouteIds: ["route-vault-disposable"],
        allowedEndpointOrigins: [downstreamOrigin],
        materialDigest: createHash("sha256").update(downstreamSecret).digest("hex"),
        status: "ACTIVE",
        issuedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString()
      }
    }],
    clock: () => now,
    leaseIdFactory: () => "lease-vault-disposable"
  });
  const session = bindAuthenticatedIdentityToSessionV1({
    schemaVersion: "1.0.0",
    userId: "user-vault-disposable",
    agentId: "agent-vault-disposable",
    clientId: "client-vault-disposable",
    host: { hostId: "host-vault-disposable", name: "Disposable Vault verifier", version: "1.0.0" },
    authentication: { method: "MUTUAL_TLS", credentialId: "credential-vault-disposable",
      identityRevision: 1, authenticatedAt: now.toISOString() }
  }, "transport-vault-disposable");
  const authorization = { approvalId: "approval-vault-disposable", actionHash: "b".repeat(64),
    forwardingAttemptId: "forward-vault-disposable" };
  const lease = broker.issueLease(session, { credentialProfileId: "profile-vault-disposable",
    audienceId: "audience-vault-disposable", routeId: "route-vault-disposable",
    endpointOrigin: downstreamOrigin, ...authorization });
  const result = await broker.sendMcpJsonWithLease(session, {
    leaseId: lease.leaseId, credentialProfileId: lease.credentialProfileId,
    credentialRevision: revision, audienceId: lease.audienceId, routeId: lease.routeId,
    ...authorization, endpoint: `${downstreamOrigin}/mcp`, body: Buffer.from("{}"),
    maxResponseBytes: 4_096
  });
  const parsed = JSON.parse(new TextDecoder().decode(result.body));
  if (!authorizationObserved || parsed?.result?.verified !== true) {
    throw new Error("Vault credential did not reach the exact disposable downstream request");
  }
  console.log(JSON.stringify({ provider: "HashiCorp Vault", mode: "DISPOSABLE_DEV",
    secretRevision: revision, brokerLeaseExposedMaterial: false, downstreamAuthorized: true }));
} finally {
  await new Promise((resolve, reject) => downstream.close((error) => error ? reject(error) : resolve()));
}
