import { createServer as createNetServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import EmbeddedPostgres from "embedded-postgres";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { ProtectedClientCredentialRecordV1 } from "../../src/identity/protected-client-identity-v1.js";
import {
  PostgresProtectedClientIdentityStoreV1,
  ProtectedIdentityPersistenceDeniedV1
} from "../../src/persistence/postgres-identity-store-v1.js";

let postgres: EmbeddedPostgres;
let store: PostgresProtectedClientIdentityStoreV1;
let connectionString: string;

async function availablePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { resolve(); });
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => server.close((error) => {
    if (error === undefined) resolve();
    else reject(error);
  }));
  if (address === null || typeof address === "string") throw new Error("Port allocation failed");
  return address.port;
}

const at = (minute: number): string => new Date(Date.UTC(2026, 8, 11, 8, minute)).toISOString();

function record(
  fingerprint: string,
  revision = 1,
  subject = fingerprint.slice(0, 8)
): ProtectedClientCredentialRecordV1 {
  return {
    schemaVersion: "1.0.0",
    fingerprintSha256: fingerprint,
    credentialId: `credential-${String(revision)}`,
    identityRevision: revision,
    status: "ACTIVE",
    userId: `user-${subject}`,
    agentId: `agent-${subject}`,
    clientId: `client-${subject}`,
    host: { hostId: `host-${subject}`, name: "Disposable host", version: "1.0.0" },
    validFrom: at(0),
    validTo: at(59),
    activatedAt: at(revision),
    revokedAt: null
  };
}

beforeAll(async () => {
  const port = await availablePort();
  postgres = new EmbeddedPostgres({
    databaseDir: await mkdtemp(join(tmpdir(), "agent-security-identity-")),
    user: "postgres", password: "disposable-identity-password", port,
    persistent: false, onLog: () => undefined, onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  connectionString = `postgresql://postgres:disposable-identity-password@127.0.0.1:${String(port)}/postgres`;
  store = await PostgresProtectedClientIdentityStoreV1.connect({ connectionString });
}, 30_000);

afterAll(async () => {
  await store.close();
  await postgres.stop();
}, 30_000);

describe("PostgreSQL protected client identity registry", () => {
  it("resolves an active certificate by normalized SHA-256 fingerprint", async () => {
    const fingerprint = "a1".repeat(32);
    await store.registerIdentity(record(fingerprint), {
      actorId: "identity-admin", occurredAt: at(2), reasonCodes: ["identity.registered"]
    });
    const colonFingerprint = fingerprint.match(/.{2}/gu)?.join(":").toUpperCase();
    expect(await store.resolveActiveCredential(colonFingerprint ?? fingerprint, new Date(at(3))))
      .toMatchObject({ fingerprintSha256: fingerprint, identityRevision: 1, status: "ACTIVE" });
    expect(await store.resolveActiveCredential(fingerprint, new Date(at(59)))).toBeNull();
  });

  it("rotates atomically and makes the prior fingerprint inactive", async () => {
    const original = "b2".repeat(32);
    const replacement = "c3".repeat(32);
    await store.registerIdentity(record(original, 1, "rotation"), { actorId: "identity-admin", occurredAt: at(2) });
    const peer = await PostgresProtectedClientIdentityStoreV1.connect({ connectionString });
    const attempts = await Promise.allSettled([
      store.rotateCredential({
        currentFingerprintSha256: original,
        replacement: record(replacement, 2, "rotation"),
        context: { actorId: "identity-admin", occurredAt: at(3), reasonCodes: ["identity.rotated"] }
      }),
      peer.rotateCredential({
        currentFingerprintSha256: original,
        replacement: record("d4".repeat(32), 2, "rotation"),
        context: { actorId: "identity-admin", occurredAt: at(3), reasonCodes: ["identity.rotated"] }
      })
    ]);
    await peer.close();
    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(1);
    expect(await store.resolveActiveCredential(original, new Date(at(4)))).toBeNull();
    const winner = attempts[0].status === "fulfilled" ? replacement : "d4".repeat(32);
    expect(await store.resolveActiveCredential(winner, new Date(at(4))))
      .toMatchObject({ identityRevision: 2, status: "ACTIVE" });
  });

  it("revokes atomically, rejects replay, and keeps revisions and audit append-only", async () => {
    const fingerprint = "e5".repeat(32);
    await store.registerIdentity(record(fingerprint), { actorId: "identity-admin", occurredAt: at(2) });
    await store.revokeCredential({
      fingerprintSha256: fingerprint,
      context: { actorId: "identity-admin", occurredAt: at(4), reasonCodes: ["identity.revoked"] }
    });
    expect(await store.resolveActiveCredential(fingerprint, new Date(at(5)))).toBeNull();
    await expect(store.revokeCredential({
      fingerprintSha256: fingerprint,
      context: { actorId: "identity-admin", occurredAt: at(5) }
    })).rejects.toBeInstanceOf(ProtectedIdentityPersistenceDeniedV1);

    const audit = await store.readAuditEvents();
    expect(audit.slice(-2).map((event) => event.eventType)).toEqual(["REGISTERED", "REVOKED"]);
    expect(await store.verifyAuditChain()).toBe(true);
    const client = new Client({ connectionString });
    await client.connect();
    try {
      await expect(client.query("DELETE FROM protected_client_identity_revisions WHERE fingerprint_sha256 = $1", [fingerprint])).rejects.toThrow("append-only");
      await expect(client.query("UPDATE protected_client_identity_audit_events SET actor_id = 'attacker'")).rejects.toThrow("append-only");
    } finally {
      await client.end();
    }
  });

  it("detects privileged database tampering in the serialized identity audit chain", async () => {
    expect(await store.verifyAuditChain()).toBe(true);
    const client = new Client({ connectionString });
    await client.connect();
    try {
      await client.query("ALTER TABLE protected_client_identity_audit_events DISABLE TRIGGER protected_client_identity_audit_append_only");
      await client.query("UPDATE protected_client_identity_audit_events SET actor_id = 'tampered-actor' WHERE sequence_id = (SELECT min(sequence_id) FROM protected_client_identity_audit_events)");
      await client.query("ALTER TABLE protected_client_identity_audit_events ENABLE TRIGGER protected_client_identity_audit_append_only");
    } finally {
      await client.end();
    }
    expect(await store.verifyAuditChain()).toBe(false);
  });
});
