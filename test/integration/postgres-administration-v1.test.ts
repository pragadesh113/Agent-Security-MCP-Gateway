import { createServer as createNetServer } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import EmbeddedPostgres from "embedded-postgres";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { AuthenticatedClientPrincipalV1 } from "../../src/identity/client-authentication-v1.js";
import {
  PostgresProtectedAdministrationStoreV1,
  ProtectedAdministrationDeniedV1,
  type ProtectedAdministrationRecordV1
} from "../../src/persistence/postgres-administration-store-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

let postgres: EmbeddedPostgres;
let store: PostgresProtectedAdministrationStoreV1;
let deniedStore: PostgresProtectedAdministrationStoreV1;
let connectionString: string;

async function availablePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { resolve(); });
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => server.close((error) => {
    if (error === undefined) resolve(); else reject(error);
  }));
  if (address === null || typeof address === "string") throw new Error("Port allocation failed");
  return address.port;
}

const now = new Date("2026-09-11T09:00:00.000Z");
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0", userId: "admin-user", agentId: "admin-agent", clientId: "admin-client",
  host: { hostId: "admin-host", name: "Admin host", version: "1.0.0" },
  authentication: {
    method: "MUTUAL_TLS", credentialId: "admin-certificate", identityRevision: 3,
    authenticatedAt: now.toISOString()
  }
};

function schemaRecord(version: number): ProtectedAdministrationRecordV1 {
  return {
    schemaVersion: "1.0.0", kind: "SCHEMA", resourceId: "a".repeat(64), version,
    createdAt: new Date(now.getTime() + version * 1_000).toISOString(),
    document: {
      schemaDigest: "a".repeat(64),
      inputSchema: { type: "object", properties: { revision: { const: version } } },
      outputSchema: null
    }
  };
}

beforeAll(async () => {
  const port = await availablePort();
  postgres = new EmbeddedPostgres({
    databaseDir: await mkdtemp(join(tmpdir(), "agent-security-admin-")),
    user: "postgres", password: "disposable-admin-password", port, persistent: false,
    onLog: () => undefined, onError: () => undefined
  });
  await postgres.initialise();
  await postgres.start();
  connectionString = `postgresql://postgres:disposable-admin-password@127.0.0.1:${String(port)}/postgres`;
  store = await PostgresProtectedAdministrationStoreV1.connect({
    connectionString, administratorAuthorizer: (candidate) => Promise.resolve(candidate.userId === "admin-user")
  });
  deniedStore = await PostgresProtectedAdministrationStoreV1.connect({
    connectionString, administratorAuthorizer: () => Promise.resolve(false)
  });
}, 30_000);

afterAll(async () => {
  await deniedStore.close();
  await store.close();
  await postgres.stop();
}, 30_000);

describe("PostgreSQL protected administration", () => {
  it("appends monotonically versioned documents and immutable audit records", async () => {
    await store.appendVersion({ principal, record: schemaRecord(1) });
    await store.appendVersion({ principal, record: schemaRecord(2) });
    expect(await store.readCurrent(principal, "SCHEMA", "a".repeat(64))).toMatchObject({ version: 2, kind: "SCHEMA" });
    expect((await store.readAuditEvents(principal, "a".repeat(64))).map((event) => event.eventType))
      .toEqual(["CREATED", "VERSION_APPENDED"]);
    expect(await store.verifyAuditChain(principal)).toBe(true);

    const client = new Client({ connectionString });
    await client.connect();
    try {
      await expect(client.query("DELETE FROM protected_admin_versions WHERE resource_id = $1", ["a".repeat(64)]))
        .rejects.toThrow("append-only");
      await expect(client.query("UPDATE protected_admin_audit_events SET event_type = 'CREATED'"))
        .rejects.toThrow("append-only");
    } finally { await client.end(); }
  });

  it("rejects stale concurrent versions, cross-kind substitution, and authorization failure", async () => {
    const attempts = await Promise.allSettled([
      store.appendVersion({ principal, record: schemaRecord(3) }),
      store.appendVersion({ principal, record: schemaRecord(3) })
    ]);
    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(1);
    await expect(store.appendVersion({ principal, record: schemaRecord(2) }))
      .rejects.toBeInstanceOf(ProtectedAdministrationDeniedV1);
    const fixture = createPostgresTrajectoryFixtureV1("admin-kind", now);
    await expect(store.appendVersion({
      principal,
      record: {
        schemaVersion: "1.0.0", kind: "SERVER", resourceId: "a".repeat(64), version: 4,
        createdAt: now.toISOString(), document: { ...fixture.binding.server, serverId: "a".repeat(64) }
      }
    })).rejects.toThrow();
    await expect(deniedStore.appendVersion({ principal, record: {
      ...schemaRecord(4), resourceId: "b".repeat(64),
      document: { ...schemaRecord(4).document, schemaDigest: "b".repeat(64) }
    } as ProtectedAdministrationRecordV1 })).rejects.toBeInstanceOf(ProtectedAdministrationDeniedV1);
    await expect(deniedStore.readCurrent(principal, "SCHEMA", "a".repeat(64)))
      .rejects.toBeInstanceOf(ProtectedAdministrationDeniedV1);
    await expect(deniedStore.readAuditEvents(principal))
      .rejects.toBeInstanceOf(ProtectedAdministrationDeniedV1);
  });

  it("accepts strict SERVER, ROUTE, and POLICY documents and rejects malformed substitution", async () => {
    const fixture = createPostgresTrajectoryFixtureV1("admin-types", now);
    const records: ProtectedAdministrationRecordV1[] = [
      { schemaVersion: "1.0.0", kind: "SERVER", resourceId: fixture.binding.server.serverId, version: 1, createdAt: now.toISOString(), document: fixture.binding.server },
      { schemaVersion: "1.0.0", kind: "ROUTE", resourceId: fixture.binding.route.routeId, version: 1, createdAt: now.toISOString(), document: fixture.binding.route },
      { schemaVersion: "1.0.0", kind: "POLICY", resourceId: "policy-admin", version: 1, createdAt: now.toISOString(), document: { policyVersion: "policy-admin", rules: [] } }
    ];
    for (const record of records) await store.appendVersion({ principal, record });
    expect(await store.readCurrent(principal, "SERVER", fixture.binding.server.serverId)).toMatchObject({ kind: "SERVER" });
    expect(await store.readCurrent(principal, "ROUTE", fixture.binding.route.routeId)).toMatchObject({ kind: "ROUTE" });
    expect(await store.readCurrent(principal, "POLICY", "policy-admin")).toMatchObject({ kind: "POLICY" });
    await expect(store.appendVersion({ principal, record: {
      schemaVersion: "1.0.0", kind: "POLICY", resourceId: "policy-malformed", version: 1,
      createdAt: now.toISOString(), document: fixture.binding.server
    } as unknown as ProtectedAdministrationRecordV1 })).rejects.toThrow();
  });

  it("detects privileged database tampering in the serialized audit chain", async () => {
    expect(await store.verifyAuditChain(principal)).toBe(true);
    const client = new Client({ connectionString });
    await client.connect();
    try {
      await client.query("ALTER TABLE protected_admin_audit_events DISABLE TRIGGER protected_admin_audit_append_only");
      await client.query("UPDATE protected_admin_audit_events SET evidence_digest = $1 WHERE sequence_id = (SELECT min(sequence_id) FROM protected_admin_audit_events)", ["f".repeat(64)]);
      await client.query("ALTER TABLE protected_admin_audit_events ENABLE TRIGGER protected_admin_audit_append_only");
    } finally { await client.end(); }
    expect(await store.verifyAuditChain(principal)).toBe(false);
  });
});
