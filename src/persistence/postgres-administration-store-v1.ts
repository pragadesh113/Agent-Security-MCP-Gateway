import { randomUUID } from "node:crypto";
import { resolve } from "node:path";

import { Pool, type PoolClient } from "pg";
import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { boundedProtocolJsonObjectV1Schema } from "../contracts/boundary-v1.js";
import { downstreamServerV1Schema, identifierV1Schema, toolRouteV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import { authenticatedClientPrincipalV1Schema, type AuthenticatedClientPrincipalV1 } from "../identity/client-authentication-v1.js";
import { deterministicPolicyRuleV1Schema } from "../policy-engine/deterministic-policy-v1.js";
import { runForwardMigrationsV1 } from "./migrations-v1.js";

const digestV1Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const kindV1Schema = z.enum(["SERVER", "ROUTE", "SCHEMA", "POLICY"]);

const schemaDocumentV1Schema = z.object({
  schemaDigest: digestV1Schema,
  inputSchema: boundedProtocolJsonObjectV1Schema,
  outputSchema: boundedProtocolJsonObjectV1Schema.nullable()
}).strict();

const policyDocumentV1Schema = z.object({
  policyVersion: z.string().trim().min(1).max(64),
  rules: z.array(deterministicPolicyRuleV1Schema).max(1_000)
}).strict();

const common = {
  schemaVersion: z.literal("1.0.0"),
  resourceId: identifierV1Schema,
  version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  createdAt: utcTimestampV1Schema
};

export const protectedAdministrationRecordV1Schema = z.discriminatedUnion("kind", [
  z.object({ ...common, kind: z.literal("SERVER"), document: downstreamServerV1Schema }).strict(),
  z.object({ ...common, kind: z.literal("ROUTE"), document: toolRouteV1Schema }).strict(),
  z.object({ ...common, kind: z.literal("SCHEMA"), document: schemaDocumentV1Schema }).strict(),
  z.object({ ...common, kind: z.literal("POLICY"), document: policyDocumentV1Schema }).strict()
]).superRefine((record, context) => {
  const documentId = record.kind === "SERVER" ? record.document.serverId
    : record.kind === "ROUTE" ? record.document.routeId
      : record.kind === "SCHEMA" ? record.document.schemaDigest
        : record.document.policyVersion;
  if (record.resourceId !== documentId) {
    context.addIssue({ code: "custom", path: ["resourceId"], message: "Resource identifier does not match its document" });
  }
});

export type ProtectedAdministrationRecordV1 = z.infer<typeof protectedAdministrationRecordV1Schema>;
export type ProtectedAdministrationKindV1 = z.infer<typeof kindV1Schema>;

export interface ProtectedAdministrationAuditEventV1 {
  readonly sequenceId: number;
  readonly eventId: string;
  readonly resourceId: string;
  readonly kind: ProtectedAdministrationKindV1;
  readonly version: number;
  readonly eventType: "CREATED" | "VERSION_APPENDED";
  readonly actorIdentityDigest: string;
  readonly evidenceDigest: string;
  readonly previousHash: string;
  readonly eventHash: string;
  readonly occurredAt: string;
}

export type ProtectedAdministratorAuthorizerV1 = (
  principal: AuthenticatedClientPrincipalV1
) => boolean | Promise<boolean>;

export interface PostgresProtectedAdministrationConfigV1 {
  readonly connectionString: string;
  readonly administratorAuthorizer: ProtectedAdministratorAuthorizerV1;
  readonly migrationsDirectory?: string;
  readonly applicationName?: string;
}

export class ProtectedAdministrationDeniedV1 extends Error {
  public constructor() {
    super("Protected administration operation denied");
    this.name = "ProtectedAdministrationDeniedV1";
  }
}

interface VersionRowV1 { readonly document: unknown; }
interface AuditRowV1 {
  readonly sequence_id: string;
  readonly event_id: string;
  readonly resource_id: string;
  readonly resource_kind: ProtectedAdministrationKindV1;
  readonly version: string;
  readonly event_type: ProtectedAdministrationAuditEventV1["eventType"];
  readonly actor_identity_digest: string;
  readonly evidence_digest: string;
  readonly previous_hash: string;
  readonly event_hash: string;
  readonly occurred_at: Date;
}

/** Durable append-only administration boundary for protected configuration. */
export class PostgresProtectedAdministrationStoreV1 {
  readonly #pool: Pool;
  readonly #authorizer: ProtectedAdministratorAuthorizerV1;

  private constructor(pool: Pool, authorizer: ProtectedAdministratorAuthorizerV1) {
    this.#pool = pool;
    this.#authorizer = authorizer;
  }

  public static async connect(config: PostgresProtectedAdministrationConfigV1): Promise<PostgresProtectedAdministrationStoreV1> {
    if (typeof config.administratorAuthorizer !== "function") throw new TypeError("An administrator authorizer is required");
    const connectionString = z.url().refine((value) => ["postgres:", "postgresql:"].includes(new URL(value).protocol)).parse(config.connectionString);
    const pool = new Pool({ connectionString, application_name: config.applicationName ?? "agent-security-administration", connectionTimeoutMillis: 5_000, max: 10 });
    try {
      await pool.query("SELECT 1");
      await runForwardMigrationsV1(pool, config.migrationsDirectory ?? resolve(process.cwd(), "migrations"));
      return new PostgresProtectedAdministrationStoreV1(pool, config.administratorAuthorizer);
    } catch (error) {
      await pool.end().catch(() => undefined);
      throw error;
    }
  }

  public async close(): Promise<void> { await this.#pool.end(); }

  public async appendVersion(input: {
    readonly principal: AuthenticatedClientPrincipalV1;
    readonly record: ProtectedAdministrationRecordV1;
  }): Promise<void> {
    const principal = authenticatedClientPrincipalV1Schema.parse(input.principal);
    const record = protectedAdministrationRecordV1Schema.parse(input.record);
    await this.#authorizePrincipal(principal);
    const actorIdentityDigest = computeCanonicalDigestV1(principal);
    await this.#transaction(async (client) => {
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`protected-admin:${record.resourceId}`]);
      await client.query(
        `INSERT INTO protected_admin_resources(resource_id, resource_kind, created_at)
         VALUES ($1,$2,$3) ON CONFLICT (resource_id) DO NOTHING`,
        [record.resourceId, record.kind, record.createdAt]
      );
      const resource = await client.query<{ resource_kind: string }>(
        "SELECT resource_kind FROM protected_admin_resources WHERE resource_id = $1 FOR UPDATE",
        [record.resourceId]
      );
      if (resource.rows[0]?.resource_kind !== record.kind) throw new ProtectedAdministrationDeniedV1();
      const current = await client.query<{ version: string }>(
        "SELECT version FROM protected_admin_versions WHERE resource_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE",
        [record.resourceId]
      );
      const expectedVersion = current.rows[0] === undefined ? 1 : Number(current.rows[0].version) + 1;
      if (record.version !== expectedVersion) throw new ProtectedAdministrationDeniedV1();
      const documentDigest = computeCanonicalDigestV1(record);
      await client.query(
        `INSERT INTO protected_admin_versions(resource_id, resource_kind, version, document,
          document_digest, created_at, created_by_identity_digest)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7)`,
        [record.resourceId, record.kind, record.version, JSON.stringify(record), documentDigest,
          record.createdAt, actorIdentityDigest]
      );
      const eventType = record.version === 1 ? "CREATED" : "VERSION_APPENDED";
      await client.query("SELECT pg_advisory_xact_lock(hashtext('protected-admin:audit-chain'))");
      const latest = await client.query<{ event_hash: string }>(
        "SELECT event_hash FROM protected_admin_audit_events ORDER BY sequence_id DESC LIMIT 1"
      );
      const previousHash = latest.rows[0]?.event_hash ?? "0".repeat(64);
      const eventId = randomUUID();
      const evidenceDigest = computeCanonicalDigestV1({ record, actorIdentityDigest, eventType });
      const eventHash = computeCanonicalDigestV1({
        eventId, resourceId: record.resourceId, kind: record.kind, version: record.version,
        eventType, actorIdentityDigest, evidenceDigest, previousHash, occurredAt: record.createdAt
      });
      await client.query(
        `INSERT INTO protected_admin_audit_events(event_id, resource_id, resource_kind, version,
          actor_identity_digest, event_type, evidence_digest, previous_hash, event_hash, occurred_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [eventId, record.resourceId, record.kind, record.version, actorIdentityDigest,
          eventType, evidenceDigest, previousHash, eventHash, record.createdAt]
      );
    });
  }

  public async readCurrent(
    principalInput: AuthenticatedClientPrincipalV1,
    kindInput: ProtectedAdministrationKindV1,
    resourceIdInput: string
  ): Promise<ProtectedAdministrationRecordV1 | null> {
    const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
    await this.#authorizePrincipal(principal);
    const kind = kindV1Schema.parse(kindInput);
    const resourceId = identifierV1Schema.parse(resourceIdInput);
    const selected = await this.#pool.query<VersionRowV1>(
      `SELECT document FROM protected_admin_versions
       WHERE resource_id = $1 AND resource_kind = $2 ORDER BY version DESC LIMIT 1`,
      [resourceId, kind]
    );
    if (selected.rows[0] === undefined) return null;
    const record = protectedAdministrationRecordV1Schema.parse(selected.rows[0].document);
    if (record.kind !== kind || record.resourceId !== resourceId) throw new ProtectedAdministrationDeniedV1();
    return record;
  }

  public async readAuditEvents(
    principalInput: AuthenticatedClientPrincipalV1,
    resourceIdInput?: string
  ): Promise<readonly ProtectedAdministrationAuditEventV1[]> {
    const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
    await this.#authorizePrincipal(principal);
    const resourceId = resourceIdInput === undefined ? undefined : identifierV1Schema.parse(resourceIdInput);
    const selected = resourceId === undefined
      ? await this.#pool.query<AuditRowV1>("SELECT * FROM protected_admin_audit_events ORDER BY sequence_id")
      : await this.#pool.query<AuditRowV1>("SELECT * FROM protected_admin_audit_events WHERE resource_id = $1 ORDER BY sequence_id", [resourceId]);
    return selected.rows.map((row) => ({
      sequenceId: Number(row.sequence_id), eventId: row.event_id, resourceId: row.resource_id,
      kind: row.resource_kind, version: Number(row.version), eventType: row.event_type,
      actorIdentityDigest: row.actor_identity_digest, evidenceDigest: row.evidence_digest,
      previousHash: row.previous_hash, eventHash: row.event_hash,
      occurredAt: row.occurred_at.toISOString()
    }));
  }

  public async verifyAuditChain(principalInput: AuthenticatedClientPrincipalV1): Promise<boolean> {
    const events = await this.readAuditEvents(principalInput);
    let previousHash = "0".repeat(64);
    for (const event of events) {
      const { sequenceId: _sequenceId, eventHash, ...hashInput } = event;
      void _sequenceId;
      if (event.previousHash !== previousHash || computeCanonicalDigestV1(hashInput) !== eventHash) {
        return false;
      }
      previousHash = eventHash;
    }
    return true;
  }

  async #authorizePrincipal(principal: AuthenticatedClientPrincipalV1): Promise<void> {
    let authorized = false;
    try { authorized = await this.#authorizer(principal); } catch { throw new ProtectedAdministrationDeniedV1(); }
    if (!authorized) throw new ProtectedAdministrationDeniedV1();
  }

  async #transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (error instanceof ProtectedAdministrationDeniedV1) throw error;
      throw new ProtectedAdministrationDeniedV1();
    } finally { client.release(); }
  }
}
