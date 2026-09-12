import { randomUUID } from "node:crypto";
import { resolve } from "node:path";

import { Pool, type PoolClient } from "pg";
import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import {
  normalizeTlsCertificateFingerprintSha256V1,
  protectedClientCredentialRecordV1Schema,
  type ProtectedClientCredentialRecordV1,
  type ProtectedClientCredentialStoreV1
} from "../identity/protected-client-identity-v1.js";
import { runForwardMigrationsV1 } from "./migrations-v1.js";

const mutationContextV1Schema = z.object({
  actorId: identifierV1Schema,
  reasonCodes: z.array(z.string().trim().min(1).max(128)).max(32).default([]),
  occurredAt: utcTimestampV1Schema
}).strict();

export interface ProtectedIdentityMutationContextV1 {
  readonly actorId: string;
  readonly reasonCodes?: readonly string[];
  readonly occurredAt: string;
}

export interface ProtectedClientIdentityAuditEventV1 {
  readonly sequenceId: number;
  readonly eventId: string;
  readonly identityId: string;
  readonly revision: number;
  readonly eventType: "REGISTERED" | "ROTATED" | "REVOKED";
  readonly actorId: string;
  readonly reasonCodes: readonly string[];
  readonly evidenceDigest: string;
  readonly previousHash: string;
  readonly eventHash: string;
  readonly occurredAt: string;
}

export interface PostgresProtectedIdentityConfigV1 {
  readonly connectionString: string;
  readonly migrationsDirectory?: string;
  readonly applicationName?: string;
}

export class ProtectedIdentityPersistenceDeniedV1 extends Error {
  public constructor() {
    super("Protected client identity persistence operation denied");
    this.name = "ProtectedIdentityPersistenceDeniedV1";
  }
}

interface RevisionRowV1 {
  readonly identity_id: string;
  readonly revision: string;
  readonly record_document: unknown;
}

interface AuditRowV1 {
  readonly sequence_id: string;
  readonly event_id: string;
  readonly identity_id: string;
  readonly revision: string;
  readonly event_type: ProtectedClientIdentityAuditEventV1["eventType"];
  readonly actor_id: string;
  readonly reason_codes: string[];
  readonly evidence_digest: string;
  readonly previous_hash: string;
  readonly event_hash: string;
  readonly occurred_at: Date;
}

/** PostgreSQL-only protected identity registry. It never stores certificate bytes. */
export class PostgresProtectedClientIdentityStoreV1 implements ProtectedClientCredentialStoreV1 {
  readonly #pool: Pool;

  private constructor(pool: Pool) {
    this.#pool = pool;
  }

  public static async connect(config: PostgresProtectedIdentityConfigV1): Promise<PostgresProtectedClientIdentityStoreV1> {
    const connectionString = z.url().refine((value) => ["postgres:", "postgresql:"].includes(new URL(value).protocol)).parse(config.connectionString);
    const pool = new Pool({
      connectionString,
      application_name: config.applicationName ?? "agent-security-identity",
      connectionTimeoutMillis: 5_000,
      max: 10
    });
    try {
      await pool.query("SELECT 1");
      await runForwardMigrationsV1(pool, config.migrationsDirectory ?? resolve(process.cwd(), "migrations"));
      return new PostgresProtectedClientIdentityStoreV1(pool);
    } catch (error) {
      await pool.end().catch(() => undefined);
      throw error;
    }
  }

  public async close(): Promise<void> {
    await this.#pool.end();
  }

  public async resolveActiveCredential(
    fingerprintSha256: string,
    now: Date
  ): Promise<ProtectedClientCredentialRecordV1 | null> {
    const fingerprint = normalizeTlsCertificateFingerprintSha256V1(fingerprintSha256);
    if (Number.isNaN(now.getTime())) throw new TypeError("A valid lookup time is required");
    const selected = await this.#pool.query<{ record_document: unknown }>(
      `SELECT candidate.record_document
       FROM protected_client_identity_revisions candidate
       WHERE candidate.fingerprint_sha256 = $1
         AND candidate.status = 'ACTIVE'
         AND candidate.valid_from <= $2 AND candidate.valid_to > $2
         AND (candidate.record_document->>'activatedAt')::timestamptz <= $2
         AND NOT EXISTS (
           SELECT 1 FROM protected_client_identity_revisions newer
           WHERE newer.identity_id = candidate.identity_id AND newer.revision > candidate.revision
         )
       ORDER BY candidate.recorded_at DESC
       LIMIT 2`,
      [fingerprint, now.toISOString()]
    );
    if (selected.rows.length === 0) return null;
    if (selected.rows.length !== 1) throw new ProtectedIdentityPersistenceDeniedV1();
    return protectedClientCredentialRecordV1Schema.parse(selected.rows[0]?.record_document);
  }

  public async registerIdentity(
    recordInput: ProtectedClientCredentialRecordV1,
    contextInput: ProtectedIdentityMutationContextV1
  ): Promise<void> {
    const record = protectedClientCredentialRecordV1Schema.parse(recordInput);
    const context = mutationContextV1Schema.parse(contextInput);
    if (record.identityRevision !== 1 || record.status !== "ACTIVE" ||
      Date.parse(context.occurredAt) < Date.parse(record.activatedAt) ||
      Date.parse(context.occurredAt) >= Date.parse(record.validTo)) {
      throw new ProtectedIdentityPersistenceDeniedV1();
    }
    await this.#transaction(async (client) => {
      const identityId = identityIdFor(record);
      await this.#lock(client, identityId, record.fingerprintSha256);
      const existing = await client.query("SELECT 1 FROM protected_client_identity_revisions WHERE identity_id = $1 OR fingerprint_sha256 = $2 LIMIT 1", [identityId, record.fingerprintSha256]);
      if ((existing.rowCount ?? 0) !== 0) throw new ProtectedIdentityPersistenceDeniedV1();
      await this.#insertRevision(client, identityId, record);
      await this.#appendAudit(client, identityId, record, "REGISTERED", context);
    });
  }

  public async rotateCredential(input: {
    readonly currentFingerprintSha256: string;
    readonly replacement: ProtectedClientCredentialRecordV1;
    readonly context: ProtectedIdentityMutationContextV1;
  }): Promise<void> {
    const currentFingerprint = normalizeTlsCertificateFingerprintSha256V1(input.currentFingerprintSha256);
    const replacement = protectedClientCredentialRecordV1Schema.parse(input.replacement);
    const context = mutationContextV1Schema.parse(input.context);
    if (replacement.status !== "ACTIVE" || currentFingerprint === replacement.fingerprintSha256) {
      throw new ProtectedIdentityPersistenceDeniedV1();
    }
    await this.#transaction(async (client) => {
      const identityId = identityIdFor(replacement);
      await this.#lock(client, identityId, currentFingerprint, replacement.fingerprintSha256);
      const current = await this.#readCurrentForUpdate(client, identityId);
      const currentRecord = current === undefined ? undefined : protectedClientCredentialRecordV1Schema.parse(current.record_document);
      if (currentRecord === undefined || currentRecord.status !== "ACTIVE" ||
        currentRecord.fingerprintSha256 !== currentFingerprint ||
        replacement.identityRevision !== currentRecord.identityRevision + 1 ||
        Date.parse(context.occurredAt) < Date.parse(replacement.activatedAt) ||
        Date.parse(context.occurredAt) >= Date.parse(replacement.validTo)) {
        throw new ProtectedIdentityPersistenceDeniedV1();
      }
      const collision = await client.query(
        `SELECT 1 FROM protected_client_identity_revisions candidate
         WHERE candidate.fingerprint_sha256 = $1 AND candidate.identity_id <> $2
           AND NOT EXISTS (SELECT 1 FROM protected_client_identity_revisions newer
             WHERE newer.identity_id = candidate.identity_id AND newer.revision > candidate.revision)
         LIMIT 1`,
        [replacement.fingerprintSha256, identityId]
      );
      if ((collision.rowCount ?? 0) !== 0) throw new ProtectedIdentityPersistenceDeniedV1();
      await this.#insertRevision(client, identityId, replacement);
      await this.#appendAudit(client, identityId, replacement, "ROTATED", context);
    });
  }

  public async revokeCredential(input: {
    readonly fingerprintSha256: string;
    readonly context: ProtectedIdentityMutationContextV1;
  }): Promise<void> {
    const fingerprint = normalizeTlsCertificateFingerprintSha256V1(input.fingerprintSha256);
    const context = mutationContextV1Schema.parse(input.context);
    await this.#transaction(async (client) => {
      await this.#lock(client, fingerprint);
      const selected = await client.query<RevisionRowV1>(
        `SELECT candidate.identity_id, candidate.revision, candidate.record_document
         FROM protected_client_identity_revisions candidate
         WHERE candidate.fingerprint_sha256 = $1
           AND NOT EXISTS (SELECT 1 FROM protected_client_identity_revisions newer
             WHERE newer.identity_id = candidate.identity_id AND newer.revision > candidate.revision)
         FOR UPDATE OF candidate`,
        [fingerprint]
      );
      if (selected.rows.length !== 1) throw new ProtectedIdentityPersistenceDeniedV1();
      const current = selected.rows[0];
      if (current === undefined) throw new ProtectedIdentityPersistenceDeniedV1();
      const record = protectedClientCredentialRecordV1Schema.parse(current.record_document);
      if (record.status !== "ACTIVE" ||
        Date.parse(context.occurredAt) < Date.parse(record.activatedAt) ||
        Date.parse(context.occurredAt) >= Date.parse(record.validTo)) {
        throw new ProtectedIdentityPersistenceDeniedV1();
      }
      const revoked = protectedClientCredentialRecordV1Schema.parse({
        ...record,
        identityRevision: Number(current.revision) + 1,
        status: "REVOKED",
        revokedAt: context.occurredAt
      });
      await this.#insertRevision(client, current.identity_id, revoked);
      await this.#appendAudit(client, current.identity_id, revoked, "REVOKED", context);
    });
  }

  public async readAuditEvents(): Promise<readonly ProtectedClientIdentityAuditEventV1[]> {
    const result = await this.#pool.query<AuditRowV1>("SELECT * FROM protected_client_identity_audit_events ORDER BY sequence_id");
    return result.rows.map((row) => ({
      sequenceId: Number(row.sequence_id), eventId: row.event_id, identityId: row.identity_id,
      revision: Number(row.revision), eventType: row.event_type, actorId: row.actor_id,
      reasonCodes: row.reason_codes, evidenceDigest: row.evidence_digest,
      previousHash: row.previous_hash, eventHash: row.event_hash,
      occurredAt: row.occurred_at.toISOString()
    }));
  }

  public async verifyAuditChain(): Promise<boolean> {
    const events = await this.readAuditEvents();
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

  async #readCurrentForUpdate(client: PoolClient, identityId: string): Promise<RevisionRowV1 | undefined> {
    const selected = await client.query<RevisionRowV1>(
      "SELECT identity_id, revision, record_document FROM protected_client_identity_revisions WHERE identity_id = $1 ORDER BY revision DESC LIMIT 1 FOR UPDATE",
      [identityId]
    );
    return selected.rows[0];
  }

  async #insertRevision(client: PoolClient, identityId: string, record: ProtectedClientCredentialRecordV1): Promise<void> {
    await client.query(
      `INSERT INTO protected_client_identity_revisions(identity_id, revision, user_id, agent_id,
        client_id, host_id, credential_id, fingerprint_sha256, status, valid_from, valid_to, record_document)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`,
      [identityId, record.identityRevision, record.userId, record.agentId, record.clientId,
        record.host.hostId, record.credentialId, record.fingerprintSha256,
        record.status, record.validFrom, record.validTo,
        JSON.stringify(record)]
    );
  }

  async #appendAudit(
    client: PoolClient,
    identityId: string,
    record: ProtectedClientCredentialRecordV1,
    eventType: ProtectedClientIdentityAuditEventV1["eventType"],
    context: z.infer<typeof mutationContextV1Schema>
  ): Promise<void> {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('protected-identity:audit-chain'))");
    const latest = await client.query<{ event_hash: string }>(
      "SELECT event_hash FROM protected_client_identity_audit_events ORDER BY sequence_id DESC LIMIT 1"
    );
    const previousHash = latest.rows[0]?.event_hash ?? "0".repeat(64);
    const eventId = randomUUID();
    const evidenceDigest = computeCanonicalDigestV1({ identityId, record, eventType, context });
    const hashInput = {
      eventId, identityId, revision: record.identityRevision, eventType,
      actorId: context.actorId, reasonCodes: context.reasonCodes,
      evidenceDigest, previousHash, occurredAt: context.occurredAt
    };
    const eventHash = computeCanonicalDigestV1(hashInput);
    await client.query(
      `INSERT INTO protected_client_identity_audit_events(event_id, identity_id, revision,
        event_type, actor_id, reason_codes, evidence_digest, previous_hash, event_hash, occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [eventId, identityId, record.identityRevision, eventType, context.actorId,
        context.reasonCodes, evidenceDigest, previousHash, eventHash, context.occurredAt]
    );
  }

  async #lock(client: PoolClient, ...keys: readonly string[]): Promise<void> {
    for (const key of [...keys].sort()) {
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`protected-identity:${key}`]);
    }
  }

  async #transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const value = await operation(client);
      await client.query("COMMIT");
      return value;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (error instanceof ProtectedIdentityPersistenceDeniedV1) throw error;
      throw new ProtectedIdentityPersistenceDeniedV1();
    } finally {
      client.release();
    }
  }
}

function identityIdFor(record: ProtectedClientCredentialRecordV1): string {
  return `identity:${computeCanonicalDigestV1({
    userId: record.userId, agentId: record.agentId, clientId: record.clientId, hostId: record.host.hostId
  })}`;
}
