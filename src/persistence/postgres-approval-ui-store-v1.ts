import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";

import { Pool, type PoolClient } from "pg";
import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import {
  approvalV1Schema,
  canonicalActionV1Schema,
  executionOutcomeV1Schema,
  type ApprovalV1,
  type ExecutionOutcomeV1
} from "../contracts/trajectory-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";
import {
  trustworthyActionInterfaceV1Schema
} from "../interfaces/trustworthy-interface-v1.js";
import {
  ApprovalWebStaleDecisionV1,
  approvalWebHumanPrincipalV1Schema,
  approvalWebRecordV1Schema,
  approvalWebSessionV1Schema,
  type ApprovalWebRecordV1,
  type ApprovalWebSessionV1,
  type ApprovalWebStoreV1
} from "../interfaces/approval-web-v1.js";
import { runForwardMigrationsV1 } from "./migrations-v1.js";

const digestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const opaqueTokenSchema = z.string().min(32).max(256).regex(/^[A-Za-z0-9_-]+$/u);

export const authenticatedApprovalHumanV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  humanId: identifierV1Schema,
  credentialId: identifierV1Schema,
  authenticationMethod: z.enum(["MUTUAL_TLS", "OIDC", "WEBAUTHN"]),
  authenticationRevision: z.number().int().positive(),
  authenticatedAt: utcTimestampV1Schema
}).strict();

export const approvalUiAdministratorV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  administratorId: identifierV1Schema,
  authenticatedAt: utcTimestampV1Schema
}).strict();

export const approvalUiBrowserSessionV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  sessionToken: opaqueTokenSchema,
  csrfToken: opaqueTokenSchema,
  humanId: identifierV1Schema,
  expiresAt: utcTimestampV1Schema
}).strict();

export const approvalUiPendingItemV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  approvalId: identifierV1Schema,
  interfaceId: identifierV1Schema,
  state: z.literal("PENDING"),
  actionHash: digestSchema,
  policyScopeId: identifierV1Schema,
  requestedAt: utcTimestampV1Schema,
  expiresAt: utcTimestampV1Schema,
  effect: z.enum(["READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER", "UNKNOWN"]),
  tier: z.number().int().min(0).max(3),
  routeId: identifierV1Schema,
  toolName: z.string().min(1).max(256),
  targetCount: z.number().int().positive().max(64),
  coverage: z.enum(["ENFORCED", "DEGRADED", "OBSERVE_ONLY", "UNPROTECTED"])
}).strict();

export const approvalUiAuditEventV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  eventId: identifierV1Schema,
  eventType: z.enum(["DECISION_RECORDED", "DECISION_REJECTED"]),
  humanId: identifierV1Schema,
  approvalId: identifierV1Schema,
  policyScopeId: identifierV1Schema,
  reasonCodes: z.array(z.string().min(1).max(128)).max(32),
  evidenceDigest: digestSchema,
  occurredAt: utcTimestampV1Schema
}).strict();

export const approvalUiDetailV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  approval: approvalV1Schema,
  view: trustworthyActionInterfaceV1Schema,
  outcome: executionOutcomeV1Schema.nullable(),
  result: z.object({
    resultId: identifierV1Schema,
    disposition: z.enum(["ALLOW", "REDACT", "DENY", "QUARANTINE"]),
    schemaValidation: z.enum(["VALID", "INVALID", "UNVERIFIED"]),
    processedAt: utcTimestampV1Schema
  }).strict().nullable().default(null),
  audit: z.array(approvalUiAuditEventV1Schema).max(256)
}).strict();

export const approvalUiDecisionInputV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  approvalId: identifierV1Schema,
  expectedActionHash: digestSchema,
  decision: z.enum(["APPROVE", "DENY"]),
  sessionToken: opaqueTokenSchema,
  csrfToken: opaqueTokenSchema,
  origin: z.url()
}).strict();

export type AuthenticatedApprovalHumanV1 = z.infer<typeof authenticatedApprovalHumanV1Schema>;
export type ApprovalUiAdministratorV1 = z.infer<typeof approvalUiAdministratorV1Schema>;
export type ApprovalUiBrowserSessionV1 = z.infer<typeof approvalUiBrowserSessionV1Schema>;
export type ApprovalUiPendingItemV1 = z.infer<typeof approvalUiPendingItemV1Schema>;
export type ApprovalUiAuditEventV1 = z.infer<typeof approvalUiAuditEventV1Schema>;
export type ApprovalUiDetailV1 = z.infer<typeof approvalUiDetailV1Schema>;
export type ApprovalUiDecisionInputV1 = z.infer<typeof approvalUiDecisionInputV1Schema>;

export class ApprovalUiPersistenceDeniedV1 extends Error {
  public constructor() {
    super("Approval interface operation denied");
    this.name = "ApprovalUiPersistenceDeniedV1";
  }
}

export class ApprovalUiPersistenceUnavailableV1 extends Error {
  public constructor() {
    super("Approval interface PostgreSQL persistence is unavailable");
    this.name = "ApprovalUiPersistenceUnavailableV1";
  }
}

export interface PostgresApprovalUiStoreV1Options {
  readonly connectionString: string;
  readonly expectedOrigin: string;
  readonly administratorAuthorizer: (authority: ApprovalUiAdministratorV1) => boolean | Promise<boolean>;
  readonly migrationsDirectory?: string;
  readonly sessionLifetimeMs?: number;
  readonly clock?: () => Date;
  readonly tokenFactory?: () => string;
  readonly csrfFactory?: () => string;
  readonly eventIdFactory?: () => string;
}

interface SessionAuthorityRow {
  readonly human_id: string;
  readonly csrf_digest: string;
  readonly authentication_revision: string;
}

interface ApprovalDetailRow {
  readonly state_revision: string;
  readonly redacted_document: unknown;
  readonly view_document: unknown;
  readonly outcome_id: string | null;
  readonly request_id: string;
  readonly action_id: string;
  readonly decision_id: string;
  readonly approval_id: string;
  readonly forwarding_attempt_id: string | null;
  readonly result_id: string | null;
  readonly provenance_id: string | null;
  readonly outcome_status: string | null;
  readonly possible_partial_effects: boolean | null;
  readonly recovery_class: string | null;
  readonly trust_evidence_eligible: boolean | null;
  readonly forwarded_at: Date | null;
  readonly finished_at: Date | null;
  readonly observed_at: Date | null;
  readonly governed_result_id: string | null;
  readonly result_disposition: "ALLOW" | "REDACT" | "DENY" | "QUARANTINE" | null;
  readonly result_schema_validation: "VALID" | "INVALID" | "UNVERIFIED" | null;
  readonly result_processed_at: Date | null;
}

interface WebSessionRow extends SessionAuthorityRow {
  readonly authentication_method: "MUTUAL_TLS" | "OIDC" | "WEBAUTHN";
  readonly subject_digest: string;
  readonly created_at: Date;
  readonly expires_at: Date;
  readonly policy_scope_ids: string[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function issueOpaque(factory: (() => string) | undefined): string {
  return opaqueTokenSchema.parse(factory?.() ?? randomBytes(32).toString("base64url"));
}

export class PostgresApprovalUiStoreV1 {
  readonly #pool: Pool;
  readonly #expectedOrigin: string;
  readonly #administratorAuthorizer: PostgresApprovalUiStoreV1Options["administratorAuthorizer"];
  readonly #sessionLifetimeMs: number;
  readonly #clock: () => Date;
  readonly #tokenFactory: (() => string) | undefined;
  readonly #csrfFactory: (() => string) | undefined;
  readonly #eventIdFactory: (() => string) | undefined;

  private constructor(pool: Pool, options: PostgresApprovalUiStoreV1Options) {
    this.#pool = pool;
    this.#expectedOrigin = new URL(options.expectedOrigin).origin;
    this.#administratorAuthorizer = options.administratorAuthorizer;
    this.#sessionLifetimeMs = options.sessionLifetimeMs ?? 30 * 60_000;
    this.#clock = options.clock ?? (() => new Date());
    this.#tokenFactory = options.tokenFactory;
    this.#csrfFactory = options.csrfFactory;
    this.#eventIdFactory = options.eventIdFactory;
  }

  public static async connect(options: PostgresApprovalUiStoreV1Options): Promise<PostgresApprovalUiStoreV1> {
    const connectionString = z.url().refine((value) => ["postgres:", "postgresql:"].includes(new URL(value).protocol)).parse(options.connectionString);
    const origin = new URL(options.expectedOrigin);
    if (origin.origin !== options.expectedOrigin ||
      (origin.protocol !== "https:" && !(origin.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(origin.hostname)))) {
      throw new TypeError("Approval UI origin must be exact HTTPS or loopback HTTP");
    }
    const lifetime = options.sessionLifetimeMs ?? 30 * 60_000;
    if (!Number.isSafeInteger(lifetime) || lifetime <= 0 || lifetime > 8 * 60 * 60_000) {
      throw new RangeError("Approval UI session lifetime must be between one millisecond and eight hours");
    }
    const pool = new Pool({ connectionString, application_name: "agent-security-approval-ui", max: 10 });
    try {
      await pool.query("SELECT 1");
      await runForwardMigrationsV1(pool, options.migrationsDirectory ?? resolve(process.cwd(), "migrations"));
      return new PostgresApprovalUiStoreV1(pool, options);
    } catch {
      await pool.end().catch(() => undefined);
      throw new ApprovalUiPersistenceUnavailableV1();
    }
  }

  public async close(): Promise<void> {
    await this.#pool.end();
  }

  public asApprovalWebStore(): ApprovalWebStoreV1 {
    return {
      createSession: (input) => this.#createWebSession(input),
      readAuthorizedSession: (input) => this.#readAuthorizedWebSession(input),
      listPending: (session) => this.#listWebPending(session),
      readApproval: (session, approvalId) => this.#readWebApproval(session, approvalId),
      decide: (input) => this.#decideWeb(input),
      reconcileExecutionFailure: (input) => this.#reconcileExecutionFailure(input)
    };
  }

  async #reconcileExecutionFailure(input: {
    readonly approvalId: string;
    readonly humanId: string;
    readonly occurredAt: string;
  }): Promise<void> {
    const approvalId = identifierV1Schema.parse(input.approvalId);
    const humanId = identifierV1Schema.parse(input.humanId);
    const occurredAt = utcTimestampV1Schema.parse(input.occurredAt);
    await this.#transaction(async (client) => {
      const selected = await client.query<{ redacted_document: unknown; policy_scope_id: string }>(
        `SELECT a.redacted_document,a.policy_scope_id
           FROM approvals a
          WHERE a.approval_id=$1 AND a.decided_by_human_id=$2
          FOR UPDATE OF a`,
        [approvalId, humanId]
      );
      const row = selected.rows[0];
      if (row === undefined) throw new ApprovalUiPersistenceDeniedV1();
      const approval = approvalV1Schema.parse(row.redacted_document);
      if (approval.state === "APPROVED") {
        const revoked = approvalV1Schema.parse({
          ...approval,
          state: "REVOKED",
          consumption: null
        });
        await client.query(
          `UPDATE approvals SET state='REVOKED',state_revision=state_revision+1,
             updated_at=$2,redacted_document=$3::jsonb
             WHERE approval_id=$1 AND state='APPROVED'`,
          [approvalId, occurredAt, JSON.stringify(revoked)]
        );
        await this.#appendUiEvent(client, {
          eventType: "DECISION_REJECTED", humanId, approvalId,
          policyScopeId: row.policy_scope_id, reasonCodes: ["approval.execution_failed"],
          evidenceDigest: computeCanonicalDigestV1({ approvalId, occurredAt }), occurredAt
        });
      }
    });
  }

  public async configureHuman(input: {
    readonly authority: ApprovalUiAdministratorV1;
    readonly human: AuthenticatedApprovalHumanV1;
    readonly policyScopeIds: readonly string[];
  }): Promise<void> {
    const authority = approvalUiAdministratorV1Schema.parse(input.authority);
    const human = authenticatedApprovalHumanV1Schema.parse(input.human);
    const scopes = z.array(identifierV1Schema).min(1).max(128).parse(input.policyScopeIds);
    if (new Set(scopes).size !== scopes.length || !(await this.#authorizeAdministrator(authority))) {
      throw new ApprovalUiPersistenceDeniedV1();
    }
    const now = this.#now();
    const subjectDigest = sha256(human.credentialId);
    const recordDigest = computeCanonicalDigestV1({
      humanId: human.humanId, subjectDigest, authenticationMethod: human.authenticationMethod,
      authenticationRevision: human.authenticationRevision, active: true
    });
    await this.#transaction(async (client) => {
      await client.query(
        `INSERT INTO approval_ui_humans(human_id,subject_digest,authentication_method,
          authentication_revision,active,record_digest,configured_at)
         VALUES ($1,$2,$3,$4,true,$5,$6)
         ON CONFLICT (human_id) DO UPDATE SET subject_digest=EXCLUDED.subject_digest,
           authentication_method=EXCLUDED.authentication_method,
           authentication_revision=EXCLUDED.authentication_revision,active=true,
           record_digest=EXCLUDED.record_digest,configured_at=EXCLUDED.configured_at`,
        [human.humanId, subjectDigest, human.authenticationMethod,
          human.authenticationRevision, recordDigest, now]
      );
      await client.query(
        "UPDATE approval_ui_scope_grants SET active=false, grant_revision=grant_revision+1, configured_at=$2 WHERE human_id=$1",
        [human.humanId, now]
      );
      for (const scope of scopes) {
        const grantDigest = computeCanonicalDigestV1({ humanId: human.humanId, policyScopeId: scope, active: true });
        await client.query(
          `INSERT INTO approval_ui_scope_grants(human_id,policy_scope_id,active,grant_revision,grant_digest,configured_at)
           VALUES ($1,$2,true,1,$3,$4) ON CONFLICT (human_id,policy_scope_id) DO UPDATE
           SET active=true,grant_revision=approval_ui_scope_grants.grant_revision+1,
             grant_digest=EXCLUDED.grant_digest,configured_at=EXCLUDED.configured_at`,
          [human.humanId, scope, grantDigest, now]
        );
      }
      await this.#appendUiEvent(client, {
        eventType: "HUMAN_CONFIGURED", humanId: human.humanId, approvalId: null,
        policyScopeId: null, reasonCodes: ["approval_ui.human_configured"],
        evidenceDigest: recordDigest, occurredAt: now
      });
    });
  }

  public async createBrowserSession(humanInput: AuthenticatedApprovalHumanV1): Promise<ApprovalUiBrowserSessionV1> {
    const human = authenticatedApprovalHumanV1Schema.parse(humanInput);
    const now = this.#now();
    if (Date.parse(human.authenticatedAt) > Date.parse(now)) throw new ApprovalUiPersistenceDeniedV1();
    const sessionToken = issueOpaque(this.#tokenFactory);
    const csrfToken = issueOpaque(this.#csrfFactory);
    const expiresAt = new Date(Date.parse(now) + this.#sessionLifetimeMs).toISOString();
    await this.#transaction(async (client) => {
      const matched = await client.query(
        `SELECT 1 FROM approval_ui_humans WHERE human_id=$1 AND subject_digest=$2
           AND authentication_method=$3 AND authentication_revision=$4 AND active=true`,
        [human.humanId, sha256(human.credentialId), human.authenticationMethod, human.authenticationRevision]
      );
      if (matched.rowCount !== 1) throw new ApprovalUiPersistenceDeniedV1();
      await client.query(
        `INSERT INTO approval_ui_sessions(session_digest,human_id,authentication_revision,
          csrf_digest,created_at,last_seen_at,expires_at) VALUES ($1,$2,$3,$4,$5,$5,$6)`,
        [sha256(sessionToken), human.humanId, human.authenticationRevision, sha256(csrfToken), now, expiresAt]
      );
      await this.#appendUiEvent(client, {
        eventType: "SESSION_CREATED", humanId: human.humanId, approvalId: null,
        policyScopeId: null, reasonCodes: ["approval_ui.session_created"],
        evidenceDigest: computeCanonicalDigestV1({ humanId: human.humanId, expiresAt }), occurredAt: now
      });
    });
    return approvalUiBrowserSessionV1Schema.parse({
      schemaVersion: "1.0.0", sessionToken, csrfToken, humanId: human.humanId, expiresAt
    });
  }

  public async listPending(sessionTokenInput: string, limitInput = 50): Promise<readonly ApprovalUiPendingItemV1[]> {
    const sessionToken = opaqueTokenSchema.parse(sessionTokenInput);
    const limit = z.number().int().min(1).max(100).parse(limitInput);
    return this.#transaction(async (client) => {
      const session = await this.#requireSession(client, sessionToken, false);
      await this.#expireDue(client, session.human_id);
      const result = await client.query<{ redacted_document: unknown; view_document: unknown }>(
        `SELECT a.redacted_document,v.view_document FROM approvals a
         JOIN approval_ui_scope_grants g ON g.policy_scope_id=a.policy_scope_id
           AND g.human_id=$1 AND g.active=true
         JOIN trustworthy_interface_views v ON v.request_id=a.request_id AND v.decision_id=a.decision_id
         WHERE a.state='PENDING' AND a.expires_at>clock_timestamp()
         ORDER BY a.requested_at, a.approval_id LIMIT $2`,
        [session.human_id, limit]
      );
      return result.rows.map((row) => {
        const approval = approvalV1Schema.parse(row.redacted_document);
        const view = trustworthyActionInterfaceV1Schema.parse(row.view_document);
        if (approval.requestId !== view.requestId || approval.actionHash.length !== 64 ||
          approval.route.policyScopeId !== view.route.policyScopeId) throw new ApprovalUiPersistenceDeniedV1();
        return approvalUiPendingItemV1Schema.parse({
          schemaVersion: "1.0.0", approvalId: approval.approvalId, interfaceId: view.interfaceId,
          state: "PENDING", actionHash: approval.actionHash,
          policyScopeId: approval.route.policyScopeId, requestedAt: approval.requestedAt,
          expiresAt: approval.expiresAt, effect: view.actionEffect, tier: view.riskTier,
          routeId: view.route.routeId, toolName: view.route.toolName,
          targetCount: view.targets.length, coverage: view.coverage
        });
      });
    });
  }

  public async readDetail(sessionTokenInput: string, approvalIdInput: string): Promise<ApprovalUiDetailV1> {
    const sessionToken = opaqueTokenSchema.parse(sessionTokenInput);
    const approvalId = identifierV1Schema.parse(approvalIdInput);
    return this.#transaction(async (client) => {
      const session = await this.#requireSession(client, sessionToken, false);
      await this.#expireDue(client, session.human_id, approvalId);
      return this.#readDetail(client, session.human_id, approvalId);
    });
  }

  public async recordDecision(inputValue: ApprovalUiDecisionInputV1): Promise<{
    readonly approval: ApprovalV1;
    readonly nextCsrfToken: string;
  }> {
    const input = approvalUiDecisionInputV1Schema.parse(inputValue);
    if (new URL(input.origin).origin !== this.#expectedOrigin || input.origin !== this.#expectedOrigin) {
      throw new ApprovalUiPersistenceDeniedV1();
    }
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const session = await this.#requireSession(client, input.sessionToken, true);
      if (!sameDigest(session.csrf_digest, sha256(input.csrfToken))) throw new ApprovalUiPersistenceDeniedV1();
      const selected = await client.query<{
        redacted_document: unknown; policy_scope_id: string; interface_id: string;
        current_state_valid: boolean; action_document: unknown;
      }>(
        `SELECT a.redacted_document,a.policy_scope_id,v.interface_id,ca.redacted_document AS action_document,
           (s.status='ACTIVE' AND d.decision='REQUIRE_APPROVAL' AND d.coverage='ENFORCED'
             AND rt.document->>'status'='ACTIVE'
             AND rt.document->'schemaIntegrity'->>'state'='VERIFIED'
             AND sv.document->'health'->>'state'='HEALTHY'
             AND sv.document->'capabilityIntegrity'->>'state'='VERIFIED'
             AND NOT EXISTS (SELECT 1 FROM policies newer WHERE newer.activated_at>d.decided_at)
             AND NOT EXISTS (
               SELECT 1 FROM identities newer
               WHERE newer.user_id=i.user_id AND newer.agent_id=i.agent_id
                 AND newer.host_id=i.host_id
                 AND (newer.identity_revision>i.identity_revision
                   OR newer.credential_id<>i.credential_id)
             )) AS current_state_valid
         FROM approvals a JOIN decisions d ON d.decision_id=a.decision_id
         JOIN canonical_actions ca ON ca.action_id=a.action_id
         JOIN requests r ON r.request_id=a.request_id JOIN sessions s ON s.state_namespace=r.state_namespace
         JOIN identities i ON i.identity_key=s.identity_key JOIN routes rt ON rt.route_id=r.route_id
         JOIN servers sv ON sv.server_id=rt.server_id
         JOIN trustworthy_interface_views v ON v.request_id=a.request_id AND v.decision_id=a.decision_id
         JOIN approval_ui_scope_grants g ON g.human_id=$2 AND g.policy_scope_id=a.policy_scope_id AND g.active=true
         WHERE a.approval_id=$1 FOR UPDATE OF a`,
        [input.approvalId, session.human_id]
      );
      const row = selected.rows[0];
      if (row === undefined) throw new ApprovalUiPersistenceDeniedV1();
      const approval = approvalV1Schema.parse(row.redacted_document);
      const action = canonicalActionV1Schema.parse(row.action_document);
      if (approval.state !== "PENDING" || approval.actionHash !== input.expectedActionHash ||
        Date.parse(approval.expiresAt) <= Date.parse(this.#now())) throw new ApprovalUiPersistenceDeniedV1();
      if (input.decision === "APPROVE" && (!row.current_state_valid ||
        !(await this.#hasCurrentEnforcedCoverage(client, approval, action.resources.map((item) => item.resourceId))))) {
        throw new ApprovalUiPersistenceDeniedV1();
      }
      const decidedAt = this.#now();
      const decided = approvalV1Schema.parse({
        ...approval, state: input.decision === "APPROVE" ? "APPROVED" : "DENIED",
        decidedAt, decidedByHumanId: session.human_id
      });
      const nextCsrfToken = issueOpaque(this.#csrfFactory);
      const updated = await client.query(
        `UPDATE approvals SET state=$2,decided_at=$3,decided_by_human_id=$4,
           redacted_document=$5::jsonb,state_revision=state_revision+1,updated_at=$3
         WHERE approval_id=$1 AND state='PENDING' AND action_hash=$6`,
        [approval.approvalId, decided.state, decidedAt, session.human_id,
          JSON.stringify(decided), input.expectedActionHash]
      );
      if (updated.rowCount !== 1) throw new ApprovalUiPersistenceDeniedV1();
      if (input.decision === "APPROVE") {
        await client.query(
          `INSERT INTO approval_runtime_dispatches(approval_id,request_id,human_id,state,created_at)
           VALUES ($1,$2,$3,'PENDING',$4)`,
          [approval.approvalId, approval.requestId, session.human_id, decidedAt]
        );
      }
      await client.query(
        "UPDATE approval_ui_sessions SET csrf_digest=$2,last_seen_at=$3 WHERE session_digest=$1",
        [sha256(input.sessionToken), sha256(nextCsrfToken), decidedAt]
      );
      await client.query(
        `INSERT INTO approval_fatigue_events(event_id,interface_id,policy_scope_id,event_type,
          decision_latency_ms,related_attempt_count,occurred_at)
         VALUES ($1,$2,$3,$4,$5,0,$6)`,
        [this.#eventId(), row.interface_id, row.policy_scope_id,
          input.decision === "APPROVE" ? "APPROVED" : "DENIED",
          Math.max(0, Date.parse(decidedAt) - Date.parse(approval.requestedAt)), decidedAt]
      );
      await this.#appendUiEvent(client, {
        eventType: "DECISION_RECORDED", humanId: session.human_id,
        approvalId: approval.approvalId, policyScopeId: row.policy_scope_id,
        reasonCodes: [input.decision === "APPROVE" ? "approval_ui.approved_once" : "approval_ui.denied"],
        evidenceDigest: computeCanonicalDigestV1({ approvalId: approval.approvalId,
          actionHash: approval.actionHash, decision: input.decision, decidedAt }), occurredAt: decidedAt
      });
      await client.query("COMMIT");
      return { approval: decided, nextCsrfToken };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (error instanceof ApprovalUiPersistenceDeniedV1) throw error;
      throw new ApprovalUiPersistenceDeniedV1();
    } finally {
      client.release();
    }
  }

  async #createWebSession(
    input: Parameters<ApprovalWebStoreV1["createSession"]>[0]
  ): Promise<ApprovalWebSessionV1> {
    const principal = approvalWebHumanPrincipalV1Schema.parse(input.principal);
    const sessionIdDigest = digestSchema.parse(input.sessionIdDigest);
    const csrfTokenDigest = digestSchema.parse(input.csrfTokenDigest);
    const createdAt = utcTimestampV1Schema.parse(input.createdAt);
    const expiresAt = utcTimestampV1Schema.parse(input.expiresAt);
    if (Date.parse(expiresAt) <= Date.parse(createdAt) ||
      Date.parse(principal.authenticatedAt) > Date.parse(createdAt) ||
      Date.parse(expiresAt) - Date.parse(createdAt) > this.#sessionLifetimeMs) {
      throw new ApprovalUiPersistenceDeniedV1();
    }
    return this.#transaction(async (client) => {
      const matched = await client.query<{ policy_scope_ids: string[] }>(
        `SELECT array_agg(g.policy_scope_id ORDER BY g.policy_scope_id) AS policy_scope_ids
         FROM approval_ui_humans h JOIN approval_ui_scope_grants g ON g.human_id=h.human_id AND g.active=true
         WHERE h.human_id=$1 AND h.subject_digest=$2 AND h.authentication_method=$3
           AND h.authentication_revision=$4 AND h.active=true GROUP BY h.human_id`,
        [principal.humanId, sha256(principal.credentialId), principal.authenticationMethod,
          principal.identityRevision]
      );
      const scopes = matched.rows[0]?.policy_scope_ids;
      if (scopes === undefined || scopes.length === 0) throw new ApprovalUiPersistenceDeniedV1();
      await client.query(
        `INSERT INTO approval_ui_sessions(session_digest,human_id,authentication_revision,
          csrf_digest,created_at,last_seen_at,expires_at) VALUES ($1,$2,$3,$4,$5,$5,$6)`,
        [sessionIdDigest, principal.humanId, principal.identityRevision, csrfTokenDigest,
          createdAt, expiresAt]
      );
      await this.#appendUiEvent(client, {
        eventType: "SESSION_CREATED", humanId: principal.humanId, approvalId: null,
        policyScopeId: null, reasonCodes: ["approval_ui.session_created"],
        evidenceDigest: computeCanonicalDigestV1({ humanId: principal.humanId,
          expiresAt }), occurredAt: createdAt
      });
      return approvalWebSessionV1Schema.parse({
        schemaVersion: "1.0.0", sessionIdDigest, csrfTokenDigest,
        humanId: principal.humanId, authenticationMethod: principal.authenticationMethod,
        credentialId: principal.credentialId, identityRevision: principal.identityRevision,
        policyScopeIds: scopes, createdAt, expiresAt
      });
    });
  }

  async #readAuthorizedWebSession(
    input: Parameters<ApprovalWebStoreV1["readAuthorizedSession"]>[0]
  ): Promise<ApprovalWebSessionV1 | null> {
    const principal = approvalWebHumanPrincipalV1Schema.parse(input.principal);
    const sessionIdDigest = digestSchema.parse(input.sessionIdDigest);
    utcTimestampV1Schema.parse(input.now);
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
        const row = await this.#selectWebSession(client, sessionIdDigest, principal.credentialId, false);
        if (row === null || row.human_id !== principal.humanId || row.authentication_method !== principal.authenticationMethod ||
          Number(row.authentication_revision) !== principal.identityRevision) {
          await client.query("COMMIT");
          return null;
        }
        const session = approvalWebSessionV1Schema.parse({
          schemaVersion: "1.0.0", sessionIdDigest, csrfTokenDigest: row.csrf_digest,
          humanId: row.human_id, authenticationMethod: row.authentication_method,
          credentialId: principal.credentialId, identityRevision: Number(row.authentication_revision),
          policyScopeIds: row.policy_scope_ids, createdAt: row.created_at.toISOString(),
          expiresAt: row.expires_at.toISOString()
        });
        await client.query("COMMIT");
        return session;
    } catch {
      await client.query("ROLLBACK").catch(() => undefined);
      throw new ApprovalUiPersistenceUnavailableV1();
    } finally {
      client.release();
    }
  }

  async #listWebPending(sessionInput: ApprovalWebSessionV1): Promise<readonly ApprovalWebRecordV1[]> {
    const session = approvalWebSessionV1Schema.parse(sessionInput);
    return this.#transaction(async (client) => {
      await this.#requireWebSessionSnapshot(client, session, false);
      await this.#expireDue(client, session.humanId);
      const selected = await client.query<{ approval_id: string }>(
        `SELECT a.approval_id FROM approvals a JOIN approval_ui_scope_grants g
           ON g.human_id=$1 AND g.policy_scope_id=a.policy_scope_id AND g.active=true
         WHERE a.state='PENDING' AND a.expires_at>clock_timestamp()
         ORDER BY a.requested_at,a.approval_id LIMIT 50`,
        [session.humanId]
      );
      const records: ApprovalWebRecordV1[] = [];
      for (const row of selected.rows) {
        const record = await this.#readWebRecord(client, session.humanId, row.approval_id);
        if (record !== null) records.push(record);
      }
      return records;
    });
  }

  async #readWebApproval(
    sessionInput: ApprovalWebSessionV1,
    approvalIdInput: string
  ): Promise<ApprovalWebRecordV1 | null> {
    const session = approvalWebSessionV1Schema.parse(sessionInput);
    const approvalId = identifierV1Schema.parse(approvalIdInput);
    return this.#transaction(async (client) => {
      await this.#requireWebSessionSnapshot(client, session, false);
      await this.#expireDue(client, session.humanId, approvalId);
      return this.#readWebRecord(client, session.humanId, approvalId);
    });
  }

  async #decideWeb(inputValue: Parameters<ApprovalWebStoreV1["decide"]>[0]): Promise<ApprovalWebRecordV1> {
    const session = approvalWebSessionV1Schema.parse(inputValue.session);
    const approvalId = identifierV1Schema.parse(inputValue.approvalId);
    const decision = z.enum(["APPROVE", "DENY"]).parse(inputValue.decision);
    const expectedRevision = z.number().int().positive().parse(inputValue.expectedRevision);
    utcTimestampV1Schema.parse(inputValue.decidedAt);
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await this.#requireWebSessionSnapshot(client, session, true);
      await this.#expireDue(client, session.humanId, approvalId);
      const selected = await client.query<{
        redacted_document: unknown; policy_scope_id: string; interface_id: string;
        state_revision: string; current_state_valid: boolean; action_document: unknown;
      }>(
        `SELECT a.redacted_document,a.policy_scope_id,a.state_revision,v.interface_id,
          ca.redacted_document AS action_document,
          (s.status='ACTIVE' AND d.decision='REQUIRE_APPROVAL' AND d.coverage='ENFORCED'
            AND d.policy_version=a.policy_version AND rt.document->>'status'='ACTIVE'
            AND rt.document->'schemaIntegrity'->>'state'='VERIFIED'
            AND sv.document->'health'->>'state'='HEALTHY'
            AND sv.document->'capabilityIntegrity'->>'state'='VERIFIED'
            AND NOT EXISTS (SELECT 1 FROM policies newer WHERE newer.activated_at>d.decided_at)
            AND NOT EXISTS (SELECT 1 FROM identities newer
              WHERE newer.user_id=i.user_id AND newer.agent_id=i.agent_id AND newer.host_id=i.host_id
                AND (newer.identity_revision>i.identity_revision OR newer.credential_id<>i.credential_id)))
            AS current_state_valid
         FROM approvals a JOIN decisions d ON d.decision_id=a.decision_id
         JOIN canonical_actions ca ON ca.action_id=a.action_id
         JOIN requests r ON r.request_id=a.request_id JOIN sessions s ON s.state_namespace=r.state_namespace
         JOIN identities i ON i.identity_key=s.identity_key JOIN routes rt ON rt.route_id=r.route_id
         JOIN servers sv ON sv.server_id=rt.server_id
         JOIN trustworthy_interface_views v ON v.request_id=a.request_id AND v.decision_id=a.decision_id
         JOIN approval_ui_scope_grants g ON g.human_id=$2 AND g.policy_scope_id=a.policy_scope_id AND g.active=true
         WHERE a.approval_id=$1 FOR UPDATE OF a`,
        [approvalId, session.humanId]
      );
      const row = selected.rows[0];
      if (row === undefined) throw new ApprovalUiPersistenceDeniedV1();
      const approval = approvalV1Schema.parse(row.redacted_document);
      const action = canonicalActionV1Schema.parse(row.action_document);
      if (approval.state !== "PENDING" || Number(row.state_revision) !== expectedRevision) {
        await client.query("COMMIT");
        throw new ApprovalWebStaleDecisionV1();
      }
      const coverageValid = decision === "DENY" || await this.#hasCurrentEnforcedCoverage(
          client, approval, action.resources.map((item) => item.resourceId)
        );
      if (decision === "APPROVE" && (!row.current_state_valid || !coverageValid)) {
        const revoked = approvalV1Schema.parse({ ...approval, state: "REVOKED", consumption: null });
        const revokedAt = this.#now();
        await client.query(
          `UPDATE approvals SET state='REVOKED',redacted_document=$2::jsonb WHERE approval_id=$1`,
          [approval.approvalId, JSON.stringify(revoked)]
        );
        await this.#appendUiEvent(client, {
          eventType: "DECISION_REJECTED", humanId: session.humanId, approvalId,
          policyScopeId: row.policy_scope_id, reasonCodes: ["approval_ui.revalidation_failed"],
          evidenceDigest: computeCanonicalDigestV1({ approvalId, expectedRevision }), occurredAt: revokedAt
        });
        await client.query("COMMIT");
        throw new ApprovalWebStaleDecisionV1();
      }
      const decidedAt = this.#now();
      const decided = approvalV1Schema.parse({
        ...approval, state: decision === "APPROVE" ? "APPROVED" : "DENIED",
        decidedAt, decidedByHumanId: session.humanId
      });
      const updated = await client.query(
        `UPDATE approvals SET state=$2,decided_at=$3,decided_by_human_id=$4,
          redacted_document=$5::jsonb WHERE approval_id=$1 AND state='PENDING' AND state_revision=$6`,
        [approvalId, decided.state, decidedAt, session.humanId, JSON.stringify(decided), expectedRevision]
      );
      if (updated.rowCount !== 1) {
        await client.query("ROLLBACK");
        throw new ApprovalWebStaleDecisionV1();
      }
      if (decision === "APPROVE") {
        await client.query(
          `INSERT INTO approval_runtime_dispatches(approval_id,request_id,human_id,state,created_at)
           VALUES ($1,$2,$3,'PENDING',$4)`,
          [approvalId, approval.requestId, session.humanId, decidedAt]
        );
      }
      await client.query(
        `INSERT INTO approval_fatigue_events(event_id,interface_id,policy_scope_id,event_type,
          decision_latency_ms,related_attempt_count,occurred_at) VALUES ($1,$2,$3,$4,$5,0,$6)`,
        [this.#eventId(), row.interface_id, row.policy_scope_id,
          decision === "APPROVE" ? "APPROVED" : "DENIED",
          Math.max(0, Date.parse(decidedAt) - Date.parse(approval.requestedAt)), decidedAt]
      );
      await this.#appendUiEvent(client, {
        eventType: "DECISION_RECORDED", humanId: session.humanId, approvalId,
        policyScopeId: row.policy_scope_id,
        reasonCodes: [decision === "APPROVE" ? "approval_ui.approved_once" : "approval_ui.denied"],
        evidenceDigest: computeCanonicalDigestV1({ approvalId, actionHash: approval.actionHash,
          decision, decidedAt }), occurredAt: decidedAt
      });
      const record = await this.#readWebRecord(client, session.humanId, approvalId);
      if (record === null) throw new ApprovalUiPersistenceDeniedV1();
      await client.query("COMMIT");
      return record;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (error instanceof ApprovalWebStaleDecisionV1 || error instanceof ApprovalUiPersistenceDeniedV1) throw error;
      throw new ApprovalUiPersistenceUnavailableV1();
    } finally {
      client.release();
    }
  }

  async #selectWebSession(
    client: PoolClient,
    sessionIdDigest: string,
    credentialId: string,
    lock: boolean
  ): Promise<WebSessionRow | null> {
    if (lock) {
      await client.query(
        "SELECT 1 FROM approval_ui_sessions WHERE session_digest=$1 FOR UPDATE",
        [sessionIdDigest]
      );
    }
    const selected = await client.query<WebSessionRow>(
      `SELECT s.human_id,s.csrf_digest,s.authentication_revision,h.authentication_method,
        h.subject_digest,s.created_at,s.expires_at,
        array_agg(g.policy_scope_id ORDER BY g.policy_scope_id) AS policy_scope_ids
       FROM approval_ui_sessions s JOIN approval_ui_humans h ON h.human_id=s.human_id
       JOIN approval_ui_scope_grants g ON g.human_id=s.human_id AND g.active=true
       WHERE s.session_digest=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
         AND h.active=true AND h.authentication_revision=s.authentication_revision
         AND h.subject_digest=$2
       GROUP BY s.session_digest,s.human_id,s.csrf_digest,s.authentication_revision,
         h.authentication_method,h.subject_digest,s.created_at,s.expires_at`,
      [sessionIdDigest, sha256(credentialId)]
    );
    return selected.rows[0] ?? null;
  }

  async #requireWebSessionSnapshot(
    client: PoolClient,
    session: ApprovalWebSessionV1,
    lock: boolean
  ): Promise<WebSessionRow> {
    const row = await this.#selectWebSession(client, session.sessionIdDigest, session.credentialId, lock);
    if (row === null || row.human_id !== session.humanId ||
      row.authentication_method !== session.authenticationMethod ||
      Number(row.authentication_revision) !== session.identityRevision ||
      row.csrf_digest !== session.csrfTokenDigest ||
      JSON.stringify(row.policy_scope_ids) !== JSON.stringify(session.policyScopeIds)) {
      throw new ApprovalUiPersistenceDeniedV1();
    }
    return row;
  }

  async #readWebRecord(
    client: PoolClient,
    humanId: string,
    approvalId: string
  ): Promise<ApprovalWebRecordV1 | null> {
    const revision = await client.query<{ state_revision: string }>(
      `SELECT a.state_revision FROM approvals a JOIN approval_ui_scope_grants g
        ON g.human_id=$2 AND g.policy_scope_id=a.policy_scope_id AND g.active=true
       WHERE a.approval_id=$1 FOR SHARE OF a`,
      [approvalId, humanId]
    );
    const value = revision.rows[0];
    if (value === undefined) return null;
    const detail = await this.#readDetail(client, humanId, approvalId);
    return approvalWebRecordV1Schema.parse({
      schemaVersion: "1.0.0", revision: Number(value.state_revision),
      approval: detail.approval, view: detail.view, outcome: detail.outcome,
      result: detail.result, audit: detail.audit
    });
  }

  async #readDetail(client: PoolClient, humanId: string, approvalId: string): Promise<ApprovalUiDetailV1> {
    const selected = await client.query<ApprovalDetailRow>(
      `SELECT a.redacted_document,v.view_document,o.outcome_id,o.request_id,o.action_id,
        o.decision_id,o.approval_id,o.forwarding_attempt_id,o.result_id,o.provenance_id,
        o.status AS outcome_status,o.possible_partial_effects,o.recovery_class,
        o.trust_evidence_eligible,f.forwarding_started_at AS forwarded_at,
        f.finished_at,o.observed_at,gr.result_id AS governed_result_id,
        gr.disposition AS result_disposition,gr.schema_validation AS result_schema_validation,
        gr.processed_at AS result_processed_at
       FROM approvals a JOIN approval_ui_scope_grants g ON g.human_id=$2
         AND g.policy_scope_id=a.policy_scope_id AND g.active=true
       JOIN trustworthy_interface_views v ON v.request_id=a.request_id AND v.decision_id=a.decision_id
       LEFT JOIN outcomes o ON o.approval_id=a.approval_id
       LEFT JOIN forwarding_attempts f ON f.forwarding_attempt_id=o.forwarding_attempt_id
       LEFT JOIN results gr ON gr.result_id=o.result_id
       WHERE a.approval_id=$1`,
      [approvalId, humanId]
    );
    const row = selected.rows[0];
    if (row === undefined) throw new ApprovalUiPersistenceDeniedV1();
    const approval = approvalV1Schema.parse(row.redacted_document);
    const view = trustworthyActionInterfaceV1Schema.parse(row.view_document);
    const outcome: ExecutionOutcomeV1 | null = row.outcome_id === null ? null : executionOutcomeV1Schema.parse({
      schemaVersion: "1.0.0", outcomeId: row.outcome_id, requestId: row.request_id,
      actionId: row.action_id, sessionId: approval.sessionId, decisionId: row.decision_id,
      approvalId: row.approval_id, forwardingAttemptId: row.forwarding_attempt_id,
      resultId: row.result_id, provenanceId: row.provenance_id, status: row.outcome_status,
      forwardedAt: row.forwarded_at?.toISOString() ?? null,
      finishedAt: row.finished_at?.toISOString() ?? null,
      possiblePartialEffects: row.possible_partial_effects,
      recoveryClass: row.recovery_class, trustEvidenceEligible: row.trust_evidence_eligible,
      observedAt: row.observed_at?.toISOString()
    });
    const result = row.governed_result_id === null ? null : {
      resultId: row.governed_result_id,
      disposition: row.result_disposition,
      schemaValidation: row.result_schema_validation,
      processedAt: row.result_processed_at?.toISOString()
    };
    const events = await client.query<{
      event_id: string; event_type: "DECISION_RECORDED" | "DECISION_REJECTED";
      human_id: string; approval_id: string; policy_scope_id: string;
      reason_codes: string[]; evidence_digest: string; occurred_at: Date;
    }>(
      `SELECT event_id,event_type,human_id,approval_id,policy_scope_id,reason_codes,
        evidence_digest,occurred_at FROM approval_ui_security_events
       WHERE approval_id=$1 AND policy_scope_id=$2 ORDER BY sequence_id`,
      [approval.approvalId, approval.route.policyScopeId]
    );
    return approvalUiDetailV1Schema.parse({
      schemaVersion: "1.0.0", approval, view, outcome, result,
      audit: events.rows.map((event) => ({
        schemaVersion: "1.0.0", eventId: event.event_id, eventType: event.event_type,
        humanId: event.human_id, approvalId: event.approval_id,
        policyScopeId: event.policy_scope_id, reasonCodes: event.reason_codes,
        evidenceDigest: event.evidence_digest, occurredAt: event.occurred_at.toISOString()
      }))
    });
  }

  async #requireSession(client: PoolClient, token: string, lock: boolean): Promise<SessionAuthorityRow> {
    const selected = await client.query<SessionAuthorityRow>(
      `SELECT s.human_id,s.csrf_digest,s.authentication_revision FROM approval_ui_sessions s
       JOIN approval_ui_humans h ON h.human_id=s.human_id
       WHERE s.session_digest=$1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
         AND h.active=true AND h.authentication_revision=s.authentication_revision
       ${lock ? "FOR UPDATE OF s" : ""}`,
      [sha256(token)]
    );
    const row = selected.rows[0];
    if (row === undefined) throw new ApprovalUiPersistenceDeniedV1();
    return row;
  }

  async #expireDue(client: PoolClient, humanId: string, approvalId?: string): Promise<void> {
    const expired = await client.query<{ redacted_document: unknown; interface_id: string; policy_scope_id: string }>(
      `SELECT a.redacted_document,v.interface_id,a.policy_scope_id FROM approvals a
       JOIN approval_ui_scope_grants g ON g.human_id=$1 AND g.policy_scope_id=a.policy_scope_id AND g.active=true
       JOIN trustworthy_interface_views v ON v.request_id=a.request_id AND v.decision_id=a.decision_id
       WHERE a.state IN ('PENDING','APPROVED') AND a.expires_at<=clock_timestamp()
         AND ($2::text IS NULL OR a.approval_id=$2) FOR UPDATE OF a`,
      [humanId, approvalId ?? null]
    );
    for (const row of expired.rows) {
      const approval = approvalV1Schema.parse(row.redacted_document);
      const now = this.#now();
      const next = approvalV1Schema.parse({ ...approval, state: "EXPIRED", consumption: null });
      await client.query(
        `UPDATE approvals SET state='EXPIRED',redacted_document=$2::jsonb,
          state_revision=state_revision+1,updated_at=$3 WHERE approval_id=$1`,
        [approval.approvalId, JSON.stringify(next), now]
      );
      await client.query(
        `INSERT INTO approval_fatigue_events(event_id,interface_id,policy_scope_id,event_type,
          decision_latency_ms,related_attempt_count,occurred_at) VALUES ($1,$2,$3,'EXPIRED',NULL,0,$4)`,
        [this.#eventId(), row.interface_id, row.policy_scope_id, now]
      );
      await this.#appendUiEvent(client, {
        eventType: "DECISION_REJECTED", humanId: "approval-ui-system", approvalId: approval.approvalId,
        policyScopeId: row.policy_scope_id, reasonCodes: ["approval.expired"],
        evidenceDigest: computeCanonicalDigestV1({ approvalId: approval.approvalId, expiredAt: now }),
        occurredAt: now
      });
    }
  }

  async #hasCurrentEnforcedCoverage(client: PoolClient, approval: ApprovalV1, resourceIds: readonly string[]): Promise<boolean> {
    const result = await client.query<{ resource_id: string }>(
      `SELECT resource_id FROM (
         SELECT DISTINCT ON (resource_id) resource_id,coverage,valid_until,report_document
         FROM coverage_events WHERE state_namespace=$1 AND server_id=$2 AND route_id=$3
           AND policy_scope_id=$4 AND environment=$5 ORDER BY resource_id,occurred_at DESC,assessment_revision DESC
       ) latest WHERE coverage='ENFORCED' AND valid_until>clock_timestamp()
         AND report_document->'scope'->>'schemaDigest'=$6
         AND report_document->'scope'->>'credentialAudienceId'=$7
         AND report_document->'scope'->>'resourcesDigest'=$8`,
      [approval.sessionId, approval.route.serverId, approval.route.routeId,
        approval.route.policyScopeId, approval.environment, approval.route.schemaDigest,
        approval.route.credentialAudienceId, approval.resourcesDigest]
    );
    const covered = new Set(result.rows.map((row) => row.resource_id));
    return resourceIds.length > 0 && resourceIds.every((item) => covered.has(item));
  }

  async #authorizeAdministrator(authority: ApprovalUiAdministratorV1): Promise<boolean> {
    try { return await this.#administratorAuthorizer(authority); } catch { return false; }
  }

  #now(): string {
    const value = this.#clock();
    if (!Number.isFinite(value.getTime())) throw new ApprovalUiPersistenceDeniedV1();
    return value.toISOString();
  }

  #eventId(): string {
    return identifierV1Schema.parse(this.#eventIdFactory?.() ?? randomUUID());
  }

  async #appendUiEvent(client: PoolClient, input: {
    readonly eventType: "HUMAN_CONFIGURED" | "SESSION_CREATED" | "DECISION_RECORDED" | "DECISION_REJECTED";
    readonly humanId: string;
    readonly approvalId: string | null;
    readonly policyScopeId: string | null;
    readonly reasonCodes: readonly string[];
    readonly evidenceDigest: string;
    readonly occurredAt: string;
  }): Promise<void> {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agent-security:approval-ui-audit:v1'))");
    const previous = await client.query<{ event_hash: string }>(
      "SELECT event_hash FROM approval_ui_security_events ORDER BY sequence_id DESC LIMIT 1"
    );
    const previousHash = previous.rows[0]?.event_hash ?? "0".repeat(64);
    const eventId = this.#eventId();
    const event = { eventId, ...input };
    const eventHash = sha256(computeCanonicalDigestV1({ previousHash, event }));
    await client.query(
      `INSERT INTO approval_ui_security_events(event_id,event_type,human_id,approval_id,
        policy_scope_id,reason_codes,evidence_digest,previous_hash,event_hash,occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [eventId, input.eventType, input.humanId, input.approvalId, input.policyScopeId,
        input.reasonCodes, input.evidenceDigest, previousHash, eventHash, input.occurredAt]
    );
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
      if (error instanceof ApprovalUiPersistenceDeniedV1) throw error;
      throw new ApprovalUiPersistenceDeniedV1();
    } finally {
      client.release();
    }
  }
}
