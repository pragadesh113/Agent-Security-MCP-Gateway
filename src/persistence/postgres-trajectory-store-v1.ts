import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";

import { Pool, type PoolClient } from "pg";
import { z } from "zod";

import {
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1
} from "../action-normalizer/canonical-action-v1.js";
import {
  approvedForwardingAuthorizationV1Schema,
  type ApprovedForwardingAuthorizationV1
} from "../approval/disposable-approval-v1.js";
import {
  toolCallRequestV1Schema,
  type ToolCallRequestV1
} from "../contracts/boundary-v1.js";
import {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  downstreamProvenanceV1Schema,
  downstreamResultV1Schema,
  executionOutcomeV1Schema,
  policyDecisionV1Schema,
  type ApprovalV1,
  type CanonicalActionV1,
  type DownstreamProvenanceV1,
  type DownstreamResultV1,
  type ExecutionOutcomeV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import {
  boundedProtocolJsonObjectV1Schema
} from "../contracts/boundary-v1.js";
import { awarenessV1Schema, type AwarenessV1 } from "../contracts/boundary-v1.js";
import {
  downstreamServerRouteBindingV1Schema,
  identifierV1Schema,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";
import { runForwardMigrationsV1 } from "./migrations-v1.js";
import {
  coverageScopeMatchesActionV1,
  exclusiveMediationAssessmentV1Schema,
  type ExclusiveMediationAssessmentV1
} from "../coverage/exclusive-mediation-v1.js";
import {
  approvalFatigueEventV1Schema,
  approvalFatigueMetricsV1Schema,
  trustworthyActionInterfaceV1Schema,
  type ApprovalFatigueEventV1,
  type ApprovalFatigueMetricsV1,
  type TrustworthyActionInterfaceV1
} from "../interfaces/trustworthy-interface-v1.js";
import {
  supervisorAssessmentAuditV1Schema,
  type SupervisorAssessmentAuditV1
} from "../supervisor/advisory-supervisor-v1.js";

const eventTypeV1Schema = z.enum([
  "DECIDED", "DENIED", "MODIFIED", "ALTERNATE_ROUTE", "REPLAYED", "BYPASS",
  "APPROVED", "FORWARDED", "RESULT_RECORDED", "COMPLETED", "FAILED",
  "CANCELLED", "TIMED_OUT", "UNKNOWN_OUTCOME", "TRUST_RECORDED", "SUPERVISOR_ASSESSED"
]);

export const securityEventInputV1Schema = z.object({
  eventId: identifierV1Schema,
  eventType: eventTypeV1Schema,
  requestId: identifierV1Schema.nullable(),
  stateNamespace: identifierV1Schema.nullable(),
  forwardingAttemptId: identifierV1Schema.nullable(),
  actorId: identifierV1Schema,
  reasonCodes: z.array(z.string().min(1).max(128)).max(64),
  evidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  occurredAt: z.iso.datetime({ offset: true })
}).strict();

export const persistedSecurityEventV1Schema = securityEventInputV1Schema.extend({
  sequenceId: z.number().int().positive(),
  previousHash: z.string().regex(/^[a-f0-9]{64}$/u),
  eventHash: z.string().regex(/^[a-f0-9]{64}$/u)
}).strict();

export const postgresPersistenceConfigV1Schema = z.object({
  connectionString: z.url().refine((value) => {
    const protocol = new URL(value).protocol;
    return protocol === "postgres:" || protocol === "postgresql:";
  }, "A PostgreSQL connection URL is required"),
  migrationsDirectory: z.string().trim().min(1).max(4_096).optional(),
  applicationName: z.string().trim().min(1).max(64).default("agent-security-gateway"),
  knownSecretValues: z.array(z.string().min(4).max(16_384)).max(1_000).default([]),
  connectionTimeoutMs: z.number().int().positive().max(60_000).default(5_000),
  maxConnections: z.number().int().positive().max(100).default(10)
}).strict();

export type SecurityEventInputV1 = z.infer<typeof securityEventInputV1Schema>;
export type PersistedSecurityEventV1 = z.infer<typeof persistedSecurityEventV1Schema>;
export type PostgresPersistenceConfigV1 = z.input<typeof postgresPersistenceConfigV1Schema>;

export class PersistenceUnavailableV1 extends Error {
  public constructor() {
    super("Required PostgreSQL persistence is unavailable");
    this.name = "PersistenceUnavailableV1";
  }
}

export class PersistenceDeniedV1 extends Error {
  public constructor() {
    super("PostgreSQL trajectory operation denied");
    this.name = "PersistenceDeniedV1";
  }
}

export class SecretPersistenceDeniedV1 extends Error {
  public constructor() {
    super("Persistence input contains a known secret");
    this.name = "SecretPersistenceDeniedV1";
  }
}

interface ApprovalRowV1 {
  readonly state: string;
  readonly decision_id: string;
  readonly unexpired: boolean;
  readonly redacted_document: unknown;
  readonly current_state_valid: boolean;
  readonly action_document: unknown;
}

interface SecurityEventRowV1 {
  readonly sequence_id: string;
  readonly event_id: string;
  readonly event_type: string;
  readonly request_id: string | null;
  readonly state_namespace: string | null;
  readonly forwarding_attempt_id: string | null;
  readonly actor_id: string;
  readonly reason_codes: string[];
  readonly evidence_digest: string;
  readonly previous_hash: string;
  readonly event_hash: string;
  readonly occurred_at: Date;
}

interface CoverageEventRowV1 {
  readonly report_document: unknown;
}

function eventHash(previousHash: string, event: SecurityEventInputV1): string {
  return createHash("sha256")
    .update(computeCanonicalDigestV1({ previousHash, event }), "utf8")
    .digest("hex");
}

function outcomeEventType(outcome: ExecutionOutcomeV1): SecurityEventInputV1["eventType"] {
  const mapping = {
    NOT_FORWARDED: "DENIED",
    FORWARDED: "FORWARDED",
    COMPLETED: "COMPLETED",
    FAILED: "FAILED",
    CANCELLED: "CANCELLED",
    TIMED_OUT: "TIMED_OUT",
    UNKNOWN: "UNKNOWN_OUTCOME"
  } as const;
  return mapping[outcome.status];
}

function exactAuthorizationMatchesApproval(
  authorization: ApprovedForwardingAuthorizationV1,
  approval: ApprovalV1
): boolean {
  return authorization.approvalId === approval.approvalId &&
    authorization.requestId === approval.requestId &&
    authorization.actionId === approval.actionId &&
    authorization.actionHash === approval.actionHash &&
    authorization.sessionId === approval.sessionId &&
    authorization.serverId === approval.route.serverId &&
    authorization.routeId === approval.route.routeId &&
    authorization.toolName === approval.route.toolName &&
    authorization.schemaDigest === approval.route.schemaDigest &&
    authorization.credentialAudienceId === approval.route.credentialAudienceId &&
    authorization.policyScopeId === approval.route.policyScopeId &&
    authorization.resourcesDigest === approval.resourcesDigest &&
    authorization.environment === approval.environment &&
    authorization.dataFlowDigest === approval.dataFlowDigest &&
    authorization.policyVersion === approval.policyVersion;
}

export class PostgresTrajectoryStoreV1 {
  readonly #pool: Pool;
  readonly #knownSecrets: readonly string[];

  private constructor(pool: Pool, knownSecrets: readonly string[]) {
    this.#pool = pool;
    this.#knownSecrets = knownSecrets;
  }

  public static async connect(configInput: PostgresPersistenceConfigV1): Promise<PostgresTrajectoryStoreV1> {
    const config = postgresPersistenceConfigV1Schema.parse(configInput);
    const pool = new Pool({
      connectionString: config.connectionString,
      application_name: config.applicationName,
      connectionTimeoutMillis: config.connectionTimeoutMs,
      max: config.maxConnections
    });
    try {
      await pool.query("SELECT 1 AS persistence_health");
      await runForwardMigrationsV1(
        pool,
        config.migrationsDirectory ?? resolve(process.cwd(), "migrations")
      );
      return new PostgresTrajectoryStoreV1(pool, Object.freeze([...config.knownSecretValues]));
    } catch {
      await pool.end().catch(() => undefined);
      throw new PersistenceUnavailableV1();
    }
  }

  public static async connectFromEnvironment(
    environment: NodeJS.ProcessEnv = process.env
  ): Promise<PostgresTrajectoryStoreV1> {
    const connectionString = environment["DATABASE_URL"];
    if (connectionString === undefined || connectionString.trim().length === 0) {
      throw new PersistenceUnavailableV1();
    }
    return PostgresTrajectoryStoreV1.connect({ connectionString });
  }

  public async close(): Promise<void> {
    await this.#pool.end();
  }

  public async persistDecisionTrajectory(input: {
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly binding: DownstreamServerRouteBindingV1;
    readonly inputSchema: Record<string, unknown>;
    readonly outputSchema: Record<string, unknown> | null;
    readonly request: ToolCallRequestV1;
    readonly action: CanonicalActionV1;
    readonly decision: PolicyDecisionV1;
    readonly policyDigest: string;
  }): Promise<void> {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    const binding = downstreamServerRouteBindingV1Schema.parse(input.binding);
    const inputSchema = boundedProtocolJsonObjectV1Schema.parse(input.inputSchema);
    const outputSchema = input.outputSchema === null
      ? null
      : boundedProtocolJsonObjectV1Schema.parse(input.outputSchema);
    const request = toolCallRequestV1Schema.parse(input.request);
    const action = canonicalActionV1Schema.parse(input.action);
    const decision = policyDecisionV1Schema.parse(input.decision);
    canonicalActionDecisionBindingV1Schema.parse({ action, decision });
    const policyDigest = z.string().regex(/^[a-f0-9]{64}$/u).parse(input.policyDigest);
    const { actionHash, ...actionHashInput } = action;
    if (request.argumentsDigest !== computeCanonicalDigestV1(request.arguments) ||
      request.payloadBytes !== computeCanonicalJsonByteLengthV1(request.arguments) ||
      actionHash !== computeCanonicalDigestV1(actionHashInput) ||
      !this.#decisionBindingsMatch(session, binding, request, action, decision)) {
      throw new PersistenceDeniedV1();
    }
    this.#assertSecretFree({ session, binding, inputSchema, outputSchema, request, action, decision });

    await this.#transaction(async (client) => {
      const identityKey = computeCanonicalDigestV1(session.identity);
      const clientInstanceKey = computeCanonicalDigestV1({
        clientId: session.identity.clientId,
        identityKey
      });
      await this.#persistFoundation(client, {
        session, binding, inputSchema, outputSchema, policyDigest,
        policyVersion: decision.policyVersion, identityKey, clientInstanceKey,
        occurredAt: request.requestedAt
      });
      await client.query(
        `INSERT INTO requests(request_id, protocol_request_id, state_namespace, route_id,
          schema_digest, arguments_digest, payload_bytes, nonce, call_chain_id, requested_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [request.requestId, String(request.protocolRequestId), session.stateNamespace,
          binding.route.routeId, request.route.schemaDigest, request.argumentsDigest,
          request.payloadBytes, request.nonce, request.callChain.callChainId, request.requestedAt]
      );
      await client.query(
        `INSERT INTO canonical_actions(action_id, request_id, action_hash, resources_digest,
          data_flow_digest, effect, environment, redacted_document, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`,
        [action.actionId, action.requestId, action.actionHash, action.resourcesDigest,
          action.dataFlowDigest, action.effect, action.environment, JSON.stringify(action), action.createdAt]
      );
      await client.query(
        `INSERT INTO decisions(decision_id, request_id, action_id, policy_version, decision,
          tier, coverage, redacted_document, decided_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`,
        [decision.decisionId, decision.requestId, decision.actionId, decision.policyVersion,
          decision.decision, decision.tier, decision.coverage, JSON.stringify(decision), decision.decidedAt]
      );
      for (const [position, reason] of decision.reasonCodes.entries()) {
        await client.query(
          "INSERT INTO decision_reasons(decision_id, position, reason_code) VALUES ($1,$2,$3)",
          [decision.decisionId, position, reason]
        );
      }
      await this.#appendEvent(client, {
        eventId: randomUUID(),
        eventType: decision.decision === "DENY" ? "DENIED" : "DECIDED",
        requestId: request.requestId,
        stateNamespace: session.stateNamespace,
        forwardingAttemptId: null,
        actorId: "policy-engine",
        reasonCodes: decision.reasonCodes,
        evidenceDigest: computeCanonicalDigestV1({
          actionHash: action.actionHash,
          decisionId: decision.decisionId,
          policyVersion: decision.policyVersion
        }),
        occurredAt: decision.decidedAt
      });
    });
  }

  public async persistApproval(approvalInput: ApprovalV1): Promise<void> {
    const approval = approvalV1Schema.parse(approvalInput);
    this.#assertSecretFree(approval);
    await this.#transaction(async (client) => {
      await this.#requireImmutableMatch(client.query(
        `INSERT INTO approvals(approval_id, decision_id, request_id, action_id, state,
          action_hash, policy_version, requested_at, decided_at, expires_at,
          decided_by_human_id, consumption_id, consumed_at, forwarding_attempt_id,
          redacted_document)
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb
         FROM decisions d
         JOIN canonical_actions a ON a.action_id = d.action_id
         JOIN requests r ON r.request_id = d.request_id
         JOIN routes rt ON rt.route_id = r.route_id
         WHERE d.decision_id = $2 AND d.request_id = $3 AND d.action_id = $4
           AND d.policy_version = $7 AND d.decision = 'REQUIRE_APPROVAL'
           AND a.action_hash = $6 AND r.state_namespace = $16
           AND rt.server_id = $17 AND rt.route_id = $18 AND rt.tool_name = $19
           AND rt.schema_digest = $20 AND rt.policy_scope_id = $21
           AND rt.environment = $22`,
        [approval.approvalId, approval.decisionId, approval.requestId, approval.actionId,
          approval.state, approval.actionHash, approval.policyVersion, approval.requestedAt,
          approval.decidedAt, approval.expiresAt, approval.decidedByHumanId,
          approval.consumption?.consumptionId ?? null,
          approval.consumption?.consumedAt ?? null,
          approval.consumption?.forwardingAttemptId ?? null, JSON.stringify(approval),
          approval.sessionId, approval.route.serverId, approval.route.routeId,
          approval.route.toolName, approval.route.schemaDigest,
          approval.route.policyScopeId, approval.environment]
      ));
      if (approval.state === "APPROVED") {
        await this.#appendEvent(client, {
          eventId: randomUUID(), eventType: "APPROVED", requestId: approval.requestId,
          stateNamespace: approval.sessionId, forwardingAttemptId: null,
          actorId: approval.decidedByHumanId ?? "approval-service", reasonCodes: [],
          evidenceDigest: computeCanonicalDigestV1({
            approvalId: approval.approvalId,
            actionHash: approval.actionHash,
            policyVersion: approval.policyVersion
          }), occurredAt: approval.decidedAt ?? approval.requestedAt
        });
      }
    });
  }

  public async consumeApprovalAndStartForwarding(
    authorizationInput: ApprovedForwardingAuthorizationV1
  ): Promise<void> {
    const authorization = approvedForwardingAuthorizationV1Schema.parse(authorizationInput);
    this.#assertSecretFree(authorization);
    const client = await this.#pool.connect();
    let denial: "MODIFIED" | "REPLAYED" | null = null;
    try {
      await client.query("BEGIN");
      const selected = await client.query<ApprovalRowV1>(
        `SELECT a.state, a.decision_id, a.expires_at > clock_timestamp() AS unexpired,
           a.redacted_document,
           ca.redacted_document AS action_document,
           (s.status = 'ACTIVE'
             AND d.decision = 'REQUIRE_APPROVAL' AND d.coverage = 'ENFORCED'
             AND d.policy_version = a.policy_version
             AND r.state_namespace = a.redacted_document->>'sessionId'
             AND r.route_id = a.redacted_document->'route'->>'routeId'
             AND r.schema_digest = a.redacted_document->'route'->>'schemaDigest'
             AND rt.server_id = a.redacted_document->'route'->>'serverId'
             AND rt.tool_name = a.redacted_document->'route'->>'toolName'
             AND rt.policy_scope_id = a.redacted_document->'route'->>'policyScopeId'
             AND rt.environment = a.redacted_document->>'environment'
             AND rt.document->>'status' = 'ACTIVE'
             AND rt.document->'schemaIntegrity'->>'state' = 'VERIFIED'
             AND sv.document->'health'->>'state' = 'HEALTHY'
             AND sv.document->'capabilityIntegrity'->>'state' = 'VERIFIED'
             AND NOT EXISTS (
               SELECT 1 FROM identities newer
               WHERE newer.user_id = i.user_id AND newer.agent_id = i.agent_id
                 AND newer.host_id = i.host_id
                 AND (newer.identity_revision > i.identity_revision
                   OR newer.credential_id <> i.credential_id)
             )) AS current_state_valid
         FROM approvals a
         JOIN decisions d ON d.decision_id = a.decision_id
         JOIN canonical_actions ca ON ca.action_id = a.action_id
         JOIN requests r ON r.request_id = a.request_id
         JOIN sessions s ON s.state_namespace = r.state_namespace
         JOIN identities i ON i.identity_key = s.identity_key
         JOIN routes rt ON rt.route_id = r.route_id
         JOIN servers sv ON sv.server_id = rt.server_id
         JOIN policies p ON p.policy_version = d.policy_version
         WHERE a.approval_id = $1
         FOR UPDATE OF a, d, ca, r, s, i, rt, sv, p`,
        [authorization.approvalId]
      );
      const row = selected.rows[0];
      if (row === undefined) {
        await client.query("ROLLBACK");
        throw new PersistenceDeniedV1();
      }
      const approval = approvalV1Schema.parse(row.redacted_document);
      const action = canonicalActionV1Schema.parse(row.action_document);
      const coverageRows = await client.query<CoverageEventRowV1>(
        `SELECT report_document
         FROM (
           SELECT DISTINCT ON (resource_id) resource_id, report_document, coverage, valid_until
           FROM coverage_events
           WHERE state_namespace = $1 AND server_id = $2 AND route_id = $3
             AND policy_scope_id = $4 AND environment = $5
           ORDER BY resource_id, occurred_at DESC, assessment_revision DESC
         ) latest
         WHERE coverage = 'ENFORCED' AND valid_until > clock_timestamp()`,
        [authorization.sessionId, authorization.serverId, authorization.routeId,
          authorization.policyScopeId, authorization.environment]
      );
      const coverage = coverageRows.rows.map((item) =>
        exclusiveMediationAssessmentV1Schema.parse(item.report_document));
      const coveredResourceIds = new Set(coverage.flatMap((item) =>
        item.coverage === "ENFORCED" && item.mutationAllowed &&
        item.scope.schemaDigest === authorization.schemaDigest &&
        item.scope.credentialAudienceId === authorization.credentialAudienceId &&
        item.scope.resourcesDigest === authorization.resourcesDigest &&
        coverageScopeMatchesActionV1(item.scope, action)
          ? [item.scope.resourceId] : []));
      const coverageValid = action.resources.every((resource) => coveredResourceIds.has(resource.resourceId));
      if (row.state !== "APPROVED" || !row.unexpired) {
        denial = "REPLAYED";
      } else if (!row.current_state_valid || !coverageValid ||
        !exactAuthorizationMatchesApproval(authorization, approval)) {
        denial = "MODIFIED";
      }
      if (denial !== null) {
        await this.#appendEvent(client, {
          eventId: randomUUID(), eventType: denial, requestId: approval.requestId,
          stateNamespace: approval.sessionId,
          forwardingAttemptId: authorization.forwardingAttemptId,
          actorId: "forwarding-coordinator", reasonCodes: [`forwarding.${denial.toLowerCase()}`],
          evidenceDigest: computeCanonicalDigestV1(authorization),
          occurredAt: authorization.authorizedAt
        });
        await client.query("COMMIT");
      } else {
        await this.#requireImmutableMatch(client.query(
          `UPDATE approvals SET state = 'CONSUMED', consumption_id = $2,
            consumed_at = $3, forwarding_attempt_id = $4,
            redacted_document = jsonb_set(jsonb_set(redacted_document, '{state}', '"CONSUMED"'),
              '{consumption}', $5::jsonb)
           WHERE approval_id = $1`,
          [authorization.approvalId, `db:${authorization.forwardingAttemptId}`,
            authorization.authorizedAt, authorization.forwardingAttemptId,
            JSON.stringify({ consumptionId: `db:${authorization.forwardingAttemptId}`,
              consumedAt: authorization.authorizedAt,
              forwardingAttemptId: authorization.forwardingAttemptId })]
        ));
        await client.query(
          `INSERT INTO forwarding_attempts(forwarding_attempt_id, request_id, action_id,
            decision_id, approval_id, route_id, state, authorization_digest,
            authorized_at, forwarding_started_at)
           VALUES ($1,$2,$3,$4,$5,$6,'FORWARDING',$7,$8,$8)`,
          [authorization.forwardingAttemptId, authorization.requestId, authorization.actionId,
            row.decision_id, authorization.approvalId, authorization.routeId,
            computeCanonicalDigestV1(authorization), authorization.authorizedAt]
        );
        await this.#appendEvent(client, {
          eventId: randomUUID(), eventType: "FORWARDED", requestId: authorization.requestId,
          stateNamespace: authorization.sessionId,
          forwardingAttemptId: authorization.forwardingAttemptId,
          actorId: "forwarding-coordinator", reasonCodes: [],
          evidenceDigest: computeCanonicalDigestV1(authorization),
          occurredAt: authorization.authorizedAt
        });
        await client.query("COMMIT");
      }
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (error instanceof PersistenceDeniedV1) throw error;
      throw new PersistenceDeniedV1();
    } finally {
      client.release();
    }
    if (denial !== null) throw new PersistenceDeniedV1();
  }

  public async recordResultAndOutcome(input: {
    readonly authorization: ApprovedForwardingAuthorizationV1;
    readonly provenance: DownstreamProvenanceV1;
    readonly result: DownstreamResultV1;
    readonly outcome: ExecutionOutcomeV1;
    readonly trustEvidenceId?: string;
  }): Promise<void> {
    const authorization = approvedForwardingAuthorizationV1Schema.parse(input.authorization);
    const provenance = downstreamProvenanceV1Schema.parse(input.provenance);
    const result = downstreamResultV1Schema.parse(input.result);
    const outcome = executionOutcomeV1Schema.parse(input.outcome);
    if (!this.#resultBindingsMatch(authorization, provenance, result, outcome)) {
      throw new PersistenceDeniedV1();
    }
    this.#assertSecretFree({ authorization, provenance, result, outcome });
    await this.#transaction(async (client) => {
      await client.query(
        `INSERT INTO result_provenance(provenance_id, request_id, forwarding_attempt_id,
          server_id, route_id, schema_digest, call_chain_id, authenticated_principal_id,
          transport_evidence_digest, received_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [provenance.provenanceId, provenance.requestId, authorization.forwardingAttemptId,
          provenance.serverId, provenance.routeId, provenance.schemaDigest,
          provenance.callChainId, provenance.authenticatedPrincipalId,
          provenance.transportEvidenceDigest, provenance.receivedAt]
      );
      await client.query(
        `INSERT INTO results(result_id, provenance_id, request_id, action_id, disposition,
          schema_validation, content_digest, byte_length, redacted_metadata, processed_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`,
        [result.resultId, result.provenanceId, result.requestId, result.actionId,
          result.disposition, result.schemaValidation, result.contentDigest,
          result.byteLength, JSON.stringify(result), result.processedAt]
      );
      await this.#insertOutcome(client, outcome);
      await this.#requireImmutableMatch(client.query(
        `UPDATE forwarding_attempts SET state = $2, finished_at = $3
         WHERE forwarding_attempt_id = $1 AND state = 'FORWARDING'`,
        [authorization.forwardingAttemptId, outcome.status, outcome.finishedAt]
      ));
      await this.#appendEvent(client, {
        eventId: randomUUID(), eventType: "RESULT_RECORDED", requestId: result.requestId,
        stateNamespace: result.sessionId, forwardingAttemptId: authorization.forwardingAttemptId,
        actorId: "result-guard", reasonCodes: result.untrustedContentMarkers,
        evidenceDigest: computeCanonicalDigestV1(result), occurredAt: result.processedAt
      });
      await this.#appendEvent(client, {
        eventId: randomUUID(), eventType: outcomeEventType(outcome), requestId: outcome.requestId,
        stateNamespace: outcome.sessionId, forwardingAttemptId: outcome.forwardingAttemptId,
        actorId: "outcome-recorder", reasonCodes: [],
        evidenceDigest: computeCanonicalDigestV1(outcome), occurredAt: outcome.observedAt
      });
      if (outcome.trustEvidenceEligible) {
        const trustEvidenceId = identifierV1Schema.parse(input.trustEvidenceId);
        await client.query(
          `INSERT INTO trust_evidence(trust_evidence_id, outcome_id, state_namespace,
            policy_scope_id, evidence_digest, eligible, mode, recorded_at)
           VALUES ($1,$2,$3,$4,$5,true,'SHADOW',$6)`,
          [trustEvidenceId, outcome.outcomeId, outcome.sessionId,
            authorization.policyScopeId, computeCanonicalDigestV1(outcome), outcome.observedAt]
        );
        await this.#appendEvent(client, {
          eventId: randomUUID(), eventType: "TRUST_RECORDED", requestId: outcome.requestId,
          stateNamespace: outcome.sessionId,
          forwardingAttemptId: outcome.forwardingAttemptId,
          actorId: "trust-shadow", reasonCodes: ["trust.shadow_only"],
          evidenceDigest: computeCanonicalDigestV1(outcome), occurredAt: outcome.observedAt
        });
      }
    });
  }

  public async recordTerminalOutcome(outcomeInput: ExecutionOutcomeV1): Promise<void> {
    const outcome = executionOutcomeV1Schema.parse(outcomeInput);
    if (outcome.resultId !== null || outcome.provenanceId !== null ||
      outcome.trustEvidenceEligible) throw new PersistenceDeniedV1();
    this.#assertSecretFree(outcome);
    await this.#transaction(async (client) => {
      await this.#insertOutcome(client, outcome);
      if (outcome.forwardingAttemptId !== null) {
        await this.#requireImmutableMatch(client.query(
          `UPDATE forwarding_attempts SET state = $2, finished_at = $3
           WHERE forwarding_attempt_id = $1 AND state = 'FORWARDING'`,
          [outcome.forwardingAttemptId, outcome.status, outcome.finishedAt]
        ));
      }
      await this.#appendEvent(client, {
        eventId: randomUUID(), eventType: outcomeEventType(outcome),
        requestId: outcome.requestId, stateNamespace: outcome.sessionId,
        forwardingAttemptId: outcome.forwardingAttemptId, actorId: "outcome-recorder",
        reasonCodes: [], evidenceDigest: computeCanonicalDigestV1(outcome),
        occurredAt: outcome.observedAt
      });
    });
  }

  public async appendSecurityEvent(eventInput: SecurityEventInputV1): Promise<PersistedSecurityEventV1> {
    const event = securityEventInputV1Schema.parse(eventInput);
    this.#assertSecretFree(event);
    return this.#transaction(async (client) => this.#appendEvent(client, event));
  }

  public async persistCoverageAssessment(
    assessmentInput: ExclusiveMediationAssessmentV1
  ): Promise<void> {
    const assessment = exclusiveMediationAssessmentV1Schema.parse(assessmentInput);
    this.#assertSecretFree(assessment);
    await this.#transaction(async (client) => {
      await client.query(
        `INSERT INTO coverage_events(coverage_event_id,state_namespace,coverage,
          evidence_digest,occurred_at,scope_id,server_id,route_id,policy_scope_id,
          environment,resource_class,resource_id,assessment_revision,assurance,
          reason_codes,report_document,valid_until)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17)`,
        [assessment.assessmentId, assessment.scope.stateNamespace, assessment.coverage,
          assessment.evidenceDigest, assessment.assessedAt,
          computeCanonicalDigestV1(assessment.scope), assessment.scope.serverId,
          assessment.scope.routeId, assessment.scope.policyScopeId,
          assessment.scope.environment, assessment.scope.resourceClass,
          assessment.scope.resourceId, assessment.revision, assessment.assurance,
          assessment.missingGuarantees.map((item) => item.reasonCode),
          JSON.stringify(assessment), assessment.expiresAt]
      );
      for (const evidence of assessment.evidence) {
        await client.query(
          `INSERT INTO coverage_control_evidence(evidence_id,coverage_event_id,
            guarantee,path_kind,verifier_id,authority,verifier_class,assurance,status,
            revision,proof_digest,observed_at,expires_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [evidence.evidenceId, assessment.assessmentId, evidence.guarantee,
            evidence.pathKind, evidence.verifierId, evidence.authority,
            evidence.verifierClass, evidence.assurance, evidence.status,
            evidence.revision, evidence.proofDigest,
            evidence.observedAt, evidence.expiresAt]
        );
      }
      if (assessment.coverage !== "ENFORCED") {
        await this.#appendEvent(client, {
          eventId: randomUUID(),
          eventType: "BYPASS",
          requestId: null,
          stateNamespace: assessment.scope.stateNamespace,
          forwardingAttemptId: null,
          actorId: "coverage-monitor",
          reasonCodes: assessment.missingGuarantees.map((item) => item.reasonCode),
          evidenceDigest: assessment.evidenceDigest,
          occurredAt: assessment.assessedAt
        });
      }
    });
  }

  public async readLatestCoverageAssessment(
    scopeInput: ExclusiveMediationAssessmentV1["scope"]
  ): Promise<ExclusiveMediationAssessmentV1 | null> {
    const scopeDigest = computeCanonicalDigestV1(scopeInput);
    const result = await this.#pool.query<CoverageEventRowV1>(
      `SELECT report_document FROM coverage_events
       WHERE scope_id = $1 ORDER BY occurred_at DESC, assessment_revision DESC LIMIT 1`,
      [scopeDigest]
    );
    const document = result.rows[0]?.report_document;
    return document === undefined ? null : exclusiveMediationAssessmentV1Schema.parse(document);
  }

  public async persistTrustworthyInterface(input: {
    readonly view: TrustworthyActionInterfaceV1;
    readonly awareness: AwarenessV1;
    readonly presentedEvent: ApprovalFatigueEventV1;
  }): Promise<void> {
    const view = trustworthyActionInterfaceV1Schema.parse(input.view);
    const awareness = awarenessV1Schema.parse(input.awareness);
    const event = approvalFatigueEventV1Schema.parse(input.presentedEvent);
    if (awareness.requestId !== view.requestId || awareness.actionId !== view.actionId ||
      awareness.decisionId !== view.decisionId || awareness.sessionId !== view.requester.sessionId ||
      awareness.coverage !== view.coverage || event.eventType !== "PRESENTED" ||
      event.interfaceId !== view.interfaceId || event.policyScopeId !== view.route.policyScopeId ||
      event.relatedAttemptCount !== view.relatedAttemptIds.length) {
      throw new PersistenceDeniedV1();
    }
    this.#assertSecretFree({ view, awareness, event });
    await this.#transaction(async (client) => {
      await client.query(
        `INSERT INTO trustworthy_interface_views(interface_id,request_id,action_id,
          decision_id,coverage_event_id,policy_scope_id,view_digest,awareness_digest,
          view_document,awareness_document,presented_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)`,
        [view.interfaceId, view.requestId, view.actionId, view.decisionId,
          view.coverageAssessmentId, view.route.policyScopeId,
          computeCanonicalDigestV1(view), computeCanonicalDigestV1(awareness),
          JSON.stringify(view), JSON.stringify(awareness), event.occurredAt]
      );
      await this.#insertFatigueEvent(client, event);
    });
  }

  public async persistApprovalFatigueEvent(eventInput: ApprovalFatigueEventV1): Promise<void> {
    const event = approvalFatigueEventV1Schema.parse(eventInput);
    this.#assertSecretFree(event);
    await this.#transaction(async (client) => this.#insertFatigueEvent(client, event));
  }

  public async persistSupervisorAssessment(assessmentInput: SupervisorAssessmentAuditV1): Promise<void> {
    const assessment = supervisorAssessmentAuditV1Schema.parse(assessmentInput);
    this.#assertSecretFree(assessment);
    await this.#transaction(async (client) => {
      const binding = await client.query<{
        request_id: string; state_namespace: string; action_id: string; action_hash: string;
        decision_id: string; policy_version: string; route_id: string; schema_digest: string;
        policy_scope_id: string;
      }>(
        `SELECT r.request_id, r.state_namespace, ca.action_id, ca.action_hash,
          d.decision_id, d.policy_version, r.route_id, r.schema_digest, rt.policy_scope_id
         FROM requests r JOIN canonical_actions ca ON ca.request_id = r.request_id
         JOIN decisions d ON d.request_id = r.request_id JOIN routes rt ON rt.route_id = r.route_id
         WHERE r.request_id = $1`,
        [assessment.requestId]
      );
      const row = binding.rows[0];
      if (row === undefined || row.action_id !== assessment.actionId || row.action_hash !== assessment.actionHash ||
        row.state_namespace !== assessment.sessionId || row.decision_id !== assessment.decisionId ||
        row.route_id !== assessment.routeId || row.schema_digest !== assessment.schemaDigest ||
        row.policy_version !== assessment.policyVersion || row.policy_scope_id !== assessment.policyScopeId) {
        throw new PersistenceDeniedV1();
      }
      await client.query(
        `INSERT INTO supervisor_assessments(assessment_id,request_id,provider_id,model_id,
          response_digest,advisory_only,assessed_at,action_id,action_hash,decision_id,
          session_id,policy_scope_id,schema_digest,policy_version,prompt_version,input_digest,
          redaction_digest,latency_ms,status,external_submission,fallback_used,failure_code,
          reason_codes,assessment_document,audit_digest)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb,$25)`,
        [assessment.assessmentId, assessment.requestId, assessment.providerId, assessment.modelId,
          assessment.responseDigest, assessment.advisoryOnly, assessment.assessedAt,
          assessment.actionId, assessment.actionHash, assessment.decisionId, assessment.sessionId,
          assessment.policyScopeId, assessment.schemaDigest, assessment.policyVersion,
          assessment.promptVersion, assessment.inputDigest, assessment.redaction.evidenceDigest,
          assessment.latencyMs, assessment.status, assessment.externalSubmission, assessment.fallbackUsed,
          assessment.failureCode, assessment.advisory.reasonCodes, JSON.stringify(assessment), assessment.auditDigest]
      );
      await this.#appendEvent(client, {
        eventId: randomUUID(), eventType: "SUPERVISOR_ASSESSED", requestId: assessment.requestId,
        stateNamespace: assessment.sessionId, forwardingAttemptId: null, actorId: "supervisor",
        reasonCodes: assessment.advisory.reasonCodes, evidenceDigest: assessment.auditDigest,
        occurredAt: assessment.assessedAt
      });
    });
  }

  public async readSupervisorAssessments(): Promise<readonly SupervisorAssessmentAuditV1[]> {
    const result = await this.#pool.query<{ assessment_document: unknown }>(
      "SELECT assessment_document FROM supervisor_assessments WHERE assessment_document ? 'schemaVersion' ORDER BY assessed_at, assessment_id"
    );
    return result.rows.map((row) => supervisorAssessmentAuditV1Schema.parse(row.assessment_document));
  }

  public async readApprovalFatigueMetrics(
    policyScopeIdInput: string,
    recordedAt = new Date().toISOString()
  ): Promise<ApprovalFatigueMetricsV1> {
    const policyScopeId = identifierV1Schema.parse(policyScopeIdInput);
    const result = await this.#pool.query<{
      presentations: string; approvals: string; denials: string; expirations: string;
      revocations: string; approval_errors: string; repeated_attempts: string;
      mean_latency: string | null;
    }>(
      `SELECT count(*) FILTER (WHERE event_type='PRESENTED') AS presentations,
        count(*) FILTER (WHERE event_type='APPROVED') AS approvals,
        count(*) FILTER (WHERE event_type='DENIED') AS denials,
        count(*) FILTER (WHERE event_type='EXPIRED') AS expirations,
        count(*) FILTER (WHERE event_type='REVOKED') AS revocations,
        count(*) FILTER (WHERE event_type='ERROR') AS approval_errors,
        coalesce(sum(related_attempt_count),0) AS repeated_attempts,
        avg(decision_latency_ms) FILTER (WHERE decision_latency_ms IS NOT NULL) AS mean_latency
       FROM approval_fatigue_events WHERE policy_scope_id=$1`,
      [policyScopeId]
    );
    const row = result.rows[0];
    return approvalFatigueMetricsV1Schema.parse({
      schemaVersion: "1.0.0", policyScopeId,
      presentations: Number(row?.presentations ?? 0), approvals: Number(row?.approvals ?? 0),
      denials: Number(row?.denials ?? 0), expirations: Number(row?.expirations ?? 0),
      revocations: Number(row?.revocations ?? 0), approvalErrors: Number(row?.approval_errors ?? 0),
      repeatedRelatedAttempts: Number(row?.repeated_attempts ?? 0),
      meanDecisionLatencyMs: Number(row?.mean_latency ?? 0), recordedAt
    });
  }

  public async persistRecoveryRecord(input: {
    readonly recoveryId: string;
    readonly outcome: ExecutionOutcomeV1;
    readonly evidenceDigest: string;
    readonly recordedAt: string;
  }): Promise<void> {
    const recoveryId = identifierV1Schema.parse(input.recoveryId);
    const outcome = executionOutcomeV1Schema.parse(input.outcome);
    const evidenceDigest = z.string().regex(/^[a-f0-9]{64}$/u).parse(input.evidenceDigest);
    const recordedAt = z.iso.datetime({ offset: true }).parse(input.recordedAt);
    this.#assertSecretFree({ recoveryId, outcome, evidenceDigest, recordedAt });
    await this.#transaction(async (client) => {
      await client.query(
        `INSERT INTO recovery_records(recovery_id,outcome_id,recovery_class,evidence_digest,recorded_at)
         VALUES ($1,$2,$3,$4,$5)`,
        [recoveryId, outcome.outcomeId, outcome.recoveryClass, evidenceDigest, recordedAt]
      );
    });
  }

  public async readSecurityEvents(): Promise<readonly PersistedSecurityEventV1[]> {
    const result = await this.#pool.query<SecurityEventRowV1>(
      "SELECT * FROM security_events ORDER BY sequence_id"
    );
    return result.rows.map((row) => persistedSecurityEventV1Schema.parse({
      sequenceId: Number(row.sequence_id), eventId: row.event_id, eventType: row.event_type,
      requestId: row.request_id, stateNamespace: row.state_namespace,
      forwardingAttemptId: row.forwarding_attempt_id, actorId: row.actor_id,
      reasonCodes: row.reason_codes, evidenceDigest: row.evidence_digest,
      previousHash: row.previous_hash, eventHash: row.event_hash,
      occurredAt: row.occurred_at.toISOString()
    }));
  }

  public async verifySecurityEventChain(): Promise<boolean> {
    const events = await this.readSecurityEvents();
    let previousHash = "0".repeat(64);
    for (const event of events) {
      const storedPrevious = event.previousHash;
      const storedHash = event.eventHash;
      const input = securityEventInputV1Schema.parse({
        eventId: event.eventId, eventType: event.eventType, requestId: event.requestId,
        stateNamespace: event.stateNamespace,
        forwardingAttemptId: event.forwardingAttemptId, actorId: event.actorId,
        reasonCodes: event.reasonCodes, evidenceDigest: event.evidenceDigest,
        occurredAt: event.occurredAt
      });
      if (storedPrevious !== previousHash || eventHash(previousHash, input) !== storedHash) {
        return false;
      }
      previousHash = storedHash;
    }
    return true;
  }

  /** Test-only diagnostics contain counts, never stored documents. */
  public async tableCounts(): Promise<Record<string, number>> {
    const tables = ["identities", "clients", "sessions", "servers", "schema_versions",
      "routes", "requests", "canonical_actions", "decisions", "approvals",
      "forwarding_attempts", "result_provenance", "results", "outcomes",
      "security_events", "trust_evidence", "coverage_events", "coverage_control_evidence",
      "trustworthy_interface_views", "approval_fatigue_events", "recovery_records", "supervisor_assessments"];
    const counts: Record<string, number> = {};
    for (const table of tables) {
      const result = await this.#pool.query<{ count: string }>(`SELECT count(*) AS count FROM ${table}`);
      counts[table] = Number(result.rows[0]?.count ?? 0);
    }
    return counts;
  }

  #assertSecretFree(value: unknown): void {
    const serialized = JSON.stringify(value);
    if (this.#knownSecrets.some((secret) => serialized.includes(secret))) {
      throw new SecretPersistenceDeniedV1();
    }
  }

  #decisionBindingsMatch(
    session: AuthenticatedSessionIdentityBindingV1,
    binding: DownstreamServerRouteBindingV1,
    request: ToolCallRequestV1,
    action: CanonicalActionV1,
    decision: PolicyDecisionV1
  ): boolean {
    return request.sessionId === session.stateNamespace && action.sessionId === session.stateNamespace &&
      action.requestId === request.requestId && decision.requestId === request.requestId &&
      request.route.routeId === binding.route.routeId && action.route.routeId === binding.route.routeId &&
      request.route.serverId === binding.server.serverId && action.route.serverId === binding.server.serverId &&
      request.route.schemaDigest === binding.route.schemaIntegrity.registeredDigest &&
      action.route.schemaDigest === binding.route.schemaIntegrity.registeredDigest &&
      request.argumentsDigest === action.arguments.digest &&
      action.identity.userId === session.identity.userId &&
      action.identity.agentId === session.identity.agentId &&
      action.identity.clientId === session.identity.clientId &&
      action.identity.hostId === session.identity.hostId;
  }

  #resultBindingsMatch(
    authorization: ApprovedForwardingAuthorizationV1,
    provenance: DownstreamProvenanceV1,
    result: DownstreamResultV1,
    outcome: ExecutionOutcomeV1
  ): boolean {
    return provenance.requestId === authorization.requestId &&
      provenance.actionId === authorization.actionId &&
      provenance.sessionId === authorization.sessionId &&
      provenance.serverId === authorization.serverId &&
      provenance.routeId === authorization.routeId &&
      provenance.schemaDigest === authorization.schemaDigest &&
      result.provenanceId === provenance.provenanceId &&
      result.requestId === authorization.requestId && result.actionId === authorization.actionId &&
      result.sessionId === authorization.sessionId && result.serverId === authorization.serverId &&
      result.routeId === authorization.routeId && result.schemaDigest === authorization.schemaDigest &&
      outcome.requestId === authorization.requestId && outcome.actionId === authorization.actionId &&
      outcome.approvalId === authorization.approvalId &&
      outcome.forwardingAttemptId === authorization.forwardingAttemptId &&
      outcome.resultId === result.resultId && outcome.provenanceId === provenance.provenanceId &&
      outcome.status === "COMPLETED" &&
      (!outcome.trustEvidenceEligible || result.disposition === "ALLOW");
  }

  async #persistFoundation(client: PoolClient, input: {
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly binding: DownstreamServerRouteBindingV1;
    readonly inputSchema: Record<string, unknown>;
    readonly outputSchema: Record<string, unknown> | null;
    readonly policyDigest: string;
    readonly policyVersion: string;
    readonly identityKey: string;
    readonly clientInstanceKey: string;
    readonly occurredAt: string;
  }): Promise<void> {
    const identityDigest = computeCanonicalDigestV1(input.session.identity);
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO identities(identity_key,user_id,agent_id,host_id,credential_id,
        identity_revision,document_digest,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (identity_key) DO UPDATE SET identity_key = EXCLUDED.identity_key
       WHERE identities.document_digest = EXCLUDED.document_digest`,
      [input.identityKey, input.session.identity.userId, input.session.identity.agentId,
        input.session.identity.hostId, input.session.identity.credentialId,
        input.session.identity.identityRevision, identityDigest, input.occurredAt]
    ));
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO clients(client_instance_key,client_id,identity_key,document_digest,created_at)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (client_instance_key) DO UPDATE
       SET client_instance_key = EXCLUDED.client_instance_key
       WHERE clients.document_digest = EXCLUDED.document_digest`,
      [input.clientInstanceKey, input.session.identity.clientId, input.identityKey,
        computeCanonicalDigestV1({ clientId: input.session.identity.clientId,
          identityKey: input.identityKey }), input.occurredAt]
    ));
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO sessions(state_namespace,transport_session_id,identity_key,
        client_instance_key,status,document_digest,created_at,updated_at)
       VALUES ($1,$2,$3,$4,'ACTIVE',$5,$6,$6) ON CONFLICT (state_namespace) DO UPDATE
       SET state_namespace = EXCLUDED.state_namespace
       WHERE sessions.document_digest = EXCLUDED.document_digest`,
      [input.session.stateNamespace, input.session.transportSessionId, input.identityKey,
        input.clientInstanceKey, computeCanonicalDigestV1(input.session), input.occurredAt]
    ));
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO servers(server_id,authenticated_principal_id,credential_audience_id,
        document,document_digest,registered_at) VALUES ($1,$2,$3,$4::jsonb,$5,$6)
       ON CONFLICT (server_id) DO UPDATE SET server_id = EXCLUDED.server_id
       WHERE servers.document_digest = EXCLUDED.document_digest`,
      [input.binding.server.serverId, input.binding.server.authenticatedPrincipalId,
        input.binding.server.credentialAudience.audienceId, JSON.stringify(input.binding.server),
        computeCanonicalDigestV1(input.binding.server), input.binding.server.registration.registeredAt]
    ));
    const schemaDocumentDigest = computeCanonicalDigestV1({
      inputSchema: input.inputSchema,
      outputSchema: input.outputSchema
    });
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO schema_versions(schema_digest,input_schema,output_schema,
        document_digest,registered_at)
       VALUES ($1,$2::jsonb,$3::jsonb,$4,$5) ON CONFLICT (schema_digest) DO UPDATE
       SET schema_digest = EXCLUDED.schema_digest
       WHERE schema_versions.document_digest = EXCLUDED.document_digest`,
      [input.binding.route.schemaIntegrity.registeredDigest,
        JSON.stringify(input.inputSchema), input.outputSchema === null ? null : JSON.stringify(input.outputSchema),
        schemaDocumentDigest, input.binding.route.registeredAt]
    ));
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO routes(route_id,server_id,schema_digest,tool_name,policy_scope_id,
        environment,document,document_digest,registered_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) ON CONFLICT (route_id) DO UPDATE
       SET route_id = EXCLUDED.route_id
       WHERE routes.document_digest = EXCLUDED.document_digest`,
      [input.binding.route.routeId, input.binding.server.serverId,
        input.binding.route.schemaIntegrity.registeredDigest, input.binding.route.toolName,
        input.binding.route.policyScopeId, input.binding.route.environment,
        JSON.stringify(input.binding.route), computeCanonicalDigestV1(input.binding.route),
        input.binding.route.registeredAt]
    ));
    await this.#requireImmutableMatch(client.query(
      `INSERT INTO policies(policy_version,policy_digest,activated_at) VALUES ($1,$2,$3)
       ON CONFLICT (policy_version) DO UPDATE SET policy_version = EXCLUDED.policy_version
       WHERE policies.policy_digest = EXCLUDED.policy_digest`,
      [input.policyVersion, input.policyDigest, input.occurredAt]
    ));
  }

  async #insertOutcome(client: PoolClient, outcome: ExecutionOutcomeV1): Promise<void> {
    await client.query(
      `INSERT INTO outcomes(outcome_id,request_id,action_id,decision_id,approval_id,
        forwarding_attempt_id,result_id,provenance_id,status,possible_partial_effects,
        recovery_class,trust_evidence_eligible,observed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [outcome.outcomeId, outcome.requestId, outcome.actionId, outcome.decisionId,
        outcome.approvalId, outcome.forwardingAttemptId, outcome.resultId,
        outcome.provenanceId, outcome.status, outcome.possiblePartialEffects,
        outcome.recoveryClass, outcome.trustEvidenceEligible, outcome.observedAt]
    );
    await client.query(
      `INSERT INTO recovery_records(recovery_id,outcome_id,recovery_class,evidence_digest,recorded_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [`recovery-${outcome.outcomeId}`, outcome.outcomeId, outcome.recoveryClass,
        computeCanonicalDigestV1({ outcomeId: outcome.outcomeId,
          recoveryClass: outcome.recoveryClass, possiblePartialEffects: outcome.possiblePartialEffects }),
        outcome.observedAt]
    );
  }

  async #insertFatigueEvent(client: PoolClient, event: ApprovalFatigueEventV1): Promise<void> {
    await client.query(
      `INSERT INTO approval_fatigue_events(event_id,interface_id,policy_scope_id,event_type,
        decision_latency_ms,related_attempt_count,occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [event.eventId, event.interfaceId, event.policyScopeId, event.eventType,
        event.decisionLatencyMs, event.relatedAttemptCount, event.occurredAt]
    );
  }

  async #requireImmutableMatch(
    query: Promise<{ readonly rowCount: number | null }>
  ): Promise<void> {
    const result = await query;
    if (result.rowCount !== 1) throw new PersistenceDeniedV1();
  }

  async #appendEvent(client: PoolClient, eventInput: SecurityEventInputV1): Promise<PersistedSecurityEventV1> {
    const event = securityEventInputV1Schema.parse(eventInput);
    this.#assertSecretFree(event);
    await client.query("SELECT pg_advisory_xact_lock(hashtext('agent-security:audit-chain:v1'))");
    const previous = await client.query<{ event_hash: string }>(
      "SELECT event_hash FROM security_events ORDER BY sequence_id DESC LIMIT 1"
    );
    const previousHash = previous.rows[0]?.event_hash ?? "0".repeat(64);
    const hash = eventHash(previousHash, event);
    const inserted = await client.query<{ sequence_id: string }>(
      `INSERT INTO security_events(event_id,event_type,request_id,state_namespace,
        forwarding_attempt_id,actor_id,reason_codes,evidence_digest,previous_hash,
        event_hash,occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING sequence_id`,
      [event.eventId, event.eventType, event.requestId, event.stateNamespace,
        event.forwardingAttemptId, event.actorId, event.reasonCodes,
        event.evidenceDigest, previousHash, hash, event.occurredAt]
    );
    return persistedSecurityEventV1Schema.parse({
      ...event,
      sequenceId: Number(inserted.rows[0]?.sequence_id),
      previousHash,
      eventHash: hash
    });
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
      throw error;
    } finally {
      client.release();
    }
  }
}
