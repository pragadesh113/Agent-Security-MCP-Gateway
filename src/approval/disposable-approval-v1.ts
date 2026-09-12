import { randomUUID } from "node:crypto";

import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  policyDecisionV1Schema,
  type ApprovalV1,
  type CanonicalActionV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import {
  capabilityIdentifierV1Schema,
  downstreamServerRouteBindingV1Schema,
  identifierV1Schema,
  utcTimestampV1Schema,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";
import type { SessionInvalidationSinkV1 } from "../identity/session-isolation-v1.js";

export const humanApprovalDecisionV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  approvalId: identifierV1Schema,
  actionHash: z.string().regex(/^[a-f0-9]{64}$/u),
  humanId: identifierV1Schema,
  authenticationMethod: z.enum(["LOCAL_TRUSTED_UI", "HARDWARE_ASSERTION", "TEST_FIXTURE"]),
  decision: z.enum(["APPROVE", "DENY"]),
  authenticatedAt: utcTimestampV1Schema
}).strict();

export const approvalAuditReaderAuthorityV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  administratorId: identifierV1Schema,
  role: z.literal("APPROVAL_AUDITOR"),
  authenticatedAt: utcTimestampV1Schema
}).strict();

export const approvedForwardingAuthorizationV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  forwardingAttemptId: identifierV1Schema,
  approvalId: identifierV1Schema,
  requestId: identifierV1Schema,
  actionId: identifierV1Schema,
  actionHash: z.string().regex(/^[a-f0-9]{64}$/u),
  sessionId: identifierV1Schema,
  serverId: identifierV1Schema,
  routeId: identifierV1Schema,
  toolName: capabilityIdentifierV1Schema,
  schemaDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  credentialAudienceId: identifierV1Schema,
  policyScopeId: identifierV1Schema,
  resourcesDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  environment: z.enum(["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"]),
  dataFlowDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  policyVersion: z.string().trim().min(1).max(64),
  authorizedAt: utcTimestampV1Schema
}).strict();

export const approvalAuditEventV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  eventId: identifierV1Schema,
  eventType: z.enum([
    "APPROVAL_REQUESTED", "HUMAN_APPROVED", "HUMAN_DENIED", "APPROVAL_EXPIRED",
    "APPROVAL_REVOKED", "CONSUMPTION_DENIED", "APPROVAL_CONSUMED",
    "FORWARDING_START_FAILED"
  ]),
  approvalId: identifierV1Schema,
  requestId: identifierV1Schema,
  actionId: identifierV1Schema,
  sessionId: identifierV1Schema,
  forwardingAttemptId: identifierV1Schema.nullable(),
  actorId: identifierV1Schema,
  evidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  reasonCodes: z.array(capabilityIdentifierV1Schema).max(32),
  occurredAt: utcTimestampV1Schema
}).strict();

export type HumanApprovalDecisionV1 = z.infer<typeof humanApprovalDecisionV1Schema>;
export type ApprovalAuditReaderAuthorityV1 = z.infer<typeof approvalAuditReaderAuthorityV1Schema>;
export type ApprovedForwardingAuthorizationV1 = z.infer<typeof approvedForwardingAuthorizationV1Schema>;
export type ApprovalAuditEventV1 = z.infer<typeof approvalAuditEventV1Schema>;

interface StoredApprovalV1 {
  approval: ApprovalV1;
  readonly action: CanonicalActionV1;
  readonly decision: PolicyDecisionV1;
  readonly session: AuthenticatedSessionIdentityBindingV1;
}

export class ApprovalDeniedV1 extends Error {
  public constructor() {
    super("Approval operation denied");
    this.name = "ApprovalDeniedV1";
  }
}

export interface DisposableApprovalServiceV1Options {
  readonly humanAuthorizer: (decision: HumanApprovalDecisionV1) => boolean;
  readonly auditAuthorizer: (authority: ApprovalAuditReaderAuthorityV1) => boolean;
  readonly identityRevalidator: (session: AuthenticatedSessionIdentityBindingV1) => boolean;
  readonly routeRevalidator: (action: CanonicalActionV1) => unknown;
  readonly policyRevalidator: (action: CanonicalActionV1) => unknown;
  readonly approvalLifetimeMs?: number;
  readonly clock?: () => Date;
  readonly approvalIdFactory?: () => string;
  readonly consumptionIdFactory?: () => string;
  readonly forwardingAttemptIdFactory?: () => string;
  readonly eventIdFactory?: () => string;
}

function actionHashIsValid(action: CanonicalActionV1): boolean {
  const { actionHash, ...hashInput } = action;
  return actionHash === computeCanonicalDigestV1(hashInput) &&
    action.resourcesDigest === computeCanonicalDigestV1(action.resources) &&
    action.dataFlowDigest === computeCanonicalDigestV1(action.dataFlow);
}

function exactApprovalBinding(approval: ApprovalV1, action: CanonicalActionV1, decision: PolicyDecisionV1): boolean {
  return approval.decisionId === decision.decisionId && approval.requestId === action.requestId &&
    approval.actionId === action.actionId && approval.actionHash === action.actionHash &&
    approval.sessionId === action.sessionId && approval.route.serverId === action.route.serverId &&
    approval.route.routeId === action.route.routeId && approval.route.toolName === action.route.toolName &&
    approval.route.schemaDigest === action.route.schemaDigest &&
    approval.route.credentialAudienceId === action.route.credentialAudienceId &&
    approval.route.policyScopeId === action.route.policyScopeId &&
    approval.resourcesDigest === action.resourcesDigest && approval.environment === action.environment &&
    approval.dataFlowDigest === action.dataFlowDigest && approval.policyVersion === decision.policyVersion &&
    approval.identity.userId === action.identity.userId && approval.identity.agentId === action.identity.agentId &&
    approval.identity.clientId === action.identity.clientId && approval.identity.hostId === action.identity.hostId;
}

function currentRouteMatches(action: CanonicalActionV1, binding: DownstreamServerRouteBindingV1): boolean {
  return binding.server.serverId === action.route.serverId && binding.route.serverId === action.route.serverId &&
    binding.route.routeId === action.route.routeId && binding.route.toolName === action.route.toolName &&
    binding.route.schemaIntegrity.registeredDigest === action.route.schemaDigest &&
    binding.route.credentialAudienceId === action.route.credentialAudienceId &&
    binding.route.policyScopeId === action.route.policyScopeId && binding.route.environment === action.environment &&
    binding.server.health.state === "HEALTHY" && binding.route.status === "ACTIVE";
}

/** Process-local automated-test component. Production persistence must use PostgreSQL. */
export class DisposableApprovalServiceV1 implements SessionInvalidationSinkV1 {
  readonly #options: DisposableApprovalServiceV1Options;
  readonly #approvals = new Map<string, StoredApprovalV1>();
  readonly #audit: ApprovalAuditEventV1[] = [];
  readonly #lifetimeMs: number;

  public constructor(options: DisposableApprovalServiceV1Options) {
    this.#options = options;
    this.#lifetimeMs = options.approvalLifetimeMs ?? 5 * 60 * 1_000;
    if (!Number.isInteger(this.#lifetimeMs) || this.#lifetimeMs <= 0 || this.#lifetimeMs > 5 * 60 * 1_000) {
      throw new Error("Approval lifetime must be between one millisecond and five minutes");
    }
  }

  public requestApproval(input: {
    readonly action: CanonicalActionV1;
    readonly decision: PolicyDecisionV1;
    readonly session: AuthenticatedSessionIdentityBindingV1;
  }): ApprovalV1 {
    const action = canonicalActionV1Schema.parse(input.action);
    const decision = policyDecisionV1Schema.parse(input.decision);
    const session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    canonicalActionDecisionBindingV1Schema.parse({ action, decision });
    if (!actionHashIsValid(action) || decision.decision !== "REQUIRE_APPROVAL" ||
      decision.coverage !== "ENFORCED" ||
      session.stateNamespace !== action.sessionId ||
      session.identity.userId !== action.identity.userId || session.identity.agentId !== action.identity.agentId ||
      session.identity.clientId !== action.identity.clientId || session.identity.hostId !== action.identity.hostId) {
      throw new ApprovalDeniedV1();
    }
    const now = this.#now();
    if (now.getTime() < Date.parse(decision.decidedAt)) throw new ApprovalDeniedV1();
    const approvalId = identifierV1Schema.parse(this.#options.approvalIdFactory?.() ?? randomUUID());
    if (this.#approvals.has(approvalId)) throw new ApprovalDeniedV1();
    const approval = approvalV1Schema.parse({
      schemaVersion: "1.0.0",
      approvalId,
      decisionId: decision.decisionId,
      requestId: action.requestId,
      actionId: action.actionId,
      actionHash: action.actionHash,
      sessionId: action.sessionId,
      identity: action.identity,
      route: action.route,
      resourcesDigest: action.resourcesDigest,
      environment: action.environment,
      dataFlowDigest: action.dataFlowDigest,
      policyVersion: decision.policyVersion,
      state: "PENDING",
      requestedAt: now.toISOString(),
      decidedAt: null,
      expiresAt: new Date(now.getTime() + this.#lifetimeMs).toISOString(),
      decidedByHumanId: null,
      consumption: null
    });
    this.#approvals.set(approvalId, {
      approval,
      action: structuredClone(action),
      decision: structuredClone(decision),
      session: structuredClone(session)
    });
    this.#record("APPROVAL_REQUESTED", this.#approvals.get(approvalId), null, "gateway", [], approval);
    return structuredClone(approval);
  }

  public recordHumanDecision(input: HumanApprovalDecisionV1): ApprovalV1 {
    const humanDecision = humanApprovalDecisionV1Schema.parse(input);
    const stored = this.#approvals.get(humanDecision.approvalId);
    if (stored === undefined || stored.approval.actionHash !== humanDecision.actionHash ||
      stored.approval.state !== "PENDING" || !this.#authorizeHuman(humanDecision)) {
      throw new ApprovalDeniedV1();
    }
    const now = this.#now();
    const authenticatedAt = Date.parse(humanDecision.authenticatedAt);
    if (authenticatedAt > now.getTime() || authenticatedAt < Date.parse(stored.approval.requestedAt)) {
      throw new ApprovalDeniedV1();
    }
    if (now.getTime() >= Date.parse(stored.approval.expiresAt)) {
      this.#expire(stored, now);
      throw new ApprovalDeniedV1();
    }
    stored.approval = approvalV1Schema.parse({
      ...stored.approval,
      state: humanDecision.decision === "APPROVE" ? "APPROVED" : "DENIED",
      decidedAt: now.toISOString(),
      decidedByHumanId: humanDecision.humanId
    });
    this.#record(
      humanDecision.decision === "APPROVE" ? "HUMAN_APPROVED" : "HUMAN_DENIED",
      stored,
      null,
      humanDecision.humanId,
      [],
      humanDecision
    );
    return structuredClone(stored.approval);
  }

  public consumeAndBeginForwarding<T>(input: {
    readonly approvalId: string;
    readonly action: CanonicalActionV1;
    readonly decision: PolicyDecisionV1;
    readonly session: AuthenticatedSessionIdentityBindingV1;
  }, beginForwarding: (authorization: ApprovedForwardingAuthorizationV1) => T): T {
    const approvalId = identifierV1Schema.parse(input.approvalId);
    const stored = this.#approvals.get(approvalId);
    if (stored === undefined) throw new ApprovalDeniedV1();
    const now = this.#now();
    if (stored.approval.state !== "APPROVED") {
      this.#denyConsumption(stored, now, "approval.not_approved");
      throw new ApprovalDeniedV1();
    }
    if (now.getTime() >= Date.parse(stored.approval.expiresAt)) {
      this.#expire(stored, now);
      throw new ApprovalDeniedV1();
    }
    let action: CanonicalActionV1;
    let decision: PolicyDecisionV1;
    let session: AuthenticatedSessionIdentityBindingV1;
    try {
      action = canonicalActionV1Schema.parse(input.action);
      decision = policyDecisionV1Schema.parse(input.decision);
      session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
      canonicalActionDecisionBindingV1Schema.parse({ action, decision });
    } catch {
      this.#denyConsumption(stored, now, "approval.invalid_candidate");
      throw new ApprovalDeniedV1();
    }
    if (!actionHashIsValid(action) ||
      !exactApprovalBinding(stored.approval, action, decision) ||
      computeCanonicalDigestV1(session) !== computeCanonicalDigestV1(stored.session)) {
      this.#denyConsumption(stored, now, "approval.binding_mismatch");
      throw new ApprovalDeniedV1();
    }

    let currentRoute: DownstreamServerRouteBindingV1;
    let currentDecision: PolicyDecisionV1;
    let identityValid = false;
    try {
      identityValid = this.#options.identityRevalidator(session);
      currentRoute = downstreamServerRouteBindingV1Schema.parse(this.#options.routeRevalidator(action));
      currentDecision = policyDecisionV1Schema.parse(this.#options.policyRevalidator(action));
      canonicalActionDecisionBindingV1Schema.parse({ action, decision: currentDecision });
    } catch {
      this.#revoke(stored, now, "approval.revalidation_failed");
      throw new ApprovalDeniedV1();
    }
    if (!identityValid || !currentRouteMatches(action, currentRoute) ||
      currentDecision.decision !== "REQUIRE_APPROVAL" || currentDecision.tier !== decision.tier ||
      currentDecision.coverage !== "ENFORCED" ||
      currentDecision.policyVersion !== stored.approval.policyVersion) {
      this.#revoke(stored, now, "approval.state_changed");
      throw new ApprovalDeniedV1();
    }

    const forwardingAttemptId = identifierV1Schema.parse(
      this.#options.forwardingAttemptIdFactory?.() ?? randomUUID()
    );
    const consumedAt = now.toISOString();
    stored.approval = approvalV1Schema.parse({
      ...stored.approval,
      state: "CONSUMED",
      consumption: {
        consumptionId: identifierV1Schema.parse(this.#options.consumptionIdFactory?.() ?? randomUUID()),
        consumedAt,
        forwardingAttemptId
      }
    });
    const authorization = approvedForwardingAuthorizationV1Schema.parse({
      schemaVersion: "1.0.0",
      forwardingAttemptId,
      approvalId,
      requestId: action.requestId,
      actionId: action.actionId,
      actionHash: action.actionHash,
      sessionId: action.sessionId,
      serverId: action.route.serverId,
      routeId: action.route.routeId,
      toolName: action.route.toolName,
      schemaDigest: action.route.schemaDigest,
      credentialAudienceId: action.route.credentialAudienceId,
      policyScopeId: action.route.policyScopeId,
      resourcesDigest: action.resourcesDigest,
      environment: action.environment,
      dataFlowDigest: action.dataFlowDigest,
      policyVersion: decision.policyVersion,
      authorizedAt: consumedAt
    });
    this.#record("APPROVAL_CONSUMED", stored, forwardingAttemptId, "gateway", [], authorization);
    try {
      return beginForwarding(Object.freeze(structuredClone(authorization)));
    } catch {
      this.#record("FORWARDING_START_FAILED", stored, forwardingAttemptId, "gateway", ["forwarding.start_failed"], authorization);
      throw new ApprovalDeniedV1();
    }
  }

  public readApproval(
    authorityInput: ApprovalAuditReaderAuthorityV1,
    approvalIdInput: string
  ): ApprovalV1 {
    const authority = approvalAuditReaderAuthorityV1Schema.parse(authorityInput);
    if (!this.#authorizeAuditReader(authority)) throw new ApprovalDeniedV1();
    const approvalId = identifierV1Schema.parse(approvalIdInput);
    const stored = this.#approvals.get(approvalId);
    if (stored === undefined) throw new ApprovalDeniedV1();
    const now = this.#now();
    if (["PENDING", "APPROVED"].includes(stored.approval.state) && now.getTime() >= Date.parse(stored.approval.expiresAt)) {
      this.#expire(stored, now);
    }
    return structuredClone(stored.approval);
  }

  public readAudit(authorityInput: ApprovalAuditReaderAuthorityV1): readonly ApprovalAuditEventV1[] {
    const authority = approvalAuditReaderAuthorityV1Schema.parse(authorityInput);
    if (!this.#authorizeAuditReader(authority)) throw new ApprovalDeniedV1();
    return structuredClone(this.#audit);
  }

  #authorizeAuditReader(authority: ApprovalAuditReaderAuthorityV1): boolean {
    let authorized = false;
    try {
      authorized = this.#options.auditAuthorizer(authority);
    } catch {
      authorized = false;
    }
    return authorized;
  }

  public invalidateSession(transportSessionId: string): void {
    for (const stored of this.#approvals.values()) {
      if (stored.session.transportSessionId === transportSessionId &&
        ["PENDING", "APPROVED"].includes(stored.approval.state)) {
        this.#revoke(stored, this.#now(), "identity.session_invalidated");
      }
    }
  }

  #authorizeHuman(decision: HumanApprovalDecisionV1): boolean {
    try {
      return this.#options.humanAuthorizer(decision);
    } catch {
      return false;
    }
  }

  #now(): Date {
    const now = this.#options.clock?.() ?? new Date();
    if (!Number.isFinite(now.getTime())) throw new ApprovalDeniedV1();
    return now;
  }

  #expire(stored: StoredApprovalV1, now: Date): void {
    if (!["PENDING", "APPROVED"].includes(stored.approval.state)) return;
    stored.approval = approvalV1Schema.parse({ ...stored.approval, state: "EXPIRED", consumption: null });
    this.#record("APPROVAL_EXPIRED", stored, null, "gateway", ["approval.expired"], { expiredAt: now.toISOString() });
  }

  #revoke(stored: StoredApprovalV1, now: Date, reasonCode: string): void {
    if (["CONSUMED", "DENIED", "EXPIRED", "REVOKED"].includes(stored.approval.state)) return;
    stored.approval = approvalV1Schema.parse({ ...stored.approval, state: "REVOKED", consumption: null });
    this.#record("APPROVAL_REVOKED", stored, null, "gateway", [reasonCode], { revokedAt: now.toISOString() });
  }

  #denyConsumption(stored: StoredApprovalV1, now: Date, reasonCode: string): void {
    this.#record("CONSUMPTION_DENIED", stored, null, "gateway", [reasonCode], { deniedAt: now.toISOString() });
  }

  #record(
    eventType: ApprovalAuditEventV1["eventType"],
    stored: StoredApprovalV1 | undefined,
    forwardingAttemptId: string | null,
    actorId: string,
    reasonCodes: string[],
    evidence: unknown
  ): void {
    if (stored === undefined) throw new ApprovalDeniedV1();
    this.#audit.push(approvalAuditEventV1Schema.parse({
      schemaVersion: "1.0.0",
      eventId: identifierV1Schema.parse(this.#options.eventIdFactory?.() ?? randomUUID()),
      eventType,
      approvalId: stored.approval.approvalId,
      requestId: stored.approval.requestId,
      actionId: stored.approval.actionId,
      sessionId: stored.approval.sessionId,
      forwardingAttemptId,
      actorId,
      evidenceDigest: computeCanonicalDigestV1(evidence),
      reasonCodes,
      occurredAt: this.#now().toISOString()
    }));
  }
}
