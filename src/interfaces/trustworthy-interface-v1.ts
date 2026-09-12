import { randomUUID } from "node:crypto";

import { z } from "zod";

import {
  awarenessV1Schema,
  type AwarenessV1
} from "../contracts/boundary-v1.js";
import {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  executionOutcomeV1Schema,
  policyDecisionV1Schema,
  type ApprovalV1,
  type CanonicalActionV1,
  type ExecutionOutcomeV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import { identifierV1Schema } from "../contracts/v1.js";
import {
  coverageScopeMatchesActionV1,
  exclusiveMediationAssessmentV1Schema,
  type ExclusiveMediationAssessmentV1
} from "../coverage/exclusive-mediation-v1.js";

const safeTextV1Schema = z.string().trim().min(1).max(1_024).refine((value) => {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 31 || codeUnit === 127) return false;
  }
  return true;
}, "Display text cannot contain control characters");

const uniqueIdentifiersV1Schema = z.array(identifierV1Schema).max(128).superRefine((values, context) => {
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", message: "Identifiers must be unique" });
  }
});

export const trustworthyActionInterfaceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  interfaceId: identifierV1Schema,
  requestId: identifierV1Schema,
  actionId: identifierV1Schema,
  decisionId: identifierV1Schema,
  requester: z.object({
    userId: identifierV1Schema,
    agentId: identifierV1Schema,
    clientId: identifierV1Schema,
    hostId: identifierV1Schema,
    sessionId: identifierV1Schema
  }).strict(),
  route: z.object({
    serverId: identifierV1Schema,
    toolName: identifierV1Schema,
    routeId: identifierV1Schema,
    schemaDigest: z.string().regex(/^[a-f0-9]{64}$/u),
    credentialAudienceId: identifierV1Schema,
    policyScopeId: identifierV1Schema
  }).strict(),
  targets: z.array(z.object({
    resourceId: identifierV1Schema,
    resourceClass: z.string().min(1).max(32),
    canonicalReference: safeTextV1Schema,
    classification: z.string().min(1).max(32)
  }).strict()).min(1).max(64),
  dataFlow: z.object({
    direction: z.string().min(1).max(32),
    classifications: z.array(z.string().min(1).max(32)).min(1).max(16),
    externalDestination: z.boolean(),
    destinationId: identifierV1Schema.nullable()
  }).strict(),
  provenance: z.object({
    parserId: identifierV1Schema,
    parserVersion: z.string().min(1).max(64),
    parsingStatus: z.string().min(1).max(32),
    influences: z.array(z.string().min(1).max(32)).max(16)
  }).strict(),
  riskTier: z.number().int().min(0).max(3),
  actionEffect: z.enum(["READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER", "UNKNOWN"]),
  decision: z.enum(["DENY", "REQUIRE_APPROVAL", "SANDBOX", "ALLOW_WITH_CONSTRAINTS"]),
  reversibility: z.string().min(1).max(64),
  recoveryClass: z.string().min(1).max(64),
  blastRadius: z.enum(["LOCAL_SINGLE", "LOCAL_MULTIPLE", "EXTERNAL_SINGLE", "EXTERNAL_MULTIPLE", "UNKNOWN"]),
  relatedAttemptIds: uniqueIdentifiersV1Schema,
  coverage: z.enum(["ENFORCED", "DEGRADED", "OBSERVE_ONLY", "UNPROTECTED"]),
  coverageAssessmentId: identifierV1Schema,
  coverageEvidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  missingGuarantees: z.array(z.string().regex(/^coverage\.[a-z0-9_.-]+$/u)).max(64),
  possiblePartialEffects: z.boolean(),
  generatedFromCanonicalData: z.literal(true),
  generatedAt: z.iso.datetime({ offset: true })
}).strict().superRefine((view, context) => {
  if (view.coverage !== "ENFORCED" && view.missingGuarantees.length === 0) {
    context.addIssue({ code: "custom", path: ["missingGuarantees"], message: "Coverage gaps must be explicit" });
  }
  if (view.riskTier === 3 && view.decision !== "DENY" && view.decision !== "REQUIRE_APPROVAL") {
    context.addIssue({ code: "custom", path: ["decision"], message: "Tier 3 has no bulk or persistent allow state" });
  }
});

export const approvalFatigueMetricsV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  policyScopeId: identifierV1Schema,
  presentations: z.number().int().nonnegative(),
  approvals: z.number().int().nonnegative(),
  denials: z.number().int().nonnegative(),
  expirations: z.number().int().nonnegative(),
  revocations: z.number().int().nonnegative(),
  approvalErrors: z.number().int().nonnegative(),
  repeatedRelatedAttempts: z.number().int().nonnegative(),
  meanDecisionLatencyMs: z.number().nonnegative(),
  recordedAt: z.iso.datetime({ offset: true })
}).strict();

export const approvalFatigueEventV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  eventId: identifierV1Schema,
  interfaceId: identifierV1Schema,
  policyScopeId: identifierV1Schema,
  eventType: z.enum(["PRESENTED", "APPROVED", "DENIED", "EXPIRED", "REVOKED", "ERROR"]),
  decisionLatencyMs: z.number().int().nonnegative().nullable(),
  relatedAttemptCount: z.number().int().nonnegative().max(1_000),
  occurredAt: z.iso.datetime({ offset: true })
}).strict().superRefine((event, context) => {
  if ((event.eventType === "APPROVED" || event.eventType === "DENIED") !==
    (event.decisionLatencyMs !== null)) {
    context.addIssue({ code: "custom", path: ["decisionLatencyMs"], message: "Human decisions require latency" });
  }
});

export type TrustworthyActionInterfaceV1 = z.infer<typeof trustworthyActionInterfaceV1Schema>;
export type ApprovalFatigueMetricsV1 = z.infer<typeof approvalFatigueMetricsV1Schema>;
export type ApprovalFatigueEventV1 = z.infer<typeof approvalFatigueEventV1Schema>;

function recoveryClass(action: CanonicalActionV1, outcome: ExecutionOutcomeV1 | null): string {
  if (outcome !== null) return outcome.recoveryClass;
  if (action.effect === "READ") return "NOT_APPLICABLE";
  return action.reversibility;
}

function blastRadius(action: CanonicalActionV1): TrustworthyActionInterfaceV1["blastRadius"] {
  if (action.environment === "UNKNOWN" || action.resources.some((item) => item.resourceClass === "UNKNOWN")) {
    return "UNKNOWN";
  }
  if (action.dataFlow.externalDestination) {
    return action.resources.length === 1 ? "EXTERNAL_SINGLE" : "EXTERNAL_MULTIPLE";
  }
  return action.resources.length === 1 ? "LOCAL_SINGLE" : "LOCAL_MULTIPLE";
}

export interface TrustworthyInterfaceBuilderV1Options {
  readonly clock?: () => Date;
  readonly interfaceIdFactory?: () => string;
  readonly awarenessIdFactory?: () => string;
}

export class TrustworthyInterfaceBuilderV1 {
  readonly #clock: () => Date;
  readonly #interfaceIdFactory: () => string;
  readonly #awarenessIdFactory: () => string;

  public constructor(options: TrustworthyInterfaceBuilderV1Options = {}) {
    this.#clock = options.clock ?? (() => new Date());
    this.#interfaceIdFactory = options.interfaceIdFactory ?? randomUUID;
    this.#awarenessIdFactory = options.awarenessIdFactory ?? randomUUID;
  }

  public build(input: {
    readonly action: CanonicalActionV1;
    readonly decision: PolicyDecisionV1;
    readonly coverage: ExclusiveMediationAssessmentV1;
    readonly outcome?: ExecutionOutcomeV1 | null;
    readonly relatedAttemptIds?: readonly string[];
  }): { readonly view: TrustworthyActionInterfaceV1; readonly awareness: AwarenessV1 } {
    const action = canonicalActionV1Schema.parse(input.action);
    const decision = policyDecisionV1Schema.parse(input.decision);
    canonicalActionDecisionBindingV1Schema.parse({ action, decision });
    if (decision.decision === "ALLOW") throw new Error("Awareness is required only for non-allow decisions");
    const coverage = exclusiveMediationAssessmentV1Schema.parse(input.coverage);
    if (!coverageScopeMatchesActionV1(coverage.scope, action) || decision.coverage !== coverage.coverage) {
      throw new Error("Coverage does not match the canonical action and decision");
    }
    const outcome = input.outcome === undefined || input.outcome === null
      ? null
      : executionOutcomeV1Schema.parse(input.outcome);
    if (outcome !== null && (outcome.requestId !== action.requestId || outcome.actionId !== action.actionId ||
      outcome.decisionId !== decision.decisionId || outcome.sessionId !== action.sessionId)) {
      throw new Error("Outcome does not match the canonical action and decision");
    }
    const relatedAttemptIds = uniqueIdentifiersV1Schema.parse(input.relatedAttemptIds ?? []);
    const missingGuarantees = [...new Set(coverage.missingGuarantees.map((item) => item.reasonCode))].sort();
    const generatedAt = this.#clock().toISOString();
    const view = trustworthyActionInterfaceV1Schema.parse({
      schemaVersion: "1.0.0",
      interfaceId: this.#interfaceIdFactory(),
      requestId: action.requestId,
      actionId: action.actionId,
      decisionId: decision.decisionId,
      requester: { ...action.identity, sessionId: action.sessionId },
      route: action.route,
      targets: action.resources,
      dataFlow: action.dataFlow,
      provenance: {
        parserId: action.parsingEvidence.parserId,
        parserVersion: action.parsingEvidence.parserVersion,
        parsingStatus: action.parsingEvidence.status,
        influences: action.influences
      },
      riskTier: decision.tier,
      actionEffect: action.effect,
      decision: decision.decision,
      reversibility: action.reversibility,
      recoveryClass: recoveryClass(action, outcome),
      blastRadius: blastRadius(action),
      relatedAttemptIds,
      coverage: coverage.coverage,
      coverageAssessmentId: coverage.assessmentId,
      coverageEvidenceDigest: coverage.evidenceDigest,
      missingGuarantees,
      possiblePartialEffects: outcome?.possiblePartialEffects ?? false,
      generatedFromCanonicalData: true,
      generatedAt
    });
    const alternatives: AwarenessV1["alternatives"] = [{
      alternativeId: "alternative-no-effect",
      summary: "Do not execute this action; no protected effect will be attempted.",
      routeId: null,
      disposition: "AVAILABLE",
      reasonCodes: ["alternative.no_effect"]
    }];
    if (decision.decision === "REQUIRE_APPROVAL") {
      alternatives.push({
        alternativeId: "alternative-exact-approval",
        summary: "Request one time-limited human approval for this exact canonical action.",
        routeId: action.route.routeId,
        disposition: coverage.coverage === "ENFORCED" ? "REQUIRES_APPROVAL" : "NOT_AVAILABLE",
        reasonCodes: coverage.coverage === "ENFORCED"
          ? ["alternative.exact_approval"] : ["coverage.not_enforced"]
      });
    }
    const targetSummary = action.resources.length === 1
      ? `${action.resources[0]?.resourceClass ?? "UNKNOWN"} target`
      : `${String(action.resources.length)} canonical targets`;
    const awareness = awarenessV1Schema.parse({
      schemaVersion: "1.0.0",
      awarenessId: this.#awarenessIdFactory(),
      requestId: action.requestId,
      sessionId: action.sessionId,
      actionId: action.actionId,
      decisionId: decision.decisionId,
      decision: decision.decision,
      tier: decision.tier,
      factualSummary: `${decision.decision} for ${action.effect} on ${targetSummary} through ${action.route.toolName}.`,
      reasonCodes: decision.reasonCodes,
      coverage: coverage.coverage,
      missingGuarantees,
      alternatives,
      generatedFromCanonicalData: true,
      generatedAt
    });
    return { view, awareness };
  }
}

interface MutableFatigueMetricsV1 {
  presentations: number;
  approvals: number;
  denials: number;
  expirations: number;
  revocations: number;
  approvalErrors: number;
  repeatedRelatedAttempts: number;
  totalDecisionLatencyMs: number;
  decisionsWithLatency: number;
}

export class ApprovalFatigueRecorderV1 {
  readonly #metrics = new Map<string, MutableFatigueMetricsV1>();
  readonly #clock: () => Date;

  public constructor(clock: () => Date = () => new Date()) {
    this.#clock = clock;
  }

  public recordPresentation(viewInput: TrustworthyActionInterfaceV1): void {
    const view = trustworthyActionInterfaceV1Schema.parse(viewInput);
    const metrics = this.#forScope(view.route.policyScopeId);
    metrics.presentations += 1;
    metrics.repeatedRelatedAttempts += view.relatedAttemptIds.length;
  }

  public recordApproval(viewInput: TrustworthyActionInterfaceV1, approvalInput: ApprovalV1): void {
    const view = trustworthyActionInterfaceV1Schema.parse(viewInput);
    const approval = approvalV1Schema.parse(approvalInput);
    if (view.decision !== "REQUIRE_APPROVAL" || approval.requestId !== view.requestId ||
      approval.actionId !== view.actionId || approval.decisionId !== view.decisionId ||
      approval.sessionId !== view.requester.sessionId) {
      throw new Error("Approval metric does not match its canonical interface");
    }
    const metrics = this.#forScope(view.route.policyScopeId);
    if (approval.state === "APPROVED" || approval.state === "CONSUMED") metrics.approvals += 1;
    else if (approval.state === "DENIED") metrics.denials += 1;
    else if (approval.state === "EXPIRED") metrics.expirations += 1;
    else if (approval.state === "REVOKED") metrics.revocations += 1;
    else metrics.approvalErrors += 1;
    if (approval.decidedAt !== null) {
      metrics.totalDecisionLatencyMs += Math.max(0, Date.parse(approval.decidedAt) - Date.parse(approval.requestedAt));
      metrics.decisionsWithLatency += 1;
    }
  }

  public recordError(policyScopeId: string): void {
    this.#forScope(identifierV1Schema.parse(policyScopeId)).approvalErrors += 1;
  }

  public snapshot(policyScopeIdInput: string): ApprovalFatigueMetricsV1 {
    const policyScopeId = identifierV1Schema.parse(policyScopeIdInput);
    const metrics = this.#forScope(policyScopeId);
    return approvalFatigueMetricsV1Schema.parse({
      schemaVersion: "1.0.0",
      policyScopeId,
      presentations: metrics.presentations,
      approvals: metrics.approvals,
      denials: metrics.denials,
      expirations: metrics.expirations,
      revocations: metrics.revocations,
      approvalErrors: metrics.approvalErrors,
      repeatedRelatedAttempts: metrics.repeatedRelatedAttempts,
      meanDecisionLatencyMs: metrics.decisionsWithLatency === 0
        ? 0 : metrics.totalDecisionLatencyMs / metrics.decisionsWithLatency,
      recordedAt: this.#clock().toISOString()
    });
  }

  #forScope(policyScopeId: string): MutableFatigueMetricsV1 {
    const existing = this.#metrics.get(policyScopeId);
    if (existing !== undefined) return existing;
    const created: MutableFatigueMetricsV1 = {
      presentations: 0, approvals: 0, denials: 0, expirations: 0, revocations: 0,
      approvalErrors: 0, repeatedRelatedAttempts: 0, totalDecisionLatencyMs: 0,
      decisionsWithLatency: 0
    };
    this.#metrics.set(policyScopeId, created);
    return created;
  }
}
