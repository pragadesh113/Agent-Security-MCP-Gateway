import { randomUUID } from "node:crypto";

import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import {
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  policyDecisionV1Schema,
  type CanonicalActionV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import {
  capabilityIdentifierV1Schema,
  coverageStateV1Schema,
  identifierV1Schema,
  sha256DigestV1Schema
} from "../contracts/v1.js";
import { policyAdvisoryV1Schema, type PolicyAdvisoryV1 } from "../policy-engine/deterministic-policy-v1.js";

const openingDelimiter = "<<<UNTRUSTED_CONTEXT_V1>>>";
const closingDelimiter = "<<<END_UNTRUSTED_CONTEXT_V1>>>";
const fragmentSourceV1Schema = z.enum(["USER_INPUT", "TOOL_DESCRIPTION", "TOOL_RESULT", "RESOURCE_CONTENT"]);
const supervisorDecisionV1Schema = z.enum(["DENY", "REQUIRE_APPROVAL"]);
const supervisorStatusV1Schema = z.enum([
  "COMPLETED", "DISABLED", "NOT_REQUIRED", "TIMEOUT", "INVALID_OUTPUT", "LOW_CONFIDENCE", "PROVIDER_FAILURE"
]);

export const supervisorUntrustedFragmentInputV1Schema = z.object({
  fragmentId: identifierV1Schema,
  source: fragmentSourceV1Schema,
  content: z.string().max(16_384)
}).strict();

const providerFragmentV1Schema = z.object({
  fragmentId: identifierV1Schema,
  source: fragmentSourceV1Schema,
  redactedExcerpt: z.string().max(512),
  excerptDigest: sha256DigestV1Schema
}).strict().superRefine((fragment, context) => {
  if (fragment.redactedExcerpt.includes(openingDelimiter) || fragment.redactedExcerpt.includes(closingDelimiter)) {
    context.addIssue({ code: "custom", path: ["redactedExcerpt"], message: "Delimiter text must be neutralized" });
  }
  if (fragment.excerptDigest !== computeCanonicalDigestV1(fragment.redactedExcerpt)) {
    context.addIssue({ code: "custom", path: ["excerptDigest"], message: "Excerpt digest does not match" });
  }
});

const redactionSummaryV1Schema = z.object({
  secretReplacements: z.number().int().nonnegative().max(10_000),
  patternReplacements: z.number().int().nonnegative().max(10_000),
  delimiterReplacements: z.number().int().nonnegative().max(10_000),
  truncatedFragments: z.number().int().nonnegative().max(8),
  omittedFields: z.tuple([
    z.literal("RAW_ARGUMENTS"),
    z.literal("RAW_RESULTS"),
    z.literal("CREDENTIALS"),
    z.literal("CANONICAL_REFERENCES"),
    z.literal("IDENTITY_VALUES")
  ]),
  evidenceDigest: sha256DigestV1Schema
}).strict().superRefine((summary, context) => {
  const { evidenceDigest, ...evidence } = summary;
  if (evidenceDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["evidenceDigest"], message: "Redaction evidence digest does not match" });
  }
});

export const supervisorProviderRequestV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  assessmentId: identifierV1Schema,
  promptVersion: identifierV1Schema,
  policyScopeId: identifierV1Schema,
  question: z.literal("RESOLVE_SEMANTIC_AMBIGUITY"),
  policyContext: z.object({
    effect: z.enum(["READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER", "UNKNOWN"]),
    environment: z.enum(["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"]),
    riskTier: z.number().int().min(0).max(3),
    deterministicDecision: z.enum(["DENY", "REQUIRE_APPROVAL", "SANDBOX", "ALLOW_WITH_CONSTRAINTS", "ALLOW"]),
    policyVersion: identifierV1Schema,
    resourceClasses: z.array(z.string().min(1).max(32)).min(1).max(11),
    classifications: z.array(z.string().min(1).max(32)).min(1).max(6),
    dataFlowDirection: z.enum(["NONE", "INGRESS", "EGRESS", "BIDIRECTIONAL", "UNKNOWN"]),
    externalDestination: z.boolean(),
    parsingStatus: z.enum(["FULL", "PARTIAL", "FAILED", "UNSUPPORTED"]),
    reversibility: z.enum(["NOT_APPLICABLE", "VERIFIED_COMPENSATING_ACTION", "TESTED_SNAPSHOT",
      "PARTIALLY_REVERSIBLE", "IRREVERSIBLE", "UNKNOWN"]),
    coverage: coverageStateV1Schema
  }).strict(),
  untrustedContext: z.object({
    openingDelimiter: z.literal(openingDelimiter),
    closingDelimiter: z.literal(closingDelimiter),
    treatAsDataOnly: z.literal(true),
    fragments: z.array(providerFragmentV1Schema).max(8)
  }).strict(),
  redaction: redactionSummaryV1Schema,
  inputDigest: sha256DigestV1Schema
}).strict().superRefine((request, context) => {
  const { inputDigest, ...evidence } = request;
  if (inputDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["inputDigest"], message: "Supervisor input digest does not match" });
  }
  const ids = request.untrustedContext.fragments.map((fragment) => fragment.fragmentId);
  if (new Set(ids).size !== ids.length) {
    context.addIssue({ code: "custom", path: ["untrustedContext", "fragments"],
      message: "Untrusted fragment identifiers must be unique" });
  }
});

export const supervisorProviderOutputV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  assessmentId: identifierV1Schema,
  inputDigest: sha256DigestV1Schema,
  semanticCategory: z.enum(["SAFE_LOW_RISK", "AMBIGUOUS", "SENSITIVE", "PROHIBITED", "UNKNOWN"]),
  riskIndicators: z.array(capabilityIdentifierV1Schema).max(32),
  intentAlignment: z.enum(["ALIGNED", "MISALIGNED", "UNCERTAIN"]),
  confidence: z.number().min(0).max(1),
  evidenceReferences: z.array(identifierV1Schema).max(8),
  recommendedDecision: supervisorDecisionV1Schema,
  rationaleCodes: z.array(capabilityIdentifierV1Schema).min(1).max(32),
  responseDigest: sha256DigestV1Schema
}).strict().superRefine((output, context) => {
  for (const [path, values] of [["riskIndicators", output.riskIndicators],
    ["evidenceReferences", output.evidenceReferences], ["rationaleCodes", output.rationaleCodes]] as const) {
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: "custom", path: [path], message: "Supervisor output arrays must be unique" });
    }
  }
  const { responseDigest, ...evidence } = output;
  if (responseDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["responseDigest"], message: "Supervisor response digest does not match" });
  }
});

export const supervisorAssessmentAuditV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  assessmentId: identifierV1Schema,
  requestId: identifierV1Schema,
  actionId: identifierV1Schema,
  actionHash: sha256DigestV1Schema,
  decisionId: identifierV1Schema,
  sessionId: identifierV1Schema,
  policyScopeId: identifierV1Schema,
  routeId: identifierV1Schema,
  schemaDigest: sha256DigestV1Schema,
  policyVersion: identifierV1Schema,
  providerId: identifierV1Schema,
  modelId: identifierV1Schema,
  promptVersion: identifierV1Schema,
  status: supervisorStatusV1Schema,
  externalSubmission: z.boolean(),
  inputDigest: sha256DigestV1Schema,
  responseDigest: sha256DigestV1Schema,
  redaction: redactionSummaryV1Schema,
  advisory: policyAdvisoryV1Schema,
  fallbackUsed: z.boolean(),
  failureCode: capabilityIdentifierV1Schema.nullable(),
  latencyMs: z.number().int().nonnegative().max(3_600_000),
  advisoryOnly: z.literal(true),
  assessedAt: z.iso.datetime({ offset: true }),
  auditDigest: sha256DigestV1Schema
}).strict().superRefine((audit, context) => {
  const completed = audit.status === "COMPLETED";
  if (completed === audit.fallbackUsed || completed !== (audit.failureCode === null)) {
    context.addIssue({ code: "custom", path: ["fallbackUsed"], message: "Supervisor fallback state is inconsistent" });
  }
  if ((audit.status === "DISABLED" || audit.status === "NOT_REQUIRED") && audit.externalSubmission) {
    context.addIssue({ code: "custom", path: ["externalSubmission"], message: "Disabled supervisor cannot submit externally" });
  }
  const { auditDigest, ...evidence } = audit;
  if (auditDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["auditDigest"], message: "Supervisor audit digest does not match" });
  }
});

export type SupervisorUntrustedFragmentInputV1 = z.infer<typeof supervisorUntrustedFragmentInputV1Schema>;
export type SupervisorProviderRequestV1 = z.infer<typeof supervisorProviderRequestV1Schema>;
export type SupervisorProviderOutputV1 = z.infer<typeof supervisorProviderOutputV1Schema>;
export type SupervisorAssessmentAuditV1 = z.infer<typeof supervisorAssessmentAuditV1Schema>;

export interface AdvisorySupervisorProviderV1 {
  readonly providerId: string;
  readonly modelId: string;
  assess(request: SupervisorProviderRequestV1, signal: AbortSignal): unknown;
}

export interface SupervisorAuditSinkV1 {
  record(assessment: SupervisorAssessmentAuditV1): void | Promise<void>;
}

export interface AdvisorySupervisorV1Options {
  readonly provider: AdvisorySupervisorProviderV1;
  readonly auditSink: SupervisorAuditSinkV1;
  readonly globallyEnabled?: boolean;
  readonly disabledPolicyScopeIds?: readonly string[];
  readonly minimumConfidence?: number;
  readonly timeoutMs?: number;
  readonly promptVersion?: string;
  readonly knownSecretValues?: readonly string[];
  readonly assessmentIdFactory?: () => string;
  readonly clock?: () => Date;
  readonly monotonicClock?: () => number;
}

export class SupervisorAuditUnavailableV1 extends Error {
  public constructor() {
    super("Supervisor audit persistence is unavailable");
    this.name = "SupervisorAuditUnavailableV1";
  }
}

function unresolved(action: CanonicalActionV1): boolean {
  return action.effect === "UNKNOWN" || action.environment === "UNKNOWN" ||
    action.parsingEvidence.status !== "FULL" || action.resources.some((resource) =>
      resource.resourceClass === "UNKNOWN" || resource.classification === "UNKNOWN") ||
    action.dataFlow.direction === "UNKNOWN" || action.dataFlow.classifications.includes("UNKNOWN");
}

function fallbackDecision(decision: PolicyDecisionV1): "DENY" | "REQUIRE_APPROVAL" {
  return decision.decision === "DENY" || decision.coverage !== "ENFORCED" ? "DENY" : "REQUIRE_APPROVAL";
}

function replaceAllCount(value: string, pattern: RegExp, replacement: string): { value: string; count: number } {
  let count = 0;
  return { value: value.replace(pattern, () => { count += 1; return replacement; }), count };
}

export class AdvisorySupervisorV1 {
  readonly #provider: AdvisorySupervisorProviderV1;
  readonly #auditSink: SupervisorAuditSinkV1;
  readonly #globallyEnabled: boolean;
  readonly #disabledPolicyScopeIds: ReadonlySet<string>;
  readonly #minimumConfidence: number;
  readonly #timeoutMs: number;
  readonly #promptVersion: string;
  readonly #knownSecretValues: readonly string[];
  readonly #assessmentIdFactory: () => string;
  readonly #clock: () => Date;
  readonly #monotonicClock: () => number;

  public constructor(options: AdvisorySupervisorV1Options) {
    this.#provider = options.provider;
    identifierV1Schema.parse(options.provider.providerId);
    identifierV1Schema.parse(options.provider.modelId);
    this.#auditSink = options.auditSink;
    this.#globallyEnabled = options.globallyEnabled ?? false;
    this.#disabledPolicyScopeIds = new Set((options.disabledPolicyScopeIds ?? []).map((scope) => identifierV1Schema.parse(scope)));
    this.#minimumConfidence = z.number().min(0.5).max(1).parse(options.minimumConfidence ?? 0.8);
    this.#timeoutMs = z.number().int().positive().max(60_000).parse(options.timeoutMs ?? 5_000);
    this.#promptVersion = identifierV1Schema.parse(options.promptVersion ?? "supervisor-prompt-v1");
    this.#knownSecretValues = Object.freeze((options.knownSecretValues ?? []).map((secret) =>
      z.string().min(4).max(16_384).parse(secret)));
    this.#assessmentIdFactory = options.assessmentIdFactory ?? randomUUID;
    this.#clock = options.clock ?? (() => new Date());
    this.#monotonicClock = options.monotonicClock ?? (() => performance.now());
  }

  public async assess(input: {
    readonly action: CanonicalActionV1;
    readonly deterministicDecision: PolicyDecisionV1;
    readonly untrustedFragments?: readonly SupervisorUntrustedFragmentInputV1[];
  }): Promise<{ readonly advisory: PolicyAdvisoryV1; readonly audit: SupervisorAssessmentAuditV1;
    readonly providerRequest: SupervisorProviderRequestV1 }> {
    const action = canonicalActionV1Schema.parse(input.action);
    const deterministicDecision = policyDecisionV1Schema.parse(input.deterministicDecision);
    canonicalActionDecisionBindingV1Schema.parse({ action, decision: deterministicDecision });
    const assessmentId = identifierV1Schema.parse(this.#assessmentIdFactory());
    const providerRequest = this.#buildProviderRequest(assessmentId, action, deterministicDecision,
      input.untrustedFragments ?? []);
    const enabled = this.#globallyEnabled && !this.#disabledPolicyScopeIds.has(action.route.policyScopeId);
    const required = unresolved(action);
    const fallback = fallbackDecision(deterministicDecision);
    const started = this.#monotonicClock();
    let status: z.infer<typeof supervisorStatusV1Schema> = required ? "PROVIDER_FAILURE" : "NOT_REQUIRED";
    let externalSubmission = false;
    let responseDigest = computeCanonicalDigestV1({ status: "NO_PROVIDER_RESPONSE" });
    let advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
      decision: fallback, reasonCodes: [required ? "supervisor.fallback" : "supervisor.not_required"] });
    let failureCode: string | null = required ? "supervisor.provider_failure" : "supervisor.not_required";

    if (required && !enabled) {
      status = "DISABLED";
      failureCode = "supervisor.disabled";
      advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
        decision: fallback, reasonCodes: ["supervisor.disabled"] });
    } else if (required) {
      externalSubmission = true;
      const abort = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const providerResult = await Promise.race([
          Promise.resolve(this.#provider.assess(providerRequest, abort.signal)),
          new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => { abort.abort(); reject(new Error("SUPERVISOR_TIMEOUT")); }, this.#timeoutMs);
          })
        ]);
        const parsed = supervisorProviderOutputV1Schema.safeParse(providerResult);
        if (!parsed.success || parsed.data.assessmentId !== providerRequest.assessmentId ||
          parsed.data.inputDigest !== providerRequest.inputDigest || parsed.data.evidenceReferences.some((reference) =>
          !providerRequest.untrustedContext.fragments.some((fragment) => fragment.fragmentId === reference))) {
          status = "INVALID_OUTPUT";
          failureCode = "supervisor.invalid_output";
          advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
            decision: fallback, reasonCodes: ["supervisor.invalid_output"] });
        } else {
          responseDigest = parsed.data.responseDigest;
          if (parsed.data.confidence < this.#minimumConfidence) {
            status = "LOW_CONFIDENCE";
            failureCode = "supervisor.low_confidence";
            advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
              decision: fallback, reasonCodes: ["supervisor.low_confidence"] });
          } else {
            status = "COMPLETED";
            failureCode = null;
            advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
              decision: parsed.data.recommendedDecision,
              reasonCodes: parsed.data.rationaleCodes.map((reason) => `assessment.${reason}`) });
          }
        }
      } catch (error) {
        if (error instanceof Error && error.message === "SUPERVISOR_TIMEOUT") {
          status = "TIMEOUT";
          failureCode = "supervisor.timeout";
        } else {
          status = "PROVIDER_FAILURE";
          failureCode = "supervisor.provider_failure";
        }
        advisory = policyAdvisoryV1Schema.parse({ schemaVersion: "1.0.0", source: "SUPERVISOR",
          decision: fallback, reasonCodes: [failureCode] });
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }
    const latencyMs = Math.max(0, Math.round(this.#monotonicClock() - started));
    const auditBody = {
      schemaVersion: "1.0.0" as const,
      assessmentId,
      requestId: action.requestId,
      actionId: action.actionId,
      actionHash: action.actionHash,
      decisionId: deterministicDecision.decisionId,
      sessionId: action.sessionId,
      policyScopeId: action.route.policyScopeId,
      routeId: action.route.routeId,
      schemaDigest: action.route.schemaDigest,
      policyVersion: deterministicDecision.policyVersion,
      providerId: this.#provider.providerId,
      modelId: this.#provider.modelId,
      promptVersion: this.#promptVersion,
      status,
      externalSubmission,
      inputDigest: providerRequest.inputDigest,
      responseDigest,
      redaction: providerRequest.redaction,
      advisory,
      fallbackUsed: status !== "COMPLETED",
      failureCode,
      latencyMs,
      advisoryOnly: true as const,
      assessedAt: this.#clock().toISOString()
    };
    const audit = supervisorAssessmentAuditV1Schema.parse({ ...auditBody,
      auditDigest: computeCanonicalDigestV1(auditBody) });
    try {
      await this.#auditSink.record(audit);
    } catch {
      throw new SupervisorAuditUnavailableV1();
    }
    return { advisory, audit, providerRequest };
  }

  #buildProviderRequest(
    assessmentId: string,
    action: CanonicalActionV1,
    decision: PolicyDecisionV1,
    fragmentInputs: readonly SupervisorUntrustedFragmentInputV1[]
  ): SupervisorProviderRequestV1 {
    const inputs = z.array(supervisorUntrustedFragmentInputV1Schema).max(8).parse(fragmentInputs);
    let secretReplacements = 0;
    let patternReplacements = 0;
    let delimiterReplacements = 0;
    let truncatedFragments = 0;
    const fragments = inputs.map((input) => {
      let excerpt = "";
      for (let index = 0; index < input.content.length; index += 1) {
        const code = input.content.charCodeAt(index);
        excerpt += code <= 31 || code === 127 ? " " : input.content[index] ?? "";
      }
      excerpt = excerpt.replace(/\s+/gu, " ").trim();
      for (const secret of this.#knownSecretValues) {
        const replacement = replaceAllCount(excerpt, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "gu"),
          "[REDACTED_SECRET]");
        excerpt = replacement.value;
        secretReplacements += replacement.count;
      }
      for (const pattern of [/\bBearer\s+[^\s,;]+/giu,
        /\b(?:api[_-]?key|token|password|secret|credential|authorization|path|file|uri|reference|argument|result)\s*[:=]\s*[^\s,;]+/giu]) {
        const replacement = replaceAllCount(excerpt, pattern, "[REDACTED_CREDENTIAL]");
        excerpt = replacement.value;
        patternReplacements += replacement.count;
      }
      for (const delimiter of [openingDelimiter, closingDelimiter]) {
        const replacement = replaceAllCount(excerpt,
          new RegExp(delimiter.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "gu"), "[REDACTED_DELIMITER]");
        excerpt = replacement.value;
        delimiterReplacements += replacement.count;
      }
      if (excerpt.length > 512) {
        excerpt = excerpt.slice(0, 512);
        truncatedFragments += 1;
      }
      return { fragmentId: input.fragmentId, source: input.source, redactedExcerpt: excerpt,
        excerptDigest: computeCanonicalDigestV1(excerpt) };
    });
    const redactionBody = {
      secretReplacements,
      patternReplacements,
      delimiterReplacements,
      truncatedFragments,
      omittedFields: ["RAW_ARGUMENTS", "RAW_RESULTS", "CREDENTIALS", "CANONICAL_REFERENCES", "IDENTITY_VALUES"] as const
    };
    const redaction = { ...redactionBody, evidenceDigest: computeCanonicalDigestV1(redactionBody) };
    const requestBody = {
      schemaVersion: "1.0.0" as const,
      assessmentId,
      promptVersion: this.#promptVersion,
      policyScopeId: action.route.policyScopeId,
      question: "RESOLVE_SEMANTIC_AMBIGUITY" as const,
      policyContext: {
        effect: action.effect,
        environment: action.environment,
        riskTier: decision.tier,
        deterministicDecision: decision.decision,
        policyVersion: decision.policyVersion,
        resourceClasses: [...new Set(action.resources.map((resource) => resource.resourceClass))].sort(),
        classifications: [...new Set([
          ...action.resources.map((resource) => resource.classification), ...action.dataFlow.classifications
        ])].sort(),
        dataFlowDirection: action.dataFlow.direction,
        externalDestination: action.dataFlow.externalDestination,
        parsingStatus: action.parsingEvidence.status,
        reversibility: action.reversibility,
        coverage: decision.coverage
      },
      untrustedContext: { openingDelimiter, closingDelimiter, treatAsDataOnly: true as const, fragments },
      redaction
    };
    return supervisorProviderRequestV1Schema.parse({ ...requestBody,
      inputDigest: computeCanonicalDigestV1(requestBody) });
  }
}
