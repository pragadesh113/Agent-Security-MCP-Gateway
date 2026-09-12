import { z } from "zod";

import {
  capabilityIdentifierV1Schema,
  coverageStateV1Schema,
  identifierV1Schema,
  sha256DigestV1Schema,
  utcTimestampV1Schema
} from "./v1.js";

const boundedTextV1Schema = z
  .string()
  .trim()
  .min(1)
  .max(1_024)
  .refine((value) => {
    for (let index = 0; index < value.length; index += 1) {
      const codeUnit = value.charCodeAt(index);
      if (codeUnit <= 31 || codeUnit === 127) {
        return false;
      }
    }
    return true;
  }, "Text cannot contain control characters");

const uniqueIdentifiersV1Schema = z
  .array(identifierV1Schema)
  .max(128)
  .superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: "custom", message: "Identifiers must be unique" });
    }
  });

const uniqueCodesV1Schema = z
  .array(capabilityIdentifierV1Schema)
  .max(128)
  .superRefine((values, context) => {
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: "custom", message: "Codes must be unique" });
    }
  });

const environmentV1Schema = z.enum([
  "DEVELOPMENT",
  "TEST",
  "STAGING",
  "PRODUCTION",
  "UNKNOWN"
]);

const resourceClassV1Schema = z.enum([
  "FILESYSTEM",
  "SHELL",
  "GIT",
  "PACKAGE",
  "NETWORK",
  "DATABASE",
  "CLOUD",
  "BROWSER",
  "PROCESS",
  "DEPLOYMENT",
  "UNKNOWN"
]);

const dataClassificationV1Schema = z.enum([
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "SECRET",
  "CREDENTIAL",
  "UNKNOWN"
]);

const identityBindingV1Schema = z
  .object({
    userId: identifierV1Schema,
    agentId: identifierV1Schema,
    clientId: identifierV1Schema,
    hostId: identifierV1Schema
  })
  .strict();

const routeBindingV1Schema = z
  .object({
    serverId: identifierV1Schema,
    routeId: identifierV1Schema,
    toolName: capabilityIdentifierV1Schema,
    schemaDigest: sha256DigestV1Schema,
    credentialAudienceId: identifierV1Schema,
    policyScopeId: identifierV1Schema
  })
  .strict();

const dataFlowV1Schema = z
  .object({
    direction: z.enum(["NONE", "INGRESS", "EGRESS", "BIDIRECTIONAL", "UNKNOWN"]),
    classifications: z.array(dataClassificationV1Schema).min(1).max(16),
    externalDestination: z.boolean(),
    destinationId: identifierV1Schema.nullable()
  })
  .strict()
  .superRefine((dataFlow, context) => {
    if (new Set(dataFlow.classifications).size !== dataFlow.classifications.length) {
      context.addIssue({
        code: "custom",
        path: ["classifications"],
        message: "Data classifications must be unique"
      });
    }

    if (dataFlow.externalDestination !== (dataFlow.destinationId !== null)) {
      context.addIssue({
        code: "custom",
        path: ["destinationId"],
        message: "External destinations require one bound destination identifier"
      });
    }

    if (dataFlow.direction === "NONE" && dataFlow.externalDestination) {
      context.addIssue({
        code: "custom",
        path: ["direction"],
        message: "A NONE data flow cannot have an external destination"
      });
    }
  });

export const canonicalActionV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    actionHash: sha256DigestV1Schema,
    sessionId: identifierV1Schema,
    identity: identityBindingV1Schema,
    route: routeBindingV1Schema,
    arguments: z
      .object({
        digest: sha256DigestV1Schema,
        keys: uniqueCodesV1Schema,
        secretValuesRemoved: z.literal(true)
      })
      .strict(),
    resources: z
      .array(
        z
          .object({
            resourceId: identifierV1Schema,
            resourceClass: resourceClassV1Schema,
            canonicalReference: boundedTextV1Schema,
            classification: dataClassificationV1Schema
          })
          .strict()
      )
      .min(1)
      .max(64),
    resourcesDigest: sha256DigestV1Schema,
    effect: z.enum([
      "READ",
      "WRITE",
      "EXECUTE",
      "DELETE",
      "DISCLOSE",
      "ADMINISTER",
      "UNKNOWN"
    ]),
    environment: environmentV1Schema,
    dataFlow: dataFlowV1Schema,
    dataFlowDigest: sha256DigestV1Schema,
    parsingEvidence: z
      .object({
        parserId: identifierV1Schema,
        parserVersion: z.string().trim().min(1).max(64),
        status: z.enum(["FULL", "PARTIAL", "FAILED", "UNSUPPORTED"]),
        evidenceDigest: sha256DigestV1Schema
      })
      .strict(),
    reversibility: z.enum([
      "NOT_APPLICABLE",
      "VERIFIED_COMPENSATING_ACTION",
      "TESTED_SNAPSHOT",
      "PARTIALLY_REVERSIBLE",
      "IRREVERSIBLE",
      "UNKNOWN"
    ]),
    callChain: z
      .object({
        callChainId: identifierV1Schema,
        parentActionId: identifierV1Schema.nullable(),
        ancestorActionIds: uniqueIdentifiersV1Schema,
        depth: z.number().int().nonnegative().max(64),
        delegationDepth: z.number().int().nonnegative().max(32)
      })
      .strict(),
    influences: z
      .array(
        z.enum([
          "USER_INPUT",
          "TOOL_DESCRIPTION",
          "TOOL_RESULT",
          "RESOURCE_CONTENT",
          "MODEL_GENERATED",
          "UNKNOWN"
        ])
      )
      .max(16),
    createdAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((action, context) => {
    const resourceIds = action.resources.map((resource) => resource.resourceId);
    if (new Set(resourceIds).size !== resourceIds.length) {
      context.addIssue({
        code: "custom",
        path: ["resources"],
        message: "Canonical resource IDs must be unique"
      });
    }

    if (action.callChain.ancestorActionIds.length !== action.callChain.depth) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "depth"],
        message: "Call-chain depth must equal the bound ancestor count"
      });
    }

    if (
      (action.callChain.depth === 0) !== (action.callChain.parentActionId === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "parentActionId"],
        message: "Only root actions may omit a parent action"
      });
    }

    if (action.callChain.delegationDepth > action.callChain.depth) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "delegationDepth"],
        message: "Delegation depth cannot exceed total call depth"
      });
    }

    if (new Set(action.influences).size !== action.influences.length) {
      context.addIssue({
        code: "custom",
        path: ["influences"],
        message: "Influence markers must be unique"
      });
    }
  });

const decisionV1Schema = z.enum([
  "DENY",
  "REQUIRE_APPROVAL",
  "SANDBOX",
  "ALLOW_WITH_CONSTRAINTS",
  "ALLOW"
]);

export const policyDecisionV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    decisionId: identifierV1Schema,
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    actionHash: sha256DigestV1Schema,
    sessionId: identifierV1Schema,
    serverId: identifierV1Schema,
    routeId: identifierV1Schema,
    schemaDigest: sha256DigestV1Schema,
    decision: decisionV1Schema,
    tier: z.number().int().min(0).max(3),
    reasonCodes: uniqueCodesV1Schema.min(1),
    constraints: z
      .array(
        z
          .object({
            constraintId: identifierV1Schema,
            type: capabilityIdentifierV1Schema,
            parametersDigest: sha256DigestV1Schema
          })
          .strict()
      )
      .max(32),
    sandboxProfileId: identifierV1Schema.nullable(),
    coverage: coverageStateV1Schema,
    policyVersion: z.string().trim().min(1).max(64),
    decidedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((decision, context) => {
    if (
      decision.tier === 3 &&
      decision.decision !== "DENY" &&
      decision.decision !== "REQUIRE_APPROVAL"
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "Tier 3 decisions must deny or require exact human approval"
      });
    }

    if (
      (decision.decision === "ALLOW_WITH_CONSTRAINTS") !==
      (decision.constraints.length > 0)
    ) {
      context.addIssue({
        code: "custom",
        path: ["constraints"],
        message: "Only constrained allows may carry enforceable constraints"
      });
    }

    if ((decision.decision === "SANDBOX") !== (decision.sandboxProfileId !== null)) {
      context.addIssue({
        code: "custom",
        path: ["sandboxProfileId"],
        message: "Only sandbox decisions require a sandbox profile"
      });
    }

    const constraintIds = decision.constraints.map((constraint) => constraint.constraintId);
    if (new Set(constraintIds).size !== constraintIds.length) {
      context.addIssue({
        code: "custom",
        path: ["constraints"],
        message: "Constraint identifiers must be unique"
      });
    }
  });

export const canonicalActionDecisionBindingV1Schema = z
  .object({
    action: canonicalActionV1Schema,
    decision: policyDecisionV1Schema
  })
  .strict()
  .superRefine(({ action, decision }, context) => {
    const bindings = [
      ["requestId", action.requestId, decision.requestId],
      ["actionId", action.actionId, decision.actionId],
      ["actionHash", action.actionHash, decision.actionHash],
      ["sessionId", action.sessionId, decision.sessionId],
      ["serverId", action.route.serverId, decision.serverId],
      ["routeId", action.route.routeId, decision.routeId],
      ["schemaDigest", action.route.schemaDigest, decision.schemaDigest]
    ] as const;

    for (const [field, expected, actual] of bindings) {
      if (expected !== actual) {
        context.addIssue({
          code: "custom",
          path: ["decision", field],
          message: `Decision ${field} must match its canonical action`
        });
      }
    }

    const unresolved =
      action.effect === "UNKNOWN" ||
      action.environment === "UNKNOWN" ||
      action.parsingEvidence.status !== "FULL" ||
      action.resources.some((resource) => resource.resourceClass === "UNKNOWN") ||
      action.dataFlow.direction === "UNKNOWN" ||
      action.dataFlow.classifications.includes("UNKNOWN");
    if (
      unresolved &&
      decision.decision !== "DENY" &&
      decision.decision !== "REQUIRE_APPROVAL"
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision", "decision"],
        message: "Unknown or incompletely parsed actions must deny or require approval"
      });
    }

    if (unresolved && decision.tier < 2) {
      context.addIssue({
        code: "custom",
        path: ["decision", "tier"],
        message: "Unknown or incompletely parsed actions cannot be Tier 0 or Tier 1"
      });
    }

    const tierThreeAction =
      action.environment === "PRODUCTION" ||
      action.effect === "DELETE" ||
      action.effect === "ADMINISTER" ||
      action.reversibility === "IRREVERSIBLE" ||
      (action.effect !== "READ" &&
        action.effect !== "UNKNOWN" &&
        (action.reversibility === "PARTIALLY_REVERSIBLE" ||
          action.reversibility === "UNKNOWN")) ||
      action.resources.some((resource) => resource.classification === "CREDENTIAL");
    if (tierThreeAction && decision.tier !== 3) {
      context.addIssue({
        code: "custom",
        path: ["decision", "tier"],
        message: "Production, destructive, privileged, credential, or irreversible actions are Tier 3"
      });
    }

    const mutating = action.effect !== "READ";
    if (mutating && decision.coverage !== "ENFORCED" && decision.decision !== "DENY") {
      context.addIssue({
        code: "custom",
        path: ["decision", "decision"],
        message: "Mutations must deny when coverage is not ENFORCED"
      });
    }

    if (
      decision.tier === 0 &&
      (action.effect !== "READ" ||
        action.parsingEvidence.status !== "FULL" ||
        action.dataFlow.externalDestination ||
        action.resources.some((resource) => resource.classification !== "PUBLIC"))
    ) {
      context.addIssue({
        code: "custom",
        path: ["decision", "tier"],
        message: "Tier 0 requires a fully parsed, public, non-egressing read"
      });
    }
  });

export const approvalV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    approvalId: identifierV1Schema,
    decisionId: identifierV1Schema,
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    actionHash: sha256DigestV1Schema,
    sessionId: identifierV1Schema,
    identity: identityBindingV1Schema,
    route: routeBindingV1Schema,
    resourcesDigest: sha256DigestV1Schema,
    environment: environmentV1Schema,
    dataFlowDigest: sha256DigestV1Schema,
    policyVersion: z.string().trim().min(1).max(64),
    state: z.enum(["PENDING", "APPROVED", "DENIED", "EXPIRED", "CONSUMED", "REVOKED"]),
    requestedAt: utcTimestampV1Schema,
    decidedAt: utcTimestampV1Schema.nullable(),
    expiresAt: utcTimestampV1Schema,
    decidedByHumanId: identifierV1Schema.nullable(),
    consumption: z
      .object({
        consumptionId: identifierV1Schema,
        consumedAt: utcTimestampV1Schema,
        forwardingAttemptId: identifierV1Schema
      })
      .strict()
      .nullable()
  })
  .strict()
  .superRefine((approval, context) => {
    const requestedAt = Date.parse(approval.requestedAt);
    const expiresAt = Date.parse(approval.expiresAt);
    if (expiresAt <= requestedAt || expiresAt - requestedAt > 5 * 60 * 1_000) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "Approval expiry must be after request and no more than five minutes later"
      });
    }

    const requiresHumanDecision = new Set(["APPROVED", "DENIED", "CONSUMED"]);
    const hasDecisionEvidence =
      approval.decidedAt !== null || approval.decidedByHumanId !== null;
    if (
      approval.state !== "EXPIRED" &&
      approval.state !== "REVOKED" &&
      requiresHumanDecision.has(approval.state) !== hasDecisionEvidence
    ) {
      context.addIssue({
        code: "custom",
        path: ["decidedAt"],
        message: "Approval state and human-decision evidence are inconsistent"
      });
    }

    if ((approval.decidedAt === null) !== (approval.decidedByHumanId === null)) {
      context.addIssue({
        code: "custom",
        path: ["decidedByHumanId"],
        message: "Human identity and decision timestamp must be present together"
      });
    }

    if (approval.decidedAt !== null) {
      const decidedAt = Date.parse(approval.decidedAt);
      if (decidedAt < requestedAt || decidedAt > expiresAt) {
        context.addIssue({
          code: "custom",
          path: ["decidedAt"],
          message: "Human decisions must occur within the approval validity window"
        });
      }
    }

    if ((approval.state === "CONSUMED") !== (approval.consumption !== null)) {
      context.addIssue({
        code: "custom",
        path: ["consumption"],
        message: "Only consumed approvals may carry one consumption record"
      });
    }

    if (approval.consumption !== null) {
      const consumedAt = Date.parse(approval.consumption.consumedAt);
      if (approval.decidedAt === null || consumedAt < Date.parse(approval.decidedAt)) {
        context.addIssue({
          code: "custom",
          path: ["consumption", "consumedAt"],
          message: "Approval cannot be consumed before the human decision"
        });
      }
      if (consumedAt > expiresAt) {
        context.addIssue({
          code: "custom",
          path: ["consumption", "consumedAt"],
          message: "Expired approvals cannot be consumed"
        });
      }
    }
  });

export const downstreamProvenanceV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    provenanceId: identifierV1Schema,
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    sessionId: identifierV1Schema,
    callChainId: identifierV1Schema,
    serverId: identifierV1Schema,
    authenticatedPrincipalId: identifierV1Schema,
    routeId: identifierV1Schema,
    toolName: capabilityIdentifierV1Schema,
    schemaDigest: sha256DigestV1Schema,
    transportEvidenceDigest: sha256DigestV1Schema,
    receivedAt: utcTimestampV1Schema,
    contentTrust: z.literal("UNTRUSTED")
  })
  .strict();

export const downstreamResultV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    resultId: identifierV1Schema,
    provenanceId: identifierV1Schema,
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    sessionId: identifierV1Schema,
    serverId: identifierV1Schema,
    routeId: identifierV1Schema,
    resultKind: z.enum(["SUCCESS", "TOOL_ERROR", "PROTOCOL_ERROR"]),
    mediaType: z.string().trim().min(1).max(128),
    byteLength: z.number().int().nonnegative().max(64 * 1_024 * 1_024),
    contentDigest: sha256DigestV1Schema,
    schemaValidation: z.enum(["VALID", "INVALID", "UNVERIFIED"]),
    schemaDigest: sha256DigestV1Schema,
    classifications: z.array(dataClassificationV1Schema).min(1).max(16),
    redaction: z
      .object({
        state: z.enum(["NONE", "APPLIED", "FAILED"]),
        fieldsRedacted: z.number().int().nonnegative().max(100_000),
        evidenceDigest: sha256DigestV1Schema
      })
      .strict(),
    untrustedContentMarkers: uniqueCodesV1Schema,
    disposition: z.enum(["ALLOW", "REDACT", "DENY", "QUARANTINE"]),
    processedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((result, context) => {
    if (new Set(result.classifications).size !== result.classifications.length) {
      context.addIssue({
        code: "custom",
        path: ["classifications"],
        message: "Result classifications must be unique"
      });
    }

    if (
      result.schemaValidation !== "VALID" &&
      result.disposition !== "DENY" &&
      result.disposition !== "QUARANTINE"
    ) {
      context.addIssue({
        code: "custom",
        path: ["disposition"],
        message: "Invalid or unverified results must deny or quarantine"
      });
    }

    if (
      (result.redaction.state === "APPLIED") !==
      (result.redaction.fieldsRedacted > 0 && result.disposition === "REDACT")
    ) {
      context.addIssue({
        code: "custom",
        path: ["redaction"],
        message: "Applied redaction requires redacted fields and REDACT disposition"
      });
    }

    if (result.disposition === "REDACT" && result.redaction.state !== "APPLIED") {
      context.addIssue({
        code: "custom",
        path: ["redaction", "state"],
        message: "REDACT disposition requires successfully applied redaction"
      });
    }

    if (result.redaction.state === "FAILED" && result.disposition !== "DENY") {
      context.addIssue({
        code: "custom",
        path: ["disposition"],
        message: "Failed redaction must deny the result"
      });
    }

    if (
      result.classifications.includes("CREDENTIAL") &&
      result.disposition !== "REDACT" &&
      result.disposition !== "DENY" &&
      result.disposition !== "QUARANTINE"
    ) {
      context.addIssue({
        code: "custom",
        path: ["disposition"],
        message: "Credential-bearing results cannot pass without protective disposition"
      });
    }
  });

export const executionOutcomeV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    outcomeId: identifierV1Schema,
    requestId: identifierV1Schema,
    actionId: identifierV1Schema,
    sessionId: identifierV1Schema,
    decisionId: identifierV1Schema,
    approvalId: identifierV1Schema.nullable(),
    forwardingAttemptId: identifierV1Schema.nullable(),
    resultId: identifierV1Schema.nullable(),
    provenanceId: identifierV1Schema.nullable(),
    status: z.enum([
      "NOT_FORWARDED",
      "FORWARDED",
      "COMPLETED",
      "FAILED",
      "CANCELLED",
      "TIMED_OUT",
      "UNKNOWN"
    ]),
    forwardedAt: utcTimestampV1Schema.nullable(),
    finishedAt: utcTimestampV1Schema.nullable(),
    possiblePartialEffects: z.boolean(),
    recoveryClass: z.enum([
      "NOT_APPLICABLE",
      "VERIFIED_COMPENSATING_ACTION",
      "TESTED_SNAPSHOT",
      "PARTIALLY_REVERSIBLE",
      "IRREVERSIBLE",
      "UNKNOWN"
    ]),
    trustEvidenceEligible: z.boolean(),
    observedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((outcome, context) => {
    const forwarded = outcome.status !== "NOT_FORWARDED";
    if (
      forwarded !==
      (outcome.forwardingAttemptId !== null && outcome.forwardedAt !== null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["forwardingAttemptId"],
        message: "Forwarded outcomes require one attempt identifier and timestamp"
      });
    }

    const terminal = new Set(["COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT", "UNKNOWN"]);
    if (terminal.has(outcome.status) !== (outcome.finishedAt !== null)) {
      context.addIssue({
        code: "custom",
        path: ["finishedAt"],
        message: "Only terminal outcomes require a completion timestamp"
      });
    }

    if (
      (outcome.resultId === null) !== (outcome.provenanceId === null) ||
      (outcome.status === "COMPLETED" && outcome.resultId === null)
    ) {
      context.addIssue({
        code: "custom",
        path: ["resultId"],
        message: "Completed results require paired result and provenance identifiers"
      });
    }

    if (outcome.forwardedAt !== null && outcome.finishedAt !== null) {
      if (Date.parse(outcome.finishedAt) < Date.parse(outcome.forwardedAt)) {
        context.addIssue({
          code: "custom",
          path: ["finishedAt"],
          message: "Terminal outcomes cannot predate forwarding"
        });
      }
    }

    if (outcome.status === "UNKNOWN" && !outcome.possiblePartialEffects) {
      context.addIssue({
        code: "custom",
        path: ["possiblePartialEffects"],
        message: "Unknown outcomes must surface possible partial effects"
      });
    }

    if (outcome.status !== "COMPLETED" && outcome.trustEvidenceEligible) {
      context.addIssue({
        code: "custom",
        path: ["trustEvidenceEligible"],
        message: "Only completed outcomes may be eligible for positive trust evidence"
      });
    }
  });

export const requestOutcomeTrajectoryV1Schema = z
  .object({
    action: canonicalActionV1Schema,
    decision: policyDecisionV1Schema,
    approval: approvalV1Schema.nullable(),
    provenance: downstreamProvenanceV1Schema.nullable(),
    result: downstreamResultV1Schema.nullable(),
    outcome: executionOutcomeV1Schema
  })
  .strict()
  .superRefine((trajectory, context) => {
    const actionDecision = canonicalActionDecisionBindingV1Schema.safeParse({
      action: trajectory.action,
      decision: trajectory.decision
    });
    if (!actionDecision.success) {
      context.addIssue({
        code: "custom",
        path: ["decision"],
        message: "Decision does not safely bind to the canonical action"
      });
    }

    const { action, decision, approval, provenance, result, outcome } = trajectory;
    if (Date.parse(decision.decidedAt) < Date.parse(action.createdAt)) {
      context.addIssue({
        code: "custom",
        path: ["decision", "decidedAt"],
        message: "Policy decisions cannot predate their canonical action"
      });
    }
    const outcomeBindings = [
      [action.requestId, outcome.requestId],
      [action.actionId, outcome.actionId],
      [action.sessionId, outcome.sessionId],
      [decision.decisionId, outcome.decisionId]
    ];
    if (outcomeBindings.some(([expected, actual]) => expected !== actual)) {
      context.addIssue({
        code: "custom",
        path: ["outcome"],
        message: "Outcome identifiers must bind to the same request trajectory"
      });
    }

    const approvalRequired = decision.decision === "REQUIRE_APPROVAL";
    if (approvalRequired !== (approval !== null)) {
      context.addIssue({
        code: "custom",
        path: ["approval"],
        message: "Only REQUIRE_APPROVAL decisions may carry approval state"
      });
    }

    if (approval !== null) {
      if (Date.parse(approval.requestedAt) < Date.parse(decision.decidedAt)) {
        context.addIssue({
          code: "custom",
          path: ["approval", "requestedAt"],
          message: "Approval requests cannot predate the policy decision"
        });
      }
      const exactApprovalBindings = [
        [approval.decisionId, decision.decisionId],
        [approval.requestId, action.requestId],
        [approval.actionId, action.actionId],
        [approval.actionHash, action.actionHash],
        [approval.sessionId, action.sessionId],
        [approval.route.serverId, action.route.serverId],
        [approval.route.routeId, action.route.routeId],
        [approval.route.toolName, action.route.toolName],
        [approval.route.schemaDigest, action.route.schemaDigest],
        [approval.route.credentialAudienceId, action.route.credentialAudienceId],
        [approval.route.policyScopeId, action.route.policyScopeId],
        [approval.resourcesDigest, action.resourcesDigest],
        [approval.environment, action.environment],
        [approval.dataFlowDigest, action.dataFlowDigest],
        [approval.policyVersion, decision.policyVersion]
      ];
      const identityMatches = Object.entries(action.identity).every(
        ([key, value]) => approval.identity[key as keyof typeof approval.identity] === value
      );
      if (
        exactApprovalBindings.some(([expected, actual]) => expected !== actual) ||
        !identityMatches
      ) {
        context.addIssue({
          code: "custom",
          path: ["approval"],
          message: "Approval must bind the exact identity, action, route, resources, and policy"
        });
      }

      if (outcome.status !== "NOT_FORWARDED") {
        if (
          approval.state !== "CONSUMED" ||
          approval.consumption?.forwardingAttemptId !== outcome.forwardingAttemptId ||
          outcome.forwardedAt === null ||
          Date.parse(approval.consumption.consumedAt) > Date.parse(outcome.forwardedAt)
        ) {
          context.addIssue({
            code: "custom",
            path: ["approval", "consumption"],
            message: "Approved forwarding requires prior atomic consumption for the same attempt"
          });
        }
      }
    }

    if (outcome.approvalId !== (approval?.approvalId ?? null)) {
      context.addIssue({
        code: "custom",
        path: ["outcome", "approvalId"],
        message: "Outcome approval binding is inconsistent"
      });
    }

    if (decision.decision === "DENY" && outcome.status !== "NOT_FORWARDED") {
      context.addIssue({
        code: "custom",
        path: ["outcome", "status"],
        message: "Denied decisions cannot produce forwarded outcomes"
      });
    }

    if ((provenance === null) !== (result === null)) {
      context.addIssue({
        code: "custom",
        path: ["result"],
        message: "Results and provenance must be present together"
      });
    }

    if (provenance !== null && result !== null) {
      const provenanceBindings = [
        [provenance.provenanceId, result.provenanceId],
        [provenance.requestId, action.requestId],
        [result.requestId, action.requestId],
        [provenance.actionId, action.actionId],
        [result.actionId, action.actionId],
        [provenance.sessionId, action.sessionId],
        [result.sessionId, action.sessionId],
        [provenance.callChainId, action.callChain.callChainId],
        [provenance.serverId, action.route.serverId],
        [result.serverId, action.route.serverId],
        [provenance.routeId, action.route.routeId],
        [result.routeId, action.route.routeId],
        [provenance.toolName, action.route.toolName],
        [provenance.schemaDigest, action.route.schemaDigest],
        [result.schemaDigest, action.route.schemaDigest],
        [outcome.resultId, result.resultId],
        [outcome.provenanceId, provenance.provenanceId]
      ];
      if (provenanceBindings.some(([expected, actual]) => expected !== actual)) {
        context.addIssue({
          code: "custom",
          path: ["result"],
          message: "Result provenance must bind to the exact request, route, and outcome"
        });
      }

      if (
        outcome.forwardedAt === null ||
        Date.parse(provenance.receivedAt) < Date.parse(outcome.forwardedAt) ||
        Date.parse(result.processedAt) < Date.parse(provenance.receivedAt) ||
        (outcome.finishedAt !== null &&
          Date.parse(outcome.finishedAt) < Date.parse(result.processedAt))
      ) {
        context.addIssue({
          code: "custom",
          path: ["result", "processedAt"],
          message: "Forwarding, receipt, processing, and completion timestamps are out of order"
        });
      }

      if (
        outcome.trustEvidenceEligible &&
        (result.schemaValidation !== "VALID" ||
          (result.disposition !== "ALLOW" && result.disposition !== "REDACT"))
      ) {
        context.addIssue({
          code: "custom",
          path: ["outcome", "trustEvidenceEligible"],
          message: "Only safely released valid results may create eligible trust evidence"
        });
      }
    }
  });

export type CanonicalActionV1 = z.infer<typeof canonicalActionV1Schema>;
export type PolicyDecisionV1 = z.infer<typeof policyDecisionV1Schema>;
export type ApprovalV1 = z.infer<typeof approvalV1Schema>;
export type DownstreamProvenanceV1 = z.infer<typeof downstreamProvenanceV1Schema>;
export type DownstreamResultV1 = z.infer<typeof downstreamResultV1Schema>;
export type ExecutionOutcomeV1 = z.infer<typeof executionOutcomeV1Schema>;
export type RequestOutcomeTrajectoryV1 = z.infer<typeof requestOutcomeTrajectoryV1Schema>;
