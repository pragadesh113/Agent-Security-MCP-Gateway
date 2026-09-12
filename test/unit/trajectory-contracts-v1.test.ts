import { describe, expect, it } from "vitest";

import {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  downstreamProvenanceV1Schema,
  downstreamResultV1Schema,
  executionOutcomeV1Schema,
  gatewayScaffoldStatus,
  policyDecisionV1Schema,
  requestOutcomeTrajectoryV1Schema
} from "../../src/index.js";

const digest = (character: string): string => character.repeat(64);

const baseAction = {
  schemaVersion: "1.0.0",
  requestId: "request-001",
  actionId: "action-001",
  actionHash: digest("1"),
  sessionId: "session-001",
  identity: {
    userId: "user-001",
    agentId: "agent-001",
    clientId: "client-001",
    hostId: "host-001"
  },
  route: {
    serverId: "server-001",
    routeId: "route-001",
    toolName: "filesystem.read_file",
    schemaDigest: digest("a"),
    credentialAudienceId: "audience-filesystem-test",
    policyScopeId: "scope-disposable-repository"
  },
  arguments: {
    digest: digest("2"),
    keys: ["path"],
    secretValuesRemoved: true
  },
  resources: [
    {
      resourceId: "resource-readme",
      resourceClass: "FILESYSTEM",
      canonicalReference: "V:/disposable/repository/README.md",
      classification: "PUBLIC"
    }
  ],
  resourcesDigest: digest("3"),
  effect: "READ",
  environment: "TEST",
  dataFlow: {
    direction: "NONE",
    classifications: ["PUBLIC"],
    externalDestination: false,
    destinationId: null
  },
  dataFlowDigest: digest("4"),
  parsingEvidence: {
    parserId: "filesystem-parser",
    parserVersion: "1.0.0",
    status: "FULL",
    evidenceDigest: digest("5")
  },
  reversibility: "NOT_APPLICABLE",
  callChain: {
    callChainId: "call-chain-001",
    parentActionId: null,
    ancestorActionIds: [],
    depth: 0,
    delegationDepth: 0
  },
  influences: ["USER_INPUT"],
  createdAt: "2026-09-01T12:00:00.000Z"
} as const;

const baseDecision = {
  schemaVersion: "1.0.0",
  decisionId: "decision-001",
  requestId: baseAction.requestId,
  actionId: baseAction.actionId,
  actionHash: baseAction.actionHash,
  sessionId: baseAction.sessionId,
  serverId: baseAction.route.serverId,
  routeId: baseAction.route.routeId,
  schemaDigest: baseAction.route.schemaDigest,
  decision: "ALLOW",
  tier: 0,
  reasonCodes: ["policy.safe_read"],
  constraints: [],
  sandboxProfileId: null,
  coverage: "ENFORCED",
  policyVersion: "policy-1.0.0",
  decidedAt: "2026-09-01T12:00:01.000Z"
} as const;

const baseProvenance = {
  schemaVersion: "1.0.0",
  provenanceId: "provenance-001",
  requestId: baseAction.requestId,
  actionId: baseAction.actionId,
  sessionId: baseAction.sessionId,
  callChainId: baseAction.callChain.callChainId,
  serverId: baseAction.route.serverId,
  authenticatedPrincipalId: "principal-server-001",
  routeId: baseAction.route.routeId,
  toolName: baseAction.route.toolName,
  schemaDigest: baseAction.route.schemaDigest,
  transportEvidenceDigest: digest("6"),
  receivedAt: "2026-09-01T12:00:32.000Z",
  contentTrust: "UNTRUSTED"
} as const;

const baseResult = {
  schemaVersion: "1.0.0",
  resultId: "result-001",
  provenanceId: baseProvenance.provenanceId,
  requestId: baseAction.requestId,
  actionId: baseAction.actionId,
  sessionId: baseAction.sessionId,
  serverId: baseAction.route.serverId,
  routeId: baseAction.route.routeId,
  resultKind: "SUCCESS",
  mediaType: "application/json",
  byteLength: 128,
  contentDigest: digest("7"),
  schemaValidation: "VALID",
  schemaDigest: baseAction.route.schemaDigest,
  classifications: ["PUBLIC"],
  redaction: {
    state: "NONE",
    fieldsRedacted: 0,
    evidenceDigest: digest("8")
  },
  untrustedContentMarkers: [],
  disposition: "ALLOW",
  processedAt: "2026-09-01T12:00:33.000Z"
} as const;

const baseOutcome = {
  schemaVersion: "1.0.0",
  outcomeId: "outcome-001",
  requestId: baseAction.requestId,
  actionId: baseAction.actionId,
  sessionId: baseAction.sessionId,
  decisionId: baseDecision.decisionId,
  approvalId: null,
  forwardingAttemptId: "forwarding-001",
  resultId: baseResult.resultId,
  provenanceId: baseProvenance.provenanceId,
  status: "COMPLETED",
  forwardedAt: "2026-09-01T12:00:31.500Z",
  finishedAt: "2026-09-01T12:00:34.000Z",
  possiblePartialEffects: false,
  recoveryClass: "NOT_APPLICABLE",
  trustEvidenceEligible: true,
  observedAt: "2026-09-01T12:00:34.000Z"
} as const;

const safeReadTrajectory = {
  action: baseAction,
  decision: baseDecision,
  approval: null,
  provenance: baseProvenance,
  result: baseResult,
  outcome: baseOutcome
} as const;

const tierThreeAction = {
  ...baseAction,
  actionId: "action-production-delete",
  actionHash: digest("9"),
  resources: [
    {
      ...baseAction.resources[0],
      resourceId: "resource-production-record",
      classification: "CONFIDENTIAL"
    }
  ],
  resourcesDigest: digest("b"),
  effect: "DELETE",
  environment: "PRODUCTION",
  reversibility: "IRREVERSIBLE"
} as const;

const tierThreeDecision = {
  ...baseDecision,
  decisionId: "decision-production-delete",
  actionId: tierThreeAction.actionId,
  actionHash: tierThreeAction.actionHash,
  decision: "REQUIRE_APPROVAL",
  tier: 3,
  reasonCodes: ["invariant.tier3_approval"]
} as const;

const consumedApproval = {
  schemaVersion: "1.0.0",
  approvalId: "approval-production-delete",
  decisionId: tierThreeDecision.decisionId,
  requestId: tierThreeAction.requestId,
  actionId: tierThreeAction.actionId,
  actionHash: tierThreeAction.actionHash,
  sessionId: tierThreeAction.sessionId,
  identity: tierThreeAction.identity,
  route: tierThreeAction.route,
  resourcesDigest: tierThreeAction.resourcesDigest,
  environment: tierThreeAction.environment,
  dataFlowDigest: tierThreeAction.dataFlowDigest,
  policyVersion: tierThreeDecision.policyVersion,
  state: "CONSUMED",
  requestedAt: "2026-09-01T12:00:02.000Z",
  decidedAt: "2026-09-01T12:00:30.000Z",
  expiresAt: "2026-09-01T12:05:02.000Z",
  decidedByHumanId: "human-001",
  consumption: {
    consumptionId: "consumption-001",
    consumedAt: "2026-09-01T12:00:31.000Z",
    forwardingAttemptId: "forwarding-production-delete"
  }
} as const;

const tierThreeProvenance = {
  ...baseProvenance,
  provenanceId: "provenance-production-delete",
  actionId: tierThreeAction.actionId
} as const;

const tierThreeResult = {
  ...baseResult,
  resultId: "result-production-delete",
  provenanceId: tierThreeProvenance.provenanceId,
  actionId: tierThreeAction.actionId
} as const;

const tierThreeOutcome = {
  ...baseOutcome,
  outcomeId: "outcome-production-delete",
  actionId: tierThreeAction.actionId,
  decisionId: tierThreeDecision.decisionId,
  approvalId: consumedApproval.approvalId,
  forwardingAttemptId: consumedApproval.consumption.forwardingAttemptId,
  resultId: tierThreeResult.resultId,
  provenanceId: tierThreeProvenance.provenanceId,
  trustEvidenceEligible: false
} as const;

const tierThreeTrajectory = {
  action: tierThreeAction,
  decision: tierThreeDecision,
  approval: consumedApproval,
  provenance: tierThreeProvenance,
  result: tierThreeResult,
  outcome: tierThreeOutcome
} as const;

describe("request-to-outcome V1 trajectory", () => {
  it("accepts a fully bound safe read trajectory", () => {
    expect(requestOutcomeTrajectoryV1Schema.parse(safeReadTrajectory)).toEqual(
      safeReadTrajectory
    );
  });

  it("accepts Tier 3 only with exact prior single-use human approval", () => {
    expect(requestOutcomeTrajectoryV1Schema.parse(tierThreeTrajectory)).toEqual(
      tierThreeTrajectory
    );
  });

  it("accepts an unresolved action only as a non-forwarded denial", () => {
    const unknownAction = {
      ...baseAction,
      actionId: "action-unknown",
      actionHash: digest("c"),
      resources: [
        {
          ...baseAction.resources[0],
          resourceClass: "UNKNOWN",
          classification: "UNKNOWN"
        }
      ],
      effect: "UNKNOWN",
      environment: "UNKNOWN",
      dataFlow: {
        ...baseAction.dataFlow,
        direction: "UNKNOWN",
        classifications: ["UNKNOWN"]
      },
      parsingEvidence: { ...baseAction.parsingEvidence, status: "FAILED" },
      reversibility: "UNKNOWN"
    } as const;
    const denyDecision = {
      ...baseDecision,
      decisionId: "decision-unknown",
      actionId: unknownAction.actionId,
      actionHash: unknownAction.actionHash,
      decision: "DENY",
      tier: 2,
      reasonCodes: ["policy.unknown_action"],
      coverage: "UNPROTECTED"
    } as const;
    const deniedOutcome = {
      ...baseOutcome,
      outcomeId: "outcome-unknown",
      actionId: unknownAction.actionId,
      decisionId: denyDecision.decisionId,
      forwardingAttemptId: null,
      resultId: null,
      provenanceId: null,
      status: "NOT_FORWARDED",
      forwardedAt: null,
      finishedAt: null,
      recoveryClass: "UNKNOWN",
      trustEvidenceEligible: false
    } as const;

    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        action: unknownAction,
        decision: denyDecision,
        approval: null,
        provenance: null,
        result: null,
        outcome: deniedOutcome
      }).success
    ).toBe(true);
  });

  it("rejects Tier 3 allow decisions and low-risk treatment of unknown actions", () => {
    expect(
      policyDecisionV1Schema.safeParse({
        ...tierThreeDecision,
        decision: "ALLOW",
        constraints: []
      }).success
    ).toBe(false);

    const partialAction = {
      ...baseAction,
      parsingEvidence: { ...baseAction.parsingEvidence, status: "PARTIAL" }
    } as const;
    expect(
      canonicalActionDecisionBindingV1Schema.safeParse({
        action: partialAction,
        decision: baseDecision
      }).success
    ).toBe(false);
  });

  it("rejects mutations when coverage is degraded", () => {
    const mutation = {
      ...baseAction,
      effect: "WRITE",
      reversibility: "VERIFIED_COMPENSATING_ACTION"
    } as const;
    const degradedAllow = {
      ...baseDecision,
      decision: "ALLOW",
      tier: 1,
      coverage: "DEGRADED",
      reasonCodes: ["policy.local_write"]
    } as const;
    expect(
      canonicalActionDecisionBindingV1Schema.safeParse({
        action: mutation,
        decision: degradedAllow
      }).success
    ).toBe(false);
  });

  it("accepts internally consistent constrained and sandbox decisions", () => {
    expect(
      policyDecisionV1Schema.safeParse({
        ...baseDecision,
        decision: "ALLOW_WITH_CONSTRAINTS",
        tier: 1,
        constraints: [
          {
            constraintId: "constraint-path-prefix",
            type: "filesystem.path_prefix",
            parametersDigest: digest("f")
          }
        ]
      }).success
    ).toBe(true);
    expect(
      policyDecisionV1Schema.safeParse({
        ...baseDecision,
        decision: "SANDBOX",
        tier: 2,
        sandboxProfileId: "sandbox-disposable-read"
      }).success
    ).toBe(true);
    expect(
      policyDecisionV1Schema.safeParse({
        ...baseDecision,
        constraints: [
          {
            constraintId: "constraint-unenforced",
            type: "filesystem.path_prefix",
            parametersDigest: digest("f")
          }
        ]
      }).success
    ).toBe(false);
  });

  it("rejects decision identity, action, route, or schema mismatches", () => {
    expect(
      canonicalActionDecisionBindingV1Schema.safeParse({
        action: baseAction,
        decision: { ...baseDecision, actionHash: digest("d") }
      }).success
    ).toBe(false);
    expect(
      canonicalActionDecisionBindingV1Schema.safeParse({
        action: baseAction,
        decision: { ...baseDecision, routeId: "route-attacker" }
      }).success
    ).toBe(false);
  });

  it("rejects approval windows longer than five minutes or inconsistent states", () => {
    expect(
      approvalV1Schema.safeParse({
        ...consumedApproval,
        expiresAt: "2026-09-01T12:05:02.001Z"
      }).success
    ).toBe(false);
    expect(
      approvalV1Schema.safeParse({
        ...consumedApproval,
        state: "PENDING",
        decidedByHumanId: null,
        consumption: null
      }).success
    ).toBe(false);
  });

  it("rejects modified or unconsumed approvals before forwarding", () => {
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: { ...consumedApproval, resourcesDigest: digest("e") }
      }).success
    ).toBe(false);

    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: {
          ...consumedApproval,
          identity: { ...consumedApproval.identity, agentId: "agent-attacker" }
        }
      }).success
    ).toBe(false);

    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: {
          ...consumedApproval,
          route: { ...consumedApproval.route, schemaDigest: digest("e") }
        }
      }).success
    ).toBe(false);

    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: { ...consumedApproval, policyVersion: "policy-attacker" }
      }).success
    ).toBe(false);

    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: {
          ...consumedApproval,
          state: "APPROVED",
          consumption: null
        }
      }).success
    ).toBe(false);
  });

  it("rejects consumption after forwarding and mismatched forwarding attempts", () => {
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        approval: {
          ...consumedApproval,
          consumption: {
            ...consumedApproval.consumption,
            consumedAt: "2026-09-01T12:00:32.000Z"
          }
        }
      }).success
    ).toBe(false);
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...tierThreeTrajectory,
        outcome: {
          ...tierThreeOutcome,
          forwardingAttemptId: "forwarding-attacker"
        }
      }).success
    ).toBe(false);
  });

  it("rejects unverified, credential-bearing, or unsuccessfully redacted results", () => {
    expect(
      downstreamResultV1Schema.safeParse({
        ...baseResult,
        schemaValidation: "UNVERIFIED"
      }).success
    ).toBe(false);
    expect(
      downstreamResultV1Schema.safeParse({
        ...baseResult,
        classifications: ["CREDENTIAL"]
      }).success
    ).toBe(false);
    expect(
      downstreamResultV1Schema.safeParse({
        ...baseResult,
        disposition: "REDACT"
      }).success
    ).toBe(false);
  });

  it("accepts fail-safe quarantine and successful credential redaction", () => {
    expect(
      downstreamResultV1Schema.safeParse({
        ...baseResult,
        schemaValidation: "UNVERIFIED",
        disposition: "QUARANTINE"
      }).success
    ).toBe(true);
    expect(
      downstreamResultV1Schema.safeParse({
        ...baseResult,
        classifications: ["CREDENTIAL"],
        redaction: {
          ...baseResult.redaction,
          state: "APPLIED",
          fieldsRedacted: 1
        },
        disposition: "REDACT"
      }).success
    ).toBe(true);
  });

  it("rejects result provenance and chronology mismatches", () => {
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...safeReadTrajectory,
        provenance: { ...baseProvenance, routeId: "route-attacker" }
      }).success
    ).toBe(false);
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...safeReadTrajectory,
        result: {
          ...baseResult,
          processedAt: "2026-09-01T12:00:31.000Z"
        }
      }).success
    ).toBe(false);
  });

  it("rejects forwarded denials and unknown outcomes that hide partial effects", () => {
    expect(
      requestOutcomeTrajectoryV1Schema.safeParse({
        ...safeReadTrajectory,
        decision: { ...baseDecision, decision: "DENY", tier: 2 }
      }).success
    ).toBe(false);

    expect(
      executionOutcomeV1Schema.safeParse({
        ...baseOutcome,
        resultId: null,
        provenanceId: null,
        status: "UNKNOWN",
        possiblePartialEffects: false,
        trustEvidenceEligible: false
      }).success
    ).toBe(false);
  });

  it("rejects forward-incompatible schema versions across the trajectory", () => {
    expect(
      canonicalActionV1Schema.safeParse({ ...baseAction, schemaVersion: "2.0.0" }).success
    ).toBe(false);
    expect(
      policyDecisionV1Schema.safeParse({ ...baseDecision, schemaVersion: "2.0.0" })
        .success
    ).toBe(false);
    expect(
      approvalV1Schema.safeParse({ ...consumedApproval, schemaVersion: "2.0.0" }).success
    ).toBe(false);
    expect(
      downstreamProvenanceV1Schema.safeParse({
        ...baseProvenance,
        schemaVersion: "2.0.0"
      }).success
    ).toBe(false);
    expect(
      downstreamResultV1Schema.safeParse({ ...baseResult, schemaVersion: "2.0.0" })
        .success
    ).toBe(false);
    expect(
      executionOutcomeV1Schema.safeParse({ ...baseOutcome, schemaVersion: "2.0.0" })
        .success
    ).toBe(false);
  });

  it("rejects malformed call-chain and data-flow bindings", () => {
    expect(
      canonicalActionV1Schema.safeParse({
        ...baseAction,
        callChain: {
          ...baseAction.callChain,
          parentActionId: "parent-001",
          depth: 0
        }
      }).success
    ).toBe(false);
    expect(
      canonicalActionV1Schema.safeParse({
        ...baseAction,
        dataFlow: {
          ...baseAction.dataFlow,
          externalDestination: true,
          destinationId: null
        }
      }).success
    ).toBe(false);
    expect(
      canonicalActionV1Schema.safeParse({
        ...baseAction,
        resources: [baseAction.resources[0], baseAction.resources[0]]
      }).success
    ).toBe(false);
    expect(
      canonicalActionV1Schema.safeParse({
        ...baseAction,
        influences: ["USER_INPUT", "USER_INPUT"]
      }).success
    ).toBe(false);
    expect(
      canonicalActionV1Schema.safeParse({
        ...baseAction,
        arguments: { ...baseAction.arguments, secretValuesRemoved: false }
      }).success
    ).toBe(false);
  });

  it("keeps the runtime non-forwarding and UNPROTECTED", () => {
    expect(gatewayScaffoldStatus).toMatchObject({
      coverage: "UNPROTECTED",
      acceptsLifecycleTraffic: true,
      protectedForwardingEnabled: false
    });
  });
});
