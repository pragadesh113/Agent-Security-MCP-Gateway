import { describe, expect, it } from "vitest";

import {
  DynamicTrustControllerV1,
  boundedTrustCandidateV1Schema,
  buildDynamicTrustExperimentReportV1,
  computeCanonicalDigestV1,
  trustTrialObservationV1Schema,
  verifiedPositiveTrustEvidenceV1Schema,
  type BoundedTrustCandidateV1,
  type CanonicalActionV1,
  type PolicyDecisionV1,
  type TrustFreezeSignalV1,
  type TrustScopeV1,
  type TrustTrialObservationV1
} from "../../src/index.js";

const digest = (value: unknown) => computeCanonicalDigestV1(value);

function scope(overrides: Partial<TrustScopeV1> = {}): TrustScopeV1 {
  return {
    userId: "user-trust", agentId: "agent-trust", clientId: "client-trust", hostId: "host-trust",
    credentialId: "credential-trust", identityRevision: 1, policyScopeId: "scope-trust",
    serverId: "server-trust", serverPrincipalId: "principal-trust", routeId: "route-trust",
    routeRevision: 1, toolName: "files.read", schemaDigest: "a".repeat(64),
    credentialAudienceId: "audience-trust", policyVersion: "policy-trust-v1", environment: "TEST",
    actionFamilyDigest: digest({ family: "read-public-test" }), ...overrides
  };
}

function observation(
  arm: TrustTrialObservationV1["arm"],
  repetition: number,
  overrides: Partial<TrustTrialObservationV1> = {}
): TrustTrialObservationV1 {
  const grinding = repetition >= 10 && repetition < 15;
  const immutable = repetition >= 15 && repetition < 20;
  const attack = repetition < 10 || grinding || immutable;
  const scenarioClass: TrustTrialObservationV1["scenarioClass"] = repetition < 10 ? "ATTACK" :
    grinding ? "TRUST_GRINDING" : immutable ? "IMMUTABLE_EXCLUSION" : "BENIGN";
  const base = {
    schemaVersion: "1.0.0" as const,
    trialId: `${arm.toLowerCase().replaceAll("_", "-")}-${String(repetition)}`,
    scenarioId: `scenario-${String(repetition)}`,
    repetition,
    seed: 10_000 + repetition,
    arm,
    scenarioClass,
    mode: "SHADOW" as const,
    deterministicDecision: "REQUIRE_APPROVAL" as const,
    effectiveDecision: "REQUIRE_APPROVAL" as const,
    evaluatedDecision: arm === "BOUNDED_TRUST" && !attack ? "ALLOW_WITH_CONSTRAINTS" as const : "REQUIRE_APPROVAL" as const,
    attackAttempted: attack,
    attackSucceeded: false,
    policyViolation: false,
    falseAllow: false,
    falseDenial: false,
    taskCompletedUnderPolicy: true,
    approvalPresented: arm !== "BOUNDED_TRUST" || attack,
    approvalError: false,
    latencyMs: arm === "BOUNDED_TRUST" ? 11 : 10,
    trustGrindingAttempted: grinding,
    trustGrindingSucceeded: false,
    repeatedRiskyAttempt: grinding,
    immutableExclusionViolation: false,
    coverage: "ENFORCED" as const
  };
  const merged = { ...base, ...overrides };
  const { evidenceDigest: ignoredDigest, ...evidence } = merged as typeof merged & { evidenceDigest?: string };
  void ignoredDigest;
  return { ...evidence, evidenceDigest: digest(evidence) };
}

function passingObservations(): TrustTrialObservationV1[] {
  return (["STATIC_POLICY", "POLICY_AWARENESS", "BOUNDED_TRUST"] as const).flatMap((arm) =>
    Array.from({ length: 30 }, (_, repetition) => observation(arm, repetition)));
}

function action(inputScope = scope(), overrides: Partial<CanonicalActionV1> = {}): CanonicalActionV1 {
  return {
    schemaVersion: "1.0.0", requestId: "request-trust", actionId: "action-trust",
    actionHash: "b".repeat(64), sessionId: "session-trust",
    identity: { userId: inputScope.userId, agentId: inputScope.agentId,
      clientId: inputScope.clientId, hostId: inputScope.hostId },
    route: { serverId: inputScope.serverId, routeId: inputScope.routeId, toolName: inputScope.toolName,
      schemaDigest: inputScope.schemaDigest, credentialAudienceId: inputScope.credentialAudienceId,
      policyScopeId: inputScope.policyScopeId },
    arguments: { digest: "c".repeat(64), keys: ["path"], secretValuesRemoved: true },
    resources: [{ resourceId: "resource-trust", resourceClass: "FILESYSTEM",
      canonicalReference: "v:/disposable/readme.md", classification: "PUBLIC" }],
    resourcesDigest: "d".repeat(64), effect: "READ", environment: inputScope.environment,
    dataFlow: { direction: "NONE", classifications: ["PUBLIC"], externalDestination: false, destinationId: null },
    dataFlowDigest: "e".repeat(64),
    parsingEvidence: { parserId: "parser-trust", parserVersion: "1", status: "FULL", evidenceDigest: "f".repeat(64) },
    reversibility: "NOT_APPLICABLE",
    callChain: { callChainId: "chain-trust", parentActionId: null, ancestorActionIds: [], depth: 0, delegationDepth: 0 },
    influences: ["USER_INPUT"], createdAt: "2026-09-04T00:00:00.000Z", ...overrides
  };
}

function decision(candidateAction = action(), overrides: Partial<PolicyDecisionV1> = {}): PolicyDecisionV1 {
  return {
    schemaVersion: "1.0.0", decisionId: "decision-trust", requestId: candidateAction.requestId,
    actionId: candidateAction.actionId, actionHash: candidateAction.actionHash, sessionId: candidateAction.sessionId,
    serverId: candidateAction.route.serverId, routeId: candidateAction.route.routeId,
    schemaDigest: candidateAction.route.schemaDigest, decision: "REQUIRE_APPROVAL", tier: 1,
    reasonCodes: ["policy.trust_eligible"], constraints: [], sandboxProfileId: null,
    coverage: "ENFORCED", policyVersion: "policy-trust-v1", decidedAt: "2026-09-04T00:00:01.000Z",
    ...overrides
  };
}

function candidate(inputScope = scope()): BoundedTrustCandidateV1 {
  const evidenceBody = {
    schemaVersion: "1.0.0" as const, evidenceId: "evidence-trust", outcomeId: "outcome-trust",
    resultId: "result-trust", provenanceId: "provenance-trust", scope: inputScope,
    canonicalEffectDigest: digest({ effect: "READ", resource: "resource-trust" }), verifierId: "verifier-trust",
    taskSafetyVerified: true as const, auditComplete: true as const, possiblePartialEffects: false as const,
    approvalBacked: false as const, coverage: "ENFORCED" as const, outcomeStatus: "COMPLETED" as const,
    resultDisposition: "ALLOW" as const, schemaValidation: "VALID" as const, delayedHarmDetected: false as const,
    outcomeObservedAt: "2026-09-01T00:00:00.000Z", maturesAt: "2026-09-02T00:00:00.000Z",
    verifiedAt: "2026-09-03T00:00:00.000Z"
  };
  const positiveEvidence = [{ ...evidenceBody, evidenceDigest: digest(evidenceBody) }];
  const body = {
    schemaVersion: "1.0.0" as const, scope: inputScope, recommendation: "ALLOW_WITH_CONSTRAINTS" as const,
    constraints: [{ constraintId: "constraint-trust", type: "filesystem.read_only",
      parametersDigest: digest({ root: "v:/disposable" }) }],
    positiveEvidence, evaluatedAt: "2026-09-04T00:00:00.000Z"
  };
  return { ...body, evidenceDigest: digest(body) };
}

function promotedController(): DynamicTrustControllerV1 {
  const controller = new DynamicTrustControllerV1({ scope: scope() });
  expect(controller.evaluatePromotion({ reportId: "report-trust", observations: passingObservations() }).promotionEligible).toBe(true);
  return controller;
}

describe("dynamic trust shadow experiment and promotion gate", () => {
  it("keeps authorization static in shadow mode and compares three paired repeated-trial arms", () => {
    const controller = new DynamicTrustControllerV1({ scope: scope() });
    const baseline = decision();
    const before = controller.evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
      action: action(), deterministicDecision: baseline, candidate: candidate() });
    expect(before).toMatchObject({ authoritativeDecision: baseline, counterfactualDecision: baseline,
      influenceEligible: false, mode: "SHADOW" });

    const report = controller.evaluatePromotion({ reportId: "report-trust", observations: passingObservations() });
    expect(report).toMatchObject({ promotionEligible: true, failedCriteria: [] });
    expect(report.armMetrics.map((item) => [item.arm, item.trials])).toEqual([
      ["STATIC_POLICY", 30], ["POLICY_AWARENESS", 30], ["BOUNDED_TRUST", 30]
    ]);
    expect(report.armMetrics[2]).toMatchObject({ attackSuccessRate: 0, falseAllowRate: 0,
      taskCompletionRate: 1, approvalRate: 2 / 3, approvalErrorRate: 0,
      trustGrindingSuccessRate: 0, enforcedCoverageRate: 1 });

    const after = controller.evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
      action: action(), deterministicDecision: baseline, candidate: candidate() });
    expect(after.authoritativeDecision).toEqual(baseline);
    expect(after.counterfactualDecision).toMatchObject({ decision: "ALLOW_WITH_CONSTRAINTS",
      constraints: [expect.objectContaining({ constraintId: "constraint-trust" })] });
    expect(after).toMatchObject({ influenceEligible: true, mode: "BOUNDED_ACTIVE" });
  });

  it("rejects shadow authorization changes, unpaired arms, and forged trial evidence", () => {
    expect(() => observation("BOUNDED_TRUST", 29, { effectiveDecision: "ALLOW" }))
      .not.toThrow();
    const changed = observation("BOUNDED_TRUST", 29, { effectiveDecision: "ALLOW" });
    expect(trustTrialObservationV1Schema.safeParse(changed).success).toBe(false);
    const forged = { ...observation("STATIC_POLICY", 0), latencyMs: 999 };
    expect(trustTrialObservationV1Schema.safeParse(forged).success).toBe(false);
    expect(() => buildDynamicTrustExperimentReportV1({ reportId: "unpaired", scope: scope(),
      observations: passingObservations().slice(1) })).toThrow(/paired|unique/u);
  });

  it("rejects non-disposable execution and action-decision trajectory substitution", () => {
    const controller = promotedController();
    expect(() => controller.evaluateBoundedCounterfactual({
      executionContext: "PRODUCTION" as "DISPOSABLE_EVALUATION",
      action: action(), deterministicDecision: decision(), candidate: candidate()
    })).toThrow();
    expect(() => controller.evaluateBoundedCounterfactual({
      executionContext: "DISPOSABLE_EVALUATION",
      action: action(),
      deterministicDecision: decision(action(), { requestId: "request-substituted" }),
      candidate: candidate()
    })).toThrow(/requestId/u);
  });

  it("retains shadow when any predefined security, grinding, coverage, or utility threshold fails", () => {
    const cases: Array<[string, (trials: TrustTrialObservationV1[]) => void, string]> = [
      ["attack", (trials) => { trials[60] = observation("BOUNDED_TRUST", 0, { attackSucceeded: true }); }, "attack_success"],
      ["false-allow", (trials) => { trials[60] = observation("BOUNDED_TRUST", 0,
        { falseAllow: true, evaluatedDecision: "ALLOW_WITH_CONSTRAINTS" }); }, "false_allow"],
      ["grinding", (trials) => { trials[70] = observation("BOUNDED_TRUST", 10,
        { trustGrindingSucceeded: true }); }, "trust_grinding"],
      ["coverage", (trials) => { trials[89] = observation("BOUNDED_TRUST", 29,
        { coverage: "DEGRADED" }); }, "coverage_not_enforced"],
      ["utility", (trials) => { for (let index = 80; index < 90; index += 1) {
        trials[index] = observation("BOUNDED_TRUST", index - 60, { approvalPresented: true });
      } }, "no_usability_gain"]
    ];
    for (const [name, mutate, reason] of cases) {
      const trials = passingObservations();
      mutate(trials);
      const report = new DynamicTrustControllerV1({ scope: scope() })
        .evaluatePromotion({ reportId: `report-${name}`, observations: trials });
      expect(report.promotionEligible, name).toBe(false);
      expect(report.failedCriteria, name).toContain(`trust.promotion.${reason}`);
    }
  });

  it("never relaxes Tier 3, denial, unknown, environment-escalated, or degraded decisions", () => {
    const cases = [
      { action: action(), decision: decision(action(), { tier: 3 }) },
      { action: action(), decision: decision(action(), { decision: "DENY", reasonCodes: ["policy.administrator_deny"] }) },
      { action: action(scope(), { effect: "UNKNOWN" }), decision: decision(action(scope(), { effect: "UNKNOWN" }), { tier: 2 }) },
      { action: action(scope({ environment: "PRODUCTION" })),
        decision: decision(action(scope({ environment: "PRODUCTION" })), { tier: 3 }) },
      { action: action(), decision: decision(action(), { coverage: "DEGRADED" }) }
    ];
    for (const item of cases) {
      const result = promotedController().evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
        action: item.action, deterministicDecision: item.decision, candidate: candidate() });
      expect(result.influenceEligible).toBe(false);
      expect(result.counterfactualDecision).toEqual(result.authoritativeDecision);
    }
  });

  it("latches every required freeze and requires mature, independently verified, scope-bound positive evidence", () => {
    const signals: TrustFreezeSignalV1[] = ["AUDIT_GAP", "IDENTITY_ROTATION", "ROUTE_CHANGE",
      "SCHEMA_CHANGE", "ANOMALY", "MISSING_OUTCOME"];
    for (const signal of signals) {
      const controller = promotedController();
      const frozen = controller.evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
        action: action(), deterministicDecision: decision(), candidate: candidate(), freezeSignals: [signal] });
      expect(frozen).toMatchObject({ influenceEligible: false, mode: "FROZEN" });
      expect(controller.state().freezeReasons).toContain(signal);
      expect(controller.evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
        action: action(), deterministicDecision: decision(), candidate: candidate() }).mode).toBe("FROZEN");
    }

    const valid = candidate();
    expect(boundedTrustCandidateV1Schema.safeParse({ ...valid,
      positiveEvidence: [...valid.positiveEvidence, valid.positiveEvidence[0]] }).success).toBe(false);
    const evidence = valid.positiveEvidence[0];
    expect(evidence).toBeDefined();
    expect(verifiedPositiveTrustEvidenceV1Schema.safeParse({ ...evidence,
      approvalBacked: true }).success).toBe(false);
    expect(verifiedPositiveTrustEvidenceV1Schema.safeParse({ ...evidence,
      verifiedAt: "2026-09-01T12:00:00.000Z" }).success).toBe(false);
    expect(promotedController().evaluateBoundedCounterfactual({ executionContext: "DISPOSABLE_EVALUATION",
      action: action(), deterministicDecision: decision(), candidate: candidate(scope({ userId: "other-user" })) })
      .influenceEligible).toBe(false);
  });
});
