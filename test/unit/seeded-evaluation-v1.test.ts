import { describe, expect, it } from "vitest";

import {
  SeededSecurityEvaluationHarnessV1,
  assertCompleteEvaluationCatalogV1,
  attackClassV1Schema,
  computeCanonicalDigestV1,
  createRequiredEvaluationCatalogV1,
  type EvaluationScenarioV1,
  type SeededTrialContextV1
} from "../../src/index.js";

const protocol = new Set([
  "REPLAY", "FLOODING", "RECURSION", "CANCELLATION", "SCHEMA_DRIFT",
  "ROUTE_COLLISION", "IMPERSONATION", "CREDENTIAL_AUDIENCE"
]);
const policy = new Set([
  "ALTERNATE_TOOL", "ALTERNATE_SERVER", "ALTERNATE_PATH", "ENCODING", "TRANSPORT",
  "RETRY", "SPLIT_PAYLOAD", "CONCURRENCY", "TOCTOU"
]);
const content = new Set([
  "DIRECT_INJECTION", "INDIRECT_INJECTION", "OBFUSCATED_INJECTION",
  "PROPAGATED_INJECTION", "TOOL_DESCRIPTION_INJECTION", "TOOL_RESULT_INJECTION"
]);

function suite(attackClass: string): EvaluationScenarioV1["suite"] {
  if (protocol.has(attackClass)) return "PROTOCOL";
  if (policy.has(attackClass)) return "POLICY_INVARIANCE";
  if (content.has(attackClass)) return "CONTENT";
  return "HUMAN_TRUST";
}

const completeCatalog: EvaluationScenarioV1[] = attackClassV1Schema.options.map((attackClass, index) => ({
  schemaVersion: "1.0.0",
  scenarioId: `scenario-${attackClass.toLowerCase().replaceAll("_", "-")}`,
  suite: suite(attackClass),
  attackClass,
  expectedDisposition: "PREVENT",
  repetitions: 3,
  seed: 1_000 + index,
  configDigest: computeCanonicalDigestV1({ attackClass, fixture: "seeded-evaluation-v1" })
}));

describe("seeded security evaluation harness", () => {
  it("requires every mandated attack class across all four suites", () => {
    expect(createRequiredEvaluationCatalogV1()).toHaveLength(attackClassV1Schema.options.length);
    expect(() => { assertCompleteEvaluationCatalogV1(completeCatalog); }).not.toThrow();
    expect(() => { assertCompleteEvaluationCatalogV1(completeCatalog.slice(1)); })
      .toThrow(/REPLAY/u);
    expect(new Set(completeCatalog.map((item) => item.suite))).toEqual(new Set([
      "PROTOCOL", "POLICY_INVARIANCE", "CONTENT", "HUMAN_TRUST"
    ]));
  });

  it("repeats deterministically and reports security, usability, cost, and coverage metrics", async () => {
    const scenarios = [
      ...completeCatalog,
      {
        schemaVersion: "1.0.0" as const,
        scenarioId: "scenario-benign-safe-replan",
        suite: "HUMAN_TRUST" as const,
        attackClass: "SAFE_REPLANNING" as const,
        expectedDisposition: "ALLOW" as const,
        repetitions: 3,
        seed: 9_999,
        configDigest: computeCanonicalDigestV1({ benign: true })
      }
    ];
    const execute = ({ scenario, random }: SeededTrialContextV1) => {
      const attackAttempted = scenario.expectedDisposition === "PREVENT";
      return {
        evidenceSource: "DETERMINISTIC_ASSERTION" as const,
        evidenceDigest: computeCanonicalDigestV1({ scenario: scenario.scenarioId, outcome: "prevented" }),
        attackAttempted,
        attackSucceeded: false,
        baselineAttackSucceeded: attackAttempted,
        policyAllowed: !attackAttempted,
        taskCompleted: !attackAttempted,
        policyViolation: false,
        latencyMs: Math.floor(random() * 10) + 1,
        costUnits: 2,
        approvalPresented: scenario.attackClass === "APPROVAL_FATIGUE",
        approvalError: false,
        replannedSafely: !attackAttempted,
        coverage: "ENFORCED" as const
      };
    };
    const harness = new SeededSecurityEvaluationHarnessV1();
    const first = await harness.run(scenarios, execute);
    const second = await harness.run(scenarios, execute);

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      trialCount: scenarios.length * 3,
      attackTrialCount: completeCatalog.length * 3,
      preventionRate: 1,
      attackSuccessRate: 0,
      baselineAttackSuccessRate: 1,
      riskRatio: 0,
      falseAllowRate: 0,
      falseDenialRate: 0,
      approvalErrorRate: 0,
      safeReplanRate: 3 / (scenarios.length * 3),
      enforcedCoverageRate: 1
    });
    expect(first.completionUnderPolicyRate).toBe(3 / first.trialCount);
    expect(first.totalCostUnits).toBe(first.trialCount * 2);
    expect(first.trialsDigest).toBe(computeCanonicalDigestV1(first.trials));
  });

  it("rejects contradictory or structurally invalid observations", async () => {
    const harness = new SeededSecurityEvaluationHarnessV1();
    await expect(harness.run([completeCatalog[0] as EvaluationScenarioV1], () => ({
      evidenceSource: "DETERMINISTIC_ASSERTION",
      evidenceDigest: computeCanonicalDigestV1({ contradictory: true }),
      attackAttempted: false,
      attackSucceeded: false,
      baselineAttackSucceeded: true,
      policyAllowed: false,
      taskCompleted: false,
      policyViolation: false,
      latencyMs: 1,
      costUnits: 0,
      approvalPresented: false,
      approvalError: false,
      replannedSafely: false,
      coverage: "UNPROTECTED"
    }))).rejects.toThrow(/classification/u);
  });
});
