import { describe, expect, it } from "vitest";

import {
  ApprovalFatigueRecorderV1,
  DeterministicPolicyEngineV1,
  ExclusiveMediationMonitorV1,
  TrustworthyInterfaceBuilderV1,
  approvalV1Schema,
  computeCanonicalDigestV1,
  trustworthyActionInterfaceV1Schema,
  type CoverageEvidenceProbeV1,
  type CoveragePathKindV1,
  type CoverageScopeV1,
  type MediationGuaranteeV1
} from "../../src/index.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

const now = new Date("2026-09-04T12:00:00.000Z");
const guarantees = {
  GATEWAY_MEDIATED: [
    "CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT",
    "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS",
    "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"
  ],
  NATIVE: ["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"],
  DIRECT: ["CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION", "DOWNSTREAM_AUTHORIZATION"]
} as const satisfies Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>>;

async function enforcedCoverage() {
  const candidate = createPostgresTrajectoryFixtureV1("interface", now);
  const resource = candidate.action.resources[0];
  if (resource === undefined) throw new Error("Interface fixture requires a resource");
  const scope: CoverageScopeV1 = {
    ...candidate.action.identity,
    stateNamespace: candidate.action.sessionId,
    ...candidate.action.route,
    credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
    environment: candidate.action.environment,
    resourceId: resource.resourceId,
    resourceClass: resource.resourceClass,
    resourcesDigest: candidate.action.resourcesDigest
  };
  const probes: CoverageEvidenceProbeV1[] = (Object.entries(guarantees) as Array<
    [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
  >).flatMap(([pathKind, required]) => required.map((guarantee) => {
    const verifierId = `fixture-${pathKind.toLowerCase()}-${guarantee.toLowerCase()}`;
    return {
      guarantee,
      pathKind,
      verifierId,
      authority: "interface-fixture-authority",
      observe: (observedScope: CoverageScopeV1) => ({
        schemaVersion: "1.0.0" as const,
        evidenceId: `${verifierId}-evidence`,
        guarantee,
        pathKind,
        verifierId,
        authority: "interface-fixture-authority",
        verifierClass: "TEST_FIXTURE" as const,
        assurance: "DISPOSABLE_TEST" as const,
        scope: observedScope,
        status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
        revision: 1,
        observedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 30_000).toISOString(),
        proofDigest: computeCanonicalDigestV1({ pathKind, guarantee, fixture: "interface" })
      })
    };
  }));
  const authorities = Object.fromEntries(
    [...new Set(Object.values(guarantees).flat())].map((guarantee) =>
      [guarantee, ["interface-fixture-authority"]])
  );
  const coverage = await new ExclusiveMediationMonitorV1({
    probes,
    assurance: "DISPOSABLE_TEST",
    trustedAuthorities: authorities,
    clock: () => now,
    assessmentIdFactory: () => "assessment-interface"
  }).assess(scope);
  return { candidate, coverage };
}

describe("trustworthy approval and awareness interfaces", () => {
  it("derives the complete human view and awareness only from canonical records", async () => {
    const { candidate, coverage } = await enforcedCoverage();
    const builder = new TrustworthyInterfaceBuilderV1({
      clock: () => now,
      interfaceIdFactory: () => "interface-exact",
      awarenessIdFactory: () => "awareness-exact"
    });
    const { view, awareness } = builder.build({
      action: candidate.action,
      decision: candidate.decision,
      coverage,
      relatedAttemptIds: ["attempt-earlier"]
    });

    expect(view).toMatchObject({
      requester: { ...candidate.action.identity, sessionId: candidate.action.sessionId },
      route: candidate.action.route,
      targets: candidate.action.resources,
      dataFlow: candidate.action.dataFlow,
      riskTier: 3,
      decision: "REQUIRE_APPROVAL",
      reversibility: candidate.action.reversibility,
      recoveryClass: candidate.action.reversibility,
      blastRadius: "LOCAL_SINGLE",
      relatedAttemptIds: ["attempt-earlier"],
      coverage: "ENFORCED",
      generatedFromCanonicalData: true
    });
    expect(awareness.alternatives.map((item) => item.alternativeId)).toEqual([
      "alternative-no-effect", "alternative-exact-approval"
    ]);
    expect(awareness.factualSummary).not.toContain(JSON.stringify(candidate.request.arguments));
    expect(JSON.stringify({ view, awareness })).not.toContain("credentialValue");
  });

  it("rejects coverage, outcome, and action substitutions", async () => {
    const { candidate, coverage } = await enforcedCoverage();
    const builder = new TrustworthyInterfaceBuilderV1();
    expect(() => builder.build({
      action: candidate.action,
      decision: candidate.decision,
      coverage: { ...coverage, scope: { ...coverage.scope, routeId: "route-other" } }
    })).toThrow();
    expect(() => builder.build({
      action: candidate.action,
      decision: candidate.decision,
      coverage,
      outcome: { ...candidate.outcome, requestId: "request-other" }
    })).toThrow();
  });

  it("emits factual awareness with a safe alternative for a coverage denial", async () => {
    const { candidate, coverage } = await enforcedCoverage();
    const decision = new DeterministicPolicyEngineV1({
      policyVersion: candidate.decision.policyVersion,
      clock: () => now,
      decisionIdFactory: () => "decision-denied-interface"
    }).evaluate({ action: candidate.action, coverage: "DEGRADED" });
    const degraded = {
      ...coverage,
      coverage: "DEGRADED" as const,
      mutationAllowed: false,
      paths: coverage.paths.map((item) => item.pathKind === "DIRECT"
        ? { ...item, coverage: "DEGRADED" as const, reasonCodes: ["coverage.network_isolation.missing"] }
        : item),
      missingGuarantees: [{
        guarantee: "NETWORK_ISOLATION" as const,
        pathKind: "DIRECT" as const,
        reasonCode: "coverage.network_isolation.missing",
        verifierId: null
      }]
    };
    degraded.evidenceDigest = computeCanonicalDigestV1({
      assurance: degraded.assurance,
      scope: degraded.scope,
      coverage: degraded.coverage,
      paths: degraded.paths,
      missingGuarantees: degraded.missingGuarantees,
      evidence: degraded.evidence
    });
    const { awareness } = new TrustworthyInterfaceBuilderV1().build({
      action: candidate.action,
      decision,
      coverage: degraded
    });
    expect(awareness).toMatchObject({
      decision: "DENY",
      coverage: "DEGRADED",
      missingGuarantees: ["coverage.network_isolation.missing"]
    });
    expect(awareness.alternatives).toHaveLength(1);
  });

  it("records approval fatigue without adding bulk or persistent approval controls", async () => {
    const { candidate, coverage } = await enforcedCoverage();
    const { view } = new TrustworthyInterfaceBuilderV1({ clock: () => now }).build({
      action: candidate.action,
      decision: candidate.decision,
      coverage,
      relatedAttemptIds: ["attempt-one", "attempt-two"]
    });
    const recorder = new ApprovalFatigueRecorderV1(() => now);
    recorder.recordPresentation(view);
    recorder.recordApproval(view, candidate.approval);
    recorder.recordError(view.route.policyScopeId);
    expect(recorder.snapshot(view.route.policyScopeId)).toMatchObject({
      presentations: 1,
      approvals: 1,
      approvalErrors: 1,
      repeatedRelatedAttempts: 2,
      meanDecisionLatencyMs: 1_000
    });
    expect(approvalV1Schema.safeParse({ ...candidate.approval, alwaysAllow: true }).success).toBe(false);
    expect(trustworthyActionInterfaceV1Schema.safeParse({ ...view, bulkApproval: true }).success).toBe(false);
  });
});
