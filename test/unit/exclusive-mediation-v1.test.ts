import { describe, expect, it } from "vitest";

import {
  CoverageAssessmentDeniedV1,
  CoverageBoundPolicyEvaluatorV1,
  DeterministicPolicyEngineV1,
  ExclusiveMediationMonitorV1,
  computeCanonicalDigestV1,
  type CanonicalActionV1,
  type CoverageEvidenceProbeV1,
  type CoverageEvidenceStatusV1,
  type CoverageEvidenceV1,
  type CoveragePathKindV1,
  type CoverageScopeV1,
  type MediationGuaranteeV1
} from "../../src/index.js";

const currentTime = "2026-09-04T10:00:00.000Z";
const observedAt = "2026-09-04T09:59:00.000Z";
const expiresAt = "2026-09-04T10:04:00.000Z";

const scope: CoverageScopeV1 = {
  userId: "user-coverage",
  agentId: "agent-coverage",
  clientId: "client-coverage",
  hostId: "host-coverage",
  stateNamespace: "namespace-coverage",
  serverId: "server-coverage",
  routeId: "route-coverage",
  toolName: "filesystem.write",
  schemaDigest: "a".repeat(64),
  policyScopeId: "scope-coverage",
  environment: "TEST",
  credentialAudienceId: "audience-coverage",
  credentialProfileId: "profile-coverage",
  resourceClass: "FILESYSTEM",
  resourceId: "resource-coverage",
  resourcesDigest: computeCanonicalDigestV1([{
    resourceId: "resource-coverage",
    resourceClass: "FILESYSTEM",
    canonicalReference: "v:/disposable/coverage.txt",
    classification: "INTERNAL"
  }])
};

interface ProbeDefinition {
  readonly pathKind: CoveragePathKindV1;
  readonly guarantee: MediationGuaranteeV1;
}

const definitions: readonly ProbeDefinition[] = [
  ...[
    "CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT",
    "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS",
    "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"
  ].map((guarantee) => ({
    pathKind: "GATEWAY_MEDIATED" as const,
    guarantee: guarantee as MediationGuaranteeV1
  })),
  ...["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"].map(
    (guarantee) => ({
      pathKind: "NATIVE" as const,
      guarantee: guarantee as MediationGuaranteeV1
    })
  ),
  ...[
    "CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION",
    "DOWNSTREAM_AUTHORIZATION"
  ].map((guarantee) => ({
    pathKind: "DIRECT" as const,
    guarantee: guarantee as MediationGuaranteeV1
  }))
];

type ProbeOverride = Partial<CoverageEvidenceV1> | "THROW" | "HANG";

function keyOf(definition: ProbeDefinition): string {
  return `${definition.pathKind}:${definition.guarantee}`;
}

function authorityFor(guarantee: MediationGuaranteeV1): string {
  return `authority.${guarantee.toLowerCase()}`;
}

function verifierFor(definition: ProbeDefinition): string {
  return `verifier.${definition.pathKind.toLowerCase()}.${definition.guarantee.toLowerCase()}`;
}

function enforcingStatus(pathKind: CoveragePathKindV1): CoverageEvidenceStatusV1 {
  return pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" : "VERIFIED_BLOCKED";
}

function evidenceFor(
  definition: ProbeDefinition,
  override: Partial<CoverageEvidenceV1> = {}
): CoverageEvidenceV1 {
  const status = override.status ?? enforcingStatus(definition.pathKind);
  const revision = override.revision ?? 1;
  const evidence: CoverageEvidenceV1 = {
    schemaVersion: "1.0.0",
    evidenceId: `evidence.${definition.pathKind.toLowerCase()}.${definition.guarantee.toLowerCase()}`,
    guarantee: definition.guarantee,
    pathKind: definition.pathKind,
    verifierId: verifierFor(definition),
    authority: authorityFor(definition.guarantee),
    verifierClass: "TEST_FIXTURE",
    assurance: "DISPOSABLE_TEST",
    scope,
    status,
    revision,
    observedAt,
    expiresAt,
    proofDigest: computeCanonicalDigestV1({
      pathKind: definition.pathKind,
      guarantee: definition.guarantee,
      status,
      revision
    }),
    ...override
  };
  return evidence;
}

function trustedAuthorities(): Partial<Record<MediationGuaranteeV1, readonly string[]>> {
  return Object.fromEntries(
    definitions.map(({ guarantee }) => [guarantee, [authorityFor(guarantee)]])
  );
}

function createHarness(options: {
  readonly definitions?: readonly ProbeDefinition[];
  readonly overrides?: ReadonlyMap<string, ProbeOverride>;
} = {}) {
  const selectedDefinitions = options.definitions ?? definitions;
  const overrides = options.overrides ?? new Map<string, ProbeOverride>();
  const probes: CoverageEvidenceProbeV1[] = selectedDefinitions.map((definition) => ({
    guarantee: definition.guarantee,
    pathKind: definition.pathKind,
    verifierId: verifierFor(definition),
    authority: authorityFor(definition.guarantee),
    observe: () => {
      const override = overrides.get(keyOf(definition));
      if (override === "THROW") throw new Error("disposable coverage probe failed");
      if (override === "HANG") return new Promise<CoverageEvidenceV1>(() => undefined);
      return evidenceFor(definition, override);
    }
  }));
  const monitor = new ExclusiveMediationMonitorV1({
    probes,
    assurance: "DISPOSABLE_TEST",
    trustedAuthorities: trustedAuthorities(),
    clock: () => new Date(currentTime),
    assessmentIdFactory: () => "assessment-coverage"
  });
  return { monitor, overrides, probes };
}

function path(
  assessment: Awaited<ReturnType<ExclusiveMediationMonitorV1["assess"]>>,
  pathKind: CoveragePathKindV1
) {
  const result = assessment.paths.find((candidate) => candidate.pathKind === pathKind);
  if (result === undefined) throw new Error(`Missing ${pathKind} assessment`);
  return result;
}

function definition(pathKind: CoveragePathKindV1, guarantee: MediationGuaranteeV1) {
  const result = definitions.find(
    (candidate) => candidate.pathKind === pathKind && candidate.guarantee === guarantee
  );
  if (result === undefined) throw new Error(`Missing ${pathKind}:${guarantee} definition`);
  return result;
}

function writeAction(): CanonicalActionV1 {
  const resources = [{
    resourceId: scope.resourceId,
    resourceClass: scope.resourceClass,
    canonicalReference: "v:/disposable/coverage.txt",
    classification: "INTERNAL" as const
  }];
  const dataFlow = {
    direction: "NONE" as const,
    classifications: ["INTERNAL" as const],
    externalDestination: false,
    destinationId: null
  };
  const withoutHash = {
    schemaVersion: "1.0.0" as const,
    requestId: "request-coverage",
    actionId: "action-coverage",
    sessionId: scope.stateNamespace,
    identity: {
      userId: scope.userId,
      agentId: scope.agentId,
      clientId: scope.clientId,
      hostId: scope.hostId
    },
    route: {
      serverId: scope.serverId,
      routeId: scope.routeId,
      toolName: scope.toolName,
      schemaDigest: scope.schemaDigest,
      credentialAudienceId: scope.credentialAudienceId,
      policyScopeId: scope.policyScopeId
    },
    arguments: {
      digest: computeCanonicalDigestV1({ path: "coverage.txt" }),
      keys: ["path"],
      secretValuesRemoved: true as const
    },
    resources,
    resourcesDigest: computeCanonicalDigestV1(resources),
    effect: "WRITE" as const,
    environment: scope.environment,
    dataFlow,
    dataFlowDigest: computeCanonicalDigestV1(dataFlow),
    parsingEvidence: {
      parserId: "filesystem-v1",
      parserVersion: "1.0.0",
      status: "FULL" as const,
      evidenceDigest: computeCanonicalDigestV1({ parser: "filesystem-v1" })
    },
    reversibility: "TESTED_SNAPSHOT" as const,
    callChain: {
      callChainId: "chain-coverage",
      parentActionId: null,
      ancestorActionIds: [],
      depth: 0,
      delegationDepth: 0
    },
    influences: ["USER_INPUT" as const],
    createdAt: currentTime
  };
  return { ...withoutHash, actionHash: computeCanonicalDigestV1(withoutHash) };
}

describe("exclusive mediation coverage", () => {
  it("reports ENFORCED only when every gateway and bypass guarantee is verified", async () => {
    const harness = createHarness();
    expect(await harness.probes[0]?.observe(scope)).toMatchObject({
      authority: "authority.client_authentication",
      status: "VERIFIED_ENFORCING"
    });
    const assessment = await harness.monitor.assess(scope);

    expect(assessment).toMatchObject({
      coverage: "ENFORCED",
      mutationAllowed: true,
      missingGuarantees: []
    });
    expect(assessment.paths).toEqual([
      { pathKind: "GATEWAY_MEDIATED", coverage: "ENFORCED", reasonCodes: [] },
      { pathKind: "NATIVE", coverage: "ENFORCED", reasonCodes: [] },
      { pathKind: "DIRECT", coverage: "ENFORCED", reasonCodes: [] }
    ]);
    expect(assessment.evidence).toHaveLength(definitions.length);
  });

  it("degrades on a missing guarantee and names the exact path and guarantee", async () => {
    const omitted = definition("DIRECT", "NETWORK_ISOLATION");
    const selected = definitions.filter((candidate) => candidate !== omitted);
    const assessment = await createHarness({ definitions: selected }).monitor.assess(scope);

    expect(assessment.coverage).toBe("DEGRADED");
    expect(assessment.mutationAllowed).toBe(false);
    expect(path(assessment, "DIRECT")).toEqual({
      pathKind: "DIRECT",
      coverage: "DEGRADED",
      reasonCodes: ["coverage.network_isolation.missing"]
    });
    expect(assessment.missingGuarantees).toContainEqual({
      guarantee: "NETWORK_ISOLATION",
      pathKind: "DIRECT",
      reasonCode: "coverage.network_isolation.missing",
      verifierId: null
    });
  });

  it.each([
    ["stale", { expiresAt: currentTime }, "coverage.network_isolation.stale"],
    ["broken", { status: "BROKEN" as const }, "coverage.network_isolation.broken"],
    ["reachable", { status: "REACHABLE" as const }, "coverage.network_isolation.reachable"],
    ["observe-only", { status: "OBSERVE_ONLY" as const }, "coverage.network_isolation.observe_only"]
  ])("degrades a direct bypass when its evidence is %s", async (_label, override, reasonCode) => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const overrides = new Map<string, ProbeOverride>([[keyOf(target), override]]);
    const assessment = await createHarness({ overrides }).monitor.assess(scope);

    expect(assessment.coverage).toBe("DEGRADED");
    expect(assessment.mutationAllowed).toBe(false);
    expect(path(assessment, "DIRECT").reasonCodes).toContain(reasonCode);
  });

  it("reports UNPROTECTED for a broken gateway path and OBSERVE_ONLY for a monitoring-only gateway", async () => {
    const target = definition("GATEWAY_MEDIATED", "POLICY_ENFORCEMENT");
    const broken = await createHarness({
      overrides: new Map([[keyOf(target), { status: "BROKEN" }]])
    }).monitor.assess(scope);
    const observed = await createHarness({
      overrides: new Map([[keyOf(target), { status: "OBSERVE_ONLY" }]])
    }).monitor.assess(scope);

    expect(broken.coverage).toBe("UNPROTECTED");
    expect(path(broken, "GATEWAY_MEDIATED").reasonCodes)
      .toEqual(["coverage.policy_enforcement.broken"]);
    expect(observed.coverage).toBe("OBSERVE_ONLY");
    expect(path(observed, "GATEWAY_MEDIATED").reasonCodes)
      .toEqual(["coverage.policy_enforcement.observe_only"]);
  });

  it.each([
    [
      "wrong scope",
      { scope: { ...scope, resourceId: "resource-attacker" } },
      "coverage.network_isolation.scope_or_source_mismatch"
    ],
    [
      "untrusted authority",
      { authority: "authority.attacker" },
      "coverage.network_isolation.untrusted_authority"
    ],
    [
      "future-dated evidence",
      { observedAt: "2026-09-04T10:00:31.000Z", expiresAt: "2026-09-04T10:05:31.000Z" },
      "coverage.network_isolation.future_dated"
    ]
  ])("rejects %s with an exact diagnostic", async (_label, override, reasonCode) => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const assessment = await createHarness({
      overrides: new Map([[keyOf(target), override]])
    }).monitor.assess(scope);

    expect(assessment.coverage).toBe("DEGRADED");
    expect(path(assessment, "DIRECT").reasonCodes).toContain(reasonCode);
    expect(assessment.evidence.some((item) =>
      item.pathKind === target.pathKind && item.guarantee === target.guarantee
    )).toBe(false);
  });

  it("rejects an evidence revision rollback", async () => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const overrides = new Map<string, ProbeOverride>([[keyOf(target), { revision: 2 }]]);
    const { monitor } = createHarness({ overrides });
    expect((await monitor.assess(scope)).coverage).toBe("ENFORCED");

    overrides.set(keyOf(target), { revision: 1 });
    const rolledBack = await monitor.assess(scope);

    expect(rolledBack.coverage).toBe("DEGRADED");
    expect(path(rolledBack, "DIRECT").reasonCodes)
      .toContain("coverage.network_isolation.revision_rollback");
  });

  it("rejects same-revision evidence equivocation", async () => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const overrides = new Map<string, ProbeOverride>();
    const { monitor } = createHarness({ overrides });
    expect((await monitor.assess(scope)).coverage).toBe("ENFORCED");

    overrides.set(keyOf(target), { status: "REACHABLE" });
    const equivocation = await monitor.assess(scope);
    expect(equivocation.coverage).toBe("DEGRADED");
    expect(path(equivocation, "DIRECT").reasonCodes)
      .toContain("coverage.network_isolation.revision_equivocation");
  });

  it("fails closed when a probe throws", async () => {
    const target = definition("NATIVE", "OS_ISOLATION");
    const assessment = await createHarness({
      overrides: new Map([[keyOf(target), "THROW"]])
    }).monitor.assess(scope);

    expect(assessment.coverage).toBe("DEGRADED");
    expect(path(assessment, "NATIVE").reasonCodes)
      .toContain("coverage.os_isolation.probe_failed");
  });

  it("times out a hung probe and fails closed", async () => {
    const target = definition("NATIVE", "OS_ISOLATION");
    const overrides = new Map<string, ProbeOverride>([[keyOf(target), "HANG"]]);
    const base = createHarness({ overrides });
    const monitor = new ExclusiveMediationMonitorV1({
      probes: base.probes,
      assurance: "DISPOSABLE_TEST",
      trustedAuthorities: trustedAuthorities(),
      clock: () => new Date(currentTime),
      probeTimeoutMs: 10
    });
    const assessment = await monitor.assess(scope);
    expect(assessment.coverage).toBe("DEGRADED");
    expect(path(assessment, "NATIVE").reasonCodes)
      .toContain("coverage.os_isolation.probe_failed");
  });

  it("rejects disposable fixture evidence in deployment assurance", async () => {
    const base = createHarness();
    const monitor = new ExclusiveMediationMonitorV1({
      probes: base.probes,
      assurance: "DEPLOYMENT",
      trustedAuthorities: trustedAuthorities(),
      clock: () => new Date(currentTime)
    });
    const assessment = await monitor.assess(scope);
    expect(assessment.coverage).toBe("UNPROTECTED");
    expect(assessment.missingGuarantees.some((item) =>
      item.reasonCode.endsWith(".ineligible_verifier_class"))).toBe(true);
  });

  it("computes the same evidence digest regardless of probe order", async () => {
    const forward = await createHarness().monitor.assess(scope);
    const reverse = await createHarness({ definitions: [...definitions].reverse() })
      .monitor.assess(scope);

    expect(reverse.evidenceDigest).toBe(forward.evidenceDigest);
    expect(reverse.evidence).toEqual(forward.evidence);
    expect(reverse.paths).toEqual(forward.paths);
  });

  it("reassesses immediately before mutation and denies a TOCTOU evidence change", async () => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const overrides = new Map<string, ProbeOverride>();
    const { monitor } = createHarness({ overrides });
    const initial = await monitor.assess(scope);

    await expect(monitor.assertCurrentForMutation(scope, initial.evidenceDigest))
      .resolves.toMatchObject({ coverage: "ENFORCED", mutationAllowed: true });

    overrides.set(keyOf(target), { revision: 2, status: "REACHABLE" });
    await expect(monitor.assertCurrentForMutation(scope, initial.evidenceDigest))
      .rejects.toBeInstanceOf(CoverageAssessmentDeniedV1);
  });

  it("binds policy evaluation to coverage and denies a mutation after bypass degradation", async () => {
    const target = definition("DIRECT", "NETWORK_ISOLATION");
    const monitor = createHarness({
      overrides: new Map([[keyOf(target), { status: "REACHABLE" }]])
    }).monitor;
    const policy = new DeterministicPolicyEngineV1({
      policyVersion: "policy-coverage-v1",
      clock: () => new Date(currentTime),
      decisionIdFactory: () => "decision-coverage"
    });
    const evaluated = await new CoverageBoundPolicyEvaluatorV1(monitor, policy).evaluate({
      action: writeAction(),
      scope
    });

    expect(evaluated.assessment.coverage).toBe("DEGRADED");
    expect(evaluated.decision).toMatchObject({
      decision: "DENY",
      coverage: "DEGRADED",
      reasonCodes: ["invariant.mutation_requires_enforced_coverage"]
    });
  });

  it("rejects action and coverage scope substitution before policy evaluation", async () => {
    const policy = new DeterministicPolicyEngineV1({ policyVersion: "policy-coverage-v1" });
    const evaluator = new CoverageBoundPolicyEvaluatorV1(createHarness().monitor, policy);
    await expect(evaluator.evaluate({
      action: writeAction(),
      scope: { ...scope, resourceId: "resource-other" }
    })).rejects.toBeInstanceOf(CoverageAssessmentDeniedV1);
  });
});
