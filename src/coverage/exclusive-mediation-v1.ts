import { randomUUID } from "node:crypto";

import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import type {
  DeterministicPolicyEngineV1,
  PolicyAdvisoryV1
} from "../policy-engine/deterministic-policy-v1.js";
import {
  canonicalActionV1Schema,
  type CanonicalActionV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import {
  coverageStateV1Schema,
  identifierV1Schema,
  type CoverageStateV1
} from "../contracts/v1.js";

export const coveragePathKindV1Schema = z.enum([
  "GATEWAY_MEDIATED",
  "NATIVE",
  "DIRECT"
]);

export const mediationGuaranteeV1Schema = z.enum([
  "CLIENT_AUTHENTICATION",
  "ROUTE_INTEGRITY",
  "POLICY_ENFORCEMENT",
  "POSTGRES_PERSISTENCE",
  "APPROVAL_ENFORCEMENT",
  "PROTOCOL_GUARDS",
  "DOWNSTREAM_AUTHENTICATION",
  "RESULT_MEDIATION",
  "CREDENTIAL_EXCLUSIVITY",
  "NETWORK_ISOLATION",
  "IAM_ISOLATION",
  "SANDBOX_ISOLATION",
  "OS_ISOLATION",
  "DOWNSTREAM_AUTHORIZATION"
]);

export const coverageEvidenceStatusV1Schema = z.enum([
  "VERIFIED_ENFORCING",
  "VERIFIED_BLOCKED",
  "OBSERVE_ONLY",
  "REACHABLE",
  "BROKEN",
  "UNKNOWN"
]);

export const coverageAssuranceV1Schema = z.enum(["DISPOSABLE_TEST", "DEPLOYMENT"]);
export const coverageVerifierClassV1Schema = z.enum([
  "GATEWAY_SELF_CHECK",
  "INDEPENDENT_CONTROL",
  "TEST_FIXTURE"
]);

export const coverageScopeV1Schema = z.object({
  userId: identifierV1Schema,
  agentId: identifierV1Schema,
  clientId: identifierV1Schema,
  hostId: identifierV1Schema,
  stateNamespace: identifierV1Schema,
  serverId: identifierV1Schema,
  routeId: identifierV1Schema,
  toolName: identifierV1Schema,
  schemaDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  policyScopeId: identifierV1Schema,
  environment: z.enum(["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"]),
  credentialAudienceId: identifierV1Schema,
  credentialProfileId: identifierV1Schema,
  resourceClass: z.enum([
    "FILESYSTEM", "SHELL", "GIT", "PACKAGE", "NETWORK", "DATABASE", "CLOUD",
    "BROWSER", "PROCESS", "DEPLOYMENT", "UNKNOWN"
  ]),
  resourceId: identifierV1Schema,
  resourcesDigest: z.string().regex(/^[a-f0-9]{64}$/u)
}).strict();

export const coverageEvidenceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  evidenceId: identifierV1Schema,
  guarantee: mediationGuaranteeV1Schema,
  pathKind: coveragePathKindV1Schema,
  verifierId: identifierV1Schema,
  authority: identifierV1Schema,
  verifierClass: coverageVerifierClassV1Schema,
  assurance: coverageAssuranceV1Schema,
  scope: coverageScopeV1Schema,
  status: coverageEvidenceStatusV1Schema,
  revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  observedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true }),
  proofDigest: z.string().regex(/^[a-f0-9]{64}$/u)
}).strict().superRefine((evidence, context) => {
  if (Date.parse(evidence.expiresAt) <= Date.parse(evidence.observedAt)) {
    context.addIssue({
      code: "custom",
      path: ["expiresAt"],
      message: "Coverage evidence must expire after it was observed"
    });
  }
});

const missingGuaranteeV1Schema = z.object({
  guarantee: mediationGuaranteeV1Schema,
  pathKind: coveragePathKindV1Schema,
  reasonCode: z.string().regex(/^coverage\.[a-z0-9_.-]+$/u),
  verifierId: identifierV1Schema.nullable()
}).strict();

const coveragePathAssessmentV1Schema = z.object({
  pathKind: coveragePathKindV1Schema,
  coverage: coverageStateV1Schema,
  reasonCodes: z.array(z.string().regex(/^coverage\.[a-z0-9_.-]+$/u)).max(64)
}).strict();

export const exclusiveMediationAssessmentV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  assessmentId: identifierV1Schema,
  revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  assurance: coverageAssuranceV1Schema,
  scope: coverageScopeV1Schema,
  coverage: coverageStateV1Schema,
  mutationAllowed: z.boolean(),
  paths: z.array(coveragePathAssessmentV1Schema).length(3),
  missingGuarantees: z.array(missingGuaranteeV1Schema).max(64),
  evidence: z.array(coverageEvidenceV1Schema).max(64),
  evidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
  assessedAt: z.iso.datetime({ offset: true }),
  expiresAt: z.iso.datetime({ offset: true })
}).strict().superRefine((assessment, context) => {
  if (assessment.mutationAllowed !== (assessment.coverage === "ENFORCED")) {
    context.addIssue({ code: "custom", path: ["mutationAllowed"], message: "Only ENFORCED coverage permits mutations" });
  }
  const pathKinds = assessment.paths.map((path) => path.pathKind);
  if (new Set(pathKinds).size !== 3) {
    context.addIssue({ code: "custom", path: ["paths"], message: "Every coverage path must be reported exactly once" });
  }
  if (new Set(assessment.evidence.map((item) => item.evidenceId)).size !== assessment.evidence.length) {
    context.addIssue({ code: "custom", path: ["evidence"], message: "Coverage evidence identifiers must be unique" });
  }
  if (assessment.evidence.some((item) => !exactScope(item.scope, assessment.scope))) {
    context.addIssue({ code: "custom", path: ["evidence"], message: "Every evidence item must match the assessment scope" });
  }
  if (assessment.evidence.some((item) => item.assurance !== assessment.assurance ||
    (assessment.assurance === "DEPLOYMENT" && item.verifierClass === "TEST_FIXTURE"))) {
    context.addIssue({ code: "custom", path: ["evidence"], message: "Evidence assurance must match the assessment" });
  }
  if (assessment.coverage === "ENFORCED") {
    for (const [pathKind, guarantees] of Object.entries(requiredByPath) as Array<
      [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
    >) {
      const expectedStatus = pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" : "VERIFIED_BLOCKED";
      for (const guarantee of guarantees) {
        if (!assessment.evidence.some((item) => item.pathKind === pathKind &&
          item.guarantee === guarantee && item.status === expectedStatus)) {
          context.addIssue({
            code: "custom",
            path: ["evidence"],
            message: `ENFORCED coverage lacks ${pathKind}:${guarantee}`
          });
        }
      }
    }
    if (assessment.missingGuarantees.length > 0 ||
      assessment.paths.some((path) => path.coverage !== "ENFORCED")) {
      context.addIssue({ code: "custom", path: ["coverage"], message: "ENFORCED coverage cannot contain path gaps" });
    }
  }
  if (Date.parse(assessment.expiresAt) <= Date.parse(assessment.assessedAt)) {
    context.addIssue({ code: "custom", path: ["expiresAt"], message: "Coverage assessment must be fresh after evaluation" });
  }
  const computedDigest = computeCanonicalDigestV1({
    assurance: assessment.assurance,
    scope: assessment.scope,
    coverage: assessment.coverage,
    paths: assessment.paths,
    missingGuarantees: assessment.missingGuarantees,
    evidence: assessment.evidence
  });
  if (assessment.evidenceDigest !== computedDigest) {
    context.addIssue({ code: "custom", path: ["evidenceDigest"], message: "Coverage evidence digest does not match the assessment" });
  }
});

export type CoveragePathKindV1 = z.infer<typeof coveragePathKindV1Schema>;
export type MediationGuaranteeV1 = z.infer<typeof mediationGuaranteeV1Schema>;
export type CoverageEvidenceStatusV1 = z.infer<typeof coverageEvidenceStatusV1Schema>;
export type CoverageAssuranceV1 = z.infer<typeof coverageAssuranceV1Schema>;
export type CoverageVerifierClassV1 = z.infer<typeof coverageVerifierClassV1Schema>;
export type CoverageScopeV1 = z.infer<typeof coverageScopeV1Schema>;
export type CoverageEvidenceV1 = z.infer<typeof coverageEvidenceV1Schema>;
export type ExclusiveMediationAssessmentV1 = z.infer<typeof exclusiveMediationAssessmentV1Schema>;

export interface CoverageEvidenceProbeV1 {
  readonly guarantee: MediationGuaranteeV1;
  readonly pathKind: CoveragePathKindV1;
  readonly verifierId: string;
  readonly authority: string;
  observe(scope: CoverageScopeV1): CoverageEvidenceV1 | Promise<CoverageEvidenceV1>;
}

export interface ExclusiveMediationMonitorV1Options {
  readonly probes: readonly CoverageEvidenceProbeV1[];
  readonly assurance: CoverageAssuranceV1;
  readonly trustedAuthorities: Readonly<Partial<Record<MediationGuaranteeV1, readonly string[]>>>;
  readonly clock?: () => Date;
  readonly assessmentIdFactory?: () => string;
  readonly maxFutureSkewMs?: number;
  readonly maxEvidenceAgeMs?: number;
  readonly maxEvidenceTtlMs?: number;
  readonly probeTimeoutMs?: number;
}

const requiredByPath: Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>> = {
  GATEWAY_MEDIATED: [
    "CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT",
    "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS",
    "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"
  ],
  NATIVE: ["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"],
  DIRECT: [
    "CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION",
    "DOWNSTREAM_AUTHORIZATION"
  ]
};

function exactScope(left: CoverageScopeV1, right: CoverageScopeV1): boolean {
  return computeCanonicalDigestV1(left) === computeCanonicalDigestV1(right);
}

export function coverageScopeMatchesActionV1(
  scopeInput: CoverageScopeV1,
  actionInput: CanonicalActionV1
): boolean {
  const scope = coverageScopeV1Schema.parse(scopeInput);
  const action = canonicalActionV1Schema.parse(actionInput);
  const resourceBound = action.resources.some((resource) =>
    resource.resourceId === scope.resourceId && resource.resourceClass === scope.resourceClass);
  return action.identity.userId === scope.userId && action.identity.agentId === scope.agentId &&
    action.identity.clientId === scope.clientId && action.identity.hostId === scope.hostId &&
    action.sessionId === scope.stateNamespace && action.route.serverId === scope.serverId &&
    action.route.routeId === scope.routeId && action.route.toolName === scope.toolName &&
    action.route.schemaDigest === scope.schemaDigest &&
    action.route.policyScopeId === scope.policyScopeId &&
    action.route.credentialAudienceId === scope.credentialAudienceId &&
    action.environment === scope.environment && action.resourcesDigest === scope.resourcesDigest &&
    resourceBound;
}

function reason(guarantee: MediationGuaranteeV1, suffix: string): string {
  return `coverage.${guarantee.toLowerCase()}.${suffix}`;
}

function pathCoverage(
  pathKind: CoveragePathKindV1,
  statuses: readonly CoverageEvidenceStatusV1[],
  hasMissing: boolean
): CoverageStateV1 {
  if (pathKind === "GATEWAY_MEDIATED") {
    if (statuses.length === 0) return "UNPROTECTED";
    if (statuses.some((status) => status === "REACHABLE" || status === "BROKEN")) return "UNPROTECTED";
    if (statuses.includes("OBSERVE_ONLY")) return "OBSERVE_ONLY";
    if (hasMissing || statuses.includes("UNKNOWN")) return "DEGRADED";
    return "ENFORCED";
  }
  if (statuses.includes("REACHABLE")) return "UNPROTECTED";
  if (statuses.includes("OBSERVE_ONLY")) return "OBSERVE_ONLY";
  if (hasMissing || statuses.some((status) => status === "BROKEN" || status === "UNKNOWN")) return "DEGRADED";
  return "ENFORCED";
}

export class CoverageAssessmentDeniedV1 extends Error {
  public constructor() {
    super("Protected operation denied by current exclusive-mediation coverage");
    this.name = "CoverageAssessmentDeniedV1";
  }
}

export class ExclusiveMediationMonitorV1 {
  readonly #clock: () => Date;
  readonly #assurance: CoverageAssuranceV1;
  readonly #assessmentIdFactory: () => string;
  readonly #maxFutureSkewMs: number;
  readonly #maxEvidenceAgeMs: number;
  readonly #maxEvidenceTtlMs: number;
  readonly #probeTimeoutMs: number;
  readonly #probes: readonly CoverageEvidenceProbeV1[];
  readonly #trustedAuthorities: ReadonlyMap<MediationGuaranteeV1, ReadonlySet<string>>;
  readonly #probeKeys = new Set<string>();
  readonly #evidenceRevisions = new Map<string, { readonly revision: number; readonly digest: string }>();
  readonly #assessmentRevisions = new Map<string, number>();

  public constructor(options: ExclusiveMediationMonitorV1Options) {
    const positiveBounded = (value: number | undefined, fallback: number, name: string): number => {
      const selected = value ?? fallback;
      if (!Number.isSafeInteger(selected) || selected <= 0 || selected > 3_600_000) {
        throw new Error(`${name} must be a positive duration no greater than one hour`);
      }
      return selected;
    };
    this.#clock = options.clock ?? (() => new Date());
    this.#assurance = coverageAssuranceV1Schema.parse(options.assurance);
    this.#assessmentIdFactory = options.assessmentIdFactory ?? randomUUID;
    this.#maxFutureSkewMs = positiveBounded(options.maxFutureSkewMs, 30_000, "maxFutureSkewMs");
    this.#maxEvidenceAgeMs = positiveBounded(options.maxEvidenceAgeMs, 60_000, "maxEvidenceAgeMs");
    this.#maxEvidenceTtlMs = positiveBounded(options.maxEvidenceTtlMs, 300_000, "maxEvidenceTtlMs");
    this.#probeTimeoutMs = positiveBounded(options.probeTimeoutMs, 2_000, "probeTimeoutMs");
    const probes: CoverageEvidenceProbeV1[] = [];
    for (const probe of [...options.probes]) {
      mediationGuaranteeV1Schema.parse(probe.guarantee);
      coveragePathKindV1Schema.parse(probe.pathKind);
      identifierV1Schema.parse(probe.verifierId);
      identifierV1Schema.parse(probe.authority);
      const key = `${probe.pathKind}:${probe.guarantee}`;
      if (this.#probeKeys.has(key)) throw new Error(`Duplicate coverage probe: ${key}`);
      this.#probeKeys.add(key);
      probes.push(Object.freeze({
        guarantee: probe.guarantee,
        pathKind: probe.pathKind,
        verifierId: probe.verifierId,
        authority: probe.authority,
        observe: probe.observe.bind(probe)
      }));
    }
    this.#probes = Object.freeze(probes);
    const trusted = new Map<MediationGuaranteeV1, ReadonlySet<string>>();
    for (const guarantee of mediationGuaranteeV1Schema.options) {
      trusted.set(guarantee, new Set(options.trustedAuthorities[guarantee] ?? []));
    }
    this.#trustedAuthorities = trusted;
  }

  public async assess(scopeInput: CoverageScopeV1): Promise<ExclusiveMediationAssessmentV1> {
    const scope = coverageScopeV1Schema.parse(scopeInput);
    const now = this.#clock();
    const accepted: CoverageEvidenceV1[] = [];
    const failures = new Map<string, { readonly reasonCode: string; readonly verifierId: string | null }>();

    await Promise.all(this.#probes.map(async (probe) => {
      const key = `${probe.pathKind}:${probe.guarantee}`;
      try {
        let timeout: ReturnType<typeof setTimeout> | undefined;
        const timeoutPromise = new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => {
            reject(new Error("coverage probe timed out"));
          }, this.#probeTimeoutMs);
        });
        const observed = await Promise.race([
          Promise.resolve(probe.observe(scope)),
          timeoutPromise
        ]).finally(() => {
          if (timeout !== undefined) clearTimeout(timeout);
        });
        const evidence = coverageEvidenceV1Schema.parse(observed);
        const trusted = this.#trustedAuthorities.get(probe.guarantee)?.has(evidence.authority) === true;
        const needsIndependentVerifier = probe.pathKind !== "GATEWAY_MEDIATED" ||
          probe.guarantee === "CREDENTIAL_EXCLUSIVITY";
        const eligibleVerifier = this.#assurance === "DEPLOYMENT"
          ? evidence.verifierClass === (needsIndependentVerifier ? "INDEPENDENT_CONTROL" : evidence.verifierClass) &&
            evidence.verifierClass !== "TEST_FIXTURE"
          : evidence.verifierClass === "TEST_FIXTURE";
        const validBinding = evidence.guarantee === probe.guarantee && evidence.pathKind === probe.pathKind &&
          evidence.verifierId === probe.verifierId && evidence.authority === probe.authority &&
          evidence.assurance === this.#assurance && exactScope(evidence.scope, scope);
        const observedMs = Date.parse(evidence.observedAt);
        const expiresMs = Date.parse(evidence.expiresAt);
        if (!trusted) failures.set(key, { reasonCode: reason(probe.guarantee, "untrusted_authority"), verifierId: probe.verifierId });
        else if (!eligibleVerifier) failures.set(key, { reasonCode: reason(probe.guarantee, "ineligible_verifier_class"), verifierId: probe.verifierId });
        else if (!validBinding) failures.set(key, { reasonCode: reason(probe.guarantee, "scope_or_source_mismatch"), verifierId: probe.verifierId });
        else if (observedMs > now.getTime() + this.#maxFutureSkewMs) failures.set(key, { reasonCode: reason(probe.guarantee, "future_dated"), verifierId: probe.verifierId });
        else if (now.getTime() - observedMs > this.#maxEvidenceAgeMs) failures.set(key, { reasonCode: reason(probe.guarantee, "too_old"), verifierId: probe.verifierId });
        else if (expiresMs - observedMs > this.#maxEvidenceTtlMs) failures.set(key, { reasonCode: reason(probe.guarantee, "ttl_exceeded"), verifierId: probe.verifierId });
        else if (expiresMs <= now.getTime()) failures.set(key, { reasonCode: reason(probe.guarantee, "stale"), verifierId: probe.verifierId });
        else {
          const revisionKey = `${computeCanonicalDigestV1(scope)}:${key}:${probe.verifierId}`;
          const evidenceDigest = computeCanonicalDigestV1(evidence);
          const previous = this.#evidenceRevisions.get(revisionKey);
          if (previous !== undefined && evidence.revision < previous.revision) {
            failures.set(key, { reasonCode: reason(probe.guarantee, "revision_rollback"), verifierId: probe.verifierId });
          } else if (previous !== undefined && evidence.revision === previous.revision && evidenceDigest !== previous.digest) {
            failures.set(key, { reasonCode: reason(probe.guarantee, "revision_equivocation"), verifierId: probe.verifierId });
          } else {
            this.#evidenceRevisions.set(revisionKey, { revision: evidence.revision, digest: evidenceDigest });
            accepted.push(evidence);
          }
        }
      } catch {
        failures.set(key, { reasonCode: reason(probe.guarantee, "probe_failed"), verifierId: probe.verifierId });
      }
    }));

    const missingGuarantees: z.infer<typeof missingGuaranteeV1Schema>[] = [];
    const paths = coveragePathKindV1Schema.options.map((pathKind) => {
      const evidenceForPath: CoverageEvidenceV1[] = [];
      for (const guarantee of requiredByPath[pathKind]) {
        const key = `${pathKind}:${guarantee}`;
        const evidence = accepted.find((item) => item.pathKind === pathKind && item.guarantee === guarantee);
        const failure = failures.get(key);
        if (evidence === undefined) {
          missingGuarantees.push({
            guarantee,
            pathKind,
            reasonCode: failure?.reasonCode ?? reason(guarantee, "missing"),
            verifierId: failure?.verifierId ?? null
          });
        } else {
          evidenceForPath.push(evidence);
          const expectedStatus = pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" : "VERIFIED_BLOCKED";
          if (evidence.status !== expectedStatus) {
            missingGuarantees.push({
              guarantee,
              pathKind,
              reasonCode: reason(guarantee, evidence.status.toLowerCase()),
              verifierId: evidence.verifierId
            });
          }
        }
      }
      const pathMissing = missingGuarantees.filter((item) => item.pathKind === pathKind);
      return {
        pathKind,
        coverage: pathCoverage(pathKind, evidenceForPath.map((item) => item.status), pathMissing.length > 0),
        reasonCodes: pathMissing.map((item) => item.reasonCode).sort()
      };
    });
    const gateway = paths.find((path) => path.pathKind === "GATEWAY_MEDIATED");
    const bypassUnsafe = paths.some((path) => path.pathKind !== "GATEWAY_MEDIATED" && path.coverage !== "ENFORCED");
    let coverage: CoverageStateV1;
    if (gateway?.coverage === "UNPROTECTED") coverage = "UNPROTECTED";
    else if (gateway?.coverage === "OBSERVE_ONLY") coverage = "OBSERVE_ONLY";
    else if (gateway?.coverage !== "ENFORCED" || bypassUnsafe) coverage = "DEGRADED";
    else coverage = "ENFORCED";
    accepted.sort((left, right) => `${left.pathKind}:${left.guarantee}:${left.verifierId}`.localeCompare(`${right.pathKind}:${right.guarantee}:${right.verifierId}`));
    missingGuarantees.sort((left, right) => `${left.pathKind}:${left.guarantee}:${left.reasonCode}`.localeCompare(`${right.pathKind}:${right.guarantee}:${right.reasonCode}`));
    const earliestExpiryMs = accepted.reduce(
      (earliest, item) => Math.min(earliest, Date.parse(item.expiresAt)),
      Number.POSITIVE_INFINITY
    );
    const expiresAt = new Date(Number.isFinite(earliestExpiryMs) ? earliestExpiryMs : now.getTime() + 1).toISOString();
    const revisionKey = computeCanonicalDigestV1(scope);
    const revision = (this.#assessmentRevisions.get(revisionKey) ?? 0) + 1;
    this.#assessmentRevisions.set(revisionKey, revision);
    const evidenceDigest = computeCanonicalDigestV1({ assurance: this.#assurance, scope, coverage, paths, missingGuarantees, evidence: accepted });
    return exclusiveMediationAssessmentV1Schema.parse({
      schemaVersion: "1.0.0",
      assessmentId: this.#assessmentIdFactory(),
      revision,
      assurance: this.#assurance,
      scope,
      coverage,
      mutationAllowed: coverage === "ENFORCED",
      paths,
      missingGuarantees,
      evidence: accepted,
      evidenceDigest,
      assessedAt: now.toISOString(),
      expiresAt
    });
  }

  public async assertCurrentForMutation(
    scope: CoverageScopeV1,
    expectedEvidenceDigest: string
  ): Promise<ExclusiveMediationAssessmentV1> {
    const current = await this.assess(scope);
    if (!current.mutationAllowed || current.evidenceDigest !== expectedEvidenceDigest) {
      throw new CoverageAssessmentDeniedV1();
    }
    return current;
  }

  public async executeProtectedMutation<T>(input: {
    readonly scope: CoverageScopeV1;
    readonly expectedEvidenceDigest: string;
    readonly operation: (current: ExclusiveMediationAssessmentV1) => Promise<T>;
  }): Promise<T> {
    const current = await this.assertCurrentForMutation(input.scope, input.expectedEvidenceDigest);
    return input.operation(current);
  }
}

export class CoverageBoundPolicyEvaluatorV1 {
  readonly #monitor: ExclusiveMediationMonitorV1;
  readonly #policy: DeterministicPolicyEngineV1;

  public constructor(monitor: ExclusiveMediationMonitorV1, policy: DeterministicPolicyEngineV1) {
    this.#monitor = monitor;
    this.#policy = policy;
  }

  public async evaluate(input: {
    readonly action: CanonicalActionV1;
    readonly scope: CoverageScopeV1;
    readonly advisories?: readonly PolicyAdvisoryV1[];
  }): Promise<{ readonly assessment: ExclusiveMediationAssessmentV1; readonly decision: PolicyDecisionV1 }> {
    const action = canonicalActionV1Schema.parse(input.action);
    const scope = coverageScopeV1Schema.parse(input.scope);
    if (!coverageScopeMatchesActionV1(scope, action)) {
      throw new CoverageAssessmentDeniedV1();
    }
    const assessment = await this.#monitor.assess(input.scope);
    const decision = this.#policy.evaluate({
      action,
      coverage: assessment.coverage,
      ...(input.advisories === undefined ? {} : { advisories: input.advisories })
    });
    return { assessment, decision };
  }
}
