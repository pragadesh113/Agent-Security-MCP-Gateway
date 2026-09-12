import { randomUUID } from "node:crypto";

import { z } from "zod";

import {
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  policyDecisionV1Schema,
  type CanonicalActionV1,
  type PolicyDecisionV1
} from "../contracts/trajectory-v1.js";
import { capabilityIdentifierV1Schema, coverageStateV1Schema, identifierV1Schema, type CoverageStateV1 } from "../contracts/v1.js";
import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";

const decisionV1Schema = z.enum(["DENY", "REQUIRE_APPROVAL", "SANDBOX", "ALLOW_WITH_CONSTRAINTS", "ALLOW"]);
const effectV1Schema = z.enum(["READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER", "UNKNOWN"]);
const environmentV1Schema = z.enum(["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"]);
const resourceClassV1Schema = z.enum(["FILESYSTEM", "SHELL", "GIT", "PACKAGE", "NETWORK", "DATABASE", "CLOUD", "BROWSER", "PROCESS", "DEPLOYMENT", "UNKNOWN"]);
const classificationV1Schema = z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "CREDENTIAL", "UNKNOWN"]);
const constraintV1Schema = z.object({
  constraintId: identifierV1Schema,
  type: capabilityIdentifierV1Schema,
  parametersDigest: z.string().regex(/^[a-f0-9]{64}$/u)
}).strict();

export const deterministicPolicyRuleV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  ruleId: identifierV1Schema,
  authority: z.enum(["BUILT_IN", "ADMINISTRATOR"]),
  effects: z.array(effectV1Schema).max(7),
  environments: z.array(environmentV1Schema).max(5),
  resourceClasses: z.array(resourceClassV1Schema).max(11),
  classifications: z.array(classificationV1Schema).max(6),
  resourceIds: z.array(identifierV1Schema).max(128),
  routeIds: z.array(identifierV1Schema).max(128),
  decision: decisionV1Schema,
  tierFloor: z.number().int().min(0).max(3),
  reasonCodes: z.array(capabilityIdentifierV1Schema).min(1).max(32),
  constraints: z.array(constraintV1Schema).max(32),
  sandboxProfileId: identifierV1Schema.nullable()
}).strict().superRefine((rule, context) => {
  if (rule.authority === "BUILT_IN" && rule.decision !== "DENY") {
    context.addIssue({ code: "custom", path: ["decision"], message: "Built-in rules are immutable denials" });
  }
  if ((rule.decision === "ALLOW_WITH_CONSTRAINTS") !== (rule.constraints.length > 0)) {
    context.addIssue({ code: "custom", path: ["constraints"], message: "Only constrained rules carry constraints" });
  }
  if ((rule.decision === "SANDBOX") !== (rule.sandboxProfileId !== null)) {
    context.addIssue({ code: "custom", path: ["sandboxProfileId"], message: "Only sandbox rules carry a sandbox profile" });
  }
});

export const policyAdvisoryV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  source: z.enum(["TRUST", "SUPERVISOR"]),
  decision: z.enum(["DENY", "REQUIRE_APPROVAL", "ALLOW"]),
  reasonCodes: z.array(capabilityIdentifierV1Schema).min(1).max(32)
}).strict();

export type DeterministicPolicyRuleV1 = z.infer<typeof deterministicPolicyRuleV1Schema>;
export type PolicyAdvisoryV1 = z.infer<typeof policyAdvisoryV1Schema>;

const decisionPriority: Readonly<Record<PolicyDecisionV1["decision"], number>> = {
  ALLOW: 0,
  ALLOW_WITH_CONSTRAINTS: 1,
  SANDBOX: 2,
  REQUIRE_APPROVAL: 3,
  DENY: 4
};

function isUnresolved(action: CanonicalActionV1): boolean {
  return action.effect === "UNKNOWN" || action.environment === "UNKNOWN" ||
    action.parsingEvidence.status !== "FULL" || action.resources.some((resource) =>
      resource.resourceClass === "UNKNOWN" || resource.classification === "UNKNOWN") ||
    action.dataFlow.direction === "UNKNOWN" || action.dataFlow.classifications.includes("UNKNOWN");
}

export function classifyCanonicalRiskTierV1(actionInput: CanonicalActionV1): 0 | 1 | 2 | 3 {
  const action = canonicalActionV1Schema.parse(actionInput);
  if (action.environment === "PRODUCTION" || action.effect === "DELETE" || action.effect === "ADMINISTER" ||
    action.resources.some((resource) => resource.classification === "CREDENTIAL") ||
    (action.effect !== "READ" && action.effect !== "UNKNOWN" &&
      ["PARTIALLY_REVERSIBLE", "IRREVERSIBLE", "UNKNOWN"].includes(action.reversibility))) return 3;
  if (isUnresolved(action)) return 2;
  if (action.effect === "READ" && !action.dataFlow.externalDestination &&
    action.resources.every((resource) => resource.classification === "PUBLIC")) return 0;
  if (action.effect === "WRITE" && ["DEVELOPMENT", "TEST"].includes(action.environment) &&
    !action.dataFlow.externalDestination && ["VERIFIED_COMPENSATING_ACTION", "TESTED_SNAPSHOT"].includes(action.reversibility) &&
    action.resources.every((resource) => ["PUBLIC", "INTERNAL"].includes(resource.classification))) return 1;
  return 2;
}

function matches(rule: DeterministicPolicyRuleV1, action: CanonicalActionV1): boolean {
  const any = <T>(configured: readonly T[], observed: readonly T[]): boolean =>
    configured.length === 0 || configured.some((value) => observed.includes(value));
  return any(rule.effects, [action.effect]) && any(rule.environments, [action.environment]) &&
    any(rule.resourceClasses, action.resources.map((resource) => resource.resourceClass)) &&
    any(rule.classifications, action.resources.map((resource) => resource.classification)) &&
    any(rule.resourceIds, action.resources.map((resource) => resource.resourceId)) &&
    any(rule.routeIds, [action.route.routeId]);
}

export interface DeterministicPolicyEngineV1Options {
  readonly policyVersion: string;
  readonly rules?: readonly DeterministicPolicyRuleV1[];
  readonly tierTwoSandboxProfileId?: string;
  readonly allowTierZeroInDegradedCoverage?: boolean;
  readonly clock?: () => Date;
  readonly decisionIdFactory?: () => string;
}

export class DeterministicPolicyEngineV1 {
  readonly #options: DeterministicPolicyEngineV1Options;
  readonly #rules: readonly DeterministicPolicyRuleV1[];

  public constructor(options: DeterministicPolicyEngineV1Options) {
    this.#options = options;
    identifierV1Schema.parse(options.policyVersion);
    if (options.tierTwoSandboxProfileId !== undefined) identifierV1Schema.parse(options.tierTwoSandboxProfileId);
    this.#rules = (options.rules ?? []).map((rule) => deterministicPolicyRuleV1Schema.parse(rule));
  }

  public evaluate(input: {
    readonly action: CanonicalActionV1;
    readonly coverage: CoverageStateV1;
    readonly advisories?: readonly PolicyAdvisoryV1[];
  }): PolicyDecisionV1 {
    const action = canonicalActionV1Schema.parse(input.action);
    const coverage = coverageStateV1Schema.parse(input.coverage);
    const advisories = (input.advisories ?? []).map((item) => policyAdvisoryV1Schema.parse(item));
    let tier = classifyCanonicalRiskTierV1(action);
    const unresolved = isUnresolved(action);
    let decision: PolicyDecisionV1["decision"];
    let reasonCodes: string[];
    let sandboxProfileId: string | null = null;
    let constraints: PolicyDecisionV1["constraints"] = [];

    if (unresolved) {
      decision = coverage === "ENFORCED" ? "REQUIRE_APPROVAL" : "DENY";
      reasonCodes = ["invariant.unresolved_action"];
    } else if (tier === 3) {
      decision = coverage === "ENFORCED" ? "REQUIRE_APPROVAL" : "DENY";
      reasonCodes = ["invariant.tier3_approval"];
    } else if (action.effect !== "READ" && coverage !== "ENFORCED") {
      decision = "DENY";
      reasonCodes = ["invariant.mutation_requires_enforced_coverage"];
    } else if (tier === 0 && (coverage === "ENFORCED" || (coverage === "DEGRADED" && this.#options.allowTierZeroInDegradedCoverage === true))) {
      decision = "ALLOW";
      reasonCodes = ["policy.proven_safe_read"];
    } else if (tier === 1 && coverage === "ENFORCED") {
      decision = "ALLOW";
      reasonCodes = ["policy.reversible_local_write"];
    } else if (tier === 2 && coverage === "ENFORCED" && this.#options.tierTwoSandboxProfileId !== undefined) {
      decision = "SANDBOX";
      sandboxProfileId = this.#options.tierTwoSandboxProfileId;
      reasonCodes = ["policy.tier2_sandbox"];
    } else if (tier === 2 && coverage === "ENFORCED") {
      decision = "REQUIRE_APPROVAL";
      reasonCodes = ["policy.tier2_approval"];
    } else {
      decision = "DENY";
      reasonCodes = ["coverage.not_enforced"];
    }

    const applicableRules = this.#rules.filter((rule) => matches(rule, action));
    for (const rule of applicableRules) {
      tier = Math.max(tier, rule.tierFloor) as 0 | 1 | 2 | 3;
      reasonCodes.push(...rule.reasonCodes);
      if (decisionPriority[rule.decision] > decisionPriority[decision]) {
        decision = rule.decision;
        constraints = rule.constraints;
        sandboxProfileId = rule.sandboxProfileId;
      } else if (rule.decision === decision && decision === "ALLOW_WITH_CONSTRAINTS") {
        constraints = [...constraints, ...rule.constraints];
      } else if (rule.decision === decision && decision === "SANDBOX" && sandboxProfileId !== rule.sandboxProfileId) {
        decision = "DENY";
        sandboxProfileId = null;
        reasonCodes.push("policy.conflicting_sandbox_profiles");
      }
    }
    for (const advisory of advisories) {
      reasonCodes.push(...advisory.reasonCodes.map((reason) => `advisory.${advisory.source.toLowerCase()}.${reason}`));
      if (decisionPriority[advisory.decision] > decisionPriority[decision]) {
        decision = advisory.decision;
        constraints = [];
        sandboxProfileId = null;
      }
    }
    if (tier === 3 && decision !== "DENY") {
      decision = "REQUIRE_APPROVAL";
      constraints = [];
      sandboxProfileId = null;
      reasonCodes.push("invariant.tier3_approval");
    }
    if (applicableRules.some((rule) => rule.authority === "BUILT_IN")) {
      decision = "DENY";
      constraints = [];
      sandboxProfileId = null;
      reasonCodes.push("invariant.immutable_deny");
    }
    if (action.effect !== "READ" && coverage !== "ENFORCED") {
      decision = "DENY";
      constraints = [];
      sandboxProfileId = null;
    }
    if (decision !== "ALLOW_WITH_CONSTRAINTS") constraints = [];
    if (decision !== "SANDBOX") sandboxProfileId = null;
    const constraintsById = new Map<string, PolicyDecisionV1["constraints"][number]>();
    for (const constraint of constraints) {
      const existing = constraintsById.get(constraint.constraintId);
      if (existing !== undefined && computeCanonicalDigestV1(existing) !== computeCanonicalDigestV1(constraint)) {
        decision = "DENY";
        constraints = [];
        sandboxProfileId = null;
        reasonCodes.push("policy.conflicting_constraints");
        constraintsById.clear();
        break;
      }
      constraintsById.set(constraint.constraintId, constraint);
    }
    const uniqueConstraints = [...constraintsById.values()];
    const parsed = policyDecisionV1Schema.parse({
      schemaVersion: "1.0.0",
      decisionId: identifierV1Schema.parse(this.#options.decisionIdFactory?.() ?? randomUUID()),
      requestId: action.requestId, actionId: action.actionId, actionHash: action.actionHash,
      sessionId: action.sessionId, serverId: action.route.serverId, routeId: action.route.routeId,
      schemaDigest: action.route.schemaDigest, decision, tier,
      reasonCodes: [...new Set(reasonCodes)].sort(), constraints: uniqueConstraints,
      sandboxProfileId, coverage, policyVersion: this.#options.policyVersion,
      decidedAt: (this.#options.clock?.() ?? new Date()).toISOString()
    });
    canonicalActionDecisionBindingV1Schema.parse({ action, decision: parsed });
    return parsed;
  }
}

export function createConstraintV1(constraintId: string, type: string, parameters: unknown): PolicyDecisionV1["constraints"][number] {
  return constraintV1Schema.parse({ constraintId, type, parametersDigest: computeCanonicalDigestV1(parameters) });
}
