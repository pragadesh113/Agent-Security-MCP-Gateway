import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const arm = z.enum(["BASELINE", "DEFENSE"]);

export const operationalHostV1Schema = z.object({
  hostId: identifierV1Schema,
  hostName: z.string().trim().min(1).max(128),
  hostVersion: z.string().trim().min(1).max(64),
  adapterId: identifierV1Schema,
  adapterVersion: z.string().trim().min(1).max(64),
  adapterDigest: digest
}).strict();

const metrics = z.object({
  attackAttempted: z.boolean(), attackSucceeded: z.boolean(), policyViolation: z.boolean(),
  taskCompleted: z.boolean(), policyAllowed: z.boolean(), approvalPresented: z.boolean(),
  approvalError: z.boolean(), replannedSafely: z.boolean(), latencyMs: z.number().nonnegative().max(3_600_000),
  costUnits: z.number().nonnegative().max(1_000_000),
  coverage: z.enum(["ENFORCED", "DEGRADED", "OBSERVE_ONLY", "UNPROTECTED"])
}).strict().superRefine((value, context) => {
  if (value.attackSucceeded && (!value.attackAttempted || !value.policyViolation)) {
    context.addIssue({ code: "custom", path: ["attackSucceeded"], message: "Attack success requires an attempted policy violation" });
  }
  if (value.approvalError && !value.approvalPresented) {
    context.addIssue({ code: "custom", path: ["approvalError"], message: "Approval error requires presentation" });
  }
  if (value.replannedSafely && (!value.taskCompleted || value.policyViolation)) {
    context.addIssue({ code: "custom", path: ["replannedSafely"], message: "Safe replanning requires safe completion" });
  }
});

export const operationalTrialEvidenceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"), trialId: identifierV1Schema, arm,
  hostId: identifierV1Schema, adapterId: identifierV1Schema,
  scenarioId: identifierV1Schema, repetition: z.number().int().nonnegative().max(9_999),
  seed: z.number().int().nonnegative().max(0xffff_ffff),
  adaptiveAttackerDigest: digest, scenarioConfigurationDigest: digest,
  sourceDigest: digest, runtimeDigest: digest,
  trajectoryReference: z.string().trim().min(1).max(2_048), trajectoryDigest: digest,
  metrics, startedAt: utcTimestampV1Schema, finishedAt: utcTimestampV1Schema,
  evidenceDigest: digest
}).strict().superRefine((value, context) => {
  if (Date.parse(value.finishedAt) < Date.parse(value.startedAt)) {
    context.addIssue({ code: "custom", path: ["finishedAt"], message: "Trial cannot finish before it starts" });
  }
  const { evidenceDigest, ...material } = value;
  if (evidenceDigest !== computeCanonicalDigestV1(material)) {
    context.addIssue({ code: "custom", path: ["evidenceDigest"], message: "Trial evidence digest does not match" });
  }
});

export const operationalTrialReproductionV1Schema = z.object({
  harnessId: identifierV1Schema, harnessVersion: z.string().trim().min(1).max(64),
  scenarioCatalogReference: z.string().trim().min(1).max(2_048),
  scenarioCatalogDigest: digest, adaptiveAttackerReference: z.string().trim().min(1).max(2_048),
  adaptiveAttackerDigest: digest, configurationReference: z.string().trim().min(1).max(2_048),
  configurationDigest: digest, sourceRevision: z.string().trim().min(1).max(256),
  sourceDigest: digest, runtimeReference: z.string().trim().min(1).max(2_048), runtimeDigest: digest,
  seedDerivation: z.string().trim().min(1).max(512)
}).strict();

export const operationalTrialEvidenceBundleV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"), bundleId: identifierV1Schema,
  hosts: z.array(operationalHostV1Schema).min(2).max(32),
  arms: z.tuple([
    z.object({ arm: z.literal("BASELINE"), configurationDigest: digest }).strict(),
    z.object({ arm: z.literal("DEFENSE"), configurationDigest: digest }).strict()
  ]),
  reproduction: operationalTrialReproductionV1Schema,
  trials: z.array(operationalTrialEvidenceV1Schema).min(8).max(100_000),
  generatedAt: utcTimestampV1Schema, bundleDigest: digest
}).strict().superRefine((value, context) => {
  const { bundleDigest, ...material } = value;
  if (bundleDigest !== computeCanonicalDigestV1(material)) {
    context.addIssue({ code: "custom", path: ["bundleDigest"], message: "Bundle digest does not match" });
  }
});

export type OperationalHostV1 = z.infer<typeof operationalHostV1Schema>;
export type OperationalTrialEvidenceV1 = z.infer<typeof operationalTrialEvidenceV1Schema>;
export type OperationalTrialReproductionV1 = z.infer<typeof operationalTrialReproductionV1Schema>;
export type OperationalTrialEvidenceBundleV1 = z.infer<typeof operationalTrialEvidenceBundleV1Schema>;

function pairKey(trial: OperationalTrialEvidenceV1): string {
  return `${trial.hostId}\u0000${trial.scenarioId}\u0000${String(trial.repetition)}`;
}

export function createOperationalTrialEvidenceBundleV1(input: {
  readonly bundleId: string;
  readonly hosts: readonly OperationalHostV1[];
  readonly baselineConfigurationDigest: string;
  readonly defenseConfigurationDigest: string;
  readonly reproduction: OperationalTrialReproductionV1;
  readonly trials: readonly OperationalTrialEvidenceV1[];
  readonly generatedAt: string;
}): OperationalTrialEvidenceBundleV1 {
  const hosts = input.hosts.map((item) => operationalHostV1Schema.parse(item))
    .sort((left, right) => left.hostId.localeCompare(right.hostId));
  if (new Set(hosts.map((item) => item.hostId)).size !== hosts.length ||
    new Set(hosts.map((item) => item.adapterId)).size !== hosts.length) {
    throw new Error("Operational hosts and adapters must be unique");
  }
  const reproduction = operationalTrialReproductionV1Schema.parse(input.reproduction);
  const hostMap = new Map(hosts.map((item) => [item.hostId, item]));
  const trials = input.trials.map((item) => operationalTrialEvidenceV1Schema.parse(item))
    .sort((left, right) => pairKey(left).localeCompare(pairKey(right)) || left.arm.localeCompare(right.arm));
  if (new Set(trials.map((item) => item.trialId)).size !== trials.length ||
    new Set(trials.map((item) => item.evidenceDigest)).size !== trials.length) {
    throw new Error("Operational trial evidence is duplicated");
  }
  const pairs = new Map<string, OperationalTrialEvidenceV1[]>();
  for (const trial of trials) {
    const host = hostMap.get(trial.hostId);
    if (host === undefined || trial.adapterId !== host.adapterId ||
      trial.sourceDigest !== reproduction.sourceDigest || trial.runtimeDigest !== reproduction.runtimeDigest ||
      trial.adaptiveAttackerDigest !== reproduction.adaptiveAttackerDigest) {
      throw new Error("Operational trial authority was substituted");
    }
    const expectedConfiguration = trial.arm === "BASELINE"
      ? input.baselineConfigurationDigest : input.defenseConfigurationDigest;
    if (trial.scenarioConfigurationDigest !== expectedConfiguration) {
      throw new Error("Operational trial configuration was substituted");
    }
    const pair = pairs.get(pairKey(trial)) ?? [];
    pair.push(trial); pairs.set(pairKey(trial), pair);
  }
  for (const host of hosts) {
    const hostTrials = trials.filter((trial) => trial.hostId === host.hostId);
    if (hostTrials.length === 0) throw new Error("Every named host requires evidence");
  }
  for (const pair of pairs.values()) {
    if (pair.length !== 2 || new Set(pair.map((item) => item.arm)).size !== 2 ||
      new Set(pair.map((item) => item.seed)).size !== 1) {
      throw new Error("Baseline and defense trials must be exactly paired with one seed");
    }
  }
  const material = {
    schemaVersion: "1.0.0" as const, bundleId: identifierV1Schema.parse(input.bundleId), hosts,
    arms: [
      { arm: "BASELINE" as const, configurationDigest: digest.parse(input.baselineConfigurationDigest) },
      { arm: "DEFENSE" as const, configurationDigest: digest.parse(input.defenseConfigurationDigest) }
    ] as const,
    reproduction, trials, generatedAt: utcTimestampV1Schema.parse(input.generatedAt)
  };
  return operationalTrialEvidenceBundleV1Schema.parse({
    ...material, bundleDigest: computeCanonicalDigestV1(material)
  });
}
