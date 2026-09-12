import { describe, expect, it } from "vitest";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import {
  createOperationalTrialEvidenceBundleV1,
  operationalTrialEvidenceBundleV1Schema,
  type OperationalTrialEvidenceV1
} from "../../src/evaluation/operational-trial-evidence-v1.js";

const d = (value: string): string => computeCanonicalDigestV1(value);
const hosts = ["named-host-a", "named-host-b"].map((hostId) => ({
  hostId, hostName: hostId === "named-host-a" ? "Named MCP Host A" : "Named MCP Host B",
  hostVersion: "1.2.3", adapterId: `adapter-${hostId}`, adapterVersion: "1.0.0",
  adapterDigest: d(`adapter-${hostId}`)
}));
const reproduction = {
  harnessId: "operational-harness", harnessVersion: "1.0.0",
  scenarioCatalogReference: "evidence/scenarios.json", scenarioCatalogDigest: d("catalog"),
  adaptiveAttackerReference: "evidence/adaptive-attacker.json", adaptiveAttackerDigest: d("attacker"),
  configurationReference: "evidence/config.json", configurationDigest: d("config"),
  sourceRevision: "revision-abc", sourceDigest: d("source"),
  runtimeReference: "evidence/runtime.json", runtimeDigest: d("runtime"),
  seedDerivation: "seed = baseSeed + repetition"
};

function trial(hostId: string, repetition: number, arm: "BASELINE" | "DEFENSE"): OperationalTrialEvidenceV1 {
  const material = {
    schemaVersion: "1.0.0" as const, trialId: `${hostId}-${String(repetition)}-${arm.toLowerCase()}`,
    arm, hostId, adapterId: `adapter-${hostId}`, scenarioId: "adaptive-schema-drift",
    repetition, seed: 100 + repetition, adaptiveAttackerDigest: d("attacker"),
    scenarioConfigurationDigest: d(arm === "BASELINE" ? "baseline" : "defense"),
    sourceDigest: d("source"), runtimeDigest: d("runtime"),
    trajectoryReference: `evidence/${hostId}/${String(repetition)}/${arm}.json`,
    trajectoryDigest: d(`trajectory-${hostId}-${String(repetition)}-${arm}`),
    metrics: { attackAttempted: true, attackSucceeded: arm === "BASELINE",
      policyViolation: arm === "BASELINE", taskCompleted: false, policyAllowed: arm === "BASELINE",
      approvalPresented: false, approvalError: false, replannedSafely: false,
      latencyMs: arm === "BASELINE" ? 10 : 20, costUnits: 1,
      coverage: arm === "BASELINE" ? "UNPROTECTED" as const : "ENFORCED" as const },
    startedAt: "2026-09-11T10:00:00.000Z", finishedAt: "2026-09-11T10:00:01.000Z"
  };
  return { ...material, evidenceDigest: computeCanonicalDigestV1(material) };
}

function validInput() {
  const trials = hosts.flatMap((host) => [0, 1].flatMap((repetition) =>
    [trial(host.hostId, repetition, "BASELINE"), trial(host.hostId, repetition, "DEFENSE")]));
  return { bundleId: "operational-evidence", hosts, baselineConfigurationDigest: d("baseline"),
    defenseConfigurationDigest: d("defense"), reproduction, trials,
    generatedAt: "2026-09-11T10:01:00.000Z" };
}

describe("operational repeated-trial evidence v1", () => {
  it("builds a deterministic, reproducible paired evidence bundle", () => {
    const input = validInput();
    const first = createOperationalTrialEvidenceBundleV1(input);
    const second = createOperationalTrialEvidenceBundleV1({ ...input, trials: [...input.trials].reverse(), hosts: [...input.hosts].reverse() });
    expect(first.bundleDigest).toBe(second.bundleDigest);
    expect(first.hosts.map((host) => host.hostName)).toEqual(["Named MCP Host A", "Named MCP Host B"]);
    expect(first.reproduction).toEqual(reproduction);
  });

  it("rejects incomplete, duplicate, and unpaired evidence", () => {
    const input = validInput();
    const firstTrial = input.trials[0];
    if (firstTrial === undefined) throw new Error("Fixture is incomplete");
    expect(() => createOperationalTrialEvidenceBundleV1({ ...input, hosts: input.hosts.slice(0, 1) })).toThrow();
    expect(() => createOperationalTrialEvidenceBundleV1({ ...input, trials: [...input.trials, firstTrial] })).toThrow("duplicated");
    expect(() => createOperationalTrialEvidenceBundleV1({ ...input, trials: input.trials.slice(1) })).toThrow("paired");
  });

  it("rejects host, adapter, seed, configuration, runtime, and digest substitution", () => {
    const input = validInput();
    const firstTrial = input.trials[0];
    if (firstTrial === undefined) throw new Error("Fixture is incomplete");
    const replace = (changes: Partial<OperationalTrialEvidenceV1>) => {
      const changed = { ...firstTrial, ...changes };
      const { evidenceDigest: discarded, ...material } = changed;
      void discarded;
      return { ...changed, evidenceDigest: computeCanonicalDigestV1(material) };
    };
    for (const changed of [
      replace({ adapterId: "adapter-attacker" }), replace({ seed: 999 }),
      replace({ scenarioConfigurationDigest: d("substituted") }), replace({ runtimeDigest: d("substituted") })
    ]) {
      expect(() => createOperationalTrialEvidenceBundleV1({ ...input, trials: [changed, ...input.trials.slice(1)] })).toThrow();
    }
    expect(operationalTrialEvidenceBundleV1Schema.safeParse({
      ...createOperationalTrialEvidenceBundleV1(input), bundleDigest: d("forged")
    }).success).toBe(false);
  });
});
