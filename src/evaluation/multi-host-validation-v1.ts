import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { coverageStateV1Schema, identifierV1Schema } from "../contracts/v1.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/u);

export const bypassInventoryEntryV1Schema = z.object({
  capabilityId: identifierV1Schema,
  kind: z.enum(["NATIVE", "DIRECT"]),
  mechanism: z.enum(["SHELL", "FILESYSTEM", "BROWSER", "NETWORK", "CREDENTIAL", "DOWNSTREAM_API", "OTHER"]),
  coverage: z.enum(["DEGRADED", "OBSERVE_ONLY", "UNPROTECTED"]),
  gatewayProtected: z.literal(false),
  reasonCodes: z.array(z.string().regex(/^coverage\.[a-z0-9_.-]+$/u)).min(1).max(32)
}).strict();

export const hostWorkflowObservationV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  hostId: identifierV1Schema,
  hostAdapterId: identifierV1Schema,
  sessionId: identifierV1Schema,
  canonicalEffectDigest: digest,
  policyDecision: z.enum(["DENY", "REQUIRE_APPROVAL", "SANDBOX", "ALLOW_WITH_CONSTRAINTS", "ALLOW"]),
  taskCompleted: z.boolean(),
  policyViolation: z.boolean(),
  approvalPresented: z.boolean(),
  approvalError: z.boolean(),
  latencyMs: z.number().nonnegative().max(3_600_000),
  compartmentDigests: z.object({
    identity: digest,
    route: digest,
    quota: digest,
    approval: digest,
    trust: digest,
    result: digest,
    audit: digest
  }).strict(),
  bypassInventory: z.array(bypassInventoryEntryV1Schema).min(1).max(64),
  coverage: coverageStateV1Schema,
  evidenceDigest: digest
}).strict().superRefine((observation, context) => {
  if (observation.policyViolation && observation.taskCompleted) {
    context.addIssue({ code: "custom", path: ["taskCompleted"], message: "Unsafe completion is not completion under policy" });
  }
  if (observation.approvalError && !observation.approvalPresented) {
    context.addIssue({ code: "custom", path: ["approvalError"], message: "Approval errors require a presentation" });
  }
  const { evidenceDigest, ...evidence } = observation;
  if (evidenceDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["evidenceDigest"], message: "Host evidence digest does not match" });
  }
});

export const multiHostValidationReportV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  reportId: identifierV1Schema,
  hostIds: z.array(identifierV1Schema).min(2).max(32),
  repetitions: z.number().int().min(2).max(10_000),
  equivalentPolicyDecisions: z.literal(true),
  isolatedCompartments: z.literal(true),
  observations: z.array(hostWorkflowObservationV1Schema).min(4).max(100_000),
  hostMetrics: z.array(z.object({
    hostId: identifierV1Schema,
    trials: z.number().int().positive(),
    completionRate: z.number().min(0).max(1),
    taskFailureRate: z.number().min(0).max(1),
    policyViolationRate: z.number().min(0).max(1),
    approvalRate: z.number().min(0).max(1),
    approvalErrorRate: z.number().min(0).max(1),
    meanLatencyMs: z.number().nonnegative(),
    enforcedCoverageRate: z.number().min(0).max(1)
  }).strict()).min(2).max(32),
  reportDigest: digest
}).strict().superRefine((report, context) => {
  const { reportDigest, ...evidence } = report;
  if (reportDigest !== computeCanonicalDigestV1(evidence)) {
    context.addIssue({ code: "custom", path: ["reportDigest"], message: "Report digest does not match" });
  }
});

export type HostWorkflowObservationV1 = z.infer<typeof hostWorkflowObservationV1Schema>;
export type MultiHostValidationReportV1 = z.infer<typeof multiHostValidationReportV1Schema>;

export interface McpHostAdapterV1 {
  readonly hostId: string;
  readonly hostAdapterId: string;
  run(repetition: number): HostWorkflowObservationV1 | Promise<HostWorkflowObservationV1>;
}

function rate(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

export class MultiHostValidationHarnessV1 {
  public async run(input: {
    readonly adapters: readonly McpHostAdapterV1[];
    readonly repetitions: number;
    readonly reportId?: string;
  }): Promise<MultiHostValidationReportV1> {
    const repetitions = z.number().int().min(2).max(10_000).parse(input.repetitions);
    const adapters = [...input.adapters];
    if (adapters.length < 2 || new Set(adapters.map((item) => item.hostId)).size !== adapters.length ||
      new Set(adapters.map((item) => item.hostAdapterId)).size !== adapters.length) {
      throw new Error("At least two uniquely identified MCP host adapters are required");
    }
    adapters.forEach((adapter) => {
      identifierV1Schema.parse(adapter.hostId);
      identifierV1Schema.parse(adapter.hostAdapterId);
    });
    const observations: HostWorkflowObservationV1[] = [];
    for (let repetition = 0; repetition < repetitions; repetition += 1) {
      const concurrent = await Promise.all(adapters.map(async (adapter) => {
        const observation = hostWorkflowObservationV1Schema.parse(await adapter.run(repetition));
        if (observation.hostId !== adapter.hostId || observation.hostAdapterId !== adapter.hostAdapterId) {
          throw new Error("Host adapter identity does not match its observation");
        }
        return observation;
      }));
      if (new Set(concurrent.map((item) => item.canonicalEffectDigest)).size !== 1 ||
        new Set(concurrent.map((item) => item.policyDecision)).size !== 1) {
        throw new Error("Equivalent host workflows produced different canonical policy outcomes");
      }
      const compartmentNames = ["identity", "route", "quota", "approval", "trust", "result", "audit"] as const;
      for (const name of compartmentNames) {
        if (new Set(concurrent.map((item) => item.compartmentDigests[name])).size !== concurrent.length) {
          throw new Error(`Concurrent host sessions collided in ${name}`);
        }
      }
      observations.push(...concurrent);
    }
    if (new Set(observations.map((item) => item.sessionId)).size !== observations.length) {
      throw new Error("Host workflow session identifiers collided");
    }
    for (const name of ["identity", "route", "quota", "approval", "trust", "result", "audit"] as const) {
      if (new Set(observations.map((item) => item.compartmentDigests[name])).size !== observations.length) {
        throw new Error(`Host workflow history collided in ${name}`);
      }
    }
    const hostMetrics = adapters.map((adapter) => {
      const trials = observations.filter((item) => item.hostId === adapter.hostId);
      const approvals = trials.filter((item) => item.approvalPresented);
      return {
        hostId: adapter.hostId,
        trials: trials.length,
        completionRate: rate(trials.filter((item) => item.taskCompleted && !item.policyViolation).length, trials.length),
        taskFailureRate: rate(trials.filter((item) => !item.taskCompleted).length, trials.length),
        policyViolationRate: rate(trials.filter((item) => item.policyViolation).length, trials.length),
        approvalRate: rate(approvals.length, trials.length),
        approvalErrorRate: rate(approvals.filter((item) => item.approvalError).length, approvals.length),
        meanLatencyMs: rate(trials.reduce((sum, item) => sum + item.latencyMs, 0), trials.length),
        enforcedCoverageRate: rate(trials.filter((item) => item.coverage === "ENFORCED").length, trials.length)
      };
    });
    const reportInput = {
      schemaVersion: "1.0.0" as const,
      reportId: input.reportId ?? "multi-host-validation",
      hostIds: adapters.map((item) => item.hostId),
      repetitions,
      equivalentPolicyDecisions: true as const,
      isolatedCompartments: true as const,
      observations,
      hostMetrics
    };
    return multiHostValidationReportV1Schema.parse({
      ...reportInput,
      reportDigest: computeCanonicalDigestV1(reportInput)
    });
  }
}
