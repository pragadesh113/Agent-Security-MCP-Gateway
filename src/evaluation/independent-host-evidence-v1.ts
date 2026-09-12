import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";

const digestV1Schema = z.string().regex(/^[a-f0-9]{64}$/u);

function isProtectedHttpsOrigin(value: string): boolean {
  try {
    const endpoint = new URL(value);
    if (endpoint.protocol !== "https:" || endpoint.origin !== value ||
      endpoint.username !== "" || endpoint.password !== "") {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export const authenticatedHostAdapterEvidenceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  adapterId: identifierV1Schema,
  authenticationMethod: z.enum(["MUTUAL_TLS", "SIGNED_ATTESTATION"]),
  authorityId: identifierV1Schema,
  credentialId: identifierV1Schema,
  identityRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  endpointOrigin: z.string().max(2_048).refine(isProtectedHttpsOrigin, {
    message: "Named host evidence requires a canonical HTTPS origin without userinfo"
  }),
  verifiedAt: utcTimestampV1Schema,
  evidenceDigest: digestV1Schema
}).strict().superRefine((evidence, context) => {
  const { evidenceDigest, ...digestInput } = evidence;
  if (evidenceDigest !== computeCanonicalDigestV1(digestInput)) {
    context.addIssue({
      code: "custom",
      path: ["evidenceDigest"],
      message: "Authenticated adapter evidence digest does not match"
    });
  }
});

export const namedIndependentHostEvidenceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  hostId: identifierV1Schema,
  productName: z.string().trim().min(1).max(128),
  productVersion: z.string().trim().min(1).max(64),
  operatorId: identifierV1Schema,
  operatorName: z.string().trim().min(1).max(128),
  adapter: authenticatedHostAdapterEvidenceV1Schema,
  identityDigest: digestV1Schema
}).strict().superRefine((host, context) => {
  const { identityDigest, ...digestInput } = host;
  if (identityDigest !== computeCanonicalDigestV1(digestInput)) {
    context.addIssue({
      code: "custom",
      path: ["identityDigest"],
      message: "Named host identity digest does not match"
    });
  }
});

export const independentHostWorkflowEvidenceV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  hostId: identifierV1Schema,
  operatorId: identifierV1Schema,
  adapterId: identifierV1Schema,
  workflowClass: z.enum(["BENIGN", "ADVERSARIAL"]),
  scenarioId: identifierV1Schema,
  throughOperationalRuntime: z.literal(true),
  runtimeDigest: digestV1Schema,
  configurationDigest: digestV1Schema,
  trajectoryDigest: digestV1Schema,
  policyDecision: z.enum([
    "DENY", "REQUIRE_APPROVAL", "SANDBOX", "ALLOW_WITH_CONSTRAINTS", "ALLOW"
  ]),
  attackAttempted: z.boolean(),
  attackSucceeded: z.boolean(),
  policyViolation: z.boolean(),
  taskCompleted: z.boolean(),
  observedAt: utcTimestampV1Schema,
  evidenceDigest: digestV1Schema
}).strict().superRefine((evidence, context) => {
  if (evidence.attackAttempted !== (evidence.workflowClass === "ADVERSARIAL")) {
    context.addIssue({
      code: "custom",
      path: ["attackAttempted"],
      message: "Only adversarial host workflows can be attack attempts"
    });
  }
  if (evidence.attackSucceeded && !evidence.policyViolation) {
    context.addIssue({
      code: "custom",
      path: ["policyViolation"],
      message: "A successful attack is a policy violation"
    });
  }
  if (evidence.taskCompleted && evidence.policyViolation) {
    context.addIssue({
      code: "custom",
      path: ["taskCompleted"],
      message: "Unsafe completion is not completion under policy"
    });
  }
  const { evidenceDigest, ...digestInput } = evidence;
  if (evidenceDigest !== computeCanonicalDigestV1(digestInput)) {
    context.addIssue({
      code: "custom",
      path: ["evidenceDigest"],
      message: "Host workflow evidence digest does not match"
    });
  }
});

export const independentHostEvidenceReportV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  reportId: identifierV1Schema,
  validationScope: z.literal("EVIDENCE_CONTRACT_ONLY"),
  runtimeDigest: digestV1Schema,
  configurationDigest: digestV1Schema,
  hosts: z.array(namedIndependentHostEvidenceV1Schema).min(2).max(32),
  workflows: z.array(independentHostWorkflowEvidenceV1Schema).min(4).max(100_000),
  validatedAt: utcTimestampV1Schema,
  reportDigest: digestV1Schema
}).strict().superRefine((report, context) => {
  const { reportDigest, ...digestInput } = report;
  if (reportDigest !== computeCanonicalDigestV1(digestInput)) {
    context.addIssue({
      code: "custom",
      path: ["reportDigest"],
      message: "Independent host report digest does not match"
    });
  }
});

export type AuthenticatedHostAdapterEvidenceV1 = z.infer<
  typeof authenticatedHostAdapterEvidenceV1Schema
>;
export type NamedIndependentHostEvidenceV1 = z.infer<
  typeof namedIndependentHostEvidenceV1Schema
>;
export type IndependentHostWorkflowEvidenceV1 = z.infer<
  typeof independentHostWorkflowEvidenceV1Schema
>;
export type IndependentHostEvidenceReportV1 = z.infer<
  typeof independentHostEvidenceReportV1Schema
>;

export class IndependentHostEvidenceGateV1 {
  public validate(input: {
    readonly reportId: string;
    readonly runtimeDigest: string;
    readonly configurationDigest: string;
    readonly hosts: readonly NamedIndependentHostEvidenceV1[];
    readonly workflows: readonly IndependentHostWorkflowEvidenceV1[];
    readonly validatedAt: string;
  }): IndependentHostEvidenceReportV1 {
    const runtimeDigest = digestV1Schema.parse(input.runtimeDigest);
    const configurationDigest = digestV1Schema.parse(input.configurationDigest);
    const validatedAt = utcTimestampV1Schema.parse(input.validatedAt);
    const hosts = input.hosts.map((host) => namedIndependentHostEvidenceV1Schema.parse(host));
    const workflows = input.workflows.map((workflow) =>
      independentHostWorkflowEvidenceV1Schema.parse(workflow)
    );
    if (hosts.length < 2) {
      throw new Error("At least two independently operated named MCP hosts are required");
    }
    this.#requireUnique(hosts.map((host) => host.hostId), "host identities");
    this.#requireUnique(
      hosts.map((host) => host.productName.normalize("NFKC").toLowerCase()),
      "named host products"
    );
    this.#requireUnique(hosts.map((host) => host.operatorId), "host operators");
    this.#requireUnique(
      hosts.map((host) => host.operatorName.normalize("NFKC").toLowerCase()),
      "host operator names"
    );
    this.#requireUnique(hosts.map((host) => host.adapter.adapterId), "host adapters");
    this.#requireUnique(hosts.map((host) => host.adapter.authorityId), "adapter authorities");
    this.#requireUnique(hosts.map((host) => host.adapter.endpointOrigin), "adapter endpoints");

    const trajectoryDigests = new Set<string>();
    for (const host of hosts) {
      const hostWorkflows = workflows.filter((workflow) => workflow.hostId === host.hostId);
      if (!hostWorkflows.some((workflow) => workflow.workflowClass === "BENIGN") ||
        !hostWorkflows.some((workflow) => workflow.workflowClass === "ADVERSARIAL")) {
        throw new Error("Every named host requires benign and adversarial runtime evidence");
      }
      for (const workflow of hostWorkflows) {
        if (workflow.operatorId !== host.operatorId ||
          workflow.adapterId !== host.adapter.adapterId ||
          workflow.runtimeDigest !== runtimeDigest ||
          workflow.configurationDigest !== configurationDigest) {
          throw new Error("Named host workflow evidence binding does not match");
        }
        if (Date.parse(workflow.observedAt) < Date.parse(host.adapter.verifiedAt) ||
          Date.parse(workflow.observedAt) > Date.parse(validatedAt)) {
          throw new Error("Named host evidence chronology does not match");
        }
        if (trajectoryDigests.has(workflow.trajectoryDigest)) {
          throw new Error("Named host workflow trajectories must be unique");
        }
        trajectoryDigests.add(workflow.trajectoryDigest);
      }
    }
    const knownHostIds = new Set(hosts.map((host) => host.hostId));
    if (workflows.some((workflow) => !knownHostIds.has(workflow.hostId))) {
      throw new Error("Workflow evidence references an unknown named host");
    }

    const reportInput = {
      schemaVersion: "1.0.0" as const,
      reportId: identifierV1Schema.parse(input.reportId),
      validationScope: "EVIDENCE_CONTRACT_ONLY" as const,
      runtimeDigest,
      configurationDigest,
      hosts,
      workflows,
      validatedAt
    };
    return independentHostEvidenceReportV1Schema.parse({
      ...reportInput,
      reportDigest: computeCanonicalDigestV1(reportInput)
    });
  }

  #requireUnique(values: readonly string[], label: string): void {
    if (new Set(values).size !== values.length) {
      throw new Error(`Independent host evidence reuses ${label}`);
    }
  }
}
