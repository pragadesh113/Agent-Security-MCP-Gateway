import { describe, expect, it } from "vitest";

import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import {
  IndependentHostEvidenceGateV1,
  authenticatedHostAdapterEvidenceV1Schema,
  type IndependentHostWorkflowEvidenceV1,
  type NamedIndependentHostEvidenceV1
} from "../../src/evaluation/independent-host-evidence-v1.js";

const runtimeDigest = "a".repeat(64);
const configurationDigest = "b".repeat(64);

function host(index: number): NamedIndependentHostEvidenceV1 {
  const adapterInput = {
    schemaVersion: "1.0.0" as const,
    adapterId: `adapter-${String(index)}`,
    authenticationMethod: "MUTUAL_TLS" as const,
    authorityId: `independent-authority-${String(index)}`,
    credentialId: `host-credential-${String(index)}`,
    identityRevision: 1,
    endpointOrigin: `https://host-${String(index)}.independent.example`,
    verifiedAt: "2026-09-11T10:00:00.000Z"
  };
  const adapter = {
    ...adapterInput,
    evidenceDigest: computeCanonicalDigestV1(adapterInput)
  };
  const hostInput = {
    schemaVersion: "1.0.0" as const,
    hostId: `named-host-${String(index)}`,
    productName: `Independent MCP Host ${String(index)}`,
    productVersion: "1.0.0",
    operatorId: `operator-${String(index)}`,
    operatorName: `Independent Operator ${String(index)}`,
    adapter
  };
  return {
    ...hostInput,
    identityDigest: computeCanonicalDigestV1(hostInput)
  };
}

function workflow(
  hostEvidence: NamedIndependentHostEvidenceV1,
  workflowClass: "BENIGN" | "ADVERSARIAL"
): IndependentHostWorkflowEvidenceV1 {
  const input = {
    schemaVersion: "1.0.0" as const,
    hostId: hostEvidence.hostId,
    operatorId: hostEvidence.operatorId,
    adapterId: hostEvidence.adapter.adapterId,
    workflowClass,
    scenarioId: `${hostEvidence.hostId}-${workflowClass.toLowerCase()}`,
    throughOperationalRuntime: true as const,
    runtimeDigest,
    configurationDigest,
    trajectoryDigest: computeCanonicalDigestV1({ hostId: hostEvidence.hostId, workflowClass }),
    policyDecision: workflowClass === "BENIGN" ? "ALLOW" as const : "DENY" as const,
    attackAttempted: workflowClass === "ADVERSARIAL",
    attackSucceeded: false,
    policyViolation: false,
    taskCompleted: workflowClass === "BENIGN",
    observedAt: "2026-09-11T10:01:00.000Z"
  };
  return { ...input, evidenceDigest: computeCanonicalDigestV1(input) };
}

function validInput() {
  const hosts = [host(1), host(2)];
  return {
    reportId: "independent-host-evidence",
    runtimeDigest,
    configurationDigest,
    hosts,
    workflows: hosts.flatMap((item) => [workflow(item, "BENIGN"), workflow(item, "ADVERSARIAL")]),
    validatedAt: "2026-09-11T10:02:00.000Z"
  };
}

function rehashHost(input: NamedIndependentHostEvidenceV1): NamedIndependentHostEvidenceV1 {
  const { identityDigest: previousDigest, ...digestInput } = input;
  void previousDigest;
  return { ...digestInput, identityDigest: computeCanonicalDigestV1(digestInput) };
}

function rehashWorkflow(
  input: IndependentHostWorkflowEvidenceV1
): IndependentHostWorkflowEvidenceV1 {
  const { evidenceDigest: previousDigest, ...digestInput } = input;
  void previousDigest;
  return { ...digestInput, evidenceDigest: computeCanonicalDigestV1(digestInput) };
}

function at<T>(values: readonly T[], index: number): T {
  const value = values[index];
  if (value === undefined) throw new Error("Test fixture entry is missing");
  return value;
}

describe("independent named-host evidence gate", () => {
  it("accepts two named independent operators with benign and adversarial runtime evidence", () => {
    const report = new IndependentHostEvidenceGateV1().validate(validInput());
    expect(report.hosts).toHaveLength(2);
    expect(report.workflows).toHaveLength(4);
    expect(report.validationScope).toBe("EVIDENCE_CONTRACT_ONLY");
    const { reportDigest, ...digestInput } = report;
    expect(reportDigest).toBe(computeCanonicalDigestV1(digestInput));
  });

  it.each([
    ["operator", (input: ReturnType<typeof validInput>) => {
      input.hosts[1] = rehashHost({ ...at(input.hosts, 1), operatorId: at(input.hosts, 0).operatorId });
    }],
    ["authority", (input: ReturnType<typeof validInput>) => {
      const first = at(input.hosts, 0);
      const second = at(input.hosts, 1);
      const adapterInput = { ...second.adapter, authorityId: first.adapter.authorityId };
      const { evidenceDigest: previousDigest, ...adapterDigestInput } = adapterInput;
      void previousDigest;
      const adapter = { ...adapterDigestInput, evidenceDigest: computeCanonicalDigestV1(adapterDigestInput) };
      input.hosts[1] = rehashHost({ ...second, adapter });
    }],
    ["endpoint", (input: ReturnType<typeof validInput>) => {
      const first = at(input.hosts, 0);
      const second = at(input.hosts, 1);
      const adapterInput = { ...second.adapter, endpointOrigin: first.adapter.endpointOrigin };
      const { evidenceDigest: previousDigest, ...adapterDigestInput } = adapterInput;
      void previousDigest;
      const adapter = { ...adapterDigestInput, evidenceDigest: computeCanonicalDigestV1(adapterDigestInput) };
      input.hosts[1] = rehashHost({ ...second, adapter });
    }]
  ])("rejects reused independent %s identity", (_name, mutate) => {
    const input = validInput();
    mutate(input);
    expect(() => new IndependentHostEvidenceGateV1().validate(input)).toThrow(/reuses/u);
  });

  it("rejects missing workflow classes and substituted runtime or trajectory bindings", () => {
    const missing = validInput();
    missing.workflows = missing.workflows.filter((item) =>
      !(item.hostId === at(missing.hosts, 1).hostId && item.workflowClass === "ADVERSARIAL")
    );
    expect(() => new IndependentHostEvidenceGateV1().validate(missing)).toThrow(/benign and adversarial/u);

    const substituted = validInput();
    substituted.workflows[0] = rehashWorkflow({
      ...at(substituted.workflows, 0),
      runtimeDigest: "c".repeat(64)
    });
    expect(() => new IndependentHostEvidenceGateV1().validate(substituted)).toThrow(/binding/u);

    const collision = validInput();
    collision.workflows[1] = rehashWorkflow({
      ...at(collision.workflows, 1),
      trajectoryDigest: at(collision.workflows, 0).trajectoryDigest
    });
    expect(() => new IndependentHostEvidenceGateV1().validate(collision)).toThrow(/unique/u);
  });

  it("rejects digest substitution and unknown-host evidence", () => {
    const digestSubstitution = validInput();
    digestSubstitution.workflows[0] = {
      ...at(digestSubstitution.workflows, 0),
      taskCompleted: false
    };
    expect(() => new IndependentHostEvidenceGateV1().validate(digestSubstitution))
      .toThrow(/digest/u);

    const unknown = validInput();
    unknown.workflows.push(rehashWorkflow({
      ...at(unknown.workflows, 0),
      hostId: "unregistered-host",
      operatorId: "unregistered-operator",
      adapterId: "unregistered-adapter",
      trajectoryDigest: "d".repeat(64)
    }));
    expect(() => new IndependentHostEvidenceGateV1().validate(unknown)).toThrow(/unknown/u);
  });

  it("accepts protected HTTPS loopback but rejects TEST_FIXTURE, plaintext, userinfo, and malformed evidence", () => {
    const base = host(1).adapter;
    expect(authenticatedHostAdapterEvidenceV1Schema.safeParse({
      ...base,
      authenticationMethod: "TEST_FIXTURE"
    }).success).toBe(false);
    const loopbackInput = {
      ...base,
      endpointOrigin: "https://127.0.0.1:4174"
    };
    const { evidenceDigest: previousDigest, ...loopbackDigestInput } = loopbackInput;
    void previousDigest;
    expect(authenticatedHostAdapterEvidenceV1Schema.safeParse({
      ...loopbackDigestInput,
      evidenceDigest: computeCanonicalDigestV1(loopbackDigestInput)
    }).success).toBe(true);

    for (const endpointOrigin of ["http://127.0.0.1:4174", "https://user@host.example"]) {
      const endpointInput = { ...base, endpointOrigin };
      const { evidenceDigest: priorDigest, ...endpointDigestInput } = endpointInput;
      void priorDigest;
      expect(authenticatedHostAdapterEvidenceV1Schema.safeParse({
        ...endpointDigestInput,
        evidenceDigest: computeCanonicalDigestV1(endpointDigestInput)
      }).success).toBe(false);
    }
    expect(authenticatedHostAdapterEvidenceV1Schema.safeParse({
      ...base,
      untrustedClaim: true
    }).success).toBe(false);
  });
});
