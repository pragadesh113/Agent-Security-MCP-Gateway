import { createServer } from "node:http";

import { describe, expect, it } from "vitest";

import {
  MultiHostValidationHarnessV1,
  computeCanonicalDigestV1,
  type HostWorkflowObservationV1,
  type McpHostAdapterV1
} from "../../src/index.js";

function observation(hostId: string, adapterId: string, repetition: number): HostWorkflowObservationV1 {
  const compartment = (name: string) => computeCanonicalDigestV1({ hostId, adapterId, repetition, name });
  const base = {
    schemaVersion: "1.0.0" as const,
    hostId,
    hostAdapterId: adapterId,
    sessionId: `${hostId}-session-${String(repetition)}`,
    canonicalEffectDigest: computeCanonicalDigestV1({ effect: "READ", resource: "mcp://fixture/status" }),
    policyDecision: "REQUIRE_APPROVAL" as const,
    taskCompleted: true,
    policyViolation: false,
    approvalPresented: true,
    approvalError: false,
    latencyMs: adapterId === "adapter-header-v1" ? 4 : 6,
    compartmentDigests: {
      identity: compartment("identity"), route: compartment("route"), quota: compartment("quota"),
      approval: compartment("approval"), trust: compartment("trust"), result: compartment("result"),
      audit: compartment("audit")
    },
    bypassInventory: [
      { capabilityId: `${hostId}-native-shell`, kind: "NATIVE" as const, mechanism: "SHELL" as const,
        coverage: "UNPROTECTED" as const, gatewayProtected: false as const,
        reasonCodes: ["coverage.native.outside_gateway"] },
      { capabilityId: `${hostId}-direct-network`, kind: "DIRECT" as const, mechanism: "NETWORK" as const,
        coverage: "UNPROTECTED" as const, gatewayProtected: false as const,
        reasonCodes: ["coverage.direct.outside_gateway"] }
    ],
    coverage: "UNPROTECTED" as const
  };
  return { ...base, evidenceDigest: computeCanonicalDigestV1(base) };
}

function rehashObservation(input: HostWorkflowObservationV1): HostWorkflowObservationV1 {
  const { evidenceDigest: previousEvidenceDigest, ...evidence } = input;
  void previousEvidenceDigest;
  return { ...evidence, evidenceDigest: computeCanonicalDigestV1(evidence) };
}

describe("two-host concurrent validation", () => {
  it("runs equivalent MCP workflows through two distinct adapters with isolated state and metrics", async () => {
    let requests = 0;
    const peer = createServer((request, response) => {
      void (async () => {
        const chunks: string[] = [];
        request.setEncoding("utf8");
        for await (const chunk of request) chunks.push(String(chunk));
        const body = JSON.parse(chunks.join("")) as { method?: string; id?: number };
        if (body.method !== "initialize") {
          response.statusCode = 400;
          response.end();
          return;
        }
        requests += 1;
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id,
          result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "peer", version: "1" } } }));
      })();
    });
    await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
    const address = peer.address();
    if (address === null || typeof address === "string") throw new Error("Peer did not bind");
    const url = `http://127.0.0.1:${String(address.port)}/mcp`;
    const adapter = (hostId: string, hostAdapterId: string, headerName: string): McpHostAdapterV1 => ({
      hostId,
      hostAdapterId,
      run: async (repetition) => {
        const response = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", [headerName]: hostId },
          body: JSON.stringify({ jsonrpc: "2.0", id: repetition + 1, method: "initialize",
            params: { protocolVersion: "2025-06-18", capabilities: {},
              clientInfo: { name: hostId, version: "1.0.0" } } })
        });
        if (!response.ok) throw new Error("Disposable MCP initialization failed");
        await response.json();
        return observation(hostId, hostAdapterId, repetition);
      }
    });
    try {
      const report = await new MultiHostValidationHarnessV1().run({
        adapters: [
          adapter("host-alpha", "adapter-header-v1", "X-Host-Alpha"),
          adapter("host-beta", "adapter-client-info-v1", "X-Host-Beta")
        ],
        repetitions: 3
      });
      expect(requests).toBe(6);
      expect(report).toMatchObject({
        hostIds: ["host-alpha", "host-beta"],
        repetitions: 3,
        equivalentPolicyDecisions: true,
        isolatedCompartments: true
      });
      expect(report.hostMetrics).toEqual([
        expect.objectContaining({ hostId: "host-alpha", trials: 3, completionRate: 1,
          taskFailureRate: 0, policyViolationRate: 0, approvalRate: 1,
          meanLatencyMs: 4, enforcedCoverageRate: 0 }),
        expect.objectContaining({ hostId: "host-beta", trials: 3, completionRate: 1,
          taskFailureRate: 0, policyViolationRate: 0, approvalRate: 1,
          meanLatencyMs: 6, enforcedCoverageRate: 0 })
      ]);
      expect(report.observations.every((item) => item.bypassInventory.every((entry) =>
        entry.coverage === "UNPROTECTED"))).toBe(true);
      expect(report.observations[0]?.bypassInventory[0]).toMatchObject({ gatewayProtected: false });
    } finally {
      await new Promise<void>((resolve, reject) => peer.close((error) => {
        if (error === undefined) resolve();
        else reject(error);
      }));
    }
  });

  it("rejects colliding session compartments", async () => {
    const first = observation("host-first", "adapter-first", 0);
    const second = rehashObservation({ ...observation("host-second", "adapter-second", 0),
      compartmentDigests: first.compartmentDigests });
    await expect(new MultiHostValidationHarnessV1().run({
      adapters: [
        { hostId: first.hostId, hostAdapterId: first.hostAdapterId, run: () => first },
        { hostId: second.hostId, hostAdapterId: second.hostAdapterId, run: () => second }
      ],
      repetitions: 2
    })).rejects.toThrow(/collided/u);
  });
});
