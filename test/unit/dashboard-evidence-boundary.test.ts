import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { buildLocalEvidence } from "../../scripts/capture-local-evidence.mjs";
import {
  buildDashboardStatus,
  parseDashboardStatus,
  parseGatewayStatus,
  readBoundedJsonResponse
} from "../../scripts/dashboard-status.mjs";

const temporaryRoots: string[] = [];
const now = "2026-09-06T12:00:00.000Z";
const gatewayStatus = {
  startedAt: now,
  requestsReceived: 3,
  responses2xx: 1,
  responses4xxPlus: 2,
  downstreamToolsCalls: 0,
  forwardingEnabled: false,
  coverage: "UNPROTECTED",
  activity: [{
    time: now,
    kind: "MCP_REQUEST",
    outcome: "REJECT",
    detail: "Bearer secret-value appeared in an attacker-controlled request path"
  }]
};

async function dashboardFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "dashboard-boundary-"));
  temporaryRoots.push(root);
  await mkdir(path.join(root, "docs"));
  await writeFile(path.join(root, "docs", "featurelist.json"), JSON.stringify({
    features: [{ status: "complete" }, { status: "in_progress" }]
  }));
  await writeFile(path.join(root, "docs", "progress.md"), [
    "Latest: 21 unit files/214 tests and 9 integration files/44 tests.",
    "Historical: 3 unit files/20 tests and 1 integration files/5 tests."
  ].join("\n"));
  return buildDashboardStatus(root, { gatewayStatus });
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("dashboard and local-evidence boundaries", () => {
  it("uses the latest validation counts and sanitizes gateway activity detail", async () => {
    const dashboard = await dashboardFixture();
    expect(dashboard.validation.unit).toEqual({ files: 21, tests: 214 });
    expect(dashboard.validation.integration).toEqual({ files: 9, tests: 44 });
    expect(dashboard.gateway?.activity[0]?.detail).toBe(
      "A lifecycle request completed; downstream tools/call count remains zero."
    );
    expect(JSON.stringify(dashboard.gateway)).not.toContain("secret-value");
  });

  it("rejects unknown, unsafe-posture, and oversized gateway status values", () => {
    expect(() => parseGatewayStatus({ ...gatewayStatus, arguments: { token: "secret" } })).toThrow();
    expect(() => parseGatewayStatus({ ...gatewayStatus, downstreamToolsCalls: 1 })).toThrow();
    expect(() => parseGatewayStatus({
      ...gatewayStatus,
      activity: [{ ...gatewayStatus.activity[0], result: "arbitrary" }]
    })).toThrow();
    expect(() => parseGatewayStatus({
      ...gatewayStatus,
      activity: [{ ...gatewayStatus.activity[0], detail: "x".repeat(513) }]
    })).toThrow();
  });

  it("rejects unknown or substituted dashboard fields before evidence persistence", async () => {
    const dashboard = await dashboardFixture();
    expect(() => parseDashboardStatus({ ...dashboard, credentials: "secret" })).toThrow();
    const substituted = structuredClone(dashboard);
    const firstGate = substituted.releaseGates[0];
    if (firstGate === undefined) throw new Error("Dashboard fixture requires a release gate");
    firstGate.detail = "Bearer secret-value";
    expect(() => parseDashboardStatus(substituted)).toThrow();
    expect(() => buildLocalEvidence({
      gateway: { ...gatewayStatus, results: ["untrusted"] },
      dashboard,
      releaseManifest: {}
    })).toThrow();
  });

  it("persists only the allowlisted dashboard subset and sanitized gateway fields", async () => {
    const dashboard = await dashboardFixture();
    const evidence = buildLocalEvidence({
      gateway: gatewayStatus,
      dashboard,
      releaseManifest: { schemaVersion: "1.0.0" },
      capturedAt: now
    });
    expect(evidence.dashboard).toEqual({
      generatedAt: dashboard.generatedAt,
      coverage: dashboard.coverage,
      features: dashboard.features,
      validation: dashboard.validation,
      releaseGates: dashboard.releaseGates
    });
    expect(JSON.stringify(evidence)).not.toContain("secret-value");
    expect(evidence.gateway.activity[0]?.detail).toMatch(/^A lifecycle request completed/);
  });

  it("rejects status response bodies that exceed their byte budget", async () => {
    const declaredOversize = new Response("{}", { headers: { "content-length": "100" } });
    await expect(readBoundedJsonResponse(declaredOversize, 10)).rejects.toThrow(/exceeds/);
    const actualOversize = new Response(JSON.stringify({ value: "x".repeat(100) }));
    await expect(readBoundedJsonResponse(actualOversize, 10)).rejects.toThrow(/exceeds/);
  });
});
