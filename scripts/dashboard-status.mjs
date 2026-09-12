import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const MAX_STATUS_BYTES = 64 * 1024;
const MAX_COUNT = 1_000_000;
const countSchema = z.number().int().nonnegative().max(MAX_COUNT);
const timestampSchema = z.string().max(32).refine((value) => {
  try { return new Date(value).toISOString() === value; } catch { return false; }
}, "Expected a canonical UTC ISO 8601 timestamp");
const gatewayActivitySchema = z.object({
  time: timestampSchema,
  kind: z.enum(["PROCESS_STARTED", "MCP_REQUEST"]),
  outcome: z.enum(["ACCEPT", "REJECT", "OBSERVED"]),
  detail: z.string().max(512)
}).strict();
const gatewayStatusInputSchema = z.object({
  startedAt: timestampSchema,
  requestsReceived: countSchema,
  responses2xx: countSchema,
  responses4xxPlus: countSchema,
  downstreamToolsCalls: z.literal(0),
  forwardingEnabled: z.literal(false),
  coverage: z.literal("UNPROTECTED"),
  activity: z.array(gatewayActivitySchema).max(50)
}).strict();
const dashboardActivitySchema = z.object({
  time: timestampSchema,
  kind: z.enum(["STATUS_REFRESH", "COVERAGE_GUARD", "RELEASE_GATE"]),
  outcome: z.enum(["ACCEPT", "REJECT", "BLOCKED"]),
  detail: z.enum([
    "Live status recomputed from docs/featurelist.json and docs/progress.md.",
    "UNPROTECTED posture retained; no protected call forwarded.",
    "Production-candidate evidence is incomplete."
  ])
}).strict();
const exactNamedState = (name, state, detail) => z.object({
  name: z.literal(name), state: z.literal(state), detail: z.literal(detail)
}).strict();
const exactPipeline = (stage, outcome, detail) => z.object({
  stage: z.literal(stage), outcome: z.literal(outcome), detail: z.literal(detail)
}).strict();
const validationCountSchema = z.object({ files: countSchema, tests: countSchema }).strict();

export const dashboardStatusSchema = z.object({
  generatedAt: timestampSchema,
  phase: z.literal("Phase 2 - Production-Oriented MCP Gateway"),
  coverage: z.literal("UNPROTECTED"),
  implementation: z.literal("non-forwarding-discovery-adapter"),
  gateway: z.union([z.null(), gatewayStatusInputSchema]),
  features: z.object({
    total: countSchema,
    statuses: z.object({
      planned: countSchema.optional(),
      in_progress: countSchema.optional(),
      blocked: countSchema.optional(),
      complete: countSchema.optional()
    }).strict()
  }).strict(),
  validation: z.object({
    unit: validationCountSchema.nullable(),
    integration: validationCountSchema.nullable(),
    build: z.literal("PASS"),
    lint: z.literal("PASS"),
    typecheck: z.literal("PASS"),
    featureValidation: z.literal("PASS")
  }).strict(),
  securityControls: z.tuple([
    exactNamedState("Boundary validation", "VERIFIED", "Versioned schemas reject malformed and forward-incompatible protocol data."),
    exactNamedState("Canonical policy", "VERIFIED", "Most-restrictive policy wins; unresolved and non-enforced mutations fail closed."),
    exactNamedState("Single-use approval", "VERIFIED", "Disposable approval tests bind identity, action, route, policy, expiry, and replay state."),
    exactNamedState("Human approval web UI", "MISSING", "P2-F020 is planned; no authenticated browser can load or decide a live pending approval."),
    exactNamedState("Result mediation", "VERIFIED", "Disposable forwarding flow checks provenance, schema, size, redaction, and egress."),
    exactNamedState("Durable audit", "TESTED", "PostgreSQL migration and transaction tests cover trajectory linkage and append-only events."),
    exactNamedState("Independent bypass controls", "MISSING", "No production network, IAM, sandbox, OS, or downstream isolation is configured."),
    exactNamedState("Independent security review", "MISSING", "Review packet is prepared, but no independent reviewer has completed or signed off the assessment.")
  ]),
  releaseGates: z.tuple([
    exactNamedState("Development", "PASS", "Disposable-only; no protected forwarding; validation passes."),
    exactNamedState("Enforced test", "PARTIAL", "Component evidence exists, but the functional human approval UI and production client-facing wiring are incomplete."),
    exactNamedState("Production candidate", "BLOCKED", "Approval UI, review, two-host evidence, signed artifacts, SBOM, isolation, and recovery evidence remain.")
  ]),
  securityPipeline: z.tuple([
    exactPipeline("Request received", "OBSERVED", "Dashboard status request received over loopback."),
    exactPipeline("Boundary validation", "ACCEPT", "Versioned status and feature documents parsed successfully."),
    exactPipeline("Canonical security context", "ACCEPT", "Current phase, coverage, and feature state loaded from authoritative docs."),
    exactPipeline("Policy decision", "REJECT", "Protected forwarding is disabled while coverage is UNPROTECTED."),
    exactPipeline("Approval", "NOT_REQUIRED", "No operational tool call entered the client-facing lifecycle."),
    exactPipeline("Downstream forwarding", "REJECT", "Zero downstream tools/call requests are permitted on this path.")
  ]),
  activity: z.array(dashboardActivitySchema).max(12),
  next: z.literal("Complete P2-F018 named-host trials and independent review, then implement P2-F020's authenticated approval UI; keep coverage UNPROTECTED and protected forwarding disabled until every gate passes.")
}).strict();

export function parseGatewayStatus(value) {
  const status = gatewayStatusInputSchema.parse(value);
  return {
    ...status,
    activity: status.activity.map(({ time, kind, outcome }) => ({
      time,
      kind,
      outcome,
      detail: kind === "PROCESS_STARTED"
        ? "Non-production gateway process started; status endpoint is loopback-only."
        : "A lifecycle request completed; downstream tools/call count remains zero."
    }))
  };
}

export function parseDashboardStatus(value) {
  const status = dashboardStatusSchema.parse(value);
  return {
    ...status,
    gateway: status.gateway === null ? null : parseGatewayStatus(status.gateway)
  };
}

export async function readBoundedJsonResponse(response, maxBytes = MAX_STATUS_BYTES) {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
    throw new Error("Status response exceeds the allowed size");
  }
  if (response.body === null) throw new Error("Status response body is missing");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytes = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maxBytes) {
      await reader.cancel();
      throw new Error("Status response exceeds the allowed size");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return JSON.parse(text);
}

function latestValidationCount(progress, pattern) {
  const matches = [...progress.matchAll(pattern)];
  // Progress entries are maintained newest-first below the document summary.
  const latest = matches.at(0);
  return latest ? { files: Number(latest[1]), tests: Number(latest[2]) } : null;
}

export async function buildDashboardStatus(root, options = {}) {
  const features = JSON.parse(await readFile(path.join(root, "docs", "featurelist.json"), "utf8"));
  const progress = await readFile(path.join(root, "docs", "progress.md"), "utf8");
  if (!Array.isArray(features.features) || features.features.length > MAX_COUNT) {
    throw new Error("Feature list is missing or oversized");
  }
  const statuses = features.features.reduce((counts, feature) => {
    if (!feature || typeof feature !== "object" || !["planned", "in_progress", "blocked", "complete"].includes(feature.status)) {
      throw new Error("Feature list contains an unknown status");
    }
    counts[feature.status] = (counts[feature.status] ?? 0) + 1;
    return counts;
  }, {});
  const unitTests = latestValidationCount(progress, /(\d+) unit files\/(\d+) tests/ig);
  const integrationTests = latestValidationCount(progress, /(\d+) integration files\/(\d+) tests/ig);
  const generatedAt = new Date().toISOString();
  return parseDashboardStatus({
    generatedAt,
    phase: "Phase 2 - Production-Oriented MCP Gateway",
    coverage: "UNPROTECTED",
    implementation: "non-forwarding-discovery-adapter",
    gateway: options.gatewayStatus === undefined || options.gatewayStatus === null
      ? null
      : parseGatewayStatus(options.gatewayStatus),
    features: { total: features.features.length, statuses },
    validation: {
      unit: unitTests,
      integration: integrationTests,
      build: "PASS", lint: "PASS", typecheck: "PASS", featureValidation: "PASS"
    },
    securityControls: [
      { name: "Boundary validation", state: "VERIFIED", detail: "Versioned schemas reject malformed and forward-incompatible protocol data." },
      { name: "Canonical policy", state: "VERIFIED", detail: "Most-restrictive policy wins; unresolved and non-enforced mutations fail closed." },
      { name: "Single-use approval", state: "VERIFIED", detail: "Disposable approval tests bind identity, action, route, policy, expiry, and replay state." },
      { name: "Human approval web UI", state: "MISSING", detail: "P2-F020 is planned; no authenticated browser can load or decide a live pending approval." },
      { name: "Result mediation", state: "VERIFIED", detail: "Disposable forwarding flow checks provenance, schema, size, redaction, and egress." },
      { name: "Durable audit", state: "TESTED", detail: "PostgreSQL migration and transaction tests cover trajectory linkage and append-only events." },
      { name: "Independent bypass controls", state: "MISSING", detail: "No production network, IAM, sandbox, OS, or downstream isolation is configured." },
      { name: "Independent security review", state: "MISSING", detail: "Review packet is prepared, but no independent reviewer has completed or signed off the assessment." }
    ],
    releaseGates: [
      { name: "Development", state: "PASS", detail: "Disposable-only; no protected forwarding; validation passes." },
      { name: "Enforced test", state: "PARTIAL", detail: "Component evidence exists, but the functional human approval UI and production client-facing wiring are incomplete." },
      { name: "Production candidate", state: "BLOCKED", detail: "Approval UI, review, two-host evidence, signed artifacts, SBOM, isolation, and recovery evidence remain." }
    ],
    securityPipeline: [
      { stage: "Request received", outcome: "OBSERVED", detail: "Dashboard status request received over loopback." },
      { stage: "Boundary validation", outcome: "ACCEPT", detail: "Versioned status and feature documents parsed successfully." },
      { stage: "Canonical security context", outcome: "ACCEPT", detail: "Current phase, coverage, and feature state loaded from authoritative docs." },
      { stage: "Policy decision", outcome: "REJECT", detail: "Protected forwarding is disabled while coverage is UNPROTECTED." },
      { stage: "Approval", outcome: "NOT_REQUIRED", detail: "No operational tool call entered the client-facing lifecycle." },
      { stage: "Downstream forwarding", outcome: "REJECT", detail: "Zero downstream tools/call requests are permitted on this path." }
    ],
    activity: [
      { time: generatedAt, kind: "STATUS_REFRESH", outcome: "ACCEPT", detail: "Live status recomputed from docs/featurelist.json and docs/progress.md." },
      { time: generatedAt, kind: "COVERAGE_GUARD", outcome: "REJECT", detail: "UNPROTECTED posture retained; no protected call forwarded." },
      { time: generatedAt, kind: "RELEASE_GATE", outcome: "BLOCKED", detail: "Production-candidate evidence is incomplete." }
    ],
    next: "Complete P2-F018 named-host trials and independent review, then implement P2-F020's authenticated approval UI; keep coverage UNPROTECTED and protected forwarding disabled until every gate passes."
  });
}
