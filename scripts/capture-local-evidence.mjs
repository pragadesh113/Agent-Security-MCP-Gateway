import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  parseDashboardStatus,
  parseGatewayStatus,
  readBoundedJsonResponse
} from "./dashboard-status.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function fetchJson(url, maxBytes) {
  const response = await fetch(url, {
    headers: { Accept: "application/json", Authorization: "Bearer local-fixture" }
  });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  return readBoundedJsonResponse(response, maxBytes);
}

export function buildLocalEvidence({ gateway, dashboard, releaseManifest, capturedAt = new Date().toISOString() }) {
  const safeGateway = parseGatewayStatus(gateway);
  const safeDashboard = parseDashboardStatus(dashboard);
  if (capturedAt.length > 32 || new Date(capturedAt).toISOString() !== capturedAt) {
    throw new Error("Evidence capture timestamp must be canonical UTC ISO 8601");
  }
  return {
    schemaVersion: "1.0.0",
    capturedAt,
    scope: "DISPOSABLE_LOCAL_ONLY",
    gateway: safeGateway,
    dashboard: {
      generatedAt: safeDashboard.generatedAt,
      coverage: safeDashboard.coverage,
      features: safeDashboard.features,
      validation: safeDashboard.validation,
      releaseGates: safeDashboard.releaseGates
    },
    releaseManifest
  };
}

export async function captureLocalEvidence() {
  const npm = process.platform === "win32" ? process.env.ComSpec : "npm";
  execFileSync(npm, process.platform === "win32"
    ? ["/d", "/s", "/c", "npm run release:verify"]
    : ["run", "release:verify"], { cwd: root, stdio: "inherit" });
  const [gateway, dashboard, manifest] = await Promise.all([
    fetchJson("http://127.0.0.1:4174/status", 64 * 1024),
    fetchJson("http://127.0.0.1:4173/api/status", 128 * 1024),
    readFile(path.join(root, "artifacts", "release-manifest.json"), "utf8").then(JSON.parse)
  ]);
  const evidence = buildLocalEvidence({ gateway, dashboard, releaseManifest: manifest });
  await mkdir(path.join(root, "artifacts"), { recursive: true });
  const output = path.join(root, "artifacts", "local-evidence.json");
  await writeFile(output, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  console.log(`Local evidence captured at ${path.relative(root, output)}.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await captureLocalEvidence();
}
