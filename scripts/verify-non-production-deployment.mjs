import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const image = "agent-security-gateway:non-production";
const container = `agent-security-gateway-smoke-${randomUUID()}`;

function docker(args, options = {}) {
  return execFileSync("docker", args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit"
  });
}

function waitForGateway() {
  const probe = [
    "const deadline = Date.now() + 15000;",
    "while (Date.now() < deadline) {",
    "  try {",
    "    const response = await fetch('http://127.0.0.1:4174/status', { headers: { Authorization: 'Bearer local-fixture' } });",
    "    if (response.ok) process.exit(0);",
    "  } catch {}",
    "  await new Promise((resolve) => setTimeout(resolve, 250));",
    "}",
    "throw new Error('gateway readiness deadline exceeded');"
  ].join("\n");
  docker(["exec", container, "node", "--input-type=module", "--eval", probe]);
}

function verifyIsolation() {
  const [inspection] = JSON.parse(docker(["inspect", container], { capture: true }));
  const host = inspection?.HostConfig;
  const user = inspection?.Config?.User;
  const capDrop = host?.CapDrop ?? [];
  const securityOpt = host?.SecurityOpt ?? [];
  const portBindings = host?.PortBindings ?? {};
  if (
    host?.NetworkMode !== "none" ||
    host?.ReadonlyRootfs !== true ||
    !capDrop.includes("ALL") ||
    !securityOpt.some((option) => option.startsWith("no-new-privileges")) ||
    Object.keys(portBindings).length !== 0 ||
    user === "" || user === "0" || user === "root"
  ) {
    throw new Error("Disposable deployment isolation does not match the required hardened profile");
  }
}

docker(["build", "--file", "Dockerfile.non-production", "--tag", image, "."]);
try {
  docker([
    "run",
    "--detach",
    "--name", container,
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    image
  ]);
  verifyIsolation();
  waitForGateway();
  docker(["exec", container, "node", "scripts/smoke-gateway.mjs"]);
  const status = JSON.parse(docker([
    "exec", container, "node", "--input-type=module", "--eval",
    "const response = await fetch('http://127.0.0.1:4174/status', { headers: { Authorization: 'Bearer local-fixture' } }); console.log(await response.text());"
  ], { capture: true }));
  if (status.coverage !== "UNPROTECTED" || status.forwardingEnabled !== false || status.downstreamToolsCalls !== 0) {
    throw new Error("Disposable deployment did not retain the required non-forwarding posture");
  }
  console.log(`Disposable deployment verified in ${container}: network=none, publishedPorts=0, coverage=${status.coverage}, downstreamToolsCalls=${status.downstreamToolsCalls}.`);
} finally {
  try {
    docker(["rm", "--force", container], { capture: true });
  } catch {
    // The exact disposable container may already have stopped or been removed.
  }
}
