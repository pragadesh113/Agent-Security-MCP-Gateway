import { createServer } from "node:http";
import { isIP } from "node:net";
import { createInitializationHttpAppV1 } from "../dist/src/transport/streamable-http-initialization-v1.js";
import { DisposableDownstreamRegistryV1 } from "../dist/src/routing/downstream-registry-v1.js";

const port = Number(process.env.GATEWAY_PORT ?? 4174);
const host = process.env.GATEWAY_HOST ?? "127.0.0.1";
const startedAt = new Date().toISOString();
const telemetry = {
  requestsReceived: 0,
  responses2xx: 0,
  responses4xxPlus: 0,
  downstreamToolsCalls: 0,
  forwardingEnabled: false,
  coverage: "UNPROTECTED",
  activity: []
};
const recordActivity = (kind, outcome, detail) => {
  telemetry.activity.unshift({ time: new Date().toISOString(), kind, outcome, detail });
  telemetry.activity.length = Math.min(telemetry.activity.length, 50);
};
const isLoopbackAddress = (address) => {
  const normalized = address?.startsWith("::ffff:") ? address.slice(7) : address;
  return normalized === "::1" || (isIP(normalized ?? "") === 4 && normalized.startsWith("127."));
};
const safePath = (url) => {
  try {
    return new URL(url ?? "/", "http://127.0.0.1").pathname;
  } catch {
    return "/invalid";
  }
};
const fixturePrincipal = {
  schemaVersion: "1.0.0",
  userId: "local-user",
  agentId: "local-agent",
  clientId: "local-client",
  host: { hostId: "local-host", name: "Non-production local host", version: "0.1.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "local-fixture-credential",
    identityRevision: 1,
    authenticatedAt: new Date().toISOString()
  }
};

const registry = new DisposableDownstreamRegistryV1({
  administratorAuthorizer: () => false,
  downstreamAuthenticator: () => undefined,
  routeAuthorizer: () => true
});
const app = createInitializationHttpAppV1({
  clientAuthenticator: (attempt) => attempt.authorizationHeader === "Bearer local-fixture"
    ? fixturePrincipal
    : undefined,
  discovery: {
    provider: ({ requestId, session }) => registry.discover({
      requestId,
      session,
      policyScopeId: "scope-local-non-production",
      environment: "TEST"
    })
  }
});
const server = createServer((request, response) => {
  if (request.method === "GET" && request.url === "/status") {
    if (!isLoopbackAddress(request.socket.remoteAddress) ||
      request.headers.authorization !== "Bearer local-fixture") {
      response.writeHead(403, { "content-type": "application/json; charset=utf-8" });
      response.end(JSON.stringify({ error: "authenticated loopback telemetry is required" }));
      return;
    }
    response.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    response.end(JSON.stringify({ startedAt, ...telemetry, activity: telemetry.activity }));
    return;
  }
  telemetry.requestsReceived += 1;
  response.once("finish", () => {
    if (response.statusCode >= 200 && response.statusCode < 300) telemetry.responses2xx += 1;
    else telemetry.responses4xxPlus += 1;
    recordActivity(
      "MCP_REQUEST",
      response.statusCode >= 400 ? "REJECT" : "OBSERVED",
      `Lifecycle request ${request.method ?? "UNKNOWN"} ${safePath(request.url)} completed with HTTP ${response.statusCode}; downstream tools/call count remains zero.`
    );
  });
  app(request, response);
});
server.listen(port, host, () => {
  console.log(`Non-production gateway listening at http://${host}:${port}/mcp`);
  console.log("Authentication: Bearer local-fixture; registry-backed discovery: enabled; protected forwarding: disabled; coverage: UNPROTECTED");
  recordActivity("PROCESS_STARTED", "ACCEPT", `Non-production process started on ${host}:${port}; status endpoint is loopback-only.`);
});
const close = () => server.close(() => process.exit(0));
process.on("SIGINT", close);
process.on("SIGTERM", close);
