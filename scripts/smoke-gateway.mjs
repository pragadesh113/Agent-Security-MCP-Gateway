const configuredUrl = new URL(process.env.GATEWAY_URL ?? "http://127.0.0.1:4174");
const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
if (!(configuredUrl.protocol === "http:" || configuredUrl.protocol === "https:") || !loopbackHosts.has(configuredUrl.hostname)) {
  throw new Error("Gateway smoke tests may target loopback HTTP(S) only");
}
const baseUrl = configuredUrl.origin;
const headers = {
  Authorization: "Bearer local-fixture",
  Origin: baseUrl,
  Accept: "application/json, text/event-stream",
  "Content-Type": "application/json"
};

async function post(body, extraHeaders = {}) {
  const response = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { ...headers, ...extraHeaders },
    body: JSON.stringify(body)
  });
  const raw = await response.text();
  return { response, body: raw.length === 0 ? {} : JSON.parse(raw) };
}

const unauthorized = await fetch(`${baseUrl}/mcp`, {
  method: "POST",
  headers: { ...headers, Authorization: "Bearer invalid" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "ping", params: {} })
});
if (unauthorized.status !== 401) throw new Error(`Expected invalid credentials to return 401, got ${unauthorized.status}`);

const initialize = await post({
  jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "gateway-smoke", version: "1.0.0" } }
});
if (initialize.response.status !== 200 || initialize.body.result?.protocolVersion !== "2025-06-18") {
  throw new Error(`Initialize did not negotiate the pinned protocol: HTTP ${initialize.response.status}`);
}
if (initialize.body.result?.capabilities?.tools?.listChanged !== false) {
  throw new Error("Initialize did not advertise the configured registry-backed discovery capability");
}
const sessionId = initialize.response.headers.get("mcp-session-id");
if (sessionId === null) throw new Error("Initialize did not issue an MCP session identifier");
const sessionHeaders = { "Mcp-Session-Id": sessionId, "Mcp-Protocol-Version": "2025-06-18" };

const initialized = await post({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }, sessionHeaders);
if (initialized.response.status !== 202) throw new Error(`Initialized notification was not accepted: HTTP ${initialized.response.status}`);

const toolList = await post({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, sessionHeaders);
if (toolList.response.status !== 200 || !Array.isArray(toolList.body.result?.tools) || toolList.body.result.tools.length !== 0) {
  throw new Error("Registry-backed tools/list did not return the expected empty configured scope");
}

const toolCall = await post({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "smoke-tool", arguments: {} } }, sessionHeaders);
if (toolCall.response.status !== 200 || toolCall.body.error?.data?.coverage !== "UNPROTECTED") {
  throw new Error("Operational tools/call was not rejected by the non-forwarding guard");
}

const statusResponse = await fetch(`${baseUrl}/status`, { headers });
const status = await statusResponse.json();
if (statusResponse.status !== 200 || status.coverage !== "UNPROTECTED" || status.forwardingEnabled !== false || status.downstreamToolsCalls !== 0) {
  throw new Error("Gateway telemetry does not prove the expected non-forwarding posture");
}
console.log(`Gateway smoke passed: unauthorized=401, initialize=200, initialized=202, tools/list=${toolList.response.status}, tools/call=${toolCall.response.status}, downstreamToolsCalls=${status.downstreamToolsCalls}.`);
