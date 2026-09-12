import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildDashboardStatus,
  parseDashboardStatus,
  parseGatewayStatus,
  readBoundedJsonResponse
} from "./dashboard-status.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dashboardDir = path.join(root, "dashboard");
const port = Number(process.env.DASHBOARD_PORT ?? 4173);

async function readGatewayStatus() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 500);
    const response = await fetch("http://127.0.0.1:4174/status", {
      signal: controller.signal,
      headers: { Accept: "application/json", Authorization: "Bearer local-fixture" }
    });
    clearTimeout(timeout);
    return response.ok ? parseGatewayStatus(await readBoundedJsonResponse(response)) : null;
  } catch {
    return null;
  }
}

const server = createServer(async (request, response) => {
  try {
    if (request.url === "/api/status") {
      response.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
      const status = parseDashboardStatus(
        await buildDashboardStatus(root, { gatewayStatus: await readGatewayStatus() })
      );
      response.end(JSON.stringify(status));
      return;
    }
    if (request.url === "/" || request.url === "/index.html") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end(await readFile(path.join(dashboardDir, "index.html")));
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found");
  } catch {
    response.writeHead(500, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    response.end(JSON.stringify({ error: "dashboard status unavailable" }));
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Live dashboard listening at http://127.0.0.1:${port}`);
});

process.on("SIGINT", () => server.close(() => process.exit(0)));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
