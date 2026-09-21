import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const MAX_STDOUT_BYTES = 2 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 60_000;

function sanitizedEnvironment() {
  const allowed = [
    "APPDATA", "ComSpec", "LOCALAPPDATA", "PATH", "PATHEXT", "SystemRoot",
    "TEMP", "TMP", "USERPROFILE"
  ];
  return Object.fromEntries(allowed.flatMap((name) => {
    const value = process.env[name];
    return value === undefined ? [] : [[name, value]];
  }));
}

class StdioMcpClient {
  #child;
  #nextId = 1;
  #pending = new Map();
  #stderr = "";
  #stdoutBuffer = "";
  #stdoutBytes = 0;

  constructor(command, args) {
    const safeCommandToken = (value) => {
      if (!/^[A-Za-z0-9@._:/=+,-]+$/u.test(value)) {
        throw new Error("Unsafe MCP verifier command token");
      }
      return value;
    };
    const executable = process.platform === "win32" ? process.env.ComSpec : command;
    if (!executable) throw new Error("Windows command processor is unavailable");
    const spawnArgs = process.platform === "win32"
      ? ["/d", "/s", "/c", [command, ...args].map(safeCommandToken).join(" ")]
      : args;
    this.#child = spawn(executable, spawnArgs, {
      cwd: process.cwd(),
      env: sanitizedEnvironment(),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    this.#child.stdout.setEncoding("utf8");
    this.#child.stderr.setEncoding("utf8");
    this.#child.stdout.on("data", (chunk) => this.#onStdout(chunk));
    this.#child.stderr.on("data", (chunk) => {
      if (this.#stderr.length < MAX_STDERR_BYTES) {
        this.#stderr += chunk.slice(0, MAX_STDERR_BYTES - this.#stderr.length);
      }
    });
    this.#child.once("error", (error) => this.#rejectAll(error));
    this.#child.once("exit", (code, signal) => {
      this.#rejectAll(new Error(
        `MCP server exited before shutdown (code=${String(code)}, signal=${String(signal)}): ${this.#stderr}`
      ));
    });
  }

  #onStdout(chunk) {
    this.#stdoutBytes += Buffer.byteLength(chunk);
    if (this.#stdoutBytes > MAX_STDOUT_BYTES) {
      this.#rejectAll(new Error("MCP server stdout exceeded the verification limit"));
      this.#child.kill();
      return;
    }
    this.#stdoutBuffer += chunk;
    while (true) {
      const newline = this.#stdoutBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.#stdoutBuffer.slice(0, newline).trim();
      this.#stdoutBuffer = this.#stdoutBuffer.slice(newline + 1);
      if (line === "") continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        this.#rejectAll(new Error("MCP server emitted non-JSON stdout"));
        this.#child.kill();
        return;
      }
      if (message?.method && message.id !== undefined) {
        const response = message.method === "ping"
          ? { jsonrpc: "2.0", id: message.id, result: {} }
          : { jsonrpc: "2.0", id: message.id,
              error: { code: -32601, message: "Client capability unavailable in smoke verifier" } };
        this.#write(response);
        continue;
      }
      if (message?.id === undefined) continue;
      const pending = this.#pending.get(String(message.id));
      if (pending === undefined) continue;
      clearTimeout(pending.timeout);
      this.#pending.delete(String(message.id));
      if (message.error !== undefined) pending.reject(Object.assign(
        new Error(`MCP error ${String(message.error.code)}: ${String(message.error.message)}`),
        { mcpError: message.error }
      ));
      else pending.resolve(message.result);
    }
  }

  #write(message) {
    if (!this.#child.stdin.writable) throw new Error("MCP server stdin is unavailable");
    this.#child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  #rejectAll(error) {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.#pending.clear();
  }

  request(method, params = {}) {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.#pending.delete(String(id));
        reject(new Error(`Timed out waiting for MCP ${method}: ${this.#stderr}`));
      }, REQUEST_TIMEOUT_MS);
      this.#pending.set(String(id), { resolve, reject, timeout });
      this.#write({ jsonrpc: "2.0", id, method, params });
    });
  }

  notify(method, params = {}) {
    this.#write({ jsonrpc: "2.0", method, params });
  }

  async close() {
    if (this.#child.exitCode !== null) return;
    this.#child.stdin.end();
    await Promise.race([
      new Promise((resolve) => this.#child.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 2_000))
    ]);
    if (this.#child.exitCode === null) this.#child.kill();
  }
}

async function verifyServer(spec) {
  const client = new StdioMcpClient("npx", ["--yes", `${spec.package}@${spec.version}`, ...spec.args]);
  try {
    const initialized = await client.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "agent-security-open-source-verifier", version: "1.0.0" }
    });
    if (!initialized?.serverInfo?.name || !initialized?.protocolVersion) {
      throw new Error(`${spec.name} returned an incomplete initialize result`);
    }
    client.notify("notifications/initialized");
    const listed = await client.request("tools/list");
    if (!Array.isArray(listed?.tools) || !listed.tools.some((tool) => tool?.name === spec.safeTool)) {
      throw new Error(`${spec.name} did not advertise ${spec.safeTool}`);
    }
    const safeResult = await client.request("tools/call", {
      name: spec.safeTool,
      arguments: spec.safeArguments
    });
    if (safeResult?.isError === true || !Array.isArray(safeResult?.content)) {
      throw new Error(`${spec.name} harmless tool call failed`);
    }
    let unknownToolRejected = false;
    try {
      const unknown = await client.request("tools/call", {
        name: "agent_security_unknown_tool",
        arguments: {}
      });
      unknownToolRejected = unknown?.isError === true;
    } catch (error) {
      unknownToolRejected = error?.mcpError !== undefined;
    }
    if (!unknownToolRejected) throw new Error(`${spec.name} accepted an unknown tool`);
    return {
      name: spec.name,
      package: spec.package,
      version: spec.version,
      integrity: spec.integrity,
      license: spec.license,
      sourceRepository: spec.sourceRepository,
      protocolVersion: initialized.protocolVersion,
      serverInfo: initialized.serverInfo,
      advertisedToolCount: listed.tools.length,
      harmlessTool: spec.safeTool,
      harmlessToolCompleted: true,
      unknownToolRejected: true
    };
  } finally {
    await client.close();
  }
}

const pageServer = createServer((_request, response) => {
  response.setHeader("Content-Type", "text/html; charset=utf-8");
  response.end("<!doctype html><title>Agent Security MCP Smoke</title><h1>Disposable page</h1>");
});
await new Promise((resolve, reject) => {
  pageServer.once("error", reject);
  pageServer.listen(0, "127.0.0.1", resolve);
});
const address = pageServer.address();
if (address === null || typeof address === "string") throw new Error("Disposable page server did not bind");
const pageOrigin = `http://127.0.0.1:${String(address.port)}`;
const playwrightOutputDirectory = await mkdtemp(
  path.join(path.resolve(tmpdir()), "agent-security-playwright-mcp-")
);
const playwrightOutputArgument = playwrightOutputDirectory.replaceAll("\\", "/");

try {
  const servers = [];
  servers.push(await verifyServer({
    name: "Everything MCP Server",
    package: "@modelcontextprotocol/server-everything",
    version: "2026.8.31",
    integrity: "sha512-5U3OZh8Xq0Li4nA26l6uNvV9/1suMDuWSn+NjLZIhzinhMY6N3A4DCrxVecBGPf2PsNFKTEv5krxGPRwzxc7jQ==",
    license: "MIT",
    sourceRepository: "https://github.com/modelcontextprotocol/servers",
    args: ["stdio"],
    safeTool: "get-sum",
    safeArguments: { a: 19, b: 23 }
  }));
  servers.push(await verifyServer({
    name: "Microsoft Playwright MCP",
    package: "@playwright/mcp",
    version: "0.0.81",
    integrity: "sha512-c4eVex1nS53IzLHlwAm0J9ZISDTvA7RndFX8oVcQOrmvIrKSkByazpq79lZHWJuWTB7Gpk0sLBQoRepyIgmneA==",
    license: "Apache-2.0",
    sourceRepository: "https://github.com/microsoft/playwright-mcp",
    args: ["--headless", "--isolated", "--browser", "chrome", "--no-sandbox",
      `--allowed-origins=${pageOrigin}`, `--output-dir=${playwrightOutputArgument}`],
    safeTool: "browser_navigate",
    safeArguments: { url: pageOrigin }
  }));
  const material = {
    schemaVersion: "1.0.0",
    evidenceScope: "LOCAL_INTEROPERABILITY_ONLY",
    independentlyOperated: false,
    coverage: "UNPROTECTED",
    generatedAt: new Date().toISOString(),
    servers
  };
  const evidence = {
    ...material,
    evidenceDigest: createHash("sha256").update(JSON.stringify(material)).digest("hex")
  };
  const artifactDirectory = path.join(process.cwd(), "artifacts");
  await mkdir(artifactDirectory, { recursive: true });
  const outputPath = path.join(artifactDirectory, "open-source-mcp-smoke.json");
  await writeFile(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  console.log(JSON.stringify({ outputPath, evidenceScope: evidence.evidenceScope,
    independentlyOperated: evidence.independentlyOperated,
    servers: servers.map(({ name, version, advertisedToolCount, harmlessToolCompleted,
      unknownToolRejected }) => ({ name, version, advertisedToolCount,
      harmlessToolCompleted, unknownToolRejected })) }));
} finally {
  await new Promise((resolve, reject) => pageServer.close((error) => error ? reject(error) : resolve()));
  if (path.dirname(playwrightOutputDirectory) !== path.resolve(tmpdir())) {
    throw new Error("Refusing to remove an unexpected Playwright output directory");
  }
  await rm(playwrightOutputDirectory, { recursive: true, force: true });
}
