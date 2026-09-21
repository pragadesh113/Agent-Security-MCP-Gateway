import { readFile } from "node:fs/promises";
import { createServer } from "node:https";
import { isAbsolute, resolve } from "node:path";
import { TLSSocket } from "node:tls";
import { pathToFileURL } from "node:url";

import {
  ApprovalWebRuntimeBridgeV1,
  ClientApprovedCallExecutorV1,
  PostgresApprovalUiStoreV1,
  PostgresTrajectoryStoreV1,
  createApprovalWebAppV1
} from "../dist/src/index.js";

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Required protected approval UI configuration is missing: ${name}`);
  return value;
}

function configuredPositiveInteger(name, fallback, maximum) {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be a positive integer no greater than ${String(maximum)}`);
  }
  return value;
}

const host = process.env.APPROVAL_UI_HOST?.trim() || "127.0.0.1";
const port = Number(process.env.APPROVAL_UI_PORT ?? 4175);
const identityRevision = Number(requiredEnvironment("APPROVAL_UI_HUMAN_IDENTITY_REVISION"));
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error("APPROVAL_UI_PORT must be an integer from 1 through 65535");
}
if (!Number.isSafeInteger(identityRevision) || identityRevision < 1) {
  throw new Error("APPROVAL_UI_HUMAN_IDENTITY_REVISION must be a positive integer");
}

const origin = requiredEnvironment("APPROVAL_UI_ORIGIN");
const humanId = requiredEnvironment("APPROVAL_UI_HUMAN_ID");
const runtimeModulePath = requiredEnvironment("APPROVAL_UI_RUNTIME_MODULE");
if (!isAbsolute(runtimeModulePath)) {
  throw new Error("APPROVAL_UI_RUNTIME_MODULE must be an absolute trusted local module path");
}
const runtimeEncryptionKey = Buffer.from(
  requiredEnvironment("APPROVAL_UI_RUNTIME_KEY_BASE64"),
  "base64"
);
if (runtimeEncryptionKey.byteLength !== 32) {
  runtimeEncryptionKey.fill(0);
  throw new Error("APPROVAL_UI_RUNTIME_KEY_BASE64 must decode to exactly 32 bytes");
}
const runtimeEncryptionKeyId = requiredEnvironment("APPROVAL_UI_RUNTIME_KEY_ID");
const runtimeModule = await import(pathToFileURL(runtimeModulePath).href);
if (typeof runtimeModule.createProtectedApprovalRuntimeDependenciesV1 !== "function") {
  runtimeEncryptionKey.fill(0);
  throw new Error(
    "APPROVAL_UI_RUNTIME_MODULE must export createProtectedApprovalRuntimeDependenciesV1"
  );
}
const [certificate, privateKey, clientCertificateAuthority, indexHtml, appCss, appJavaScript] =
  await Promise.all([
    readFile(requiredEnvironment("APPROVAL_UI_TLS_CERT_FILE")),
    readFile(requiredEnvironment("APPROVAL_UI_TLS_KEY_FILE")),
    readFile(requiredEnvironment("APPROVAL_UI_CLIENT_CA_FILE")),
    readFile(resolve(process.cwd(), "approval-ui", "index.html")),
    readFile(resolve(process.cwd(), "approval-ui", "app.css")),
    readFile(resolve(process.cwd(), "approval-ui", "app.js"))
  ]);

const databaseUrl = requiredEnvironment("DATABASE_URL");
const store = await PostgresApprovalUiStoreV1.connect({
  connectionString: databaseUrl,
  expectedOrigin: origin,
  administratorAuthorizer: () => false
});
const trajectoryStore = await PostgresTrajectoryStoreV1.connect({
  connectionString: databaseUrl,
  approvalRuntimePayloadEncryption: {
    keyId: runtimeEncryptionKeyId,
    key: runtimeEncryptionKey
  }
});
runtimeEncryptionKey.fill(0);
const runtimeDependencies = await runtimeModule.createProtectedApprovalRuntimeDependenciesV1({
  trajectoryStore
});
if (runtimeDependencies === null || typeof runtimeDependencies !== "object" ||
  typeof runtimeDependencies.issueCredentialLease !== "function" ||
  typeof runtimeDependencies.forwarder?.execute !== "function") {
  await Promise.all([store.close(), trajectoryStore.close()]);
  throw new Error("Protected approval runtime dependencies are incomplete");
}
const executionTimeoutMs = runtimeDependencies.executionTimeoutMs ?? 120_000;
if (!Number.isSafeInteger(executionTimeoutMs) || executionTimeoutMs < 1 ||
  executionTimeoutMs > 5 * 60_000) {
  await Promise.all([store.close(), trajectoryStore.close()]);
  throw new Error("Protected approval execution timeout must be from 1 through 300000 milliseconds");
}
const dispatchRecoveryIntervalMs = configuredPositiveInteger(
  "APPROVAL_UI_DISPATCH_RECOVERY_INTERVAL_MS",
  10_000,
  60_000
);
const dispatchClaimTimeoutMs = configuredPositiveInteger(
  "APPROVAL_UI_DISPATCH_CLAIM_TIMEOUT_MS",
  executionTimeoutMs + 30_000,
  6 * 60_000
);
if (dispatchClaimTimeoutMs <= executionTimeoutMs) {
  await Promise.all([store.close(), trajectoryStore.close()]);
  throw new Error("APPROVAL_UI_DISPATCH_CLAIM_TIMEOUT_MS must exceed the execution timeout");
}
const executor = new ClientApprovedCallExecutorV1({
  loadApprovedCall: (input) => trajectoryStore.loadApprovedCall(input),
  store: trajectoryStore,
  issueCredentialLease: runtimeDependencies.issueCredentialLease,
  forwarder: runtimeDependencies.forwarder,
  executionTimeoutMs
});
const runtimeBridge = new ApprovalWebRuntimeBridgeV1({
  sessions: trajectoryStore,
  executor,
  dispatches: trajectoryStore
});
const assets = new Map([
  ["/index.html", { contentType: "text/html; charset=utf-8", body: indexHtml }],
  ["/assets/app.css", { contentType: "text/css; charset=utf-8", body: appCss }],
  ["/assets/app.js", { contentType: "application/javascript; charset=utf-8", body: appJavaScript }]
]);
const app = createApprovalWebAppV1({
  origin,
  store: store.asApprovalWebStore(),
  executeApprovedCall: (input) => runtimeBridge.executeApprovedCall(input),
  readStaticAsset: (path) => assets.get(path) ?? null,
  authenticateHuman: (request) => {
    const socket = request.socket instanceof TLSSocket ? request.socket : null;
    const peer = socket?.getPeerCertificate();
    const fingerprint = typeof peer?.fingerprint256 === "string"
      ? peer.fingerprint256.replaceAll(":", "").toLowerCase()
      : "";
    if (socket?.authorized !== true || !/^[a-f0-9]{64}$/u.test(fingerprint)) return null;
    return {
      schemaVersion: "1.0.0",
      humanId,
      authenticationMethod: "MUTUAL_TLS",
      credentialId: `sha256:${fingerprint}`,
      identityRevision,
      authenticatedAt: new Date().toISOString()
    };
  }
});
const server = createServer({
  cert: certificate,
  key: privateKey,
  ca: clientCertificateAuthority,
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: "TLSv1.2"
}, app);

let recoveryRunning = false;
async function recoverApprovalDispatches() {
  if (recoveryRunning) return;
  recoveryRunning = true;
  const recoveredAt = new Date();
  try {
    await trajectoryStore.recoverStaleApprovalDispatches({
      staleBefore: new Date(recoveredAt.getTime() - dispatchClaimTimeoutMs).toISOString(),
      recoveredAt: recoveredAt.toISOString()
    });
  } finally {
    recoveryRunning = false;
  }
}

await recoverApprovalDispatches();
const recoveryTimer = setInterval(() => {
  void recoverApprovalDispatches().catch(() => {
    console.error("Protected approval dispatch recovery failed closed");
  });
}, dispatchRecoveryIntervalMs);
recoveryTimer.unref();

server.listen(port, host, () => {
  console.log(`Protected mutual-TLS approval UI listening at ${origin}/approval/`);
  console.log("Human and agent authority are resolved from PostgreSQL; coverage remains UNPROTECTED.");
});

let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  clearInterval(recoveryTimer);
  await new Promise((resolveClose) => server.close(resolveClose));
  await Promise.all([store.close(), trajectoryStore.close()]);
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    void close().then(() => process.exit(0), () => process.exit(1));
  });
}
