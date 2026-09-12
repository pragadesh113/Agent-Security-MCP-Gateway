import { readFile } from "node:fs/promises";
import { createServer } from "node:https";

import { ProtectedClientIdentityProviderV1 } from "../dist/src/identity/protected-client-identity-v1.js";
import { PostgresProtectedClientIdentityStoreV1 } from "../dist/src/persistence/postgres-identity-store-v1.js";
import { createInitializationHttpAppV1 } from "../dist/src/transport/streamable-http-initialization-v1.js";

function requiredEnvironment(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Required protected gateway configuration is missing: ${name}`);
  return value;
}

const host = process.env.GATEWAY_HOST?.trim() || "127.0.0.1";
const port = Number(process.env.GATEWAY_PORT ?? 4174);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error("GATEWAY_PORT must be an integer from 1 through 65535");
}

const [certificate, privateKey, clientCertificateAuthority] = await Promise.all([
  readFile(requiredEnvironment("GATEWAY_TLS_CERT_FILE")),
  readFile(requiredEnvironment("GATEWAY_TLS_KEY_FILE")),
  readFile(requiredEnvironment("GATEWAY_CLIENT_CA_FILE"))
]);
const identityStore = await PostgresProtectedClientIdentityStoreV1.connect({
  connectionString: requiredEnvironment("DATABASE_URL")
});
const identityProvider = new ProtectedClientIdentityProviderV1({
  credentialStore: identityStore
});
const app = createInitializationHttpAppV1({
  clientAuthenticator: (attempt) => identityProvider.authenticate(attempt)
});
const server = createServer({
  cert: certificate,
  key: privateKey,
  ca: clientCertificateAuthority,
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: "TLSv1.2"
}, app);

server.listen(port, host, () => {
  console.log(`Protected mutual-TLS gateway listening at https://${host}:${port}/mcp`);
  console.log("Client identities are resolved from the durable PostgreSQL credential registry; coverage remains UNPROTECTED.");
});

let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await new Promise((resolve) => server.close(resolve));
  await identityStore.close();
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    void close().then(() => process.exit(0), () => process.exit(1));
  });
}
