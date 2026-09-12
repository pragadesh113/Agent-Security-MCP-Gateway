import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("protected gateway runtime wiring", () => {
  it("requires mutual TLS and durable PostgreSQL identity without fixture authentication", async () => {
    const source = await readFile("scripts/serve-gateway-protected.mjs", "utf8");
    const packageDocument = JSON.parse(await readFile("package.json", "utf8")) as {
      scripts?: Record<string, string>;
    };

    expect(packageDocument.scripts?.["gateway:serve:protected"])
      .toBe("npm run build && node scripts/serve-gateway-protected.mjs");
    for (const required of [
      "GATEWAY_TLS_CERT_FILE",
      "GATEWAY_TLS_KEY_FILE",
      "GATEWAY_CLIENT_CA_FILE",
      "DATABASE_URL",
      "requestCert: true",
      "rejectUnauthorized: true",
      "ProtectedClientIdentityProviderV1",
      "PostgresProtectedClientIdentityStoreV1"
    ]) {
      expect(source).toContain(required);
    }
    expect(source).not.toMatch(/TEST_FIXTURE|Bearer |authorizationHeader/u);
  });
});
