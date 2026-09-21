import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";
import { ApprovalWebRuntimeBridgeV1 } from "../../src/runtime/approval-web-runtime-v1.js";
import { ClientApprovedCallExecutorV1 } from "../../src/runtime/client-tool-call-v1.js";
import { createHashiCorpVaultApprovalRuntimeV1 } from "../../src/runtime/protected-approval-runtime-v1.js";
import { HashiCorpVaultKvV2ProviderV1 } from "../../src/identity/hashicorp-vault-provider-v1.js";
import { computeCanonicalDigestV1 } from "../../src/action-normalizer/canonical-action-v1.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

describe("protected gateway runtime wiring", () => {
  it("resolves the protected agent session before invoking the exact-call executor", async () => {
    const calls: unknown[] = [];
    const fixture = createPostgresTrajectoryFixtureV1("approval-bridge");
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: ({ approvalId, session }) => {
        calls.push({ type: "load", approvalId, session });
        return {
          session, request: fixture.request, action: fixture.action,
          decision: fixture.decision, approval: fixture.approval
        };
      },
      store: {
        consumeApprovalAndStartForwarding: (authorization) => {
          calls.push({ type: "consume", authorization });
          return Promise.resolve();
        },
        recordResultAndOutcome: () => Promise.resolve(),
        recordTerminalOutcome: (outcome) => {
          calls.push({ type: "outcome", outcome });
          return Promise.resolve();
        }
      },
      issueCredentialLease: () => "lease-approval-bridge",
      forwarder: {
        execute: ({ authorization }) => Promise.resolve({
          schemaVersion: "1.0.0",
          forwardingAttemptId: authorization.forwardingAttemptId,
          provenance: null, result: null, release: null, error: null,
          trustEvidenceEligible: false
        })
      },
      forwardingAttemptIdFactory: () => "forward-approval-bridge",
      outcomeIdFactory: () => "outcome-approval-bridge",
      clock: () => new Date("2026-09-12T12:00:05.000Z")
    });
    const bridge = new ApprovalWebRuntimeBridgeV1({
      dispatches: {
        claimApprovalDispatch: (input) => {
          calls.push({ type: "claim", input });
          return Promise.resolve();
        },
        completeApprovalDispatch: (input) => {
          calls.push({ type: "complete", input });
          return Promise.resolve();
        },
        failApprovalDispatch: (input) => {
          calls.push({ type: "fail", input });
          return Promise.resolve();
        }
      },
      sessions: {
        resolve: (input) => {
          calls.push({ type: "resolve", input });
          return Promise.resolve(fixture.session);
        }
      },
      executor,
      claimIdFactory: () => "claim-approval-bridge",
      clock: () => new Date("2026-09-12T12:00:05.000Z")
    });

    await bridge.executeApprovedCall({ approvalId: fixture.approval.approvalId, humanId: "human-bridge" });
    expect(calls.map((item) => (item as { type: string }).type)).toEqual([
      "claim", "resolve", "load", "consume", "outcome", "complete"
    ]);
    expect(calls[3]).toMatchObject({ type: "consume", authorization: {
      approvalId: fixture.approval.approvalId, forwardingAttemptId: "forward-approval-bridge"
    }});
  });

  it("claims before session resolution and durably fails the dispatch when resolution fails", async () => {
    const calls: string[] = [];
    const fixture = createPostgresTrajectoryFixtureV1("approval-bridge-resolution-failure");
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => fixture,
      store: {
        consumeApprovalAndStartForwarding: () => Promise.resolve(),
        recordResultAndOutcome: () => Promise.resolve(),
        recordTerminalOutcome: () => Promise.resolve()
      },
      issueCredentialLease: () => "unused-lease",
      forwarder: { execute: () => Promise.reject(new Error("must not execute")) }
    });
    const bridge = new ApprovalWebRuntimeBridgeV1({
      executor,
      sessions: {
        resolve: () => {
          calls.push("resolve");
          return Promise.reject(new Error("session unavailable"));
        }
      },
      dispatches: {
        claimApprovalDispatch: () => {
          calls.push("claim");
          return Promise.resolve();
        },
        completeApprovalDispatch: () => {
          calls.push("complete");
          return Promise.resolve();
        },
        failApprovalDispatch: () => {
          calls.push("fail");
          return Promise.resolve();
        }
      },
      claimIdFactory: () => "claim-resolution-failure",
      clock: () => new Date("2026-09-14T12:00:00.000Z")
    });

    await expect(bridge.executeApprovedCall({
      approvalId: fixture.approval.approvalId,
      humanId: "human-resolution-failure"
    })).rejects.toThrow("session unavailable");
    expect(calls).toEqual(["claim", "resolve", "fail"]);
  });

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

  it("requires complete protected approval runtime dependencies and wires the callback", async () => {
    const source = await readFile("scripts/serve-approval-ui-protected.mjs", "utf8");
    const packageDocument = JSON.parse(await readFile("package.json", "utf8")) as {
      scripts?: Record<string, string>;
    };
    expect(packageDocument.scripts?.["approval:serve:protected"])
      .toBe("npm run build && node scripts/serve-approval-ui-protected.mjs");
    for (const required of [
      "APPROVAL_UI_RUNTIME_MODULE",
      "APPROVAL_UI_RUNTIME_KEY_BASE64",
      "APPROVAL_UI_RUNTIME_KEY_ID",
      "PostgresTrajectoryStoreV1",
      "ClientApprovedCallExecutorV1",
      "ApprovalWebRuntimeBridgeV1",
      "dispatches: trajectoryStore",
      "recoverStaleApprovalDispatches",
      "executeApprovedCall: (input) => runtimeBridge.executeApprovedCall(input)",
      "createProtectedApprovalRuntimeDependenciesV1"
    ]) {
      expect(source).toContain(required);
    }
    expect(source).not.toMatch(/TEST_FIXTURE|Bearer |authorizationHeader/u);
  });

  it("binds an approved Vault lease to the exact durable forwarding attempt and governs the result", async () => {
    const now = new Date();
    const fixture = createPostgresTrajectoryFixtureV1(
      "protected-vault-runtime",
      new Date(now.getTime() - 20_000)
    );
    if (fixture.binding.server.transport.kind !== "STREAMABLE_HTTP") {
      throw new Error("Protected runtime fixture requires Streamable HTTP");
    }
    const downstreamOrigin = new URL(fixture.binding.server.transport.endpoint).origin;
    const secret = "protected-vault-runtime-secret";
    let downstreamAuthorization: string | null = null;
    const provider = new HashiCorpVaultKvV2ProviderV1({
      descriptor: {
        schemaVersion: "1.0.0",
        providerId: "approved-vault-runtime",
        providerType: "HASHICORP_VAULT",
        approval: {
          status: "APPROVED",
          approvedBy: "project-owner",
          approvedAt: now.toISOString(),
          configurationDigest: computeCanonicalDigestV1({ provider: "approved-vault-runtime" })
        }
      },
      endpointOrigin: "https://vault.example.test",
      tokenProvider: () => Promise.resolve(Buffer.from("vault-test-token", "utf8")),
      fetchImplementation: () => Promise.resolve(new Response(JSON.stringify({
        data: { data: { token: secret }, metadata: { version: 1 } }
      }), { status: 200, headers: { "Content-Type": "application/json" } }))
    });
    const runtime = createHashiCorpVaultApprovalRuntimeV1({
      secretManager: provider,
      credentialBindings: [{
        schemaVersion: "1.0.0",
        secretManagerProviderId: provider.descriptor.providerId,
        secretReference: "kv-v2://secret/gateway/downstream#token",
        profile: {
          schemaVersion: "1.0.0",
          credentialProfileId: fixture.binding.server.credentialAudience.credentialProfileId,
          credentialRevision: 1,
          credentialKind: "BEARER_TOKEN",
          audienceId: fixture.binding.route.credentialAudienceId,
          allowedRouteIds: [fixture.binding.route.routeId],
          allowedEndpointOrigins: [downstreamOrigin],
          materialDigest: createHash("sha256").update(secret).digest("hex"),
          status: "ACTIVE",
          issuedAt: new Date(now.getTime() - 60_000).toISOString(),
          expiresAt: new Date(now.getTime() + 60_000).toISOString()
        }
      }],
      resolveCurrentRoute: () => fixture.binding,
      authenticateDownstream: () => ({
        schemaVersion: "1.0.0",
        serverId: fixture.binding.server.serverId,
        principalId: fixture.binding.server.authenticatedPrincipalId,
        authenticationMethod: "MUTUAL_TLS",
        credentialId: "downstream-certificate-runtime",
        identityRevision: 1,
        authenticatedAt: now.toISOString()
      }),
      validateOutputSchema: ({ structuredContent }) => structuredContent?.["ok"] === true,
      classifyResult: () => ["PUBLIC"],
      evaluateEgress: () => "ALLOW",
      credentialBrokerClock: () => now,
      credentialLeaseIdFactory: () => "lease-protected-vault-runtime",
      credentialFetchImplementation: (_input, init) => {
        const headers = new Headers(init?.headers);
        downstreamAuthorization = headers.get("authorization");
        return Promise.resolve(new Response(JSON.stringify({
          jsonrpc: "2.0",
          id: fixture.request.protocolRequestId,
          result: { content: [{ type: "text", text: "completed" }], structuredContent: { ok: true } }
        }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Mcp-Server-Authorization": "verified-downstream-runtime"
          }
        }));
      },
      clock: () => now,
      resultIdFactory: () => fixture.result.resultId,
      provenanceIdFactory: () => fixture.provenance.provenanceId
    });
    expect(() => runtime.issueCredentialLease({
      call: fixture,
      authorization: { ...fixture.authorization, routeId: "route-substitution" }
    })).toThrow("Exact downstream forwarding denied");
    let persistedStatus: string | null = null;
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => fixture,
      store: {
        consumeApprovalAndStartForwarding: () => Promise.resolve(),
        recordResultAndOutcome: ({ outcome }) => {
          persistedStatus = outcome.status;
          return Promise.resolve();
        },
        recordTerminalOutcome: () => Promise.reject(new Error("unexpected terminal failure"))
      },
      issueCredentialLease: runtime.issueCredentialLease,
      forwarder: runtime.forwarder,
      clock: () => new Date(fixture.authorization.authorizedAt),
      forwardingAttemptIdFactory: () => fixture.authorization.forwardingAttemptId,
      outcomeIdFactory: () => fixture.outcome.outcomeId
    });

    const mediated = await executor.execute({
      approvalId: fixture.approval.approvalId,
      session: fixture.session
    });

    expect(downstreamAuthorization).toBe(`Bearer ${secret}`);
    expect(mediated.release?.instructionPolicy).toBe("DATA_ONLY");
    expect(mediated.result?.disposition).toBe("ALLOW");
    expect(persistedStatus).toBe("COMPLETED");
    expect(JSON.stringify(mediated)).not.toContain(secret);
  });
});
