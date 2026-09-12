import { createServer } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  DisposableProtocolGuardV1,
  bindAuthenticatedIdentityToSessionV1,
  type AuthenticatedClientPrincipalV1,
  type ProtocolGuardLimitsV1,
  type ProtocolOperationRequestV1
} from "../../src/index.js";

const openServers = new Set<ReturnType<typeof createServer>>();
const timestamp = "2026-09-03T12:00:00.000Z";
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-http-guard",
  agentId: "agent-http-guard",
  clientId: "client-http-guard",
  host: { hostId: "host-http-guard", name: "HTTP guard host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-http-guard",
    identityRevision: 1,
    authenticatedAt: timestamp
  }
};
const limits: ProtocolGuardLimitsV1 = {
  schemaVersion: "1.0.0",
  maxClockSkewMs: 30_000,
  replayTtlMs: 60_000,
  rateWindowMs: 60_000,
  callsPerWindow: 100,
  concurrentCalls: 1,
  payloadBytes: 1_024,
  resultBytes: 1_024,
  callDepth: 4,
  delegationDepth: 2,
  fanOut: 2,
  redirects: 0,
  retries: 0,
  executionMs: 100,
  circuitFailureThreshold: 1
};

function operationRequest(requestId: string): ProtocolOperationRequestV1 {
  return {
    schemaVersion: "1.0.0",
    requestId,
    nonce: `nonce-${requestId}`,
    requestedAt: timestamp,
    session: bindAuthenticatedIdentityToSessionV1(principal, "session-http-guard"),
    serverId: "server-http-guard",
    toolName: "http.read",
    routeId: "route-http-guard",
    destinationId: "destination-http-guard",
    actionFamily: "network.read",
    callChain: {
      callChainId: "chain-http-guard",
      parentRequestId: null,
      depth: 0,
      delegationDepth: 0,
      ancestry: []
    },
    payloadBytes: 0,
    expectedResultBytes: 128,
    fanOut: 0,
    redirectCount: 0,
    retryCount: 0,
    mutation: false,
    requiredDependencies: ["downstream.http"]
  };
}

function createGuard(customLimits: Partial<ProtocolGuardLimitsV1> = {}) {
  let operation = 0;
  let event = 0;
  const guard = new DisposableProtocolGuardV1({
    limits: { ...limits, ...customLimits },
    clock: () => new Date(timestamp),
    operationIdFactory: () => `http-operation-${String(++operation)}`,
    eventIdFactory: () => `http-event-${String(++event)}`
  });
  guard.recordDependencySuccess("downstream.http");
  return guard;
}

afterEach(async () => {
  await Promise.all([...openServers].map(async (server) => new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  })));
  openServers.clear();
});

describe("protocol guard over a disposable HTTP operation", () => {
  it("bounds success, concurrency, cancellation, timeout, and dependency failure", async () => {
    let requestCount = 0;
    let notifySlowRequest: (() => void) | undefined;
    const slowRequestObserved = new Promise<void>((resolve) => {
      notifySlowRequest = resolve;
    });
    const server = createServer((request, response) => {
      requestCount += 1;
      if (request.url === "/slow") {
        notifySlowRequest?.();
        setTimeout(() => {
          if (!response.writableEnded) {
            response.end("slow-result");
          }
        }, 50);
        return;
      }
      response.end("safe-result");
    });
    openServers.add(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Disposable protocol server did not bind a TCP address");
    }
    const baseUrl = `http://127.0.0.1:${String(address.port)}`;
    const guardedFetch = (
      guard: DisposableProtocolGuardV1,
      requestId: string,
      path: string,
      cancellation?: AbortSignal
    ) => guard.run(operationRequest(requestId), async ({ signal }) => {
      const response = await fetch(`${baseUrl}${path}`, { signal });
      const value = await response.text();
      return { value, resultBytes: Buffer.byteLength(value, "utf8") };
    }, cancellation);

    const guard = createGuard();
    await expect(guardedFetch(guard, "success", "/ok")).resolves.toBe("safe-result");

    const running = guardedFetch(guard, "concurrent-first", "/slow");
    await slowRequestObserved;
    await expect(guardedFetch(guard, "concurrent-second", "/ok")).rejects.toMatchObject({
      reason: "QUOTA_EXCEEDED",
      quotaDimension: "SESSION"
    });
    await expect(running).resolves.toBe("slow-result");

    const cancellation = new AbortController();
    const cancelled = guardedFetch(guard, "cancelled", "/slow", cancellation.signal);
    cancellation.abort();
    await expect(cancelled).rejects.toMatchObject({ reason: "CANCELLED" });

    const timeoutGuard = createGuard({ executionMs: 10 });
    await expect(guardedFetch(timeoutGuard, "timed-out", "/slow")).rejects.toMatchObject({
      reason: "TIMED_OUT"
    });

    const circuitGuard = createGuard();
    circuitGuard.recordDependencyFailure("downstream.http");
    const beforeCircuitDenial = requestCount;
    await expect(guardedFetch(circuitGuard, "dependency-denied", "/ok")).rejects.toMatchObject({
      reason: "DEPENDENCY_UNAVAILABLE"
    });
    expect(requestCount).toBe(beforeCircuitDenial);
    expect(circuitGuard.readAudit().map((event) => event.eventType)).toEqual([
      "CIRCUIT_OPENED", "DEPENDENCY_DENIED"
    ]);
  });
});
