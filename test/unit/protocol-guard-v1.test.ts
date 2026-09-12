import { describe, expect, it } from "vitest";

import {
  DisposableProtocolGuardV1,
  bindAuthenticatedIdentityToSessionV1,
  type AuthenticatedClientPrincipalV1,
  type ProtocolGuardLimitsV1,
  type ProtocolOperationRequestV1
} from "../../src/index.js";

const timestamp = "2026-09-03T12:00:00.000Z";
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-guard",
  agentId: "agent-guard",
  clientId: "client-guard",
  host: { hostId: "host-guard", name: "Guard test host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-guard",
    identityRevision: 1,
    authenticatedAt: timestamp
  }
};
const limits: ProtocolGuardLimitsV1 = {
  schemaVersion: "1.0.0",
  maxClockSkewMs: 30_000,
  replayTtlMs: 60_000,
  rateWindowMs: 60_000,
  callsPerWindow: 2,
  concurrentCalls: 1,
  payloadBytes: 100,
  resultBytes: 100,
  callDepth: 3,
  delegationDepth: 2,
  fanOut: 2,
  redirects: 1,
  retries: 1,
  executionMs: 25,
  circuitFailureThreshold: 2
};

function request(overrides: Partial<ProtocolOperationRequestV1> = {}): ProtocolOperationRequestV1 {
  return {
    schemaVersion: "1.0.0",
    requestId: "request-guard",
    nonce: "nonce-guard",
    requestedAt: timestamp,
    session: bindAuthenticatedIdentityToSessionV1(principal, "session-guard"),
    serverId: "server-guard",
    toolName: "tool.read",
    routeId: "route-guard",
    destinationId: "destination-guard",
    actionFamily: "filesystem.read",
    callChain: {
      callChainId: "chain-guard",
      parentRequestId: null,
      depth: 0,
      delegationDepth: 0,
      ancestry: []
    },
    payloadBytes: 10,
    expectedResultBytes: 20,
    fanOut: 0,
    redirectCount: 0,
    retryCount: 0,
    mutation: false,
    requiredDependencies: [],
    ...overrides
  };
}

function createGuard(customLimits: Partial<ProtocolGuardLimitsV1> = {}) {
  let operation = 0;
  let event = 0;
  return new DisposableProtocolGuardV1({
    limits: { ...limits, ...customLimits },
    clock: () => new Date(timestamp),
    operationIdFactory: () => `operation-${String(++operation)}`,
    eventIdFactory: () => `event-${String(++event)}`
  });
}

describe("disposable protocol guard", () => {
  it("rejects stale/future timestamps and session-scoped request or nonce replay", () => {
    const guard = createGuard();
    expect(() => guard.begin(request({ requestedAt: "2026-09-03T11:59:29.999Z" })))
      .toThrow(expect.objectContaining({ reason: "TIMESTAMP_OUT_OF_RANGE" }));
    expect(() => guard.begin(request({
      requestId: "future-request",
      nonce: "future-nonce",
      requestedAt: "2026-09-03T12:00:30.001Z"
    }))).toThrow(expect.objectContaining({ reason: "TIMESTAMP_OUT_OF_RANGE" }));

    const accepted = guard.begin(request());
    guard.complete(accepted.operationId, 10);
    expect(() => guard.begin(request())).toThrow(
      expect.objectContaining({ reason: "REPLAY_DETECTED" })
    );
    expect(() => guard.begin(request({ requestId: "request-other" }))).toThrow(
      expect.objectContaining({ reason: "REPLAY_DETECTED" })
    );

    const otherSession = bindAuthenticatedIdentityToSessionV1(principal, "session-other");
    const crossSession = guard.begin(request({ session: otherSession }));
    guard.complete(crossSession.operationId, 10);
    expect(guard.readAudit().map((event) => event.eventType)).toEqual(expect.arrayContaining([
      "FRESHNESS_DENIED", "REPLAY_DENIED", "ADMITTED", "COMPLETED"
    ]));
  });

  it.each([
    "SESSION", "USER", "AGENT", "CLIENT", "SERVER", "TOOL", "ROUTE",
    "DESTINATION", "ACTION_FAMILY"
  ] as const)("enforces the %s rate quota", (dimension) => {
    const otherPrincipal: AuthenticatedClientPrincipalV1 = {
      ...principal,
      userId: dimension === "USER" ? principal.userId : "user-other",
      agentId: dimension === "AGENT" ? principal.agentId : "agent-other",
      clientId: dimension === "CLIENT" ? principal.clientId : "client-other",
      host: { ...principal.host, hostId: "host-other" },
      authentication: {
        ...principal.authentication,
        credentialId: "credential-other"
      }
    };
    const secondSession = dimension === "SESSION"
      ? bindAuthenticatedIdentityToSessionV1(principal, "session-guard")
      : bindAuthenticatedIdentityToSessionV1(otherPrincipal, "session-other");
    const second = request({
      requestId: `request-${dimension.toLowerCase()}`,
      nonce: `nonce-${dimension.toLowerCase()}`,
      session: secondSession,
      serverId: dimension === "SERVER" ? "server-guard" : "server-other",
      toolName: dimension === "TOOL" ? "tool.read" : "tool.other",
      routeId: dimension === "ROUTE" ? "route-guard" : "route-other",
      destinationId: dimension === "DESTINATION"
        ? "destination-guard"
        : "destination-other",
      actionFamily: dimension === "ACTION_FAMILY" ? "filesystem.read" : "network.read"
    });
    const guard = createGuard({ callsPerWindow: 1 });
    const first = guard.begin(request());
    guard.complete(first.operationId, 10);
    expect(() => guard.begin(second)).toThrow(expect.objectContaining({
      reason: "QUOTA_EXCEEDED",
      quotaDimension: dimension
    }));
  });

  it("enforces concurrency quotas and releases capacity on completion", () => {
    const guard = createGuard();
    const first = guard.begin(request());
    expect(() => guard.begin(request({
      requestId: "request-concurrent",
      nonce: "nonce-concurrent"
    }))).toThrow(expect.objectContaining({
      reason: "QUOTA_EXCEEDED",
      quotaDimension: "SESSION"
    }));
    guard.complete(first.operationId, 10);
  });

  it.each([
    ["payload", { payloadBytes: 101 }],
    ["expected result", { expectedResultBytes: 101 }],
    ["depth", {
      callChain: {
        callChainId: "chain-depth",
        parentRequestId: "parent-4",
        depth: 4,
        delegationDepth: 0,
        ancestry: [
          { requestId: "parent-1", routeId: "route-1", destinationId: "dest-1", actionFamily: "a.one" },
          { requestId: "parent-2", routeId: "route-2", destinationId: "dest-2", actionFamily: "a.two" },
          { requestId: "parent-3", routeId: "route-3", destinationId: "dest-3", actionFamily: "a.three" },
          { requestId: "parent-4", routeId: "route-4", destinationId: "dest-4", actionFamily: "a.four" }
        ]
      }
    }],
    ["delegation", {
      callChain: {
        callChainId: "chain-delegation",
        parentRequestId: "parent-3",
        depth: 3,
        delegationDepth: 3,
        ancestry: [
          { requestId: "parent-1", routeId: "route-1", destinationId: "dest-1", actionFamily: "a.one" },
          { requestId: "parent-2", routeId: "route-2", destinationId: "dest-2", actionFamily: "a.two" },
          { requestId: "parent-3", routeId: "route-3", destinationId: "dest-3", actionFamily: "a.three" }
        ]
      }
    }],
    ["fan-out", { fanOut: 3 }],
    ["redirects", { redirectCount: 2 }],
    ["retries", { retryCount: 2 }]
  ] as const)("rejects the configured %s bound", (_name, override) => {
    expect(() => createGuard().begin(request({
      ...(override as Partial<ProtocolOperationRequestV1>),
      requestId: `request-${_name.replace(" ", "-")}`,
      nonce: `nonce-${_name.replace(" ", "-")}`
    }))).toThrow(expect.objectContaining({ reason: "BOUND_EXCEEDED" }));
  });

  it("enforces dynamic fan-out, redirect, retry, and result bounds", () => {
    for (const checkpoint of [
      { additionalFanOut: 3 },
      { additionalRedirects: 2 },
      { additionalRetries: 2 },
      { observedResultBytes: 101 }
    ]) {
      const guard = createGuard();
      const lease = guard.begin(request());
      expect(() => {
        guard.checkpoint(lease.operationId, checkpoint);
      }).toThrow(
        expect.objectContaining({ reason: "BOUND_EXCEEDED" })
      );
    }
    const guard = createGuard();
    const lease = guard.begin(request());
    expect(() => {
      guard.complete(lease.operationId, 21);
    }).toThrow(
      expect.objectContaining({ reason: "BOUND_EXCEEDED" })
    );

    const invalidCheckpointGuard = createGuard();
    const invalidLease = invalidCheckpointGuard.begin(request());
    expect(() => {
      invalidCheckpointGuard.checkpoint(invalidLease.operationId, {
        additionalRetries: -1
      });
    }).toThrow(expect.objectContaining({ reason: "BOUND_EXCEEDED" }));
    const replacement = invalidCheckpointGuard.begin(request({
      requestId: "request-after-invalid-checkpoint",
      nonce: "nonce-after-invalid-checkpoint"
    }));
    invalidCheckpointGuard.complete(replacement.operationId, 1);
  });

  it("detects request and equivalent route/destination/action recursion", () => {
    const ancestry = [{
      requestId: "parent-request",
      routeId: "route-guard",
      destinationId: "destination-guard",
      actionFamily: "filesystem.read"
    }];
    expect(() => createGuard().begin(request({
      requestId: "child-request",
      nonce: "child-nonce",
      callChain: {
        callChainId: "chain-recursive",
        parentRequestId: "parent-request",
        depth: 1,
        delegationDepth: 1,
        ancestry
      }
    }))).toThrow(expect.objectContaining({ reason: "RECURSION_DETECTED" }));
  });

  it("propagates cancellation and releases concurrency", async () => {
    const guard = createGuard();
    const cancellation = new AbortController();
    let observedAbort = false;
    const running = guard.run(request(), async ({ signal }) => {
      await new Promise<void>((resolve) => {
        signal.addEventListener("abort", () => {
          observedAbort = true;
          resolve();
        }, { once: true });
      });
      return { value: "late", resultBytes: 1 };
    }, cancellation.signal);
    cancellation.abort();
    await expect(running).rejects.toMatchObject({ reason: "CANCELLED" });
    expect(observedAbort).toBe(true);
    expect(guard.readAudit().at(-1)?.eventType).toBe("CANCELLED");
  });

  it("enforces execution deadlines and aborts timed-out work", async () => {
    const guard = createGuard({ executionMs: 10 });
    let observedAbort = false;
    await expect(guard.run(request(), async ({ signal }) => {
      await new Promise<void>((resolve) => {
        signal.addEventListener("abort", () => {
          observedAbort = true;
          resolve();
        }, { once: true });
      });
      return { value: "late", resultBytes: 1 };
    })).rejects.toMatchObject({ reason: "TIMED_OUT" });
    expect(observedAbort).toBe(true);
    expect(guard.readAudit().at(-1)?.eventType).toBe("TIMED_OUT");
  });

  it("opens dependency circuits and denies protected operations until trusted recovery", () => {
    const guard = createGuard();
    guard.recordDependencyFailure("policy.service");
    expect(() => guard.begin(request({
      mutation: true,
      requiredDependencies: ["policy.service"]
    }))).toThrow(expect.objectContaining({ reason: "DEPENDENCY_UNAVAILABLE" }));
    guard.recordDependencyFailure("policy.service");
    expect(guard.readAudit().map((event) => event.eventType)).toContain("CIRCUIT_OPENED");

    guard.recordDependencySuccess("policy.service");
    const lease = guard.begin(request({
      requestId: "request-recovered",
      nonce: "nonce-recovered",
      mutation: true,
      requiredDependencies: ["policy.service"]
    }));
    guard.complete(lease.operationId, 1);
  });

  it("runs a bounded legitimate operation to completion", async () => {
    const guard = createGuard();
    await expect(guard.run(request(), (tools) => {
      expect(tools.signal.aborted).toBe(false);
      tools.checkpoint({ additionalFanOut: 1, observedResultBytes: 10 });
      return Promise.resolve({ value: "safe-result", resultBytes: 10 });
    })).resolves.toBe("safe-result");
    expect(guard.readAudit().map((event) => event.eventType)).toEqual([
      "ADMITTED", "COMPLETED"
    ]);
  });
});
