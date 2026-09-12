import { describe, expect, it } from "vitest";

import {
  CanonicalActionNormalizerV1,
  ClientApprovedCallExecutorV1,
  ClientToolCallCoordinatorV1,
  DeterministicPolicyEngineV1,
  DisposableProtocolGuardV1,
  ExclusiveMediationMonitorV1,
  TrustworthyInterfaceBuilderV1,
  computeCanonicalDigestV1,
  type ClientToolCallDecisionStoreV1,
  type CoveragePathKindV1,
  type MediationGuaranteeV1
} from "../../src/index.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

const now = new Date("2026-09-08T08:00:00.000Z");

function guard(executionMs = 5_000): DisposableProtocolGuardV1 {
  return new DisposableProtocolGuardV1({
    clock: () => now,
    operationIdFactory: () => "operation-client-call",
    eventIdFactory: () => "event-client-call",
    limits: {
      schemaVersion: "1.0.0",
      maxClockSkewMs: 30_000,
      replayTtlMs: 60_000,
      rateWindowMs: 60_000,
      callsPerWindow: 10,
      concurrentCalls: 2,
      payloadBytes: 64 * 1024,
      resultBytes: 1024 * 1024,
      callDepth: 4,
      delegationDepth: 2,
      fanOut: 2,
      redirects: 0,
      retries: 0,
      executionMs,
      circuitFailureThreshold: 2
    }
  });
}

const guarantees = {
  GATEWAY_MEDIATED: ["CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT", "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS", "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"],
  NATIVE: ["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"],
  DIRECT: ["CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION", "DOWNSTREAM_AUTHORIZATION"]
} as const satisfies Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>>;

function coordinator(
  store: ClientToolCallDecisionStoreV1,
  protocolGuard = guard(),
  enforced = false,
  coverageGate?: Promise<void>
) {
  const candidate = createPostgresTrajectoryFixtureV1("client-call", now);
  const resolverId = candidate.binding.route.resourceMapping.resolverId;
  for (const dependency of ["route-registry", "canonicalizer", "policy", "postgres"]) {
    protocolGuard.recordDependencySuccess(dependency);
  }
  return {
    candidate,
    protocolGuard,
    coordinator: new ClientToolCallCoordinatorV1({
      policyScopeId: candidate.binding.route.policyScopeId,
      environment: candidate.binding.route.environment,
      policyDigest: computeCanonicalDigestV1({ version: candidate.decision.policyVersion }),
      resolveRoute: () => ({
        binding: candidate.binding,
        inputSchema: candidate.inputSchema,
        outputSchema: candidate.outputSchema
      }),
      protocolGuard,
      normalizer: new CanonicalActionNormalizerV1({
        resolvers: new Map([[resolverId, () => ({
          schemaVersion: "1.0.0",
          parserId: resolverId,
          parserVersion: "1.0.0",
          status: "FULL",
          resources: [{
            resourceId: "database-row-client-call",
            resourceClass: "DATABASE",
            reference: "postgres://disposable/orders/client-call",
            referencePlatform: "URI",
            classification: "CONFIDENTIAL"
          }],
          effect: "DELETE",
          environment: "PRODUCTION",
          dataFlow: {
            direction: "NONE",
            classifications: ["CONFIDENTIAL"],
            externalDestination: false,
            destinationId: null
          },
          reversibility: "IRREVERSIBLE",
          influences: ["USER_INPUT"]
        })]]),
        clock: () => now,
        actionIdFactory: () => "action-client-call-runtime"
      }),
      policy: new DeterministicPolicyEngineV1({
        policyVersion: candidate.decision.policyVersion,
        clock: () => now,
        decisionIdFactory: () => "decision-client-call-runtime"
      }),
      assessCoverage: async (action) => {
        await coverageGate;
        const resource = action.resources[0];
        if (resource === undefined) throw new Error("A canonical resource is required");
        const scope = {
          ...action.identity,
          stateNamespace: action.sessionId,
          ...action.route,
          credentialProfileId: candidate.binding.server.credentialAudience.credentialProfileId,
          environment: action.environment,
          resourceId: resource.resourceId,
          resourceClass: resource.resourceClass,
          resourcesDigest: action.resourcesDigest
        };
        if (enforced) {
          const probes = (Object.entries(guarantees) as Array<[CoveragePathKindV1, readonly MediationGuaranteeV1[]]>).flatMap(
            ([pathKind, required]) => required.map((guarantee) => ({
              guarantee, pathKind, verifierId: `verifier-${pathKind.toLowerCase()}-${guarantee.toLowerCase()}`,
              authority: "client-call-test-authority",
              observe: () => ({
                schemaVersion: "1.0.0" as const,
                evidenceId: `evidence-${pathKind.toLowerCase()}-${guarantee.toLowerCase()}`,
                guarantee, pathKind,
                verifierId: `verifier-${pathKind.toLowerCase()}-${guarantee.toLowerCase()}`,
                authority: "client-call-test-authority", verifierClass: "TEST_FIXTURE" as const,
                assurance: "DISPOSABLE_TEST" as const, scope,
                status: pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" as const : "VERIFIED_BLOCKED" as const,
                revision: 1, observedAt: now.toISOString(),
                expiresAt: new Date(now.getTime() + 30_000).toISOString(),
                proofDigest: computeCanonicalDigestV1({ pathKind, guarantee })
              })
            }))
          );
          return new ExclusiveMediationMonitorV1({
            probes, assurance: "DISPOSABLE_TEST",
            trustedAuthorities: Object.fromEntries([...new Set(Object.values(guarantees).flat())].map((guarantee) => [guarantee, ["client-call-test-authority"]])),
            clock: () => now, assessmentIdFactory: () => "assessment-client-call-enforced"
          }).assess(scope);
        }
        const pathKinds = ["GATEWAY_MEDIATED", "NATIVE", "DIRECT"] as const;
        const paths = pathKinds.map((pathKind) => ({
          pathKind,
          coverage: "UNPROTECTED" as const,
          reasonCodes: ["coverage.runtime.not_configured"]
        }));
        const missingGuarantees = [{
          guarantee: "CLIENT_AUTHENTICATION" as const,
          pathKind: "GATEWAY_MEDIATED" as const,
          reasonCode: "coverage.runtime.not_configured",
          verifierId: null
        }];
        return {
          schemaVersion: "1.0.0",
          assessmentId: "assessment-client-call-runtime",
          revision: 1,
          assurance: "DISPOSABLE_TEST",
          scope,
          coverage: "UNPROTECTED",
          mutationAllowed: false,
          paths,
          missingGuarantees,
          evidence: [],
          evidenceDigest: computeCanonicalDigestV1({
            assurance: "DISPOSABLE_TEST", scope, coverage: "UNPROTECTED", paths,
            missingGuarantees, evidence: []
          }),
          assessedAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + 30_000).toISOString()
        } as const;
      },
      interfaceBuilder: new TrustworthyInterfaceBuilderV1({
        clock: () => now,
        interfaceIdFactory: () => "interface-client-call-runtime",
        awarenessIdFactory: () => "awareness-client-call-runtime"
      }),
      store,
      clock: () => now,
      nonceFactory: () => "nonce-client-call-runtime",
      callChainIdFactory: () => "chain-client-call-runtime"
    })
  };
}

describe("client-facing tool-call coordinator", () => {
  it("resolves, admits, canonicalizes, decides, and persists before returning", async () => {
    const persisted: Parameters<ClientToolCallDecisionStoreV1["persistDecisionTrajectory"]>[0][] = [];
    const setup = coordinator({
      persistDecisionTrajectory: (input) => {
        persisted.push(input);
        return Promise.resolve();
      }
    });

    const result = await setup.coordinator.handle({
      requestId: "request-client-call-runtime",
      protocolRequestId: "protocol-client-call-runtime",
      session: setup.candidate.session,
      name: setup.candidate.binding.route.exposedName,
      arguments: { record_id: "row-client-call" }
    });

    expect(result).toMatchObject({
      isError: true,
      structuredContent: {
        decision: "DENY",
        tier: 3,
        coverage: "UNPROTECTED",
        downstreamInvoked: false,
        awareness: {
          awarenessId: "awareness-client-call-runtime",
          decision: "DENY",
          generatedFromCanonicalData: true,
          missingGuarantees: ["coverage.runtime.not_configured"]
        }
      }
    });
    expect(result.content[0].text).toBe(result.structuredContent.awareness.factualSummary);
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({
      request: { requestId: "request-client-call-runtime", credentialsExcluded: true },
      action: { effect: "DELETE", environment: "PRODUCTION" },
      decision: { decision: "DENY", coverage: "UNPROTECTED" }
    });
    expect(setup.protocolGuard.readAudit().map((event) => event.eventType)).toEqual([
      "ADMITTED",
      "COMPLETED"
    ]);
  });

  it("fails closed and releases protocol concurrency when persistence is unavailable", async () => {
    const setup = coordinator({
      persistDecisionTrajectory: () => Promise.reject(new Error("database unavailable"))
    });
    const input = {
      requestId: "request-client-call-failure",
      protocolRequestId: 7,
      session: setup.candidate.session,
      name: setup.candidate.binding.route.exposedName,
      arguments: { record_id: "row-client-call" }
    } as const;

    await expect(setup.coordinator.handle(input)).rejects.toThrow("database unavailable");
    expect(setup.protocolGuard.readAudit().map((event) => event.eventType)).toEqual([
      "ADMITTED",
      "OPERATION_FAILED"
    ]);
  });

  it("returns canonical awareness for an approval-required call without downstream invocation", async () => {
    const setup = coordinator({ persistDecisionTrajectory: () => Promise.resolve() }, guard(), true);
    const result = await setup.coordinator.handle({
      requestId: "request-client-call-approval", protocolRequestId: 9,
      session: setup.candidate.session, name: setup.candidate.binding.route.exposedName,
      arguments: { record_id: "row-client-call" }
    });
    expect(result.structuredContent).toMatchObject({
      decision: "REQUIRE_APPROVAL", downstreamInvoked: false,
      awareness: {
        decision: "REQUIRE_APPROVAL", generatedFromCanonicalData: true
      }
    });
    expect(result.structuredContent.awareness.alternatives.find(
      (alternative) => alternative.alternativeId === "alternative-exact-approval"
    )?.disposition).toBe("REQUIRES_APPROVAL");
  });

  it("rejects a route whose trusted scope does not match runtime configuration", async () => {
    const setup = coordinator({ persistDecisionTrajectory: () => Promise.resolve() });
    await expect(setup.coordinator.handle({
      requestId: "request-client-call-scope",
      protocolRequestId: 8,
      session: setup.candidate.session,
      name: "attacker.selected.tool",
      arguments: {}
    })).rejects.toThrow("configured call authority");
    expect(setup.protocolGuard.readAudit()).toHaveLength(0);
  });

  it("propagates cancellation and does not persist after an in-flight coverage check returns", async () => {
    let releaseCoverage: (() => void) | undefined;
    const coverageGate = new Promise<void>((resolve) => { releaseCoverage = resolve; });
    let persisted = 0;
    const setup = coordinator({
      persistDecisionTrajectory: () => { persisted += 1; return Promise.resolve(); }
    }, guard(), false, coverageGate);
    const controller = new AbortController();
    const call = setup.coordinator.handle({
      requestId: "request-client-call-cancelled", protocolRequestId: 10,
      session: setup.candidate.session, name: setup.candidate.binding.route.exposedName,
      arguments: { record_id: "row-client-call" }, signal: controller.signal
    });
    controller.abort(new Error("client disconnected"));
    await expect(call).rejects.toThrow();
    releaseCoverage?.();
    await coverageGate;
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(persisted).toBe(0);
    expect(setup.protocolGuard.readAudit().at(-1)?.eventType).toBe("CANCELLED");
  });

  it("times out admission work without allowing late decision persistence", async () => {
    let releaseCoverage: (() => void) | undefined;
    const coverageGate = new Promise<void>((resolve) => { releaseCoverage = resolve; });
    let persisted = 0;
    const setup = coordinator({
      persistDecisionTrajectory: () => { persisted += 1; return Promise.resolve(); }
    }, guard(5), false, coverageGate);
    await expect(setup.coordinator.handle({
      requestId: "request-client-call-timeout", protocolRequestId: 11,
      session: setup.candidate.session, name: setup.candidate.binding.route.exposedName,
      arguments: { record_id: "row-client-call" }
    })).rejects.toThrow();
    releaseCoverage?.();
    await coverageGate;
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(persisted).toBe(0);
    expect(setup.protocolGuard.readAudit().at(-1)?.eventType).toBe("TIMED_OUT");
  });
});

describe("approved client-call continuation", () => {
  it("durably consumes before credential use and exact forwarding", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("approved-client-call", now);
    const order: string[] = [];
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => ({
        session: candidate.session, request: candidate.request, action: candidate.action,
        decision: candidate.decision, approval: candidate.approval
      }),
      store: {
        consumeApprovalAndStartForwarding: () => { order.push("consume"); return Promise.resolve(); },
        recordResultAndOutcome: () => { order.push("persist-result"); return Promise.resolve(); },
        recordTerminalOutcome: () => Promise.reject(new Error("unexpected terminal outcome"))
      },
      issueCredentialLease: () => { order.push("lease"); return "lease-approved-client-call"; },
      forwarder: { execute: (input) => {
        order.push("forward");
        expect(input.authorization.forwardingAttemptId).toBe("attempt-approved-client-call-runtime");
        return Promise.resolve({
          schemaVersion: "1.0.0", forwardingAttemptId: input.authorization.forwardingAttemptId,
          provenance: candidate.provenance, result: candidate.result, release: null,
          error: null, trustEvidenceEligible: false
        });
      } },
      clock: () => now,
      forwardingAttemptIdFactory: () => "attempt-approved-client-call-runtime",
      outcomeIdFactory: () => "outcome-approved-client-call-runtime"
    });
    const result = await executor.execute({
      approvalId: candidate.approval.approvalId,
      session: candidate.session
    });
    expect(order).toEqual(["consume", "lease", "forward", "persist-result"]);
    expect(result.forwardingAttemptId).toBe("attempt-approved-client-call-runtime");
  });

  it("never issues a credential lease or forwards when durable consumption loses a race", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("approved-client-race", now);
    let leaseCount = 0;
    let forwardCount = 0;
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => ({
        session: candidate.session, request: candidate.request, action: candidate.action,
        decision: candidate.decision, approval: candidate.approval
      }),
      store: {
        consumeApprovalAndStartForwarding: () => Promise.reject(new Error("replayed")),
        recordResultAndOutcome: () => Promise.reject(new Error("unreachable")),
        recordTerminalOutcome: () => Promise.reject(new Error("unreachable"))
      },
      issueCredentialLease: () => { leaseCount += 1; return "lease-should-not-exist"; },
      forwarder: { execute: () => { forwardCount += 1; return Promise.reject(new Error("unreachable")); } }
    });
    await expect(executor.execute({
      approvalId: candidate.approval.approvalId,
      session: candidate.session
    })).rejects.toThrow("replayed");
    expect(leaseCount).toBe(0);
    expect(forwardCount).toBe(0);
  });

  it("persists a safe terminal outcome before returning a withheld downstream error", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("approved-client-error", now);
    const terminal: unknown[] = [];
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => ({
        session: candidate.session, request: candidate.request, action: candidate.action,
        decision: candidate.decision, approval: candidate.approval
      }),
      store: {
        consumeApprovalAndStartForwarding: () => Promise.resolve(),
        recordResultAndOutcome: () => Promise.reject(new Error("unexpected governed result")),
        recordTerminalOutcome: (outcome) => { terminal.push(outcome); return Promise.resolve(); }
      },
      issueCredentialLease: () => "lease-approved-client-error",
      forwarder: { execute: (input) => Promise.resolve({
        schemaVersion: "1.0.0", forwardingAttemptId: input.authorization.forwardingAttemptId,
        provenance: null, result: null, release: null, trustEvidenceEligible: false,
        error: {
          schemaVersion: "1.0.0", errorId: "error-approved-client-runtime",
          requestId: candidate.action.requestId, sessionId: candidate.action.sessionId,
          origin: "DOWNSTREAM", code: "downstream.transport_failure",
          safeMessage: "The downstream result was withheld by the gateway.",
          retryable: false, possiblePartialEffects: true, downstreamContentSuppressed: true,
          detailsDigest: computeCanonicalDigestV1({ failure: "transport" }),
          occurredAt: now.toISOString()
        }
      }) },
      clock: () => now,
      forwardingAttemptIdFactory: () => "attempt-approved-client-error-runtime",
      outcomeIdFactory: () => "outcome-approved-client-error-runtime"
    });
    const result = await executor.execute({
      approvalId: candidate.approval.approvalId, session: candidate.session
    });
    expect(result.release).toBeNull();
    expect(terminal).toMatchObject([{
      status: "UNKNOWN", possiblePartialEffects: true,
      forwardingAttemptId: "attempt-approved-client-error-runtime"
    }]);
  });

  it.each([
    { mode: "timeout", expected: "TIMED_OUT" },
    { mode: "cancel", expected: "CANCELLED" }
  ] as const)("persists $expected for trusted $mode aborts", async ({ mode, expected }) => {
    const candidate = createPostgresTrajectoryFixtureV1(`approved-client-${mode}`, now);
    const terminal: Array<{ status: string }> = [];
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => ({
        session: candidate.session, request: candidate.request, action: candidate.action,
        decision: candidate.decision, approval: candidate.approval
      }),
      store: {
        consumeApprovalAndStartForwarding: () => Promise.resolve(),
        recordResultAndOutcome: () => Promise.reject(new Error("unexpected governed result")),
        recordTerminalOutcome: (outcome) => { terminal.push(outcome); return Promise.resolve(); }
      },
      issueCredentialLease: () => `lease-${mode}`,
      forwarder: { execute: async (input) => {
        if (input.signal?.aborted !== true) {
          await new Promise<void>((resolve) => input.signal?.addEventListener("abort", () => { resolve(); }, { once: true }));
        }
        return {
          schemaVersion: "1.0.0", forwardingAttemptId: input.authorization.forwardingAttemptId,
          provenance: null, result: null, release: null, trustEvidenceEligible: false,
          error: {
            schemaVersion: "1.0.0", errorId: `error-${mode}`,
            requestId: candidate.action.requestId, sessionId: candidate.action.sessionId,
            origin: "DOWNSTREAM", code: "downstream.cancelled",
            safeMessage: "The downstream result was withheld by the gateway.", retryable: false,
            possiblePartialEffects: true, downstreamContentSuppressed: true,
            detailsDigest: computeCanonicalDigestV1({ mode }), occurredAt: now.toISOString()
          }
        };
      } },
      clock: () => now,
      forwardingAttemptIdFactory: () => `attempt-${mode}`,
      outcomeIdFactory: () => `outcome-${mode}`,
      executionTimeoutMs: mode === "timeout" ? 5 : 5_000
    });
    const controller = new AbortController();
    const execution = executor.execute({
      approvalId: candidate.approval.approvalId, session: candidate.session,
      signal: controller.signal
    });
    if (mode === "cancel") controller.abort(new Error("cancelled by caller"));
    await execution;
    expect(terminal[0]?.status).toBe(expected);
  });

  it("records a non-partial terminal failure when credential lease issuance fails after consumption", async () => {
    const candidate = createPostgresTrajectoryFixtureV1("approved-client-lease-failure", now);
    const terminal: Array<{ status: string; possiblePartialEffects: boolean }> = [];
    const executor = new ClientApprovedCallExecutorV1({
      loadApprovedCall: () => ({
        session: candidate.session, request: candidate.request, action: candidate.action,
        decision: candidate.decision, approval: candidate.approval
      }),
      store: {
        consumeApprovalAndStartForwarding: () => Promise.resolve(),
        recordResultAndOutcome: () => Promise.reject(new Error("unreachable")),
        recordTerminalOutcome: (outcome) => { terminal.push(outcome); return Promise.resolve(); }
      },
      issueCredentialLease: () => Promise.reject(new Error("vault unavailable")),
      forwarder: { execute: () => Promise.reject(new Error("unreachable")) },
      clock: () => now,
      forwardingAttemptIdFactory: () => "attempt-lease-failure",
      outcomeIdFactory: () => "outcome-lease-failure"
    });
    await expect(executor.execute({
      approvalId: candidate.approval.approvalId, session: candidate.session
    })).rejects.toThrow("vault unavailable");
    expect(terminal).toMatchObject([{ status: "FAILED", possiblePartialEffects: false }]);
  });
});
