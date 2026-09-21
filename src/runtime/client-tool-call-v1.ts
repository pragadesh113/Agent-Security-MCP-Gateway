import { randomUUID } from "node:crypto";

import { z } from "zod";

import {
  boundedProtocolJsonObjectV1Schema,
  toolCallRequestV1Schema,
  type ToolCallRequestV1
} from "../contracts/boundary-v1.js";
import {
  downstreamServerRouteBindingV1Schema,
  type CoverageStateV1,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import type { PolicyDecisionV1 } from "../contracts/trajectory-v1.js";
import {
  approvalV1Schema,
  canonicalActionDecisionBindingV1Schema,
  canonicalActionV1Schema,
  policyDecisionV1Schema,
  type ApprovalV1,
  type CanonicalActionV1,
  type ExecutionOutcomeV1
} from "../contracts/trajectory-v1.js";
import type { AwarenessV1 } from "../contracts/boundary-v1.js";
import {
  approvedForwardingAuthorizationV1Schema,
  type ApprovedForwardingAuthorizationV1
} from "../approval/disposable-approval-v1.js";
import type { ExclusiveMediationAssessmentV1 } from "../coverage/exclusive-mediation-v1.js";
import {
  ForwardingDeniedV1,
  type MediatedForwardingResultV1
} from "../forwarding/disposable-forwarding-v1.js";
import type { TrustworthyInterfaceBuilderV1 } from "../interfaces/trustworthy-interface-v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";
import {
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  type CanonicalActionNormalizerV1
} from "../action-normalizer/canonical-action-v1.js";
import type { DeterministicPolicyEngineV1 } from "../policy-engine/deterministic-policy-v1.js";
import type {
  DisposableProtocolGuardV1,
  GuardedOperationResultV1,
  ProtocolOperationRequestV1
} from "../protocol/protocol-guard-v1.js";

const protocolRequestIdV1Schema = z.union([
  z.string().min(1).max(128),
  z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
]);
const digestV1Schema = z.string().regex(/^[a-f0-9]{64}$/u);

export interface ResolvedClientToolRouteV1 {
  readonly binding: DownstreamServerRouteBindingV1;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown> | null;
}

export interface ClientToolCallDecisionStoreV1 {
  persistDecisionTrajectory(input: {
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly binding: DownstreamServerRouteBindingV1;
    readonly inputSchema: Record<string, unknown>;
    readonly outputSchema: Record<string, unknown> | null;
    readonly request: ToolCallRequestV1;
    readonly action: ReturnType<CanonicalActionNormalizerV1["normalize"]>;
    readonly decision: PolicyDecisionV1;
    readonly policyDigest: string;
  }): Promise<void>;
}

export interface ClientToolCallCoordinatorV1Options {
  readonly policyScopeId: string;
  readonly environment: "DEVELOPMENT" | "TEST" | "STAGING" | "PRODUCTION" | "UNKNOWN";
  readonly policyDigest: string;
  readonly resolveRoute: (input: {
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly policyScopeId: string;
    readonly environment: ClientToolCallCoordinatorV1Options["environment"];
    readonly exposedName: string;
  }) => ResolvedClientToolRouteV1;
  readonly protocolGuard: DisposableProtocolGuardV1;
  readonly normalizer: CanonicalActionNormalizerV1;
  readonly policy: DeterministicPolicyEngineV1;
  readonly assessCoverage: (
    action: ReturnType<CanonicalActionNormalizerV1["normalize"]>
  ) => ExclusiveMediationAssessmentV1 | Promise<ExclusiveMediationAssessmentV1>;
  readonly interfaceBuilder: TrustworthyInterfaceBuilderV1;
  readonly store: ClientToolCallDecisionStoreV1;
  readonly clock?: () => Date;
  readonly nonceFactory?: () => string;
  readonly callChainIdFactory?: () => string;
}

export interface ClientToolCallInputV1 {
  readonly requestId: string;
  readonly protocolRequestId: string | number;
  readonly session: AuthenticatedSessionIdentityBindingV1;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
  readonly signal?: AbortSignal;
}

export interface ClientToolCallDecisionResultV1 {
  readonly isError: true;
  readonly content: readonly [{ readonly type: "text"; readonly text: string }];
  readonly structuredContent: {
    readonly schemaVersion: "1.0.0";
    readonly decision: PolicyDecisionV1["decision"];
    readonly tier: PolicyDecisionV1["tier"];
    readonly coverage: CoverageStateV1;
    readonly downstreamInvoked: false;
    readonly awareness: AwarenessV1;
  };
}

export interface ApprovedClientToolCallV1 {
  readonly session: AuthenticatedSessionIdentityBindingV1;
  readonly request: ToolCallRequestV1;
  readonly action: CanonicalActionV1;
  readonly decision: PolicyDecisionV1;
  readonly approval: ApprovalV1;
}

export interface ClientApprovedCallStoreV1 {
  consumeApprovalAndStartForwarding(authorization: ApprovedForwardingAuthorizationV1): Promise<void>;
  recordResultAndOutcome(input: {
    readonly authorization: ApprovedForwardingAuthorizationV1;
    readonly provenance: NonNullable<MediatedForwardingResultV1["provenance"]>;
    readonly result: NonNullable<MediatedForwardingResultV1["result"]>;
    readonly outcome: ExecutionOutcomeV1;
    readonly trustEvidenceId?: string;
  }): Promise<void>;
  recordTerminalOutcome(outcome: ExecutionOutcomeV1): Promise<void>;
}

export interface ClientApprovedCallForwarderV1 {
  execute(input: {
    readonly authorization: ApprovedForwardingAuthorizationV1;
    readonly action: CanonicalActionV1;
    readonly request: ToolCallRequestV1;
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly credentialLeaseId: string;
    readonly signal?: AbortSignal;
  }): Promise<MediatedForwardingResultV1>;
}

export interface ClientApprovedCallExecutorV1Options {
  readonly loadApprovedCall: (input: {
    readonly approvalId: string;
    readonly session: AuthenticatedSessionIdentityBindingV1;
  }) => ApprovedClientToolCallV1 | Promise<ApprovedClientToolCallV1>;
  readonly store: ClientApprovedCallStoreV1;
  readonly forwarder: ClientApprovedCallForwarderV1;
  readonly issueCredentialLease: (input: {
    readonly call: ApprovedClientToolCallV1;
    readonly authorization: ApprovedForwardingAuthorizationV1;
  }) => string | Promise<string>;
  readonly clock?: () => Date;
  readonly forwardingAttemptIdFactory?: () => string;
  readonly outcomeIdFactory?: () => string;
  readonly trustEvidenceIdFactory?: () => string;
  readonly executionTimeoutMs?: number;
}

/** Trusted approval continuation. Clients select only an approval ID; all authority is reloaded. */
export class ClientApprovedCallExecutorV1 {
  readonly #options: ClientApprovedCallExecutorV1Options;

  public constructor(options: ClientApprovedCallExecutorV1Options) {
    this.#options = options;
    if (options.executionTimeoutMs !== undefined &&
      (!Number.isSafeInteger(options.executionTimeoutMs) || options.executionTimeoutMs <= 0 ||
        options.executionTimeoutMs > 5 * 60_000)) {
      throw new RangeError("Approved call timeout must be between one millisecond and five minutes");
    }
  }

  public async execute(input: {
    readonly approvalId: string;
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly signal?: AbortSignal;
  }): Promise<MediatedForwardingResultV1> {
    const approvalId = z.string().min(1).max(128).parse(input.approvalId);
    const callerSession = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    const callerAborted = (): boolean => input.signal?.aborted ?? false;
    if (callerAborted()) throw new Error("Approved client call was cancelled before consumption");
    const loaded = await this.#options.loadApprovedCall({ approvalId, session: callerSession });
    const session = authenticatedSessionIdentityBindingV1Schema.parse(loaded.session);
    const request = toolCallRequestV1Schema.parse(loaded.request);
    const action = canonicalActionV1Schema.parse(loaded.action);
    const decision = policyDecisionV1Schema.parse(loaded.decision);
    const approval = approvalV1Schema.parse(loaded.approval);
    canonicalActionDecisionBindingV1Schema.parse({ action, decision });
    if (approval.approvalId !== approvalId || approval.state !== "APPROVED" ||
      decision.decision !== "REQUIRE_APPROVAL" || decision.coverage !== "ENFORCED" ||
      session.transportSessionId !== callerSession.transportSessionId ||
      computeCanonicalDigestV1(session) !== computeCanonicalDigestV1(callerSession) ||
      request.requestId !== action.requestId || request.sessionId !== action.sessionId ||
      approval.requestId !== action.requestId || approval.actionId !== action.actionId ||
      approval.actionHash !== action.actionHash || approval.decisionId !== decision.decisionId ||
      approval.sessionId !== session.stateNamespace) {
      throw new Error("Approved client call binding is invalid");
    }
    const authorization = approvedForwardingAuthorizationV1Schema.parse({
      schemaVersion: "1.0.0",
      forwardingAttemptId: this.#options.forwardingAttemptIdFactory?.() ?? randomUUID(),
      approvalId: approval.approvalId,
      requestId: action.requestId,
      actionId: action.actionId,
      actionHash: action.actionHash,
      sessionId: action.sessionId,
      serverId: action.route.serverId,
      routeId: action.route.routeId,
      toolName: action.route.toolName,
      schemaDigest: action.route.schemaDigest,
      credentialAudienceId: action.route.credentialAudienceId,
      policyScopeId: action.route.policyScopeId,
      resourcesDigest: action.resourcesDigest,
      environment: action.environment,
      dataFlowDigest: action.dataFlowDigest,
      policyVersion: decision.policyVersion,
      authorizedAt: (this.#options.clock?.() ?? new Date()).toISOString()
    });
    await this.#options.store.consumeApprovalAndStartForwarding(authorization);
    const persistFailure = async (
      status: "FAILED" | "UNKNOWN",
      possiblePartialEffects: boolean
    ): Promise<void> => this.#options.store.recordTerminalOutcome({
      schemaVersion: "1.0.0",
      outcomeId: this.#options.outcomeIdFactory?.() ?? randomUUID(),
      requestId: action.requestId,
      actionId: action.actionId,
      sessionId: action.sessionId,
      decisionId: decision.decisionId,
      approvalId: approval.approvalId,
      forwardingAttemptId: authorization.forwardingAttemptId,
      resultId: null,
      provenanceId: null,
      status,
      forwardedAt: authorization.authorizedAt,
      finishedAt: (this.#options.clock?.() ?? new Date()).toISOString(),
      possiblePartialEffects,
      recoveryClass: action.effect === "READ" ? "NOT_APPLICABLE" :
        action.reversibility === "IRREVERSIBLE" ? "IRREVERSIBLE" : "UNKNOWN",
      trustEvidenceEligible: false,
      observedAt: (this.#options.clock?.() ?? new Date()).toISOString()
    });
    let credentialLeaseId: string;
    try {
      credentialLeaseId = await this.#options.issueCredentialLease({
        call: { session, request, action, decision, approval },
        authorization
      });
    } catch (error) {
      await persistFailure("FAILED", false);
      throw error;
    }
    const executionController = new AbortController();
    const timeoutState = { expired: false };
    const cancel = () => { executionController.abort(input.signal?.reason); };
    input.signal?.addEventListener("abort", cancel, { once: true });
    if (callerAborted()) cancel();
    const timer = this.#options.executionTimeoutMs === undefined ? undefined : setTimeout(() => {
      timeoutState.expired = true;
      executionController.abort(new Error("Approved call execution timed out"));
    }, this.#options.executionTimeoutMs);
    let mediated: MediatedForwardingResultV1;
    try {
      mediated = await this.#options.forwarder.execute({
        authorization, action, request, session, credentialLeaseId,
        signal: executionController.signal
      });
    } catch (error) {
      await persistFailure(
        error instanceof ForwardingDeniedV1 ? "FAILED" : "UNKNOWN",
        !(error instanceof ForwardingDeniedV1)
      );
      throw error;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      input.signal?.removeEventListener("abort", cancel);
    }
    const observedAt = mediated.result?.processedAt ?? (this.#options.clock?.() ?? new Date()).toISOString();
    const status: ExecutionOutcomeV1["status"] = mediated.result !== null
      ? (mediated.result.resultKind === "SUCCESS" ? "COMPLETED" : "FAILED")
      : mediated.error?.code === "downstream.cancelled"
        ? (timeoutState.expired ? "TIMED_OUT" : "CANCELLED")
        : mediated.error?.possiblePartialEffects === true ? "UNKNOWN" : "FAILED";
    const outcome: ExecutionOutcomeV1 = {
      schemaVersion: "1.0.0",
      outcomeId: this.#options.outcomeIdFactory?.() ?? randomUUID(),
      requestId: action.requestId,
      actionId: action.actionId,
      sessionId: action.sessionId,
      decisionId: decision.decisionId,
      approvalId: approval.approvalId,
      forwardingAttemptId: authorization.forwardingAttemptId,
      resultId: mediated.result?.resultId ?? null,
      provenanceId: mediated.provenance?.provenanceId ?? null,
      status,
      forwardedAt: authorization.authorizedAt,
      finishedAt: observedAt,
      possiblePartialEffects: mediated.error?.possiblePartialEffects ?? false,
      recoveryClass: action.effect === "READ" ? "NOT_APPLICABLE" :
        action.reversibility === "IRREVERSIBLE" ? "IRREVERSIBLE" : "UNKNOWN",
      trustEvidenceEligible: status === "COMPLETED" && mediated.trustEvidenceEligible,
      observedAt
    };
    if (mediated.provenance !== null && mediated.result !== null) {
      await this.#options.store.recordResultAndOutcome({
        authorization,
        provenance: mediated.provenance,
        result: mediated.result,
        outcome,
        ...(outcome.trustEvidenceEligible
          ? { trustEvidenceId: this.#options.trustEvidenceIdFactory?.() ?? randomUUID() }
          : {})
      });
    } else {
      await this.#options.store.recordTerminalOutcome(outcome);
    }
    return mediated;
  }
}

/**
 * Host-neutral call-admission slice. It deliberately stops after the decision is
 * durable; approval and forwarding are composed by the following P2-F016 slices.
 */
export class ClientToolCallCoordinatorV1 {
  readonly #options: ClientToolCallCoordinatorV1Options;

  public constructor(options: ClientToolCallCoordinatorV1Options) {
    this.#options = options;
    z.string().min(1).max(128).parse(options.policyScopeId);
    digestV1Schema.parse(options.policyDigest);
  }

  public async handle(input: ClientToolCallInputV1): Promise<ClientToolCallDecisionResultV1> {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    const requestId = z.string().min(1).max(128).parse(input.requestId);
    const protocolRequestId = protocolRequestIdV1Schema.parse(input.protocolRequestId);
    const exposedName = z.string().min(1).max(256).parse(input.name);
    const argumentsValue = boundedProtocolJsonObjectV1Schema.parse(input.arguments);
    const resolved = this.#resolve(session, exposedName);
    const now = this.#options.clock?.() ?? new Date();
    const request = toolCallRequestV1Schema.parse({
      schemaVersion: "1.0.0",
      requestId,
      protocolRequestId,
      sessionId: session.stateNamespace,
      route: {
        serverId: resolved.binding.server.serverId,
        routeId: resolved.binding.route.routeId,
        toolName: resolved.binding.route.toolName,
        exposedName: resolved.binding.route.exposedName,
        schemaDigest: resolved.binding.route.schemaIntegrity.registeredDigest,
        credentialAudienceId: resolved.binding.route.credentialAudienceId,
        policyScopeId: resolved.binding.route.policyScopeId
      },
      arguments: argumentsValue,
      argumentsDigest: computeCanonicalDigestV1(argumentsValue),
      payloadBytes: computeCanonicalJsonByteLengthV1(argumentsValue),
      nonce: this.#options.nonceFactory?.() ?? randomUUID(),
      requestedAt: now.toISOString(),
      callChain: {
        callChainId: this.#options.callChainIdFactory?.() ?? randomUUID(),
        parentRequestId: null,
        depth: 0,
        delegationDepth: 0
      },
      contentTrust: "UNTRUSTED",
      credentialsExcluded: true
    });
    const admission = this.#admissionRequest(request, session, resolved.binding);
    return this.#options.protocolGuard.run(admission, async (tools) => {
      const throwIfAborted = (): void => {
        if (tools.signal.aborted) throw tools.signal.reason;
      };
      throwIfAborted();
      const action = this.#options.normalizer.normalize({
        request,
        session,
        binding: resolved.binding
      });
      const coverage = await this.#options.assessCoverage(action);
      throwIfAborted();
      const decision = this.#options.policy.evaluate({
        action,
        coverage: coverage.coverage
      });
      throwIfAborted();
      await this.#options.store.persistDecisionTrajectory({
        session,
        binding: resolved.binding,
        inputSchema: resolved.inputSchema,
        outputSchema: resolved.outputSchema,
        request,
        action,
        decision,
        policyDigest: this.#options.policyDigest
      });
      throwIfAborted();
      const { awareness } = this.#options.interfaceBuilder.build({
        action,
        decision,
        coverage
      });
      const value: ClientToolCallDecisionResultV1 = {
        isError: true,
        content: [{ type: "text", text: awareness.factualSummary }],
        structuredContent: {
          schemaVersion: "1.0.0",
          decision: decision.decision,
          tier: decision.tier,
          coverage: decision.coverage,
          downstreamInvoked: false,
          awareness
        }
      };
      return {
        value,
        resultBytes: Buffer.byteLength(JSON.stringify(value), "utf8")
      } satisfies GuardedOperationResultV1<ClientToolCallDecisionResultV1>;
    }, input.signal);
  }

  #resolve(
    session: AuthenticatedSessionIdentityBindingV1,
    exposedName: string
  ): ResolvedClientToolRouteV1 {
    const resolved = this.#options.resolveRoute({
      session,
      policyScopeId: this.#options.policyScopeId,
      environment: this.#options.environment,
      exposedName
    });
    const binding = downstreamServerRouteBindingV1Schema.parse(resolved.binding);
    if (
      binding.route.policyScopeId !== this.#options.policyScopeId ||
      binding.route.environment !== this.#options.environment ||
      binding.route.exposedName !== exposedName
    ) {
      throw new Error("Resolved route does not match the configured call authority");
    }
    return {
      binding,
      inputSchema: boundedProtocolJsonObjectV1Schema.parse(resolved.inputSchema),
      outputSchema: resolved.outputSchema === null
        ? null
        : boundedProtocolJsonObjectV1Schema.parse(resolved.outputSchema)
    };
  }

  #admissionRequest(
    request: ToolCallRequestV1,
    session: AuthenticatedSessionIdentityBindingV1,
    binding: DownstreamServerRouteBindingV1
  ): ProtocolOperationRequestV1 {
    return {
      schemaVersion: "1.0.0",
      requestId: request.requestId,
      nonce: request.nonce,
      requestedAt: request.requestedAt,
      session,
      serverId: binding.server.serverId,
      toolName: binding.route.toolName,
      routeId: binding.route.routeId,
      destinationId: binding.server.serverId,
      actionFamily: binding.route.resourceMapping.resourceClass.toLowerCase(),
      callChain: {
        callChainId: request.callChain.callChainId,
        parentRequestId: null,
        depth: 0,
        delegationDepth: 0,
        ancestry: []
      },
      payloadBytes: request.payloadBytes,
      expectedResultBytes: 1024 * 1024,
      fanOut: 0,
      redirectCount: 0,
      retryCount: 0,
      mutation: true,
      requiredDependencies: ["route-registry", "canonicalizer", "policy", "postgres"]
    };
  }
}
