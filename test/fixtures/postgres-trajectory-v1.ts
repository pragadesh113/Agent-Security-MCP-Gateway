import {
  DeterministicPolicyEngineV1,
  bindAuthenticatedIdentityToSessionV1,
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  type ApprovalV1,
  type ApprovedForwardingAuthorizationV1,
  type AuthenticatedSessionIdentityBindingV1,
  type CanonicalActionV1,
  type DownstreamProvenanceV1,
  type DownstreamResultV1,
  type DownstreamServerRouteBindingV1,
  type ExecutionOutcomeV1,
  type PolicyDecisionV1,
  type ToolCallRequestV1
} from "../../src/index.js";

export interface PostgresTrajectoryFixtureV1 {
  readonly session: AuthenticatedSessionIdentityBindingV1;
  readonly binding: DownstreamServerRouteBindingV1;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
  readonly request: ToolCallRequestV1;
  readonly action: CanonicalActionV1;
  readonly decision: PolicyDecisionV1;
  readonly approval: ApprovalV1;
  readonly authorization: ApprovedForwardingAuthorizationV1;
  readonly provenance: DownstreamProvenanceV1;
  readonly result: DownstreamResultV1;
  readonly outcome: ExecutionOutcomeV1;
  readonly policyDigest: string;
}

export function createPostgresTrajectoryFixtureV1(
  suffix: string,
  baseTime = new Date()
): PostgresTrajectoryFixtureV1 {
  const at = (offsetMs: number): string => new Date(baseTime.getTime() + offsetMs).toISOString();
  const principal = {
    schemaVersion: "1.0.0" as const,
    userId: `user-${suffix}`,
    agentId: `agent-${suffix}`,
    clientId: `client-${suffix}`,
    host: { hostId: `host-${suffix}`, name: "PostgreSQL fixture", version: "1.0.0" },
    authentication: {
      method: "TEST_FIXTURE" as const,
      credentialId: `client-credential-${suffix}`,
      identityRevision: 1,
      authenticatedAt: at(0)
    }
  };
  const session = bindAuthenticatedIdentityToSessionV1(principal, `transport-${suffix}`);
  const inputSchema = {
    type: "object",
    properties: { record_id: { type: "string" } },
    required: ["record_id"],
    additionalProperties: false
  };
  const outputSchema = {
    type: "object",
    properties: { ok: { type: "boolean" } },
    required: ["ok"]
  };
  const schemaDigest = computeCanonicalDigestV1({ inputSchema, outputSchema });
  const binding: DownstreamServerRouteBindingV1 = {
    server: {
      schemaVersion: "1.0.0",
      serverId: `server-${suffix}`,
      displayName: "Disposable PostgreSQL trajectory server",
      authenticatedPrincipalId: `downstream-principal-${suffix}`,
      authenticationMethod: "TEST_FIXTURE",
      mcpProtocolVersion: "2025-06-18",
      transport: {
        kind: "STREAMABLE_HTTP",
        endpoint: "http://127.0.0.1:3999/mcp",
        authenticationProfileId: `server-auth-${suffix}`
      },
      credentialAudience: {
        audienceId: `audience-${suffix}`,
        credentialProfileId: `credential-profile-${suffix}`
      },
      capabilities: ["tools"],
      capabilityIntegrity: {
        registeredDigest: "a".repeat(64), observedDigest: "a".repeat(64),
        state: "VERIFIED", observedAt: at(0)
      },
      health: { state: "HEALTHY", checkedAt: at(0), reasonCodes: [] },
      registration: {
        source: "TEST_FIXTURE", registeredBy: `admin-${suffix}`,
        registeredAt: at(0), revision: 1, evidenceDigest: "b".repeat(64)
      }
    },
    route: {
      schemaVersion: "1.0.0",
      routeId: `route-${suffix}`,
      serverId: `server-${suffix}`,
      toolName: "database.delete_row",
      exposedName: `database.delete_row.${suffix}`,
      credentialAudienceId: `audience-${suffix}`,
      policyScopeId: `policy-scope-${suffix}`,
      environment: "PRODUCTION",
      resourceMapping: {
        resourceClass: "DATABASE", resolverId: `database-resolver-${suffix}`,
        scope: "disposable"
      },
      schemaIntegrity: {
        registeredDigest: schemaDigest, observedDigest: schemaDigest,
        state: "VERIFIED", observedAt: at(0)
      },
      status: "ACTIVE",
      registeredAt: at(0)
    }
  };
  const argumentsValue = { record_id: `row-${suffix}` };
  const request: ToolCallRequestV1 = {
    schemaVersion: "1.0.0",
    requestId: `request-${suffix}`,
    protocolRequestId: `protocol-${suffix}`,
    sessionId: session.stateNamespace,
    route: {
      serverId: binding.server.serverId, routeId: binding.route.routeId,
      toolName: binding.route.toolName, exposedName: binding.route.exposedName,
      schemaDigest, credentialAudienceId: binding.route.credentialAudienceId,
      policyScopeId: binding.route.policyScopeId
    },
    arguments: argumentsValue,
    argumentsDigest: computeCanonicalDigestV1(argumentsValue),
    payloadBytes: computeCanonicalJsonByteLengthV1(argumentsValue),
    nonce: `nonce-${suffix}`,
    requestedAt: at(1_000),
    callChain: {
      callChainId: `chain-${suffix}`, parentRequestId: null, depth: 0, delegationDepth: 0
    },
    contentTrust: "UNTRUSTED",
    credentialsExcluded: true
  };
  const resources = [{
    resourceId: `database-row-${suffix}`,
    resourceClass: "DATABASE" as const,
    canonicalReference: `postgres://disposable/orders/${suffix}`,
    classification: "CONFIDENTIAL" as const
  }];
  const dataFlow = {
    direction: "NONE" as const,
    classifications: ["CONFIDENTIAL" as const],
    externalDestination: false,
    destinationId: null
  };
  const actionInput = {
    schemaVersion: "1.0.0" as const,
    requestId: request.requestId,
    actionId: `action-${suffix}`,
    sessionId: session.stateNamespace,
    identity: {
      userId: principal.userId, agentId: principal.agentId,
      clientId: principal.clientId, hostId: principal.host.hostId
    },
    route: {
      serverId: binding.server.serverId, routeId: binding.route.routeId,
      toolName: binding.route.toolName, schemaDigest,
      credentialAudienceId: binding.route.credentialAudienceId,
      policyScopeId: binding.route.policyScopeId
    },
    arguments: {
      digest: request.argumentsDigest, keys: ["record_id"], secretValuesRemoved: true as const
    },
    resources,
    resourcesDigest: computeCanonicalDigestV1(resources),
    effect: "DELETE" as const,
    environment: "PRODUCTION" as const,
    dataFlow,
    dataFlowDigest: computeCanonicalDigestV1(dataFlow),
    parsingEvidence: {
      parserId: `database-resolver-${suffix}`, parserVersion: "1.0.0",
      status: "FULL" as const, evidenceDigest: "c".repeat(64)
    },
    reversibility: "IRREVERSIBLE" as const,
    callChain: {
      callChainId: request.callChain.callChainId, parentActionId: null,
      ancestorActionIds: [], depth: 0, delegationDepth: 0
    },
    influences: ["USER_INPUT" as const],
    createdAt: at(1_000)
  };
  const action: CanonicalActionV1 = {
    ...actionInput,
    actionHash: computeCanonicalDigestV1(actionInput)
  };
  const policyVersion = `policy-${suffix}`;
  const decision = new DeterministicPolicyEngineV1({
    policyVersion,
    clock: () => new Date(at(2_000)),
    decisionIdFactory: () => `decision-${suffix}`
  }).evaluate({ action, coverage: "ENFORCED" });
  const approval: ApprovalV1 = {
    schemaVersion: "1.0.0",
    approvalId: `approval-${suffix}`,
    decisionId: decision.decisionId,
    requestId: action.requestId,
    actionId: action.actionId,
    actionHash: action.actionHash,
    sessionId: action.sessionId,
    identity: action.identity,
    route: action.route,
    resourcesDigest: action.resourcesDigest,
    environment: action.environment,
    dataFlowDigest: action.dataFlowDigest,
    policyVersion,
    state: "APPROVED",
    requestedAt: at(3_000),
    decidedAt: at(4_000),
    expiresAt: at(5 * 60_000 - 1),
    decidedByHumanId: `human-${suffix}`,
    consumption: null
  };
  const authorization: ApprovedForwardingAuthorizationV1 = {
    schemaVersion: "1.0.0",
    forwardingAttemptId: `forward-${suffix}`,
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
    policyVersion,
    authorizedAt: at(5_000)
  };
  const provenance: DownstreamProvenanceV1 = {
    schemaVersion: "1.0.0",
    provenanceId: `provenance-${suffix}`,
    requestId: action.requestId,
    actionId: action.actionId,
    sessionId: action.sessionId,
    callChainId: action.callChain.callChainId,
    serverId: action.route.serverId,
    authenticatedPrincipalId: binding.server.authenticatedPrincipalId,
    routeId: action.route.routeId,
    toolName: action.route.toolName,
    schemaDigest: action.route.schemaDigest,
    transportEvidenceDigest: "d".repeat(64),
    receivedAt: at(6_000),
    contentTrust: "UNTRUSTED"
  };
  const result: DownstreamResultV1 = {
    schemaVersion: "1.0.0",
    resultId: `result-${suffix}`,
    provenanceId: provenance.provenanceId,
    requestId: action.requestId,
    actionId: action.actionId,
    sessionId: action.sessionId,
    serverId: action.route.serverId,
    routeId: action.route.routeId,
    resultKind: "SUCCESS",
    mediaType: "application/json",
    byteLength: 128,
    contentDigest: "e".repeat(64),
    schemaValidation: "VALID",
    schemaDigest: action.route.schemaDigest,
    classifications: ["PUBLIC"],
    redaction: { state: "NONE", fieldsRedacted: 0, evidenceDigest: "f".repeat(64) },
    untrustedContentMarkers: ["downstream.content.untrusted"],
    disposition: "ALLOW",
    processedAt: at(7_000)
  };
  const outcome: ExecutionOutcomeV1 = {
    schemaVersion: "1.0.0",
    outcomeId: `outcome-${suffix}`,
    requestId: action.requestId,
    actionId: action.actionId,
    sessionId: action.sessionId,
    decisionId: decision.decisionId,
    approvalId: approval.approvalId,
    forwardingAttemptId: authorization.forwardingAttemptId,
    resultId: result.resultId,
    provenanceId: provenance.provenanceId,
    status: "COMPLETED",
    forwardedAt: authorization.authorizedAt,
    finishedAt: at(8_000),
    possiblePartialEffects: false,
    recoveryClass: "IRREVERSIBLE",
    trustEvidenceEligible: true,
    observedAt: at(8_000)
  };
  return {
    session, binding, inputSchema, outputSchema, request, action, decision, approval,
    authorization, provenance, result, outcome,
    policyDigest: computeCanonicalDigestV1({ policyVersion })
  };
}
