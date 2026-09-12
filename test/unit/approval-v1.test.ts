import { describe, expect, it } from "vitest";

import {
  ApprovalDeniedV1,
  DeterministicPolicyEngineV1,
  DisposableApprovalServiceV1,
  DisposableSessionStateRepositoryV1,
  approvalV1Schema,
  bindAuthenticatedIdentityToSessionV1,
  computeCanonicalDigestV1,
  humanApprovalDecisionV1Schema,
  type ApprovalAuditReaderAuthorityV1,
  type AuthenticatedClientPrincipalV1,
  type AuthenticatedSessionIdentityBindingV1,
  type CanonicalActionV1,
  type DownstreamServerRouteBindingV1,
  type PolicyDecisionV1
} from "../../src/index.js";

const requestedAt = "2026-09-04T10:00:01.000Z";
const auditor: ApprovalAuditReaderAuthorityV1 = {
  schemaVersion: "1.0.0",
  administratorId: "auditor-approval",
  role: "APPROVAL_AUDITOR",
  authenticatedAt: requestedAt
};
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-approval",
  agentId: "agent-approval",
  clientId: "client-approval",
  host: { hostId: "host-approval", name: "Approval test host", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "client-credential-approval",
    identityRevision: 1,
    authenticatedAt: "2026-09-04T10:00:00.000Z"
  }
};

function routeBinding(schemaDigest = "a".repeat(64)): DownstreamServerRouteBindingV1 {
  return {
    server: {
      schemaVersion: "1.0.0",
      serverId: "server-approval",
      displayName: "Disposable approval server",
      authenticatedPrincipalId: "principal-server-approval",
      authenticationMethod: "TEST_FIXTURE",
      mcpProtocolVersion: "2025-06-18",
      transport: {
        kind: "STREAMABLE_HTTP",
        endpoint: "http://127.0.0.1:3250/mcp",
        authenticationProfileId: "downstream-auth-approval"
      },
      credentialAudience: { audienceId: "audience-approval", credentialProfileId: "profile-approval" },
      capabilities: ["tools"],
      capabilityIntegrity: { registeredDigest: "b".repeat(64), observedDigest: "b".repeat(64), state: "VERIFIED", observedAt: requestedAt },
      health: { state: "HEALTHY", checkedAt: requestedAt, reasonCodes: [] },
      registration: { source: "TEST_FIXTURE", registeredBy: "admin-approval", registeredAt: requestedAt, revision: 1, evidenceDigest: "c".repeat(64) }
    },
    route: {
      schemaVersion: "1.0.0",
      routeId: "route-approval",
      serverId: "server-approval",
      toolName: "database.delete_row",
      exposedName: "database.delete_row",
      credentialAudienceId: "audience-approval",
      policyScopeId: "scope-approval",
      environment: "PRODUCTION",
      resourceMapping: { resourceClass: "DATABASE", resolverId: "database-v1", scope: "disposable:production" },
      schemaIntegrity: { registeredDigest: schemaDigest, observedDigest: schemaDigest, state: "VERIFIED", observedAt: requestedAt },
      status: "ACTIVE",
      registeredAt: requestedAt
    }
  };
}

function fixture(): {
  action: CanonicalActionV1;
  decision: PolicyDecisionV1;
  session: AuthenticatedSessionIdentityBindingV1;
  binding: DownstreamServerRouteBindingV1;
} {
  const session = bindAuthenticatedIdentityToSessionV1(principal, "transport-approval");
  const binding = routeBinding();
  const resources = [{
    resourceId: "database-record-42",
    resourceClass: "DATABASE" as const,
    canonicalReference: "postgres://disposable/orders/42",
    classification: "CONFIDENTIAL" as const
  }];
  const dataFlow = { direction: "NONE" as const, classifications: ["CONFIDENTIAL" as const], externalDestination: false, destinationId: null };
  const actionInput = {
    schemaVersion: "1.0.0" as const,
    requestId: "request-approval",
    actionId: "action-approval",
    sessionId: session.stateNamespace,
    identity: {
      userId: principal.userId,
      agentId: principal.agentId,
      clientId: principal.clientId,
      hostId: principal.host.hostId
    },
    route: {
      serverId: binding.server.serverId,
      routeId: binding.route.routeId,
      toolName: binding.route.toolName,
      schemaDigest: binding.route.schemaIntegrity.registeredDigest,
      credentialAudienceId: binding.route.credentialAudienceId,
      policyScopeId: binding.route.policyScopeId
    },
    arguments: { digest: "d".repeat(64), keys: ["record_id"], secretValuesRemoved: true as const },
    resources,
    resourcesDigest: computeCanonicalDigestV1(resources),
    effect: "DELETE" as const,
    environment: "PRODUCTION" as const,
    dataFlow,
    dataFlowDigest: computeCanonicalDigestV1(dataFlow),
    parsingEvidence: { parserId: "database-v1", parserVersion: "1.0.0", status: "FULL" as const, evidenceDigest: "e".repeat(64) },
    reversibility: "IRREVERSIBLE" as const,
    callChain: { callChainId: "chain-approval", parentActionId: null, ancestorActionIds: [], depth: 0, delegationDepth: 0 },
    influences: ["USER_INPUT" as const],
    createdAt: "2026-09-04T10:00:00.000Z"
  };
  const action: CanonicalActionV1 = { ...actionInput, actionHash: computeCanonicalDigestV1(actionInput) };
  const decision = new DeterministicPolicyEngineV1({
    policyVersion: "policy-1.0.0",
    clock: () => new Date("2026-09-04T10:00:00.500Z"),
    decisionIdFactory: () => "decision-approval"
  }).evaluate({ action, coverage: "ENFORCED" });
  return { action, decision, session, binding };
}

interface ServiceState {
  now: Date;
  humanAllowed: boolean;
  auditAllowed: boolean;
  identityValid: boolean;
  currentBinding: DownstreamServerRouteBindingV1;
  currentDecision: PolicyDecisionV1;
}

function createService(state: ServiceState): DisposableApprovalServiceV1 {
  let eventSequence = 0;
  return new DisposableApprovalServiceV1({
    humanAuthorizer: (candidate) => state.humanAllowed && candidate.humanId === "human-approval",
    auditAuthorizer: (candidate) => state.auditAllowed && candidate.administratorId === auditor.administratorId,
    identityRevalidator: () => state.identityValid,
    routeRevalidator: () => state.currentBinding,
    policyRevalidator: () => state.currentDecision,
    clock: () => new Date(state.now),
    approvalIdFactory: () => "approval-exact",
    consumptionIdFactory: () => "consumption-exact",
    forwardingAttemptIdFactory: () => "forwarding-exact",
    eventIdFactory: () => `approval-event-${String(++eventSequence)}`
  });
}

function initialState(candidate = fixture()): ServiceState {
  return {
    now: new Date(requestedAt),
    humanAllowed: true,
    auditAllowed: true,
    identityValid: true,
    currentBinding: candidate.binding,
    currentDecision: candidate.decision
  };
}

function approve(service: DisposableApprovalServiceV1, candidate = fixture()) {
  const approval = service.requestApproval(candidate);
  return service.recordHumanDecision({
    schemaVersion: "1.0.0",
    approvalId: approval.approvalId,
    actionHash: candidate.action.actionHash,
    humanId: "human-approval",
    authenticationMethod: "TEST_FIXTURE",
    decision: "APPROVE",
    authenticatedAt: approval.requestedAt
  });
}

describe("disposable exact approval lifecycle", () => {
  it("creates a five-minute approval bound to identity, action, route, resources, environment, and policy", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = service.requestApproval(candidate);
    expect(approval).toMatchObject({
      decisionId: candidate.decision.decisionId,
      actionHash: candidate.action.actionHash,
      sessionId: candidate.session.stateNamespace,
      identity: candidate.action.identity,
      route: candidate.action.route,
      resourcesDigest: candidate.action.resourcesDigest,
      environment: "PRODUCTION",
      dataFlowDigest: candidate.action.dataFlowDigest,
      policyVersion: "policy-1.0.0",
      state: "PENDING"
    });
    expect(Date.parse(approval.expiresAt) - Date.parse(approval.requestedAt)).toBe(300_000);
  });

  it("accepts only authenticated, exact, single-action human decisions", () => {
    const candidate = fixture();
    const state = initialState(candidate);
    state.humanAllowed = false;
    const service = createService(state);
    const approval = service.requestApproval(candidate);
    expect(() => service.recordHumanDecision({
      schemaVersion: "1.0.0", approvalId: approval.approvalId, actionHash: candidate.action.actionHash,
      humanId: "human-approval", authenticationMethod: "TEST_FIXTURE", decision: "APPROVE",
      authenticatedAt: approval.requestedAt
    })).toThrow(ApprovalDeniedV1);
    expect(humanApprovalDecisionV1Schema.safeParse({
      schemaVersion: "1.0.0", approvalId: approval.approvalId, actionHash: candidate.action.actionHash,
      humanId: "human-approval", authenticationMethod: "TEST_FIXTURE", decision: "APPROVE",
      authenticatedAt: approval.requestedAt, alwaysAllow: true
    }).success).toBe(false);
  });

  it("records explicit human denial and never permits its consumption", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = service.requestApproval(candidate);
    const denied = service.recordHumanDecision({
      schemaVersion: "1.0.0", approvalId: approval.approvalId, actionHash: candidate.action.actionHash,
      humanId: "human-approval", authenticationMethod: "TEST_FIXTURE", decision: "DENY",
      authenticatedAt: approval.requestedAt
    });
    expect(denied.state).toBe("DENIED");
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
  });

  it("atomically consumes immediately before one exact forwarding start", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = approve(service, candidate);
    let starts = 0;
    const result = service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, (authorization) => {
      starts += 1;
      expect(service.readApproval(auditor, approval.approvalId).state).toBe("CONSUMED");
      expect(authorization).toMatchObject({
        forwardingAttemptId: "forwarding-exact",
        approvalId: approval.approvalId,
        actionHash: candidate.action.actionHash,
        routeId: candidate.binding.route.routeId,
        schemaDigest: candidate.action.route.schemaDigest
      });
      return "begun";
    });
    expect(result).toBe("begun");
    expect(starts).toBe(1);
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => { starts += 1; }); }).toThrow(ApprovalDeniedV1);
    expect(starts).toBe(1);
    expect(service.readApproval(auditor, approval.approvalId).state).toBe("CONSUMED");
  });

  it("rejects consumption before approval and repeated or reordered human decisions", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = service.requestApproval(candidate);
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
    approve(createService(initialState(candidate)), candidate);
    const decided = service.recordHumanDecision({
      schemaVersion: "1.0.0", approvalId: approval.approvalId, actionHash: candidate.action.actionHash,
      humanId: "human-approval", authenticationMethod: "TEST_FIXTURE", decision: "APPROVE",
      authenticatedAt: approval.requestedAt
    });
    expect(decided.state).toBe("APPROVED");
    expect(() => service.recordHumanDecision({
      schemaVersion: "1.0.0", approvalId: approval.approvalId, actionHash: candidate.action.actionHash,
      humanId: "human-approval", authenticationMethod: "TEST_FIXTURE", decision: "DENY",
      authenticatedAt: approval.requestedAt
    })).toThrow(ApprovalDeniedV1);
  });

  it("expires pending and already-approved records at the deadline", () => {
    for (const decideFirst of [false, true]) {
      const candidate = fixture();
      const state = initialState(candidate);
      const service = createService(state);
      const approval = decideFirst ? approve(service, candidate) : service.requestApproval(candidate);
      state.now = new Date(approval.expiresAt);
      expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
      expect(service.readApproval(auditor, approval.approvalId).state).toBe("EXPIRED");
    }
  });

  it("rejects modified action, decision, session, and approval bindings without consuming the valid approval", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = approve(service, candidate);
    const alteredAction = { ...candidate.action, resourcesDigest: "f".repeat(64) };
    const alteredDecision = { ...candidate.decision, policyVersion: "policy-2.0.0" };
    const alteredSession = { ...candidate.session, identity: { ...candidate.session.identity, identityRevision: 2 } };
    for (const changed of [
      { ...candidate, action: alteredAction },
      { ...candidate, decision: alteredDecision },
      { ...candidate, session: alteredSession }
    ]) {
      expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...changed }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
      expect(service.readApproval(auditor, approval.approvalId).state).toBe("APPROVED");
    }
  });

  it("never creates or consumes an approval while current coverage is not enforced", () => {
    const candidate = fixture();
    const degradedDecision = { ...candidate.decision, coverage: "DEGRADED" as const };
    const state = initialState(candidate);
    const service = createService(state);
    expect(() => service.requestApproval({ ...candidate, decision: degradedDecision })).toThrow();

    const approval = approve(service, candidate);
    state.currentDecision = degradedDecision;
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
    expect(service.readApproval(auditor, approval.approvalId).state).toBe("REVOKED");
  });

  it("allows exactly one winner under parallel replay attempts", async () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = approve(service, candidate);
    let starts = 0;
    const results = await Promise.allSettled(Array.from({ length: 16 }, () =>
      Promise.resolve().then(() => service.consumeAndBeginForwarding(
        { approvalId: approval.approvalId, ...candidate },
        () => ++starts
      ))
    ));
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(15);
    expect(starts).toBe(1);
  });

  it("revalidates identity, exact route/schema, and current policy immediately before consumption", () => {
    const failureStates = [
      (state: ServiceState) => { state.identityValid = false; },
      (state: ServiceState) => { state.currentBinding = { ...state.currentBinding, route: { ...state.currentBinding.route, status: "DISABLED" } }; },
      (state: ServiceState) => { state.currentDecision = { ...state.currentDecision, decision: "DENY", reasonCodes: ["policy.changed"] }; }
    ];
    for (const change of failureStates) {
      const candidate = fixture();
      const state = initialState(candidate);
      const service = createService(state);
      const approval = approve(service, candidate);
      change(state);
      let starts = 0;
      expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => { starts += 1; }); }).toThrow(ApprovalDeniedV1);
      expect(starts).toBe(0);
      expect(service.readApproval(auditor, approval.approvalId).state).toBe("REVOKED");
    }
  });

  it("revokes active approvals when their authenticated session is invalidated", () => {
    const candidate = fixture();
    const state = initialState(candidate);
    const service = createService(state);
    const sessions = new DisposableSessionStateRepositoryV1([service]);
    sessions.createSession(candidate.session);
    const approval = approve(service, candidate);
    sessions.closeSession(principal, candidate.session.transportSessionId);
    expect(service.readApproval(auditor, approval.approvalId).state).toBe("REVOKED");
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
  });

  it("keeps a failed forwarding start consumed so retry needs a new approval", () => {
    const candidate = fixture();
    const service = createService(initialState(candidate));
    const approval = approve(service, candidate);
    expect(() => service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => { throw new Error("start failed"); })).toThrow(ApprovalDeniedV1);
    expect(service.readApproval(auditor, approval.approvalId).state).toBe("CONSUMED");
    expect(() => { service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => "not-started"); }).toThrow(ApprovalDeniedV1);
  });

  it("emits only allowlisted audit metadata and protects audit/approval reads", () => {
    const candidate = fixture();
    const state = initialState(candidate);
    const service = createService(state);
    const approval = approve(service, candidate);
    service.consumeAndBeginForwarding({ approvalId: approval.approvalId, ...candidate }, () => undefined);
    const audit = service.readAudit(auditor);
    expect(audit.map((event) => event.eventType)).toEqual(["APPROVAL_REQUESTED", "HUMAN_APPROVED", "APPROVAL_CONSUMED"]);
    const serialized = JSON.stringify({ approval, audit });
    expect(serialized).not.toContain("approvalToken");
    expect(serialized).not.toContain("authorizationHeader");
    expect(serialized).not.toContain("credentialValue");
    state.auditAllowed = false;
    expect(() => service.readAudit(auditor)).toThrow(ApprovalDeniedV1);
    expect(() => service.readApproval(auditor, approval.approvalId)).toThrow(ApprovalDeniedV1);
  });

  it("rejects overlong lifetimes and invalid approval contract states", () => {
    const candidate = fixture();
    const state = initialState(candidate);
    expect(() => new DisposableApprovalServiceV1({
      humanAuthorizer: () => true,
      auditAuthorizer: () => true,
      identityRevalidator: () => true,
      routeRevalidator: () => candidate.binding,
      policyRevalidator: () => candidate.decision,
      approvalLifetimeMs: 300_001
    })).toThrow();
    expect(approvalV1Schema.safeParse({
      ...createService(state).requestApproval(candidate),
      state: "CONSUMED",
      consumption: null
    }).success).toBe(false);
  });
});
