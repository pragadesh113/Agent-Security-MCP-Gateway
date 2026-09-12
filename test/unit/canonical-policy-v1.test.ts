import { describe, expect, it } from "vitest";

import {
  CanonicalActionNormalizerV1,
  CanonicalizationDeniedV1,
  DeterministicPolicyEngineV1,
  bindAuthenticatedIdentityToSessionV1,
  classifyCanonicalRiskTierV1,
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1,
  createConstraintV1,
  normalizeCanonicalReferenceV1,
  type AuthenticatedClientPrincipalV1,
  type CanonicalActionAnalysisV1,
  type DeterministicPolicyRuleV1,
  type DownstreamServerRouteBindingV1,
  type PolicyAdvisoryV1
} from "../../src/index.js";

const now = "2026-09-04T09:00:00.000Z";
const principal: AuthenticatedClientPrincipalV1 = {
  schemaVersion: "1.0.0",
  userId: "user-policy",
  agentId: "agent-policy",
  clientId: "client-policy",
  host: { hostId: "host-policy", name: "Policy test", version: "1.0.0" },
  authentication: {
    method: "TEST_FIXTURE",
    credentialId: "credential-policy",
    identityRevision: 1,
    authenticatedAt: now
  }
};
const session = bindAuthenticatedIdentityToSessionV1(principal, "transport-policy");

function binding(options: {
  serverId?: string;
  routeId?: string;
  toolName?: string;
  exposedName?: string;
  environment?: "DEVELOPMENT" | "TEST" | "STAGING" | "PRODUCTION";
  resourceClass?: CanonicalActionAnalysisV1["resources"][number]["resourceClass"];
  resolverId?: string;
  transport?: "STREAMABLE_HTTP" | "SSE";
} = {}): DownstreamServerRouteBindingV1 {
  const serverId = options.serverId ?? "server-files";
  const routeId = options.routeId ?? "route-files";
  const toolName = options.toolName ?? "filesystem.operation";
  const digest = computeCanonicalDigestV1({ routeId });
  return {
    server: {
      schemaVersion: "1.0.0",
      serverId,
      displayName: "Disposable server",
      authenticatedPrincipalId: `principal-${serverId}`,
      authenticationMethod: "TEST_FIXTURE",
      mcpProtocolVersion: "2025-06-18",
      transport: {
        kind: options.transport ?? "STREAMABLE_HTTP",
        endpoint: "http://127.0.0.1:3210/mcp",
        authenticationProfileId: "server-auth"
      },
      credentialAudience: { audienceId: "audience-policy", credentialProfileId: "profile-policy" },
      capabilities: ["tools"],
      capabilityIntegrity: { registeredDigest: digest, observedDigest: digest, state: "VERIFIED", observedAt: now },
      health: { state: "HEALTHY", checkedAt: now, reasonCodes: [] },
      registration: { source: "TEST_FIXTURE", registeredBy: "admin-policy", registeredAt: now, revision: 1, evidenceDigest: digest }
    },
    route: {
      schemaVersion: "1.0.0",
      routeId,
      serverId,
      toolName,
      exposedName: options.exposedName ?? toolName,
      credentialAudienceId: "audience-policy",
      policyScopeId: "scope-policy",
      environment: options.environment ?? "TEST",
      resourceMapping: {
        resourceClass: options.resourceClass ?? "FILESYSTEM",
        resolverId: options.resolverId ?? "filesystem-v1",
        scope: "disposable:test"
      },
      schemaIntegrity: { registeredDigest: digest, observedDigest: digest, state: "VERIFIED", observedAt: now },
      status: "ACTIVE",
      registeredAt: now
    }
  };
}

function request(routeBinding: DownstreamServerRouteBindingV1, args: Record<string, unknown>, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: "1.0.0",
    requestId: "request-policy",
    protocolRequestId: 1,
    sessionId: session.stateNamespace,
    route: {
      serverId: routeBinding.server.serverId,
      routeId: routeBinding.route.routeId,
      toolName: routeBinding.route.toolName,
      exposedName: routeBinding.route.exposedName,
      schemaDigest: routeBinding.route.schemaIntegrity.registeredDigest,
      credentialAudienceId: routeBinding.route.credentialAudienceId,
      policyScopeId: routeBinding.route.policyScopeId
    },
    arguments: args,
    argumentsDigest: computeCanonicalDigestV1(args),
    payloadBytes: computeCanonicalJsonByteLengthV1(args),
    nonce: "nonce-policy",
    requestedAt: now,
    callChain: { callChainId: "chain-policy", parentRequestId: null, depth: 0, delegationDepth: 0 },
    contentTrust: "UNTRUSTED",
    credentialsExcluded: true,
    ...overrides
  };
}

function analysis(overrides: Partial<CanonicalActionAnalysisV1> = {}): CanonicalActionAnalysisV1 {
  return {
    schemaVersion: "1.0.0",
    parserId: "filesystem-v1",
    parserVersion: "1.0.0",
    status: "FULL",
    resources: [{
      resourceId: "resource-readme",
      resourceClass: "FILESYSTEM",
      reference: "V:\\disposable\\repo\\README.md",
      referencePlatform: "WINDOWS",
      classification: "PUBLIC"
    }],
    effect: "READ",
    environment: "TEST",
    dataFlow: { direction: "NONE", classifications: ["PUBLIC"], externalDestination: false, destinationId: null },
    reversibility: "NOT_APPLICABLE",
    influences: ["USER_INPUT"],
    ...overrides
  };
}

function firstResource(): CanonicalActionAnalysisV1["resources"][number] {
  const resource = analysis().resources[0];
  if (resource === undefined) throw new Error("Test resource is unavailable");
  return resource;
}

function normalize(routeBinding = binding(), args: Record<string, unknown> = { path: "README.md" }, resolved = analysis()) {
  return new CanonicalActionNormalizerV1({
    resolvers: new Map([[routeBinding.route.resourceMapping.resolverId, () => resolved]]),
    clock: () => new Date(now),
    actionIdFactory: () => "action-policy"
  }).normalize({ request: request(routeBinding, args), session, binding: routeBinding });
}

function engine(options: ConstructorParameters<typeof DeterministicPolicyEngineV1>[0] = { policyVersion: "policy-1.0.0" }) {
  return new DeterministicPolicyEngineV1({
    clock: () => new Date("2026-09-04T09:00:01.000Z"),
    decisionIdFactory: () => "decision-policy",
    ...options
  });
}

describe("canonical action normalization", () => {
  it("binds trusted identity, current route evidence, computed digests, and normalized resources", () => {
    const action = normalize();
    expect(action).toMatchObject({
      sessionId: session.stateNamespace,
      identity: { userId: "user-policy", agentId: "agent-policy" },
      route: { routeId: "route-files", credentialAudienceId: "audience-policy" },
      resources: [{ resourceId: "resource-readme", canonicalReference: "v:/disposable/repo/readme.md" }],
      effect: "READ",
      environment: "TEST",
      parsingEvidence: { status: "FULL" }
    });
    const { actionHash, ...hashInput } = action;
    expect(actionHash).toBe(computeCanonicalDigestV1(hashInput));
  });

  it("denies forged session, route, schema, argument digest, and byte evidence", () => {
    const routeBinding = binding();
    const normalizer = new CanonicalActionNormalizerV1({ resolvers: new Map([["filesystem-v1", () => analysis()]]) });
    for (const forged of [
      { sessionId: "session-attacker" },
      { route: { ...request(routeBinding, {}).route, routeId: "route-attacker" } },
      { route: { ...request(routeBinding, {}).route, schemaDigest: "a".repeat(64) } },
      { argumentsDigest: "b".repeat(64) },
      { payloadBytes: 99 }
    ]) {
      expect(() => normalizer.normalize({ request: request(routeBinding, {}, forged), session, binding: routeBinding })).toThrow(CanonicalizationDeniedV1);
    }
  });

  it("turns absent, failing, and route-inconsistent resolvers into unresolved actions", () => {
    const routeBinding = binding();
    for (const resolvers of [
      new Map(),
      new Map([["filesystem-v1", () => { throw new Error("resolver failed"); }]]),
      new Map([["filesystem-v1", () => analysis({ environment: "PRODUCTION" })]])
    ]) {
      const action = new CanonicalActionNormalizerV1({ resolvers, actionIdFactory: () => "action-unresolved" })
        .normalize({ request: request(routeBinding, {}), session, binding: routeBinding });
      expect(action.effect).toBe("UNKNOWN");
      expect(action.environment).toBe("UNKNOWN");
      expect(["FAILED", "UNSUPPORTED"]).toContain(action.parsingEvidence.status);
    }
  });

  it("binds ordered ancestor actions and rejects forged ancestry", () => {
    const routeBinding = binding();
    const parent = normalize(routeBinding);
    const childRequest = request(routeBinding, { path: "README.md" }, {
      requestId: "request-child",
      nonce: "nonce-child",
      callChain: { callChainId: "chain-policy", parentRequestId: parent.requestId, depth: 1, delegationDepth: 1 }
    });
    const normalizer = new CanonicalActionNormalizerV1({ resolvers: new Map([["filesystem-v1", () => analysis()]]), actionIdFactory: () => "action-child" });
    expect(normalizer.normalize({ request: childRequest, session, binding: routeBinding, ancestorActions: [parent] }).callChain)
      .toMatchObject({ parentActionId: parent.actionId, ancestorActionIds: [parent.actionId] });
    expect(() => normalizer.normalize({ request: childRequest, session, binding: routeBinding, ancestorActions: [] })).toThrow(CanonicalizationDeniedV1);
  });

  it("normalizes Windows, POSIX, URI, case, dot-segment, and percent-encoded representations", () => {
    expect(normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: "V:\\Repo\\dir\\..\\README.md", referencePlatform: "WINDOWS", classification: "PUBLIC" }))
      .toBe("v:/repo/readme.md");
    expect(normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: "/srv/repo/%52EADME.md", referencePlatform: "POSIX", classification: "PUBLIC" }))
      .toBe("/srv/repo/README.md");
    expect(normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "NETWORK", reference: "HTTPS://EXAMPLE.COM:443/a/../b?z=2&a=1#ignored", referencePlatform: "URI", classification: "PUBLIC" }))
      .toBe("https://example.com/b?a=1&z=2");
    for (let depth = 1; depth <= 8; depth += 1) {
      let nestedTraversal = "../secret";
      for (let index = 0; index < depth; index += 1) nestedTraversal = encodeURIComponent(nestedTraversal);
      expect(normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: `C:/safe/${nestedTraversal}`, referencePlatform: "WINDOWS", classification: "PUBLIC" }))
        .toBe("c:/secret");
    }
    expect(normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: "C:%2fsafe%2f..%5csecret", referencePlatform: "WINDOWS", classification: "PUBLIC" }))
      .toBe("c:/secret");
    expect(() => normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: "C:/safe/%00/secret", referencePlatform: "WINDOWS", classification: "PUBLIC" }))
      .toThrow(CanonicalizationDeniedV1);
    expect(() => normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: "C:/safe/%zz/secret", referencePlatform: "WINDOWS", classification: "PUBLIC" }))
      .toThrow(CanonicalizationDeniedV1);
    expect(() => normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "NETWORK", reference: "https://user:secret@example.com/path", referencePlatform: "URI", classification: "PUBLIC" }))
      .toThrow(CanonicalizationDeniedV1);
    let excessiveEncoding = "../secret";
    for (let index = 0; index < 17; index += 1) excessiveEncoding = encodeURIComponent(excessiveEncoding);
    expect(() => normalizeCanonicalReferenceV1({ resourceId: "r", resourceClass: "FILESYSTEM", reference: excessiveEncoding, referencePlatform: "WINDOWS", classification: "PUBLIC" }))
      .toThrow(CanonicalizationDeniedV1);
  });
});

describe("deterministic most-restrictive policy", () => {
  it("allows only a fully parsed proven public read and has no keyword-absence allow path", () => {
    expect(engine().evaluate({ action: normalize(), coverage: "ENFORCED" })).toMatchObject({ decision: "ALLOW", tier: 0 });
    const opaque = new CanonicalActionNormalizerV1({ resolvers: new Map(), actionIdFactory: () => "action-opaque" })
      .normalize({ request: request(binding(), { harmless: "looks safe" }), session, binding: binding() });
    expect(engine().evaluate({ action: opaque, coverage: "ENFORCED" })).toMatchObject({ decision: "REQUIRE_APPROVAL", tier: 2 });
    expect(engine().evaluate({ action: opaque, coverage: "UNPROTECTED" }).decision).toBe("DENY");
  });

  it("classifies production, privileged, destructive, credential, and difficult-to-reverse effects as Tier 3", () => {
    const cases = [
      analysis({ environment: "PRODUCTION" }),
      analysis({ effect: "ADMINISTER", reversibility: "VERIFIED_COMPENSATING_ACTION" }),
      analysis({ effect: "DELETE", reversibility: "TESTED_SNAPSHOT" }),
      analysis({ resources: [{ ...firstResource(), classification: "CREDENTIAL" }] }),
      analysis({ effect: "WRITE", reversibility: "PARTIALLY_REVERSIBLE" })
    ];
    for (const candidate of cases) {
      const routeBinding = binding({ environment: candidate.environment === "PRODUCTION" ? "PRODUCTION" : "TEST" });
      const action = normalize(routeBinding, {}, candidate);
      expect(classifyCanonicalRiskTierV1(action)).toBe(3);
      expect(engine().evaluate({ action, coverage: "ENFORCED" }).decision).toBe("REQUIRE_APPROVAL");
      expect(engine().evaluate({ action, coverage: "DEGRADED" }).decision).toBe("DENY");
    }
  });

  it("composes DENY over approval, sandbox, constrained allow, and allow", () => {
    const action = normalize();
    const constraint = createConstraintV1("constraint-prefix", "filesystem.path_prefix", { prefix: "v:/disposable" });
    const rules: DeterministicPolicyRuleV1[] = [
      { schemaVersion: "1.0.0", ruleId: "allow-rule", authority: "ADMINISTRATOR", effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [], decision: "ALLOW", tierFloor: 0, reasonCodes: ["rule.allow"], constraints: [], sandboxProfileId: null },
      { schemaVersion: "1.0.0", ruleId: "constraint-rule", authority: "ADMINISTRATOR", effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [], decision: "ALLOW_WITH_CONSTRAINTS", tierFloor: 0, reasonCodes: ["rule.constrain"], constraints: [constraint], sandboxProfileId: null },
      { schemaVersion: "1.0.0", ruleId: "sandbox-rule", authority: "ADMINISTRATOR", effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [], decision: "SANDBOX", tierFloor: 2, reasonCodes: ["rule.sandbox"], constraints: [], sandboxProfileId: "sandbox-read" },
      { schemaVersion: "1.0.0", ruleId: "approval-rule", authority: "ADMINISTRATOR", effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [], decision: "REQUIRE_APPROVAL", tierFloor: 2, reasonCodes: ["rule.approval"], constraints: [], sandboxProfileId: null },
      { schemaVersion: "1.0.0", ruleId: "deny-rule", authority: "BUILT_IN", effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [], decision: "DENY", tierFloor: 2, reasonCodes: ["rule.deny"], constraints: [], sandboxProfileId: null }
    ];
    expect(engine({ policyVersion: "policy-1.0.0", rules }).evaluate({ action, coverage: "ENFORCED" })).toMatchObject({ decision: "DENY", tier: 2 });
  });

  it("does not let trust or supervisor allow bypass immutable denial or Tier 3 approval", () => {
    const deniedAction = normalize();
    const immutableDeny: DeterministicPolicyRuleV1 = {
      schemaVersion: "1.0.0", ruleId: "deny-readme", authority: "BUILT_IN", effects: [], environments: [], resourceClasses: [], classifications: [], resourceIds: ["resource-readme"], routeIds: [], decision: "DENY", tierFloor: 0, reasonCodes: ["builtin.protected_resource"], constraints: [], sandboxProfileId: null
    };
    const advisories: PolicyAdvisoryV1[] = [
      { schemaVersion: "1.0.0", source: "TRUST", decision: "ALLOW", reasonCodes: ["high_trust"] },
      { schemaVersion: "1.0.0", source: "SUPERVISOR", decision: "ALLOW", reasonCodes: ["looks_safe"] }
    ];
    expect(engine({ policyVersion: "policy-1.0.0", rules: [immutableDeny] }).evaluate({ action: deniedAction, coverage: "ENFORCED", advisories }).decision).toBe("DENY");
    const tierThree = normalize(binding(), {}, analysis({ effect: "DELETE", reversibility: "TESTED_SNAPSHOT" }));
    expect(engine().evaluate({ action: tierThree, coverage: "ENFORCED", advisories }).decision).toBe("REQUIRE_APPROVAL");
  });

  it("keeps equivalent effects equally restrictive across tools, servers, aliases, paths, encodings, syntax, and transports", () => {
    const variants = [
      { binding: binding({ serverId: "server-a", routeId: "route-a", toolName: "files.remove", exposedName: "delete.file", transport: "STREAMABLE_HTTP" }), args: { path: "V:\\Repo\\target.txt" } },
      { binding: binding({ serverId: "server-b", routeId: "route-b", toolName: "shell.execute", exposedName: "run.command", transport: "SSE" }), args: { command: "del V%3A%5CRepo%5Ctarget.txt" } },
      { binding: binding({ serverId: "server-c", routeId: "route-c", toolName: "workspace.mutate", exposedName: "remove.alias" }), args: { alias: "workspace-target" } }
    ];
    const outcomes = variants.map((variant, index) => {
      const equivalent = analysis({
        parserId: `resolver-${String(index)}`,
        resources: [{ resourceId: "resource-target", resourceClass: "FILESYSTEM", reference: index === 1 ? "v%3A/repo/./target.txt" : "V:\\Repo\\target.txt", referencePlatform: "WINDOWS", classification: "INTERNAL" }],
        effect: "DELETE",
        reversibility: "TESTED_SNAPSHOT"
      });
      const action = normalize(variant.binding, variant.args, equivalent);
      return { reference: action.resources[0]?.canonicalReference, decision: engine().evaluate({ action, coverage: "ENFORCED" }).decision, tier: classifyCanonicalRiskTierV1(action) };
    });
    expect(outcomes).toEqual([
      { reference: "v:/repo/target.txt", decision: "REQUIRE_APPROVAL", tier: 3 },
      { reference: "v:/repo/target.txt", decision: "REQUIRE_APPROVAL", tier: 3 },
      { reference: "v:/repo/target.txt", decision: "REQUIRE_APPROVAL", tier: 3 }
    ]);
  });

  it("fails closed on conflicting sandbox profiles and on all non-read actions without enforced coverage", () => {
    const action = normalize();
    const sandboxRule = (id: string, profile: string): DeterministicPolicyRuleV1 => ({
      schemaVersion: "1.0.0", ruleId: id, authority: "ADMINISTRATOR",
      effects: ["READ"], environments: [], resourceClasses: [], classifications: [], resourceIds: [], routeIds: [],
      decision: "SANDBOX", tierFloor: 2, reasonCodes: [`rule.${id}`], constraints: [], sandboxProfileId: profile
    });
    expect(engine({ policyVersion: "policy-1.0.0", rules: [sandboxRule("one", "sandbox-one"), sandboxRule("two", "sandbox-two")] })
      .evaluate({ action, coverage: "ENFORCED" }).decision).toBe("DENY");
    const write = normalize(binding(), {}, analysis({ effect: "WRITE", reversibility: "VERIFIED_COMPENSATING_ACTION", resources: [{ ...firstResource(), classification: "INTERNAL" }] }));
    for (const coverage of ["DEGRADED", "OBSERVE_ONLY", "UNPROTECTED"] as const) {
      expect(engine().evaluate({ action: write, coverage }).decision).toBe("DENY");
    }
  });
});
