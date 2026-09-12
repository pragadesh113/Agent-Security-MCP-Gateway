import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { describe, expect, it } from "vitest";

import {
  CoverageBoundPolicyEvaluatorV1,
  ApprovalFatigueRecorderV1,
  DeterministicPolicyEngineV1,
  DisposableCredentialVaultV1,
  DisposableExactForwarderV1,
  ExclusiveMediationMonitorV1,
  TrustworthyInterfaceBuilderV1,
  computeCanonicalDigestV1,
  type CoverageEvidenceProbeV1,
  type CoverageEvidenceStatusV1,
  type CoveragePathKindV1,
  type CoverageScopeV1,
  type MediationGuaranteeV1
} from "../../src/index.js";
import { createPostgresTrajectoryFixtureV1 } from "../fixtures/postgres-trajectory-v1.js";

const requiredGuarantees = {
  GATEWAY_MEDIATED: [
    "CLIENT_AUTHENTICATION", "ROUTE_INTEGRITY", "POLICY_ENFORCEMENT",
    "POSTGRES_PERSISTENCE", "APPROVAL_ENFORCEMENT", "PROTOCOL_GUARDS",
    "DOWNSTREAM_AUTHENTICATION", "RESULT_MEDIATION", "CREDENTIAL_EXCLUSIVITY"
  ],
  NATIVE: ["CREDENTIAL_EXCLUSIVITY", "SANDBOX_ISOLATION", "OS_ISOLATION"],
  DIRECT: [
    "CREDENTIAL_EXCLUSIVITY", "NETWORK_ISOLATION", "IAM_ISOLATION",
    "DOWNSTREAM_AUTHORIZATION"
  ]
} as const satisfies Readonly<Record<CoveragePathKindV1, readonly MediationGuaranteeV1[]>>;

function createTestFixtureProbes(
  now: Date,
  directNetworkStatus: () => CoverageEvidenceStatusV1
): readonly CoverageEvidenceProbeV1[] {
  return (Object.entries(requiredGuarantees) as Array<
    [CoveragePathKindV1, readonly MediationGuaranteeV1[]]
  >).flatMap(([pathKind, guarantees]) => guarantees.map((guarantee) => {
    const verifierId = `test-fixture-${pathKind.toLowerCase()}-${guarantee.toLowerCase()}`;
    return {
      guarantee,
      pathKind,
      verifierId,
      authority: "test-fixture-authority",
      observe: (scope: CoverageScopeV1) => {
        const status = pathKind === "DIRECT" && guarantee === "NETWORK_ISOLATION"
          ? directNetworkStatus()
          : pathKind === "GATEWAY_MEDIATED" ? "VERIFIED_ENFORCING" : "VERIFIED_BLOCKED";
        return {
          schemaVersion: "1.0.0" as const,
          evidenceId: `${verifierId}-evidence`,
          guarantee,
          pathKind,
          verifierId,
          authority: "test-fixture-authority",
          verifierClass: "TEST_FIXTURE" as const,
          assurance: "DISPOSABLE_TEST" as const,
          scope,
          status,
          revision: status === "REACHABLE" ? 2 : 1,
          observedAt: now.toISOString(),
          expiresAt: new Date(now.getTime() + 30_000).toISOString(),
          proofDigest: computeCanonicalDigestV1({
            fixture: "exclusive-mediation-workflow-v1",
            guarantee,
            pathKind,
            status
          })
        };
      }
    };
  }));
}

describe("disposable exclusive-mediation workflow", () => {
  it("blocks direct mutation, permits the credentialed gateway path, then denies after a reachable bypass", async () => {
    const now = new Date();
    const credential = "test-fixture-route-credential";
    let mutations = 0;
    const downstream = createServer((request, response) => {
      void (async () => {
        for await (const chunk of request) {
          // Drain the disposable request before replying.
          void chunk;
        }
        if (request.headers.authorization !== `Bearer ${credential}`) {
          response.statusCode = 401;
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
        mutations += 1;
        response.statusCode = 200;
        response.setHeader("Content-Type", "application/json");
        response.setHeader("Mcp-Server-Authorization", "test-fixture-server-proof");
        response.end(JSON.stringify({
          jsonrpc: "2.0",
          id: "protocol-exclusive-mediation",
          result: {
            content: [{ type: "text", text: "disposable mutation completed" }],
            structuredContent: { ok: true }
          }
        }));
      })();
    });
    await new Promise<void>((resolve, reject) => {
      downstream.once("error", reject);
      downstream.listen(0, "127.0.0.1", () => {
        downstream.off("error", reject);
        resolve();
      });
    });

    const address = downstream.address();
    if (address === null || typeof address === "string") throw new Error("HTTP fixture failed");
    const origin = `http://127.0.0.1:${String(address.port)}`;
    const candidate = createPostgresTrajectoryFixtureV1("exclusive-mediation", now);
    const request = {
      ...candidate.request,
      protocolRequestId: "protocol-exclusive-mediation"
    };
    const binding = {
      ...candidate.binding,
      server: {
        ...candidate.binding.server,
        transport: {
          kind: "STREAMABLE_HTTP" as const,
          endpoint: `${origin}/mcp`,
          authenticationProfileId: "test-fixture-server-auth"
        }
      }
    };
    const scope: CoverageScopeV1 = {
      userId: candidate.action.identity.userId,
      agentId: candidate.action.identity.agentId,
      clientId: candidate.action.identity.clientId,
      hostId: candidate.action.identity.hostId,
      stateNamespace: candidate.action.sessionId,
      serverId: candidate.action.route.serverId,
      routeId: candidate.action.route.routeId,
      toolName: candidate.action.route.toolName,
      schemaDigest: candidate.action.route.schemaDigest,
      policyScopeId: candidate.action.route.policyScopeId,
      environment: candidate.action.environment,
      credentialAudienceId: candidate.action.route.credentialAudienceId,
      credentialProfileId: binding.server.credentialAudience.credentialProfileId,
      resourceClass: candidate.action.resources[0]?.resourceClass ?? "UNKNOWN",
      resourceId: candidate.action.resources[0]?.resourceId ?? "unknown-resource",
      resourcesDigest: candidate.action.resourcesDigest
    };
    let directNetworkStatus: CoverageEvidenceStatusV1 = "VERIFIED_BLOCKED";
    const probes = createTestFixtureProbes(now, () => directNetworkStatus);
    const authorities = Object.fromEntries(
      [...new Set(Object.values(requiredGuarantees).flat())]
        .map((guarantee) => [guarantee, ["test-fixture-authority"]])
    );
    let assessmentSequence = 0;
    const monitor = new ExclusiveMediationMonitorV1({
      probes,
      assurance: "DISPOSABLE_TEST",
      trustedAuthorities: authorities,
      clock: () => now,
      assessmentIdFactory: () => `test-fixture-assessment-${String(++assessmentSequence)}`
    });
    let decisionSequence = 0;
    const evaluator = new CoverageBoundPolicyEvaluatorV1(
      monitor,
      new DeterministicPolicyEngineV1({
        policyVersion: candidate.decision.policyVersion,
        clock: () => now,
        decisionIdFactory: () => `test-fixture-decision-${String(++decisionSequence)}`
      })
    );
    const vault = new DisposableCredentialVaultV1({
      clock: () => now,
      leaseIdFactory: () => "test-fixture-lease"
    });

    try {
      const direct = await fetch(`${origin}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "direct-test-fixture-attempt",
          method: "tools/call",
          params: { name: binding.route.toolName, arguments: request.arguments }
        })
      });
      expect(direct.status).toBe(401);
      expect(mutations).toBe(0);

      const credentialMaterial = Buffer.from(credential, "utf8");
      vault.registerCredential({
        schemaVersion: "1.0.0",
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        credentialRevision: 1,
        credentialKind: "BEARER_TOKEN",
        audienceId: binding.route.credentialAudienceId,
        allowedRouteIds: [binding.route.routeId],
        allowedEndpointOrigins: [origin],
        materialDigest: createHash("sha256").update(credentialMaterial).digest("hex"),
        status: "ACTIVE",
        issuedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + 30 * 60_000).toISOString()
      }, credentialMaterial);
      credentialMaterial.fill(0);
      const lease = vault.issueLease(candidate.session, {
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        audienceId: binding.route.credentialAudienceId,
        routeId: binding.route.routeId
      });
      const forwarder = new DisposableExactForwarderV1({
        credentialVault: vault,
        resolveCurrentRoute: () => binding,
        authenticateDownstream: ({ authentication }) => ({
          schemaVersion: "1.0.0",
          serverId: binding.server.serverId,
          principalId: binding.server.authenticatedPrincipalId,
          authenticationMethod: "TEST_FIXTURE",
          credentialId: authentication === "test-fixture-server-proof"
            ? "test-fixture-server-credential" : "invalid-test-fixture-server-credential",
          identityRevision: 1,
          authenticatedAt: now.toISOString()
        }),
        validateOutputSchema: ({ structuredContent }) => structuredContent?.["ok"] === true,
        classifyResult: () => ["PUBLIC"],
        evaluateEgress: () => "ALLOW"
      });

      const enforced = await evaluator.evaluate({ action: candidate.action, scope });
      expect(enforced.assessment.coverage).toBe("ENFORCED");
      expect(enforced.decision.decision).toBe("REQUIRE_APPROVAL");
      expect(JSON.stringify(enforced.assessment)).not.toContain(credential);
      const { view, awareness } = new TrustworthyInterfaceBuilderV1({ clock: () => now }).build({
        action: candidate.action,
        decision: enforced.decision,
        coverage: enforced.assessment,
        relatedAttemptIds: ["disposable-direct-denial"]
      });
      const fatigue = new ApprovalFatigueRecorderV1(() => now);
      fatigue.recordPresentation(view);
      fatigue.recordApproval(view, {
        ...candidate.approval,
        decisionId: enforced.decision.decisionId,
        state: "APPROVED",
        requestedAt: now.toISOString(),
        decidedAt: new Date(now.getTime() + 1_000).toISOString(),
        expiresAt: new Date(now.getTime() + 60_000).toISOString(),
        consumption: null
      });
      expect(awareness).toMatchObject({
        decision: "REQUIRE_APPROVAL",
        generatedFromCanonicalData: true,
        coverage: "ENFORCED"
      });
      expect(fatigue.snapshot(view.route.policyScopeId)).toMatchObject({
        presentations: 1,
        approvals: 1,
        repeatedRelatedAttempts: 1,
        meanDecisionLatencyMs: 1_000
      });
      const mediated = await monitor.executeProtectedMutation({
        scope,
        expectedEvidenceDigest: enforced.assessment.evidenceDigest,
        operation: async () => forwarder.execute({
          authorization: candidate.authorization,
          action: candidate.action,
          request,
          session: candidate.session,
          credentialLeaseId: lease.leaseId
        })
      });
      expect(mediated.release?.structuredContent).toEqual({ ok: true });
      expect(mutations).toBe(1);

      directNetworkStatus = "REACHABLE";
      const degraded = await evaluator.evaluate({ action: candidate.action, scope });
      expect(degraded.assessment.coverage).toBe("DEGRADED");
      expect(degraded.assessment.paths).toContainEqual(expect.objectContaining({
        pathKind: "DIRECT",
        coverage: "UNPROTECTED"
      }));
      expect(degraded.assessment.missingGuarantees).toContainEqual(expect.objectContaining({
        guarantee: "NETWORK_ISOLATION",
        pathKind: "DIRECT",
        reasonCode: "coverage.network_isolation.reachable"
      }));
      expect(degraded.decision).toMatchObject({
        decision: "DENY",
        coverage: "DEGRADED"
      });
      await expect(monitor.executeProtectedMutation({
        scope,
        expectedEvidenceDigest: enforced.assessment.evidenceDigest,
        operation: async () => forwarder.execute({
          authorization: candidate.authorization,
          action: candidate.action,
          request,
          session: candidate.session,
          credentialLeaseId: lease.leaseId
        })
      })).rejects.toThrow(/exclusive-mediation coverage/u);
      expect(JSON.stringify(degraded.assessment)).not.toContain(credential);
      expect(mutations).toBe(1);
    } finally {
      vault.destroy();
      await new Promise<void>((resolve, reject) => {
        downstream.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
      });
    }
  });
});
